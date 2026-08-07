//! Tauri command contract test (layer 2).
//!
//! For every `#[tauri::command]` function, asserts:
//!   1. The signature returns either `Result<T>` / `Result<T, E>` or a
//!      `serde::Serialize`-friendly bare type (Tauri's IPC layer needs to
//!      serialize whatever comes back).
//!   2. The body does not contain unconditional `panic!()` / `todo!()` /
//!      `unimplemented!()` / `unreachable!()` calls on the happy path —
//!      those would abort the desktop app at runtime instead of returning
//!      a typed error.
//!
//! This is a static-analysis test. Runtime invocation of commands lives
//! in the e2e golden-path test (which spins up an actual Tauri app), but
//! these static checks catch the cheap class of "command added but
//! signature drifted" / "panic snuck in" bugs without needing the full
//! mock-runtime ceremony.

use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() { walk_rs(&path, out); }
        else if path.extension().and_then(|s| s.to_str()) == Some("rs") { out.push(path); }
    }
}

#[derive(Debug, Clone)]
struct Command {
    name: String,
    signature: String,   // full `fn ...` line through the `->` return type
    body: String,        // {} block contents (single-pass, may include nested braces verbatim)
    file: PathBuf,
}

fn extract_commands() -> Vec<Command> {
    let mut files = Vec::new();
    walk_rs(&manifest_dir().join("src"), &mut files);

    let mut out = Vec::new();
    for path in files {
        let Ok(src) = fs::read_to_string(&path) else { continue };
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[tauri::command") { continue }

            // Walk forward to the `fn` line, then capture up to and including
            // the `->` return-type clause. Multi-line signatures are common,
            // so collect lines until we see `{` at the start of a balanced
            // body.
            let mut j = i + 1;
            while j < lines.len() && (lines[j].trim_start().starts_with("#[") || lines[j].trim().is_empty()) {
                j += 1;
            }
            if j >= lines.len() { continue }
            let fn_line = lines[j];
            let after_fn = fn_line
                .trim_start()
                .strip_prefix("pub async fn ")
                .or_else(|| fn_line.trim_start().strip_prefix("async fn "))
                .or_else(|| fn_line.trim_start().strip_prefix("pub fn "))
                .or_else(|| fn_line.trim_start().strip_prefix("fn "));
            let Some(rest) = after_fn else { continue };
            let name_end = rest.find(|c: char| c == '(' || c == '<').unwrap_or(rest.len());
            let name = rest[..name_end].trim().to_string();
            if name.is_empty() { continue }

            // Signature: from the `fn` line until we find the opening `{`
            // that begins the function body.
            let sig_start_idx = src
                .lines()
                .take(j)
                .map(|l| l.len() + 1)
                .sum::<usize>();
            let body_start_rel = src[sig_start_idx..]
                .find('{')
                .map(|n| sig_start_idx + n)
                .unwrap_or(src.len());
            let signature = src[sig_start_idx..body_start_rel].to_string();

            // Body: scan from `{` to matching `}` accounting for nesting.
            let bytes = src.as_bytes();
            let mut k = body_start_rel + 1;
            let mut depth = 1i32;
            while k < bytes.len() && depth > 0 {
                match bytes[k] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 { break }
                k += 1;
            }
            let body = src[body_start_rel + 1..k].to_string();

            out.push(Command { name, signature, body, file: path.clone() });
        }
    }
    out
}

/// Strip `//` and `/* */` comments and `"..."` string literals so static
/// scans of the body don't trip on tokens that appear inside them.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        // Line comment.
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"//" {
            while i < bytes.len() && bytes[i] != b'\n' { i += 1; }
            continue;
        }
        // Block comment.
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"/*" {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" { i += 1; }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // String literal (skip past closing quote, honoring \").
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() { i += 2; continue; }
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[test]
fn every_command_returns_a_serializable_type() {
    let commands = extract_commands();
    assert!(!commands.is_empty(), "command parser found nothing");

    // Tauri commands either return `Result<T>` / `Result<T, E>` or a
    // serializable bare type. We do not allow `()` returns — any command
    // that succeeds must have something for the frontend to inspect, even
    // if just `Ok(())`.
    let mut bad: Vec<String> = Vec::new();
    for cmd in &commands {
        let sig = cmd.signature.trim();
        // The `->` return clause must exist. A command with no return type
        // would default to `-> ()` which is allowed by Tauri but rejected
        // here because it gives the frontend nothing to assert on.
        if !sig.contains("->") {
            bad.push(format!(
                "{}: missing `->` return type ({})",
                cmd.name,
                cmd.file.display()
            ));
            continue;
        }
        // Acceptable: starts with `Result`, `Vec`, `Option`, `Box`, a
        // simple primitive like `bool` / `String` / `u64`, or a named
        // struct/enum (uppercase identifier). The crucial property is
        // that something nontrivial is returned.
        let ret = sig.rsplit("->").next().unwrap_or("").trim();
        let ret = ret.trim_end_matches('{').trim();
        if ret.is_empty() || ret == "()" {
            bad.push(format!("{}: returns `()` — frontend has nothing to inspect", cmd.name));
        }
    }

    assert!(
        bad.is_empty(),
        "commands with weak return signatures:\n{}",
        bad.iter().map(|b| format!("  - {}", b)).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn no_command_panics_on_happy_path() {
    let commands = extract_commands();
    let bad_tokens = ["panic!", "todo!", "unimplemented!", "unreachable!"];

    let mut violations: Vec<String> = Vec::new();
    for cmd in &commands {
        let cleaned = strip_comments_and_strings(&cmd.body);
        for tok in bad_tokens {
            if cleaned.contains(tok) {
                violations.push(format!(
                    "{}: body contains `{}` ({})",
                    cmd.name, tok, cmd.file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Tauri commands should return typed errors, never panic. Offenders:\n{}",
        violations
            .iter()
            .map(|v| format!("  - {}", v))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
