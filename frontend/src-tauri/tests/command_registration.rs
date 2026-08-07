//! Tauri command registration smoke test.
//!
//! Walks `src/` looking for `#[tauri::command]` annotations, then reads
//! `src/main.rs` and extracts the names inside the `generate_handler![ ... ]`
//! block. Asserts:
//!   1. every `#[tauri::command]` is registered in the handler block
//!   2. every name in the handler block resolves to a real annotated function
//!
//! Catches the class of bug where a command is added in source but never
//! wired into `invoke_handler!`, so the frontend gets "command not found"
//! at runtime.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Returns map of bare function name -> file path where it was found.
/// Skips files inside the `tests/` directory.
fn find_annotated_commands() -> HashMap<String, PathBuf> {
    let mut files = Vec::new();
    walk_rs_files(&manifest_dir().join("src"), &mut files);

    let mut found = HashMap::new();
    for path in files {
        let Ok(src) = fs::read_to_string(&path) else { continue };
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[tauri::command") {
                continue;
            }
            // Walk forward to the next `fn <name>` line, skipping attributes
            // and blank lines.
            for j in (i + 1)..lines.len().min(i + 10) {
                let next = lines[j].trim_start();
                if next.starts_with("#[") || next.is_empty() {
                    continue;
                }
                // Match `pub async fn name(`, `async fn name(`, `pub fn name(`, `fn name(`.
                let after_fn = next
                    .strip_prefix("pub async fn ")
                    .or_else(|| next.strip_prefix("async fn "))
                    .or_else(|| next.strip_prefix("pub fn "))
                    .or_else(|| next.strip_prefix("fn "));
                if let Some(rest) = after_fn {
                    if let Some(open) = rest.find(|c: char| c == '(' || c == '<') {
                        let name = rest[..open].trim().to_string();
                        if !name.is_empty() {
                            found.insert(name, path.clone());
                        }
                    }
                }
                break;
            }
        }
    }
    found
}

/// Extracts the leaf names from the `generate_handler![ ... ]` block in
/// `src/main.rs`. Lines in the block look like:
///     commands::system::get_system_status,
/// We capture `get_system_status`.
fn registered_commands() -> BTreeSet<String> {
    let main_rs = manifest_dir().join("src/main.rs");
    let src = fs::read_to_string(&main_rs).expect("read src/main.rs");

    let start = src
        .find("generate_handler![")
        .expect("generate_handler! block not found");
    // Find the matching `]` after the `[`. The block contents have no nested
    // brackets, so a forward scan to the first `]` after `start` is fine.
    let bracket_open = src[start..].find('[').unwrap() + start;
    let bracket_close = src[bracket_open..].find(']').expect("closing `]` for generate_handler!")
        + bracket_open;
    let body_raw = &src[bracket_open + 1..bracket_close];

    // Strip line comments first — commas inside `//` comments must not split
    // entries (e.g. `// tokens, GitHub PATs, app passwords`).
    let body: String = body_raw
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let mut names = BTreeSet::new();
    for raw in body.split(',') {
        let cleaned = raw.trim();
        let leaf = cleaned.rsplit("::").next().unwrap_or("").trim();
        if !leaf.is_empty() {
            names.insert(leaf.to_string());
        }
    }
    names
}

#[test]
fn every_command_is_registered() {
    let annotated = find_annotated_commands();
    let registered = registered_commands();

    assert!(
        !annotated.is_empty(),
        "no #[tauri::command] annotations found — parser broken?"
    );
    assert!(
        !registered.is_empty(),
        "generate_handler! block parsed as empty — parser broken?"
    );

    let mut unregistered: Vec<(String, PathBuf)> = annotated
        .iter()
        .filter(|(name, _)| !registered.contains(*name))
        .map(|(name, path)| (name.clone(), path.clone()))
        .collect();
    unregistered.sort();

    assert!(
        unregistered.is_empty(),
        "#[tauri::command] functions not listed in generate_handler!:\n{}",
        unregistered
            .iter()
            .map(|(n, p)| format!("  - {} ({})", n, p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_registered_name_has_a_command() {
    let annotated = find_annotated_commands();
    let registered = registered_commands();

    let orphan: Vec<&String> = registered
        .iter()
        .filter(|n| !annotated.contains_key(*n))
        .collect();

    assert!(
        orphan.is_empty(),
        "generate_handler! lists names with no matching #[tauri::command]:\n{}",
        orphan
            .iter()
            .map(|n| format!("  - {}", n))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
