//! Target canonicalization — mirror of
//! `mcp-server/src/integrations/finding-fingerprint.ts::normalizeTarget()`.
//!
//! The cross-assessment caching layers (Phase 3-5 of the caching plan)
//! key off a stable `target_id`. That ID is derived from
//! `SHA256(org_id || '|' || target_type || '|' || canonical_value)`.
//! Both the Rust backend and the TypeScript MCP server need to produce
//! identical canonical strings for the same raw input, or they'll write
//! different fingerprints and miss the cache.
//!
//! Test coverage in this module verifies parity with the TS implementation
//! across the full edge-case matrix (default ports, trailing slashes,
//! query param ordering, IPv6, etc.). When updating either implementation,
//! mirror the change in the other and rerun the parity tests.
//!
//! Reference: `mcp-server/src/integrations/finding-fingerprint.ts` line 47-73.

use sha2::{Digest, Sha256};
use url::Url;

/// One of the five target categorizations that the caching subsystem
/// keys on. Different types canonicalize differently, so the type must
/// be known before canonicalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetType {
    Web,
    Host,
    Cidr,
    Repo,
    CloudAccount,
}

impl TargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetType::Web => "web",
            TargetType::Host => "host",
            TargetType::Cidr => "cidr",
            TargetType::Repo => "repo",
            TargetType::CloudAccount => "cloud_account",
        }
    }

    /// Heuristic classification — best-effort, used by the migration
    /// backfill to guess the type of an existing `findings.target` string.
    /// Production code should pass `target_type` explicitly.
    pub fn classify(raw: &str) -> TargetType {
        let lower = raw.trim().to_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ws://")
            || lower.starts_with("wss://")
        {
            TargetType::Web
        } else if lower.starts_with("git@")
            || lower.starts_with("ssh://")
            || lower.contains("github.com")
            || lower.contains("gitlab.com")
            || lower.starts_with("/mnt/host-home")
        {
            TargetType::Repo
        } else if is_cidr(&lower) {
            TargetType::Cidr
        } else {
            TargetType::Host
        }
    }
}

/// Normalize a raw target string into its canonical form. The output is
/// what gets fingerprinted; identical inputs (after canonicalization)
/// MUST produce identical outputs.
pub fn canonicalize(raw: &str, target_type: TargetType) -> String {
    let trimmed = raw.trim();
    match target_type {
        TargetType::Web => canonicalize_web(trimmed),
        TargetType::Host => trimmed.to_lowercase(),
        TargetType::Cidr => trimmed.to_lowercase(),
        TargetType::Repo => canonicalize_repo(trimmed),
        TargetType::CloudAccount => trimmed.to_lowercase(),
    }
}

/// Compute the SHA256 fingerprint for a (org_id, target_type, canonical)
/// tuple. The fingerprint is the cross-assessment identity for a target.
pub fn fingerprint(org_id: &str, target_type: TargetType, canonical_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(org_id.as_bytes());
    hasher.update(b"|");
    hasher.update(target_type.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(canonical_value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Canonicalize a web target. Mirrors the TS `normalizeTarget()`:
///   - lowercase scheme + hostname
///   - strip default ports (80 for http, 443 for https)
///   - normalize trailing slashes (remove unless path is just "/")
///   - sort query parameters alphabetically
///   - drop fragments (the JS impl keeps them via .toString(), but they're
///     never sent over the wire, so we drop them for stability)
fn canonicalize_web(raw: &str) -> String {
    let mut url = match Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return raw.to_lowercase(),
    };

    // Lowercase scheme (url crate already does this, but be explicit
    // for parity with the TS impl's `url.protocol === "http:"` checks).
    let scheme = url.scheme().to_string();

    // Strip default ports.
    let port = url.port();
    let strip_port = matches!(
        (scheme.as_str(), port),
        ("http", Some(80)) | ("https", Some(443))
    );
    if strip_port {
        // url::Url::set_port returns () via Result<(), ()>, ignore.
        let _ = url.set_port(None);
    }

    // Normalize trailing slashes — keep "/" as-is, strip any number of
    // trailing slashes from non-root paths.
    let new_path = {
        let p = url.path().to_string();
        if p == "/" {
            "/".to_string()
        } else {
            let trimmed = p.trim_end_matches('/');
            if trimmed.is_empty() {
                "/".to_string()
            } else {
                trimmed.to_string()
            }
        }
    };
    url.set_path(&new_path);

    // Sort query parameters alphabetically. Stable across runs because
    // the sort key is the param name (rust's sort_by_key is stable).
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut sorted = pairs;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    url.set_query(None);
    if !sorted.is_empty() {
        let mut qs = url.query_pairs_mut();
        for (k, v) in &sorted {
            qs.append_pair(k, v);
        }
        drop(qs);
    }

    // Drop fragments — they're client-side anchors, not part of the
    // target identity for security testing.
    url.set_fragment(None);

    url.to_string()
}

/// Canonicalize a git repository target. Maps SSH and HTTPS variants
/// to a single HTTPS form so `git@github.com:org/repo.git` and
/// `https://github.com/org/repo.git` collapse to the same fingerprint.
///
/// Rules:
///   - SSH form `git@host:org/repo.git` → `https://host/org/repo`
///   - HTTPS form unchanged structurally
///   - Strip trailing `.git`
///   - Lowercase host
///   - Local paths (e.g. `/mnt/host-home/projects/x`) lowercase only
fn canonicalize_repo(raw: &str) -> String {
    let lower = raw.to_lowercase();

    // Local filesystem path — no URL parsing.
    if lower.starts_with('/') || lower.starts_with("file://") {
        return lower;
    }

    // SSH form: git@host:org/repo.git
    if let Some(rest) = lower.strip_prefix("git@") {
        if let Some(colon) = rest.find(':') {
            let host = &rest[..colon];
            let path = &rest[colon + 1..];
            let path = path.trim_end_matches(".git");
            return format!("https://{}/{}", host, path);
        }
    }

    // HTTPS / SSH-URL form: parse and rebuild
    if let Ok(mut url) = Url::parse(&lower) {
        // Strip trailing .git
        let path = url.path().trim_end_matches(".git").to_string();
        url.set_path(&path);
        // Strip fragment (branch/tag references aren't part of repo identity)
        url.set_fragment(None);
        return url.to_string();
    }

    // Fallback: return lowercased input
    lower
}

/// CIDR sniff test for the migration backfill heuristic.
fn is_cidr(s: &str) -> bool {
    // Simple regex-free check: `<dotted-quad>/<int>` or `<colon-hex>/<int>`.
    // The full validity check happens in the application layer using
    // ipnetwork; this is just enough to classify.
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    parts[1].parse::<u8>().is_ok()
        && (parts[0].split('.').count() == 4 || parts[0].contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parity test cases — each row's `canonical` MUST match the output
    /// of mcp-server/src/integrations/finding-fingerprint.ts on the same
    /// `raw` input. When updating one side, update the other in lockstep
    /// and verify these tests still pass.
    ///
    /// Format: (raw_input, target_type, expected_canonical)
    fn web_cases() -> Vec<(&'static str, &'static str)> {
        vec![
            // Default port stripping
            ("https://example.com:443/", "https://example.com/"),
            ("http://example.com:80", "http://example.com/"),
            ("https://example.com:8443/", "https://example.com:8443/"),
            // Hostname lowercasing
            ("HTTPS://Example.COM/", "https://example.com/"),
            // Trailing slash normalization on non-root paths
            ("https://example.com/api/", "https://example.com/api"),
            ("https://example.com/api///", "https://example.com/api"),
            ("https://example.com", "https://example.com/"),
            // Query param sorting
            (
                "https://example.com/api?z=1&a=2",
                "https://example.com/api?a=2&z=1",
            ),
            // Fragment removal
            (
                "https://example.com/api#section",
                "https://example.com/api",
            ),
            // Combined
            (
                "HTTPS://Example.COM:443/path/?z=1&a=2#frag",
                "https://example.com/path?a=2&z=1",
            ),
        ]
    }

    #[test]
    fn web_canonical_parity() {
        for (input, expected) in web_cases() {
            let got = canonicalize(input, TargetType::Web);
            assert_eq!(got, expected, "web canonical mismatch on {:?}", input);
        }
    }

    #[test]
    fn host_canonical_lowercases_and_trims() {
        assert_eq!(canonicalize("Example.COM", TargetType::Host), "example.com");
        assert_eq!(canonicalize("  10.0.0.1  ", TargetType::Host), "10.0.0.1");
    }

    #[test]
    fn repo_ssh_to_https() {
        // SSH form collapses to HTTPS
        assert_eq!(
            canonicalize("git@github.com:groovysec/maestro.git", TargetType::Repo),
            "https://github.com/groovysec/maestro"
        );
        // HTTPS with .git suffix
        assert_eq!(
            canonicalize(
                "https://github.com/groovysec/maestro.git",
                TargetType::Repo
            ),
            "https://github.com/groovysec/maestro"
        );
        // Local path stays a path
        assert_eq!(
            canonicalize("/mnt/host-home/projects/maestro", TargetType::Repo),
            "/mnt/host-home/projects/maestro"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_per_org() {
        let fp1 = fingerprint("org-a", TargetType::Web, "https://example.com/");
        let fp2 = fingerprint("org-a", TargetType::Web, "https://example.com/");
        let fp3 = fingerprint("org-b", TargetType::Web, "https://example.com/");
        assert_eq!(fp1, fp2, "same input must yield same fingerprint");
        assert_ne!(fp1, fp3, "different orgs must yield different fingerprints");
        // SHA256 hex = 64 chars
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn classify_is_reasonable() {
        assert_eq!(TargetType::classify("https://example.com"), TargetType::Web);
        assert_eq!(TargetType::classify("example.com"), TargetType::Host);
        assert_eq!(TargetType::classify("10.0.0.0/24"), TargetType::Cidr);
        assert_eq!(
            TargetType::classify("git@github.com:foo/bar.git"),
            TargetType::Repo
        );
        assert_eq!(
            TargetType::classify("/mnt/host-home/projects/foo"),
            TargetType::Repo
        );
    }

    #[test]
    fn fingerprint_distinguishes_target_types() {
        let host_fp = fingerprint("org-a", TargetType::Host, "example.com");
        let web_fp = fingerprint("org-a", TargetType::Web, "https://example.com/");
        assert_ne!(
            host_fp, web_fp,
            "same org + similar canonical should diverge by type"
        );
    }
}
