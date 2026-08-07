//! Unit tests for the source → category mapping that drives the findings
//! page tabs. Pure-function tests; no DB.
//!
//! Two invariants we enforce:
//!   1. Every example source emitted by the MCP server / agents lands in
//!      a known category.
//!   2. The Rust `category_from_source` function and the SQL-flavored
//!      `source_patterns_for_category` agree — anything mapped to
//!      category C by the function should be matched by C's SQL pattern
//!      list. (Otherwise the stats endpoint and the list filter would
//!      return different counts for the same finding.)

use maestro_backend::schemas::finding::{
    category_from_source, fingerprint, source_patterns_for_category,
};

/// (source_value, expected_category)
const FIXTURES: &[(&str, &str)] = &[
    // automated CVE/template scanners fold into web_app (vuln_scan dropped)
    ("nuclei", "web_app"),
    ("nikto", "web_app"),
    ("wpscan", "web_app"),
    ("run_nuclei", "web_app"),
    // web_app
    ("sqlmap", "web_app"),
    ("dalfox", "web_app"),
    ("xss-scanner", "web_app"),
    ("fuzzer", "web_app"),
    ("test_xss", "web_app"),
    ("test_sqli", "web_app"),
    ("test_idor", "web_app"),
    ("test_cors", "web_app"),
    ("test_ssrf", "web_app"),
    ("crawl_site", "web_app"),
    ("api-graphql:API-01", "web_app"),
    ("api-graphql:BIZ-01", "web_app"),
    ("manual-auth-test", "web_app"),
    ("manual-curl", "web_app"),
    ("web-app-agent", "web_app"),
    ("analyze_jwt", "web_app"),
    ("manual", "web_app"), // legacy back-compat
    // code_security
    ("semgrep", "code_security"),
    ("bandit", "code_security"),
    ("njsscan", "code_security"),
    ("gitleaks", "code_security"),
    ("trufflehog", "code_security"),
    ("trivy", "code_security"),
    ("dependency-scan", "code_security"),
    ("dependency-check", "code_security"),
    ("secret-scanner", "code_security"),
    ("iac-scan", "code_security"),
    ("cycode", "code_security"),
    ("scan_repository", "code_security"),
    ("scan_secrets", "code_security"),
    ("scan_dependencies", "code_security"),
    ("analyze_code_context", "code_security"),
    // infrastructure — network / DNS / TLS / host recon ONLY (cloud split out)
    ("nmap", "infrastructure"),
    ("dig", "infrastructure"),
    ("sslscan", "infrastructure"),
    ("testssl", "infrastructure"),
    ("check_dns_records", "infrastructure"),
    ("check_certificate", "infrastructure"),
    ("check_dnssec", "infrastructure"),
    ("enumerate_subdomains", "infrastructure"),
    ("detect_subdomain_takeover", "infrastructure"),
    ("discover_hosts", "infrastructure"),
    ("scan_ports", "infrastructure"),
    ("scan_ssl_tls", "infrastructure"),
    ("recon-infra", "infrastructure"),
    ("recon-infra/manual-probe", "infrastructure"),
    ("infra-security-agent", "infrastructure"),
    // cloud — IAM / storage / K8s / serverless / metadata (split out of infra)
    ("check_s3_bucket", "cloud"),
    ("discover_cloud_assets_external", "cloud"),
    ("audit_cloud_posture", "cloud"),
    ("test_cloud_metadata", "cloud"),
    ("test_iam_privesc", "cloud"),
    ("test_k8s_rbac", "cloud"),
    ("test_k8s_escape", "cloud"),
    ("test_container_registry", "cloud"),
    ("test_lambda_security", "cloud"),
    ("test_secrets_manager", "cloud"),
    ("test_instance_metadata", "cloud"),
    ("cloud-recon:CLOUD-05", "cloud"),
    ("cloud-exploit:CLOUD-14", "cloud"),
    // identity — AD / Entra / M365 / Okta / GWS / Ping
    ("identity-recon:IDENTITY-51", "identity"),
    ("identity-exploit:IDENTITY-54", "identity"),
    ("kerberoast_spns", "identity"),
    // exploit-tool sources fold into web_app ("Exploited" is the cross-cutting filter)
    ("metasploit", "web_app"),
    ("msfconsole", "web_app"),
    ("exploit_storage_misconfig", "web_app"),
    ("execute_custom_exploit", "web_app"),
    ("validate_cve", "web_app"),
    ("cve-validator", "web_app"),
    ("search_exploits", "web_app"),
    ("exploit-agent-safety", "web_app"),
    // ai / llm (standalone AI assessment)
    ("ai_fingerprint_target", "ai"),
    ("ai_probe_injection", "ai"),
    ("ai_extract_system_prompt", "ai"),
    ("ai_test_info_disclosure", "ai"),
    ("ai_test_output_handling", "ai"),
    ("ai_test_excessive_agency", "ai"),
    ("ai_consumption_probe", "ai"),
    ("ai-recon:AI-RECON-01", "ai"),
    ("ai-redteam:AI-PI-01", "ai"),
    ("ai-analysis", "ai"),
    // other (fallthrough)
    ("report-agent", "other"),
    ("local", "other"),
    ("qa-agent", "other"),
    ("compliance-agent", "other"),
];

#[test]
fn maps_every_known_source_to_expected_category() {
    let mut failures = Vec::new();
    for (source, expected) in FIXTURES {
        let got = category_from_source(Some(source));
        if got != *expected {
            failures.push(format!("source {source:?} → {got}, expected {expected}"));
        }
    }
    assert!(
        failures.is_empty(),
        "category_from_source mismatches:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn null_source_falls_into_other() {
    assert_eq!(category_from_source(None), "other");
}

#[test]
fn empty_source_falls_into_other() {
    assert_eq!(category_from_source(Some("")), "other");
}

#[test]
fn case_insensitive_matching() {
    // Inputs are lowercased internally — uppercase scanner names still match.
    assert_eq!(category_from_source(Some("NUCLEI")), "web_app");
    assert_eq!(category_from_source(Some("SemGrep")), "code_security");
    assert_eq!(category_from_source(Some("MetaSploit")), "web_app");
}

#[test]
fn metasploit_does_not_leak_into_vuln_scan() {
    // metasploit is an exploit framework, not a scanner. Exploit-tool sources
    // fold into web_app now (vuln_scan + exploitation are no longer categories;
    // "Exploited" is the cross-cutting exploitable filter).
    assert_eq!(category_from_source(Some("metasploit")), "web_app");
}

#[test]
fn cloud_test_does_not_leak_into_web_app() {
    // Regression: test_iam_*, test_k8s_*, etc. all start with `test_`, which
    // would naively match the web_app `test_*` fallback. The cloud (and infra
    // for zone_transfer) branches must come BEFORE that fallback. Cloud tools
    // now route to `cloud`; test_zone_transfer stays `infrastructure` (DNS).
    let cases = [
        ("test_iam_privesc", "cloud"),
        ("test_k8s_rbac", "cloud"),
        ("test_cloud_metadata", "cloud"),
        ("test_container_registry", "cloud"),
        ("test_lambda_security", "cloud"),
        ("test_instance_metadata", "cloud"),
        ("test_secrets_manager", "cloud"),
        ("test_messaging_exposure", "cloud"),
        ("test_database_exposure", "cloud"),
        ("test_credential_exposure", "cloud"),
        ("test_cross_account_trust", "cloud"),
        ("test_public_snapshots", "cloud"),
        ("test_service_account_permissions", "cloud"),
        ("test_zone_transfer", "infrastructure"),
    ];
    for (s, expected) in cases {
        let got = category_from_source(Some(s));
        assert_eq!(got, expected, "expected {s} → {expected}, got {got}");
        assert_ne!(got, "web_app", "{s} must not leak into web_app");
    }
}

#[test]
fn sql_patterns_match_function_classification() {
    // Parity check: for every (source, category) the Rust function maps,
    // the SQL ILIKE pattern list for that category must also accept the
    // source. Otherwise stats.by_category and the list filter
    // (?category=foo) would disagree on what's in each bucket.
    for (source, category) in FIXTURES {
        if *category == "other" {
            // 'other' is defined as NOT-matching-any-known, so we check
            // that it doesn't match any of the known buckets' patterns.
            for cat in ["web_app", "code_security", "cloud", "infrastructure", "identity", "ai"] {
                let patterns = source_patterns_for_category(cat);
                let matched = patterns.iter().any(|p| matches_ilike(source, p));
                assert!(
                    !matched,
                    "source {source:?} ('other') unexpectedly matched a {cat} pattern"
                );
            }
            continue;
        }
        let patterns = source_patterns_for_category(category);
        let matched = patterns.iter().any(|p| matches_ilike(source, p));
        assert!(
            matched,
            "source {source:?} should match {category} SQL patterns but did not. patterns={patterns:?}"
        );
    }
}

/// Mini ILIKE simulator for the test. Only needs to handle the simple
/// patterns we actually emit: literal text, leading `%`, trailing `%`,
/// or wrapping `%foo%`. Not a full SQL implementation — good enough for
/// these fixtures.
fn matches_ilike(s: &str, pattern: &str) -> bool {
    let s_low = s.to_ascii_lowercase();
    let p_low = pattern.to_ascii_lowercase();
    match (p_low.starts_with('%'), p_low.ends_with('%')) {
        (true, true) => {
            let inner = &p_low[1..p_low.len() - 1];
            s_low.contains(inner)
        }
        (true, false) => s_low.ends_with(&p_low[1..]),
        (false, true) => s_low.starts_with(&p_low[..p_low.len() - 1]),
        (false, false) => s_low == p_low,
    }
}

// =============================================================================
// fingerprint() tests
// =============================================================================
//
// Verifies the helper produces stable, normalized hashes — same vuln
// always hashes to the same fingerprint regardless of trivial diffs in
// case / whitespace / null-vs-empty source. Critical because the dedup
// upsert is keyed on this hash; drift between the migration's backfill
// and the runtime helper would produce ghost-duplicate rows.

#[test]
fn fingerprint_is_deterministic() {
    let a = fingerprint("SQLi in /users", "https://x.com/users", Some("sqlmap"), Some("CWE-89"));
    let b = fingerprint("SQLi in /users", "https://x.com/users", Some("sqlmap"), Some("CWE-89"));
    assert_eq!(a, b);
}

#[test]
fn fingerprint_normalizes_case_and_whitespace() {
    let a = fingerprint("SQLi in /users", "https://x.com/users", Some("sqlmap"), Some("CWE-89"));
    let b = fingerprint("  sqli IN /Users  ", "  HTTPS://x.com/users  ", Some("SQLMap"), Some("CWE-89"));
    assert_eq!(a, b, "title + target + source case/whitespace shouldn't matter");
}

#[test]
fn fingerprint_treats_null_and_empty_source_same() {
    let a = fingerprint("X", "t", None, None);
    let b = fingerprint("X", "t", Some(""), Some(""));
    assert_eq!(a, b);
}

#[test]
fn fingerprint_distinguishes_different_targets() {
    let a = fingerprint("SQLi", "https://x.com/users", Some("sqlmap"), None);
    let b = fingerprint("SQLi", "https://x.com/admin", Some("sqlmap"), None);
    assert_ne!(a, b, "different target → different fingerprint");
}

#[test]
fn fingerprint_distinguishes_different_cwes() {
    let a = fingerprint("Auth bypass", "t", Some("manual"), Some("CWE-287"));
    let b = fingerprint("Auth bypass", "t", Some("manual"), Some("CWE-306"));
    assert_ne!(a, b);
}

#[test]
fn fingerprint_returns_64_char_hex() {
    let f = fingerprint("X", "t", None, None);
    assert_eq!(f.len(), 64);
    assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
}
