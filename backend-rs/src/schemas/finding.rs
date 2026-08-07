//! Request/response schemas for `/findings`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::models::finding::Finding;
use crate::models::sql_enums::WireName;

/// Deterministic per-vulnerability fingerprint used as the dedup key in
/// the upsert path (migration 0007). The same vuln (title + target +
/// scanner + CWE) always hashes to the same fingerprint, regardless of
/// when it was found or which assessment ran.
///
/// Mirrors the migration's backfill SQL exactly:
///   sha256(lower(trim(title)) || '|' || lower(trim(target)) || '|' ||
///           lower(coalesce(source, '')) || '|' || coalesce(cwe, ''))
///
/// Pinning case + whitespace + delimiter precisely is critical — any
/// drift between the migration's backfilled fingerprints and the Rust
/// helper's runtime values would produce ghost-duplicate rows.
pub fn fingerprint(
    title: &str,
    target: &str,
    source: Option<&str>,
    cwe: Option<&str>,
) -> String {
    let normalized = format!(
        "{}|{}|{}|{}",
        title.trim().to_lowercase(),
        target.trim().to_lowercase(),
        source.unwrap_or("").to_lowercase(),
        cwe.unwrap_or(""),
    );
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Derive a high-level finding category from the `source` field that
/// scanners stamp on each finding. The frontend's category tabs are
/// based on this; without it, every finding lands in "All Findings"
/// only and the per-category counts are zero.
///
/// # Category definitions (canonical — these power the tooltips on the
/// Findings page tabs)
///
/// Categories are sliced by **testing method**, not by target layer.
/// A web-layer CVE can land in either Vuln Scan or Web App depending
/// on whether we matched it against a signature DB (template scanner)
/// or found it via class-based testing (sqlmap / browser tests).
///
/// - **Vuln Scan** — automated signature/template scanners matching
///   the target against a database of known-published CVEs.
///   Tools: nuclei, nikto, wpscan, wapiti, acunetix. Also any
///   agent test ID with `:VSCAN-` (e.g. `api-graphql:VSCAN-01`).
///   Question answered: "Does this target match any known-published
///   vulnerability signature?"
///
/// - **Web App** — class-based testing of HTTP applications.
///   Tools: sqlmap, dalfox, ffuf, dirb, gobuster, xss; any
///   `test_*` MCP tool that's web-flavored; any agent test ID
///   under `web-security:*`, `api-graphql:*` (except VSCAN), and
///   `team-lead:AUTH-*` (auth IS web app testing).
///   Question answered: "Does this app have an instance of a
///   vulnerability class (SQLi/XSS/IDOR/SSRF/auth flaw/etc)?"
///
/// - **Code Security** — static analysis of source code & supply chain.
///   Tools: semgrep, bandit, njsscan, gitleaks, trufflehog, grype,
///   trivy, snyk, dependency-check; any `scan_*` MCP tool reading
///   the repo; any agent test ID under `sast-scan:*` or `sast-analysis:*`.
///   Question answered: "Does the source code or its dependencies
///   have unsafe patterns?"
///
/// - **Infrastructure** — network, protocol, system, and cloud-config
///   layer. Tools: nmap, masscan, sslscan, testssl, dig, whois,
///   ssh-audit, dnssec checks, cloud-recon, cloud-exploit; any agent
///   test ID under `recon-infra:*`, `cloud-recon:*`, `cloud-exploit:*`.
///   Question answered: "Are the systems hosting and routing to the
///   app correctly configured?"
///
/// - **Exploitation** (source-based) — findings created by exploit
///   frameworks themselves: metasploit, msfvenom, search_exploits,
///   validate_cve, exploit-agent. These are findings about
///   exploit-tool output, distinct from the **Exploited filter**
///   on the page (which is the cross-cutting "was this proven
///   exploitable" overlay, see frontend/app/findings/page.tsx).
///
/// - **Other** — safety net. A finding lands here when its `source`
///   doesn't match any pattern above OR is NULL. Should be near-zero
///   with disciplined source naming — every non-zero count here is a
///   missing rule below.
///
/// **Cross-cutting filters** (NOT source-based — derived at the
/// frontend layer): Exploited (filters by `exploitable IN (true,
/// potentially)`), Cloud (sniffs ARN / Azure resource ID / GCP
/// project path / cloud-tool source name from the row's title +
/// source). These pull rows from any of the source-based categories
/// above and don't change the per-category source counts.
pub fn category_from_source(source: Option<&str>) -> &'static str {
    let Some(raw) = source else { return "other" };
    let s = raw.to_ascii_lowercase();

    // ========================================================================
    // 0. AI / LLM — the standalone AI assessment tools (see
    //    docs/ai-surface-plan.md). Checked FIRST so `ai_test_*` tool names and
    //    `ai-redteam:AI-PI-01`-style agent test ids don't fall through to the
    //    web_app `test_*` bucket or the identity block below.
    // ========================================================================
    if s.starts_with("ai_")            // tool names: ai_probe_injection, ai_fingerprint_target, ai_test_*, ai_consumption_probe
        || s.starts_with("ai-recon")    // agent-attributed sources: ai-recon:AI-RECON-01
        || s.starts_with("ai-redteam")  // ai-redteam:AI-PI-01, etc.
        || s.starts_with("ai-analysis")
        || s.contains("llm_assessment")
        || s.contains("ai_security")
    {
        return "ai";
    }

    // ========================================================================
    // 1. IDENTITY — AD / Entra ID / M365 red-team tools. Checked first so
    //    exploit_adcs / abuse_* / kerberoast land in `identity`, not the generic
    //    exploitation / web_app buckets below.
    // ========================================================================
    if s.starts_with("identity-recon")    // agent-attributed: identity-recon:IDENTITY-51
        || s.starts_with("identity-exploit")
        || s.starts_with("identity-analysis")
        || s.contains(":identity-")
        || s.starts_with("enum_ad")
        || s.starts_with("abuse_ad")
        || s.contains("adcs")
        || s.starts_with("kerberoast")
        || s.starts_with("asrep")
        || s.starts_with("password_spray")
        || s.contains("dcsync")
        || s.contains("abuse_delegation")
        || s.contains("read_laps")
        || s.contains("ntlm_relay")
        || s.contains("golden_ticket")
        || s.contains("entra")
        || s.contains("conditional_access")
        || s.contains("oauth_apps")
        || s.contains("consent_grant")
        || s.contains("device_code")
        || s.contains("ca_bypass")
        || s.contains("service_principal")
        || s.contains("forge_prt")
        || s.contains("cross_tenant")
        || s.contains("o365")
        || s.contains("m365")
        || s.contains("mailbox")
        || s.contains("sharepoint")
        || s.contains("access_teams")
        || s.contains("ediscovery")
        || s.contains("app_registration")
        || s.contains("aadinternals")
        // Multi-IDP providers (okta / google workspace / ping) — tool names carry
        // a stable provider token so their findings route to the identity surface.
        || s.contains("okta")
        || s.contains("gworkspace")
        || s.contains("_ping_")
        || s.starts_with("enum_ping")
        || s.starts_with("abuse_ping")
        || s.starts_with("test_ping")
    {
        return "identity";
    }

    // ========================================================================
    // 1. EXPLOITATION — checked first so metasploit doesn't fall through to
    //    vuln_scan (it's an exploit framework, not a scanner).
    // ========================================================================
    if s.contains("metasploit")
        || s.contains("msfconsole")
        || s.contains("msfvenom")
        || s.starts_with("exploit_")
        || s == "exploit"
        || s.contains("exploit-agent")
        || s.contains("exploit_agent")
        || s.contains("execute_custom_exploit")
        || s.contains("validate_cve")
        || s.contains("cve-validator")
        || s.contains("cve_validator")
        || s.contains("search_exploits")
    {
        // Exploit-tool sources fold into Web/API — "Exploited" is the
        // cross-cutting `exploitable` filter, not its own surface category.
        return "web_app";
    }

    // ========================================================================
    // 2. CLOUD — AWS / Azure / GCP / Kubernetes. First-class surface (mirrors
    //    source_patterns_for_category). Checked BEFORE infrastructure so cloud
    //    tools/sources route to "cloud", not "infra".
    // ========================================================================
    if s.contains("cloud")
        || s.starts_with("test_iam") || s.starts_with("test_k8s") || s.starts_with("test_cloud")
        || s.starts_with("test_container") || s.starts_with("test_lambda")
        || s.starts_with("test_secrets") || s.starts_with("test_service_account")
        || s.starts_with("test_instance_metadata") || s.starts_with("test_messaging_exposure")
        || s.starts_with("test_database_exposure") || s.starts_with("test_credential_exposure")
        || s.starts_with("test_cross_account") || s.starts_with("test_public_snapshot")
        || s.starts_with("audit_cloud") || s.starts_with("audit_storage")
        || s.starts_with("check_s3") || s.starts_with("check_cloud")
        || s.starts_with("scan_storage_sensitive")
        || s.contains("scoutsuite") || s.contains("prowler") || s.contains("pacu")
        || s.contains("kube-hunter") || s.contains("s3scanner")
    {
        return "cloud";
    }

    // ========================================================================
    // 3. INFRASTRUCTURE — network, DNS/TLS, recon (cloud handled above). Must
    //    come BEFORE web_app so recon/test_* tools don't get pulled into
    //    web_app by the test_* fallback at the bottom. (Cloud conditions below
    //    are now unreachable — superseded by the Cloud branch — kept harmless.)
    // ========================================================================
    // Cloud / IAM / k8s test tools (each is a separate MCP tool name)
    if s.starts_with("test_iam")
        || s.starts_with("test_k8s")
        || s.starts_with("test_cloud")
        || s.starts_with("test_container")
        || s.starts_with("test_lambda")
        || s.starts_with("test_secrets")
        || s.starts_with("test_service_account")
        || s.starts_with("test_instance_metadata")
        || s.starts_with("test_messaging_exposure")
        || s.starts_with("test_database_exposure")
        || s.starts_with("test_credential_exposure")
        || s.starts_with("test_cross_account")
        || s.starts_with("test_public_snapshot")
        || s.starts_with("test_zone_transfer")
    {
        return "infrastructure";
    }
    // Recon / discovery / enumeration tools
    if s.starts_with("discover_")
        || s.starts_with("enum_")
        || s.starts_with("enumerate_")
        || s.starts_with("fingerprint_")
        || s.starts_with("detect_subdomain")
        || s.starts_with("detect_languages")    // tech detection on a target
        || s.starts_with("map_entry_points")
        || s.starts_with("trace_data_flow")
        || s.starts_with("audit_cloud")
        || s.starts_with("audit_storage")
    {
        return "infrastructure";
    }
    // DNS / TLS / SSL / cert / port / S3 checks
    if s.starts_with("scan_ports")
        || s.starts_with("scan_ssl")
        || s.starts_with("check_dns")
        || s.starts_with("check_certificate")
        || s.starts_with("check_dnssec")
        || s.starts_with("check_s3")
        || s.starts_with("check_cloud")
        || s.starts_with("scan_storage_sensitive")
    {
        return "infrastructure";
    }
    // Scanner names that map to network/infra
    if s.contains("nmap")
        || s.contains("masscan")
        || s.contains("dig")
        || s.contains("whois")
        || s.contains("sslscan")
        || s.contains("testssl")
        || s.contains("ssh-audit")
        || s.contains("dns")
        || s.contains("certificate")
        || s.contains("subdomain")
        || s.contains("zone_transfer")
        || s.contains("dnssec")
        || s.contains("cloud")              // cloud-recon, cloud-exploit, audit_cloud_*
        || s.contains("infra-security")
        || s.contains("infra_security")
        || s == "recon"
        || s.contains("recon-agent")
        || s.contains("recon_agent")
        || s.starts_with("recon-infra")     // recon-infra agent + recon-infra/manual-probe
        || s.starts_with("recon_infra")
    {
        return "infrastructure";
    }

    // ========================================================================
    // 3. CODE_SECURITY — SAST, secret scanning, dependency scanning, IaC.
    // ========================================================================
    if s.contains("semgrep")
        || s.contains("bandit")
        || s.contains("njsscan")
        || s.contains("gitleaks")
        || s.contains("trufflehog")
        || s.contains("grype")
        || s.contains("trivy")              // container + dependency scanner
        || s.contains("snyk")
        || s.contains("dependency")             // dependency-check, dependency-scan
        || s.contains("cycode")
        || s.contains("secret-scan")
        || s.contains("secret_scan")
        || s.contains("iac-scan")
        || s.contains("iac_scan")
        || s.contains("sast")
        || s.contains("code-intel")
        || s.contains("code_intel")
        || s.contains("security-scan")
        || s.contains("security_scan")
        || s.starts_with("scan_repository")
        || s.starts_with("scan_secrets")
        || s.starts_with("scan_dependencies")
        || s.starts_with("scan_semgrep")
        || s.starts_with("scan_bandit")
        || s.starts_with("scan_njsscan")
        || s.starts_with("scan_iac")
        || s.starts_with("scan_container_image")
        || s.starts_with("analyze_code")
    {
        return "code_security";
    }

    // ========================================================================
    // 4. VULN_SCAN — nuclei / nikto / wpscan family AND any agent test ID
    //    with `:VSCAN-` (the test-matrix's vuln-scan tests, regardless of
    //    which agent ran them — `api-graphql:VSCAN-01`, `team-lead:VSCAN-02`,
    //    etc.). This is the routing fix from 2026-05-18: previously these
    //    landed in web_app because `api-graphql:*` matched first.
    // ========================================================================
    if s.contains(":vscan-")
        || s.contains("nuclei")
        || s.contains("nikto")
        || s.contains("wpscan")
        || s.contains("wapiti")
        || s.contains("acunetix")
        || s.contains("vuln_scan")
        || s.contains("vuln-scan")
        || s.contains("run_nuclei")
        || s.contains("run_nikto")
        || s.contains("run_wpscan")
    {
        // Automated CVE/template scanners fold into Web/API (a nuclei/nikto hit
        // IS the web surface; vuln_scan is a technique, not a surface).
        return "web_app";
    }

    // ========================================================================
    // 5. WEB_APP — last category, catches test_* / fuzz_* / browser_* /
    //    crawl_* / web_* / api_* / auth_* / session_* / token_* etc that
    //    didn't get classified as infrastructure above. Order: scanner names,
    //    then prefixes, then agent names.
    // ========================================================================
    if s.contains("sqlmap")
        || s.contains("dalfox")
        || s.contains("wfuzz")
        || s.contains("ffuf")
        || s.contains("dirb")
        || s.contains("gobuster")
        || s.contains("xsstrike")
        || s.contains("crawl_site")
        || s.contains("web_app")
        || s.contains("web-app")
        || s.contains("xss")
        || s.contains("fuzzer")
        || s.contains("api-security")
        || s.contains("api_security")
    {
        return "web_app";
    }
    if s.starts_with("test_")           // any test_* not caught by infrastructure above
        || s.starts_with("fuzz_")
        || s.starts_with("browser_")
        || s.starts_with("crawl_")
        || s.starts_with("web_technology")
        || s.starts_with("web_")
        || s.starts_with("analyze_jwt")
        || s.starts_with("analyze_defen")     // analyze_defenses
        || s.starts_with("analyze_session")
        || s.starts_with("analyze_token")
        || s.starts_with("auth-")
        || s.starts_with("auth_")
        || s.contains(":auth-")               // team-lead:AUTH-07, etc.
        || s.starts_with("session-")
        || s.starts_with("session_")
        || s.contains(":session-")
        || s.starts_with("token-")
        || s.starts_with("token_")
        || s.contains(":token-")
        || s.starts_with("generate_waf_bypass")
        || s.starts_with("import_cycode")     // already caught by cycode but explicit
        // NOTE: do not match broad `api-graphql` / `web-security` prefixes
        // here — that would re-catch `api-graphql:VSCAN-*` after section 4
        // already routed it to vuln_scan. The specific `:authz-` / `:hdr-`
        // / `:gql-` / `:api-` / etc. matchers ABOVE handle the real
        // web-app tests from those agents; `source_patterns_for_category`
        // mirrors this exact list so the SQL tab counts match the
        // per-row `category` field this function returns.
        || s.contains(":authz-")              // web-security:AUTHZ-01
        || s.contains(":hdr-")                // web-security:HDR-03
        || s.contains(":cors-")
        || s.contains(":inj-")
        || s.contains(":ssrf-")
        || s.contains(":cli-")
        || s.contains(":gql-")                // api-graphql:GQL-05
        || s.contains(":api-")
        || s.contains(":upload-")
        || s.contains(":biz-")
        || s.contains(":proto-")
        || s.contains(":deser-")
        || s.contains(":chain-")              // chain-analysis:CHAIN-*
        || s.starts_with("manual-auth")       // manual-auth-test → web auth testing
        || s.starts_with("manual-curl")       // manual-curl → web HTTP probe
        || s.starts_with("manual-web")
    {
        return "web_app";
    }

    // No `team-lead:` general fallback by design. The known web-test ID
    // prefixes above (`:auth-`, `:authz-`, `:hdr-`, `:cors-`, `:inj-`,
    // `:ssrf-`, `:cli-`, `:gql-`, `:api-`, `:upload-`, `:biz-`, `:proto-`,
    // `:deser-`, `:session-`, `:token-`, `:chain-`) already capture every
    // test the lead can run that's a web-app finding. An unknown
    // `team-lead:NEWTHING-01` deliberately falls through to "other" —
    // that's the signal to add a routing rule for the new prefix, not to
    // silently bucket it into web_app where it may not belong.

    // Historical "manual" findings (back-compat) — desktop has no manual
    // create-finding feature, so any source="manual" in the DB came from
    // the assessment pipeline. Treat as web_app since they're nearly all
    // web/api findings during automated runs. (The schema description
    // for `source` was tightened to disallow this going forward.)
    if s == "manual" {
        return "web_app";
    }

    "other"
}

/// All `source` substring patterns that map to a given category. Used by
/// the list filter to translate `?category=foo` into a SQL `source ILIKE
/// ANY(...)` clause.
pub fn source_patterns_for_category(category: &str) -> &'static [&'static str] {
    match category {
        "vuln_scan" => &[
            "%nuclei%", "%nikto%", "%wpscan%", "%wapiti%", "%acunetix%",
            "%vuln_scan%", "%vuln-scan%",
            "%:vscan-%",   // agent test IDs: api-graphql:VSCAN-01, team-lead:VSCAN-02
        ],
        "web_app" => &[
            // Scanner / tool name patterns
            "%sqlmap%", "%dalfox%", "%wfuzz%", "%ffuf%", "%dirb%", "%gobuster%",
            "%xsstrike%", "%crawl_site%", "%web_app%", "%web-app%",
            "%xss%", "%fuzzer%", "%api-security%", "%api_security%",
            // MCP tool-name prefixes
            "test_%", "fuzz_%",
            "browser_%", "crawl_%", "web_technology%", "web_%",
            "analyze_jwt%", "analyze_defen%", "analyze_session%", "analyze_token%",
            "auth-%", "auth_%", "session-%", "session_%", "token-%", "token_%",
            "generate_waf_bypass%", "import_cycode%",
            // Agent test-ID patterns. Each captures one prefix from the
            // test-matrix; these are mutually exclusive with vuln_scan's
            // `%:vscan-%` and with infrastructure / code_security patterns.
            // DO NOT replace these with a broad `team-lead:%` or
            // `api-graphql%` — that would re-catch `team-lead:VSCAN-01`
            // and double-count it in both vuln_scan and web_app tabs.
            "%:auth-%",                  // team-lead:AUTH-07, etc.
            "%:authz-%",                 // web-security:AUTHZ-01, etc.
            "%:hdr-%",                   // web-security:HDR-03
            "%:cors-%",                  // web-security:CORS-01
            "%:inj-%",                   // web-security:INJ-04
            "%:ssrf-%",                  // web-security:SSRF-01
            "%:cli-%",                   // web-security:CLI-02
            "%:session-%", "%:token-%",
            "%:gql-%",                   // api-graphql:GQL-05
            "%:api-%",                   // api-graphql:API-03
            "%:upload-%",                // api-graphql:UPLOAD-01
            "%:biz-%",                   // api-graphql:BIZ-01
            "%:proto-%",                 // api-graphql:PROTO-01 (HTTP smuggling, WS, cache)
            "%:deser-%",                 // api-graphql:DESER-01
            "%:chain-%",                 // chain-analysis:CHAIN-01
            // Manual / legacy fallbacks (kept narrow, don't sweep)
            "manual-auth%", "manual-curl%", "manual-web%",
            "manual",
            // Automated CVE/template scanners fold into Web/API (a nuclei/nikto hit
            // on a web endpoint IS the web surface). "vuln_scan" is no longer its
            // own tab — "scanner-sourced" is an attribute, not a surface.
            "%nuclei%", "%nikto%", "%wpscan%", "%wapiti%", "%acunetix%",
            "%vuln_scan%", "%vuln-scan%", "%:vscan-%",
            // Exploit-tool sources also fold into Web/API (category_from_source
            // routes them here too; "Exploited" is the cross-cutting filter).
            "%metasploit%", "%msfconsole%", "%msfvenom%", "exploit_%", "%exploit-agent%",
            "%exploit_agent%", "%execute_custom_exploit%", "%validate_cve%",
            "%cve-validator%", "%cve_validator%", "%search_exploits%",
        ],
        "code_security" => &[
            "%semgrep%", "%bandit%", "%njsscan%", "%gitleaks%", "%trufflehog%",
            "%grype%", "%trivy%", "%snyk%", "%dependency%", "%cycode%",
            "%secret-scan%", "%secret_scan%", "%iac-scan%", "%iac_scan%",
            "%sast%", "%code-intel%", "%code_intel%", "%security-scan%", "%security_scan%",
            "scan_repository%", "scan_secrets%", "scan_dependencies%",
            "scan_semgrep%", "scan_bandit%", "scan_njsscan%", "scan_iac%",
            "scan_container_image%", "analyze_code%",
        ],
        "infrastructure" => &[
            // Network / TLS / DNS / host recon ONLY. Cloud patterns moved to the
            // dedicated "cloud" category below so Cloud is a first-class surface tab.
            "%nmap%", "%masscan%", "%dig%", "%whois%", "%sslscan%", "%testssl%",
            "%ssh-audit%", "%dns%", "%certificate%", "%subdomain%",
            "%zone_transfer%", "%dnssec%",
            "%infra-security%", "%infra_security%", "recon", "%recon-agent%", "%recon_agent%",
            "recon-infra%", "recon_infra%", "test_zone_transfer%",
            "discover_%", "enum_%", "enumerate_%", "fingerprint_%",
            "detect_subdomain%", "detect_languages%", "map_entry_points%", "trace_data_flow%",
            "scan_ports%", "scan_ssl%", "check_dns%", "check_certificate%", "check_dnssec%",
        ],
        "cloud" => &[
            // Cloud surface — split out of infrastructure (dedicated cloud-recon/
            // exploit/analysis agents + the standalone Cloud Companion Report).
            "%cloud%", "cloud-recon%", "cloud-exploit%", "cloud-analysis%", "%:cloud-%",
            "test_iam%", "test_k8s%", "test_cloud%", "test_container%", "test_lambda%",
            "test_secrets%", "test_service_account%", "test_instance_metadata%",
            "test_messaging_exposure%", "test_database_exposure%", "test_credential_exposure%",
            "test_cross_account%", "test_public_snapshot%",
            "audit_cloud%", "audit_storage%", "check_s3%", "check_cloud%", "scan_storage_sensitive%",
            "%scoutsuite%", "%prowler%", "%pacu%", "%kube-hunter%", "%s3scanner%",
        ],
        "identity" => &[
            // Identity / IDP surface (AD / Entra / M365 / Okta / Google Workspace / Ping).
            // Their sources are identity-recon:IDENTITY-NN / identity-exploit:IDENTITY-NN,
            // which previously matched no category and fell into "other".
            "%identity%", "identity-recon%", "identity-exploit%", "identity-analysis%", "%:identity-%",
            "%bloodhound%", "%kerbrute%", "%certipy%", "%roadrecon%", "%adidnsdump%",
            "%kerberoast%", "%dcsync%",
        ],
        "exploitation" => &[
            "%metasploit%", "%msfconsole%", "%msfvenom%",
            "exploit_%", "exploit", "%exploit-agent%", "%exploit_agent%",
            "%execute_custom_exploit%", "%validate_cve%",
            "%cve-validator%", "%cve_validator%", "%search_exploits%",
        ],
        "ai" => &[
            // Tool-name sources (ai_probe_injection, ai_fingerprint_target,
            // ai_test_*, ai_consumption_probe). In SQL LIKE `_` is a single-char
            // wildcard, so `ai_%` also covers the `ai-recon`/`ai-redteam`
            // agent-attributed sources; the explicit patterns below are kept for
            // readability and to stay robust if that quirk ever changes.
            "ai_%",
            "ai-recon%", "ai-redteam%", "ai-analysis%",
            "%llm_assessment%", "%ai_security%",
        ],
        _ => &[],
    }
}

#[derive(Debug, Deserialize)]
pub struct FindingCreate {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    pub severity: String,
    pub target: String,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub references: Option<String>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_id: Option<String>,
    /// 'true' | 'potentially' | 'false' | absent — see migration 0006.
    #[serde(default)]
    pub exploitable: Option<String>,
    #[serde(default)]
    pub assessment_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Optional calibrated severity (severity-calibrator agent output).
    /// When passed alongside `severity`, the column is populated on
    /// insert/upsert so the dashboard renders the calibrated value.
    /// Migration 0016.
    #[serde(default)]
    pub calibrated_severity: Option<String>,
    /// Which calibration rule was applied (free text). Migration 0016.
    #[serde(default)]
    pub calibration_rule: Option<String>,
    /// Short prose justification. Migration 0016.
    #[serde(default)]
    pub calibration_justification: Option<String>,
    /// crossval-qa baseline-aware mode output (migration 0020). One of
    /// RE_VALIDATED | VALIDATED_FROM_BASELINE | NEW_FINDING. NULL when
    /// the producer doesn't participate in baseline-aware mode.
    #[serde(default)]
    pub validation_source: Option<String>,
    /// When validation_source = VALIDATED_FROM_BASELINE, the assessment
    /// whose evidence we're trusting. Migration 0020.
    #[serde(default)]
    pub prior_assessment_id: Option<String>,
    /// Human-readable cache-decision explanation. Migration 0020.
    #[serde(default)]
    pub baseline_skip_reason: Option<String>,
    /// Structured correlation keys (migration 0030). Optional; populated by
    /// scanners that know them and used by the DAST correlation join.
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    /// Scheduled/deterministic DAST scan that produced this finding (migration
    /// 0035). When set, the upsert stamps the row so it shows in the DAST-only
    /// vulnerabilities view. NULL/absent for LLM-assessment findings.
    #[serde(default)]
    pub scan_id: Option<String>,
    /// Oracle verdict (migration 0049): 'candidate' | 'verified' | 'refuted'.
    /// A `verified` row is one the MCP oracle layer re-proved in code and must
    /// arrive with a complete receipt — the CHECK constraint added in 0049
    /// rejects the insert otherwise, so an unearned verdict cannot be laundered
    /// into the cloud by a buggy or malicious client. Absent → 'candidate'.
    #[serde(default)]
    pub verdict: Option<String>,
    /// Which oracle earned the verdict (idempotent_replay | differential | …).
    #[serde(default)]
    pub oracle_kind: Option<String>,
    /// Machine evidence the oracle observed, including the negative control.
    #[serde(default)]
    pub receipt_json: Option<serde_json::Value>,
    /// The re-runnable recipe. This is what a human signer replays before
    /// signing, and what CI replays to detect a fixed or flaky finding.
    #[serde(default)]
    pub capsule_json: Option<serde_json::Value>,
    #[serde(default)]
    pub replay_n: Option<i32>,
    #[serde(default)]
    pub replay_successes: Option<i32>,
    #[serde(default)]
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The vulnerability mechanism the finding CLAIMS, so a receipt that proves
    /// impact by a different mechanism can be caught rather than silently
    /// accepted. See docs/oracle-verification-layer.md.
    #[serde(default)]
    pub claimed_mechanism: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FindingUpdate {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub jira_ticket: Option<String>,
    #[serde(default)]
    pub jira_url: Option<String>,
    /// Calibrated severity override. Set to "null" string or omit to leave
    /// the column unchanged (cannot clear via PATCH right now — by design;
    /// the calibrator never un-calibrates). Migration 0016.
    #[serde(default)]
    pub calibrated_severity: Option<String>,
    #[serde(default)]
    pub calibration_rule: Option<String>,
    #[serde(default)]
    pub calibration_justification: Option<String>,
    /// Triage owner. Migration 0036. Empty string clears it.
    #[serde(default)]
    pub assigned_to: Option<String>,
    /// Replace the full tag set. Migration 0036.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Human attestation toggle (migration 0036): true → stamp attested_at=NOW +
    /// attested_by=caller; false → clear both. Omitted → unchanged.
    #[serde(default)]
    pub attest: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    /// **Effective severity** — `COALESCE(calibrated_severity, original)`.
    /// The dashboard's severity tile counts + the row's primary badge
    /// pull from this. When the calibrator didn't run (or rule kept
    /// original), this equals `original_severity`.
    pub severity: String,
    /// Scanner-original severity. Preserved on the response so the UI
    /// can render "was HIGH ↓" indicators next to a downgraded badge.
    /// Always populated.
    pub original_severity: String,
    /// Post-calibration severity. NULL when calibration didn't run or
    /// kept the original. When present, equals `severity` above.
    pub calibrated_severity: Option<String>,
    /// Which calibration rule fired (e.g. "Rule 1 — outcome anchored").
    pub calibration_rule: Option<String>,
    /// Short prose justification for the calibration delta.
    pub calibration_justification: Option<String>,
    pub status: String,
    pub target: String,
    pub target_type: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub cvss_score: Option<String>,
    pub jira_ticket: Option<String>,
    pub jira_url: Option<String>,
    pub source: Option<String>,
    pub source_id: Option<String>,
    /// Derived from `source`. One of: vuln_scan, web_app, code_security,
    /// infrastructure, exploitation, other.
    pub category: String,
    /// 'true' | 'potentially' | 'false' | null. Drives the Exploited tab
    /// + Fully/Partial sub-filter on the findings page.
    pub exploitable: Option<String>,
    /// SHA256 dedup key. Same finding (title+target+source+cwe) always
    /// produces the same fingerprint — POST /findings becomes upsert.
    pub fingerprint: Option<String>,
    /// How many times this same vulnerability has been observed across
    /// assessments. Increments on every duplicate POST, frozen at 1
    /// for fresh findings. Frontend renders `×N` badge when > 1.
    pub occurrence_count: i32,
    /// Frozen at first observation. Useful for "this has been open for
    /// 47 days" remediation pressure.
    pub first_seen_at: DateTime<Utc>,
    /// Bumped on every duplicate. If this stops advancing, customer
    /// remediated the vuln.
    pub last_seen_at: DateTime<Utc>,
    pub assessment_id: Option<String>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub client_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Stable target identity FK (migration 0018). NULL on legacy rows
    /// pending the Rust-app target backfill repair.
    pub target_id: Option<String>,
    /// crossval-qa baseline-aware mode output. Migration 0020.
    pub validation_source: Option<String>,
    /// When validation_source = VALIDATED_FROM_BASELINE, the assessment
    /// whose result we trusted. Migration 0020.
    pub prior_assessment_id: Option<String>,
    /// Human-readable cache-decision explanation. Migration 0020.
    pub baseline_skip_reason: Option<String>,
    /// Set when this finding was exploitable in a prior run and re-tested
    /// as no-longer-exploitable. `remediated_at != null` is the "patched"
    /// predicate the Remediated tab + ✓ Fixed badge key off. Migration 0034.
    pub remediated_at: Option<DateTime<Utc>>,
    /// The exploitable value held before being patched ('true' |
    /// 'potentially') — drives "was fully exploited, now fixed". Migration 0034.
    pub prior_exploitable: Option<String>,
    /// The assessment whose re-test proved the fix. Migration 0034.
    pub remediated_in_assessment_id: Option<String>,
    /// Scheduled-DAST scan that produced this finding (migration 0035). NULL for
    /// LLM-assessment findings. `scan_id != null` drives the DAST-only view.
    pub scan_id: Option<String>,
    /// Triage owner. Migration 0036.
    pub assigned_to: Option<String>,
    /// Free-form triage tags. Migration 0036.
    pub tags: Vec<String>,
    /// Human attestation (top validation tier). Migration 0036.
    pub attested_at: Option<DateTime<Utc>>,
    pub attested_by: Option<String>,
    /// Derived validation tier (migrations 0036 + 0049): "human_attested" |
    /// "oracle_verified" | "ai_confirmed" | "not_exploitable" | "unproven".
    /// Drives the AI escalation bridge UI.
    pub validation_tier: String,
    /// Oracle verdict (migration 0049): 'candidate' | 'verified' | 'refuted'.
    pub verdict: Option<String>,
    /// Which oracle earned the verdict, when one did.
    pub oracle_kind: Option<String>,
    /// Machine evidence the oracle observed, including its negative control.
    pub receipt_json: Option<serde_json::Value>,
    /// The re-runnable recipe. Surfaced so the UI can offer "replay this proof".
    pub capsule_json: Option<serde_json::Value>,
    /// Replays attempted / replays that succeeded. `verified` requires equality.
    pub replay_n: Option<i32>,
    pub replay_successes: Option<i32>,
    pub verified_at: Option<DateTime<Utc>>,
    pub claimed_mechanism: Option<String>,
}

/// Derive the validation tier from attestation, the oracle verdict, and the AI
/// exploitable verdict — strongest evidence first:
///
///   human_attested  — a person confirmed it
///   oracle_verified — a named oracle re-proved it N/N in code, with a capsule
///   ai_confirmed    — an agent CLAIMS it is exploitable; nothing re-proved it
///   not_exploitable — tested and it did not hold
///   unproven        — never established either way
///
/// The gap between `oracle_verified` and `ai_confirmed` is the point of the
/// whole verification layer: before it existed, both collapsed into one tier and
/// a claim was indistinguishable from a proof. A `refuted` verdict deliberately
/// does NOT become `not_exploitable` — refutation means this particular receipt
/// failed, which is not the same as having tested the vulnerability away.
fn validation_tier_of(
    attested_at: Option<&DateTime<Utc>>,
    verdict: Option<&str>,
    exploitable: Option<&str>,
) -> &'static str {
    if attested_at.is_some() {
        return "human_attested";
    }
    if verdict == Some("verified") {
        return "oracle_verified";
    }
    match exploitable {
        Some("true") | Some("potentially") => "ai_confirmed",
        Some("false") => "not_exploitable",
        _ => "unproven",
    }
}

impl From<&Finding> for FindingResponse {
    fn from(f: &Finding) -> Self {
        let original = f.severity.wire_name().to_string();
        let calibrated = f.calibrated_severity.as_ref().map(|s| s.wire_name().to_string());
        FindingResponse {
            id: f.id.clone(),
            title: f.title.clone(),
            description: f.description.clone(),
            // Effective severity — calibrated if present, original otherwise.
            // This is what the dashboard's tiles + row badges render.
            severity: calibrated.clone().unwrap_or_else(|| original.clone()),
            original_severity: original,
            calibrated_severity: calibrated,
            calibration_rule: f.calibration_rule.clone(),
            calibration_justification: f.calibration_justification.clone(),
            status: f
                .status
                .as_ref()
                .map(|s| s.wire_name().to_string())
                .unwrap_or_else(|| "open".to_string()),
            target: f.target.clone(),
            target_type: f.target_type.clone(),
            evidence: f.evidence.clone(),
            remediation: f.remediation.clone(),
            references: f.references.clone(),
            cve: f.cve.clone(),
            cwe: f.cwe.clone(),
            cvss_score: f.cvss_score.clone(),
            jira_ticket: f.jira_ticket.clone(),
            jira_url: f.jira_url.clone(),
            source: f.source.clone(),
            source_id: f.source_id.clone(),
            category: category_from_source(f.source.as_deref()).to_string(),
            exploitable: f.exploitable.clone(),
            fingerprint: f.fingerprint.clone(),
            occurrence_count: f.occurrence_count,
            first_seen_at: f.first_seen_at,
            last_seen_at: f.last_seen_at,
            assessment_id: f.assessment_id.clone(),
            org_id: f.org_id.clone(),
            created_by: f.created_by.clone(),
            client_id: f.client_id.clone(),
            created_at: f.created_at,
            updated_at: f.updated_at,
            target_id: f.target_id.clone(),
            validation_source: f.validation_source.clone(),
            prior_assessment_id: f.prior_assessment_id.clone(),
            baseline_skip_reason: f.baseline_skip_reason.clone(),
            remediated_at: f.remediated_at,
            prior_exploitable: f.prior_exploitable.clone(),
            remediated_in_assessment_id: f.remediated_in_assessment_id.clone(),
            scan_id: f.scan_id.clone(),
            assigned_to: f.assigned_to.clone(),
            tags: f.tags.clone(),
            attested_at: f.attested_at,
            attested_by: f.attested_by.clone(),
            validation_tier: validation_tier_of(
                f.attested_at.as_ref(),
                f.verdict.as_deref(),
                f.exploitable.as_deref(),
            )
            .to_string(),
            verdict: f.verdict.clone(),
            oracle_kind: f.oracle_kind.clone(),
            receipt_json: f.receipt_json.clone(),
            capsule_json: f.capsule_json.clone(),
            replay_n: f.replay_n,
            replay_successes: f.replay_successes,
            verified_at: f.verified_at,
            claimed_mechanism: f.claimed_mechanism.clone(),
        }
    }
}
