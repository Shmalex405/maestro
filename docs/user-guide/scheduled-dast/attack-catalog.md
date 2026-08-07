# Attack catalog

> [!NOTE] Auto-generated — do not edit by hand
> This page is generated from `config/test-matrix.yml` by `scripts/gen-attack-catalog.mjs`. It is a reference, not a control surface — you select what runs via **scan policies** when you schedule or run a scan.

The deterministic DAST engine knows **234 attack techniques** across 7 surfaces. Each row below is a *technique*, not a single request — at run time one technique fans out into hundreds-to-thousands of real HTTP requests as its backing tool sweeps every discovered parameter and payload. A typical web scan fires **~5,500 requests**; see the per-scan **Statistics** view for the exact count your scan executed.

> [!TIP] Techniques vs. requests
> Counting techniques (234) and counting requests-sent (thousands) are different units. The number that matters for "how much did this scan actually attack my app" is the per-scan **attacks executed** stat, not this catalog's length.

**By surface:** **Web & API (DAST)** 73 · **Code (SAST)** 24 · **Cross-Validation** 15 · **Chain Analysis** 8 · **Cloud** 29 · **Identity / IDP** 60 · **AI / LLM** 25

## Web & API (DAST)

### API

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| API-01 | **OpenAPI/Swagger spec discovery** — Check for exposed API documentation at /swagger.json, /openapi.json, /api-docs, /swagger-ui/, /redoc, /graphql/playground. | `curl` | Always |
| API-02 | **Schema-based endpoint fuzzing** — Fuzz API endpoints with malformed inputs per schema types: oversized strings, negative numbers, null values, wrong types. | `fuzz_api_schema` | API spec discovered or endpoints enumerated |
| API-03 | **Rate limiting enforcement** — Send 50+ rapid requests to key endpoints. Verify 429 responses, check X-RateLimit-* headers, and test limit reset behavior. | `test_api_rate_limiting` | Always |
| API-04 | **API versioning bypass** — Test older API versions (v1, v2) for unpatched vulnerabilities. Replace version in URL paths and check if deprecated endpoints still respond. | `curl` | Always |
| API-05 | **Mass assignment** — Send extra fields in POST/PUT requests (role, isAdmin, permissions, balance) to check if the API blindly binds request body to object properties. | `curl` | Always |
| API-06 | **Excessive data exposure** — Check if API responses return more fields than the UI displays. Look for leaked internal IDs, email addresses, roles, or sensitive metadata. | `curl` | Always |

### AUTH

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| AUTH-01 | **Complete authentication flow** — Authenticate via the configured auth method (OTP, SSO, etc.) | `browser_navigate + browser_fill + browser_click` | Always |
| AUTH-02 | **JWT/token analysis** — Extract and decode JWT tokens. Check algorithm, claims, expiry, storage location. | `browser_evaluate` | Always |
| AUTH-03 | **Token storage security** — Check WHERE tokens are stored (localStorage, sessionStorage, cookies). Document security implications. | `browser_evaluate` | Always |
| AUTH-04 | **Unauthenticated API access** — Attempt API calls without authentication. Verify 401/403. | `curl / browser_evaluate` | Always |
| AUTH-05 | **Session fixation test** — Verify that session tokens are regenerated after successful login. Pre-login token must not persist post-login. | `test_session_fixation` | Always |
| AUTH-06 | **Session token entropy** — Collect multiple session tokens and analyze randomness. Check for predictable patterns or insufficient entropy. | `test_session_management` | Always |
| AUTH-07 | **Token replay after logout** — Capture a valid session token, logout, then attempt to reuse the token. Verify it is invalidated server-side. | `test_token_replay` | Always |
| AUTH-08 | **Password policy validation** — Test password complexity requirements, minimum length, and account lockout after failed attempts. | `test_password_policy` | Application has local password authentication (not SSO-only) |

### AUTHZ

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| AUTHZ-01 | **IDOR on primary resources** — Test ID manipulation on main API endpoints. Swap resource IDs in GET/PUT/DELETE requests to access other objects. | `test_idor` | Always |
| AUTHZ-02 | **Horizontal privilege escalation** — Using credentials of User A, attempt to access data belonging to User B at the same privilege level. | `test_idor` | Always |
| AUTHZ-03 | **Vertical privilege escalation** — Attempt admin-only actions (user management, config changes) using a regular user's session token. | `curl` | Always |
| AUTHZ-04 | **Function-level access control** — Test admin-only API endpoints without admin privileges. Check for missing authorization checks on sensitive functions. | `curl` | Always |

### BIZ

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| BIZ-01 | **Race condition** — Send concurrent identical requests to test for time-of-check to time-of-use (TOCTOU) vulnerabilities. Focus on balance operations, coupon redemption, and resource creation. | `test_race_condition` | Always |
| BIZ-02 | **Price/quantity manipulation** — Modify prices, quantities, or discount values in client-side requests. Test negative quantities, zero-price items, and integer overflow values. | `curl` | E-commerce or transaction functionality detected |
| BIZ-03 | **Workflow bypass** — Attempt to skip required steps in multi-step processes by directly calling later-stage API endpoints without completing earlier steps. | `curl / browser` | Multi-step workflows detected (checkout, registration, approval) |

### CLI

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| CLI-01 | **Source map accessibility** — Check if .js.map files are served. Try appending .map to JS bundle URLs. | `curl / browser_navigate` | Always |
| CLI-02 | **JS bundle analysis** — Inspect compiled JS for hardcoded API URLs, environment names, keys, internal endpoints across envs. | `browser_evaluate / curl` | Always |
| CLI-03 | **Config file exposure** — Check /config.js, /env.js, /settings.json, /.env for exposed configuration. | `curl` | Always |
| CLI-04 | **Error message information leakage** — Trigger errors (invalid IDs, bad queries, 404s) and check if internal identifiers, stack traces, or debug info leak. | `curl / browser_evaluate` | Always |
| CLI-05 | **DOM-based XSS** — Test for DOM manipulation vulnerabilities via URL fragments, document.location, window.name, postMessage handlers, and innerHTML sinks. | `browser_evaluate` | Always |
| CLI-06 | **Prototype pollution** — Test for JavaScript prototype pollution via __proto__, constructor.prototype in URL parameters, JSON bodies, and merge operations. | `browser_evaluate` | Always |

### CORS

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| CORS-01 | **Origin reflection** — Test if arbitrary origins are reflected in Access-Control-Allow-Origin. Send requests with evil.com origin and check response. | `test_cors` | Always |
| CORS-02 | **Null origin bypass** — Test if Origin: null is allowed by the CORS policy. Null origin can be triggered via sandboxed iframes and redirects. | `test_cors` | Always |
| CORS-03 | **Credentials with wildcard** — Check if Access-Control-Allow-Credentials: true is returned alongside a reflected or wildcard origin. This allows cross-origin credential theft. | `test_cors` | Always |

### DESER

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| DESER-01 | **Deserialization testing** — Test for insecure deserialization in Java (ObjectInputStream), Python (pickle), PHP (unserialize), and .NET (BinaryFormatter). Use out-of-band callbacks to detect blind deserialization. | `test_deserialization` | Java, Python, PHP, or .NET backend detected |

### GQL

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| GQL-01 | **Introspection query** — Send __schema introspection query. Verify it's disabled. | `curl / browser_evaluate` | Always |
| GQL-02 | **Batch query test** — Send array of queries in single request. Verify batching is blocked. | `curl` | Always |
| GQL-03 | **Schema enumeration via suggestions** — Send queries with invalid field names. Check if 'Did you mean X?' suggestions leak schema. Probe at least 10 field names across different types. | `curl` | Always |
| GQL-04 | **Bulk data enumeration (users/objects)** — Query bulk listing endpoints (users, members, etc.) to check if they return all records without authorization filtering. | `curl / browser_evaluate` | Always |
| GQL-05 | **IDOR via direct object lookup** — Use IDs from GQL-04 (or fabricate IDs) to access individual records via direct lookup queries. Test with both real and fake IDs. | `curl / browser_evaluate` | Always |
| GQL-06 | **Query aliasing rate limit bypass** — Send multiple aliased queries in single request to bypass per-request rate limiting. | `curl` | Always |
| GQL-07 | **API rate limiting** — Send 10+ rapid sequential requests. Check for 429 responses or X-RateLimit-* headers. | `curl / custom script` | Always |
| GQL-08 | **Mutation discovery** — Probe for available mutations (create, update, delete operations) | `curl` | Always |

### HDR

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| HDR-01 | **Content-Security-Policy check** — Check for CSP header on all primary targets | `browser_network_log / curl` | Always |
| HDR-02 | **CORS policy check** — Send requests with Origin header, check Access-Control-Allow-Origin. Test on BOTH frontend AND API endpoints. | `curl` | Always |
| HDR-03 | **Standard security headers** — Check HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | `curl / browser_network_log` | Always |
| HDR-04 | **Cookie security flags** — Check HttpOnly, Secure, SameSite on all cookies | `browser_get_cookies` | Always |

### INJ

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| INJ-01 | **SQL injection on parameterized endpoints** — Run sqlmap on all endpoints with user-controllable parameters | `run_sqlmap` | Parameterized endpoints discovered |
| INJ-02 | **XSS on input-reflecting endpoints** — Test for reflected and stored XSS | `test_xss` | Input-reflecting endpoints discovered |
| INJ-03 | **Server-Side Template Injection** — Inject template expressions ({{7*7}}, ${7*7}, <%= 7*7 %>) into input fields and URL parameters. Check for evaluated output. | `test_ssti` | Server-rendered pages or template engines detected |
| INJ-04 | **Command injection** — Test for OS command injection via semicolons, pipes, backticks, $() in parameters that may reach shell execution. | `run_sqlmap / custom` | Endpoints that interact with system processes (ping, DNS lookup, file conversion, etc.) |
| INJ-05 | **LDAP injection** — Test LDAP search filters for injection via special characters: *, (, ), \, NUL. Probe login and search endpoints. | `custom curl` | LDAP authentication or directory lookups detected |
| INJ-06 | **XPath injection** — Inject XPath expressions (' or '1'='1, ' or ''=') into parameters that may query XML data stores. | `custom curl` | XML-based data sources or SOAP endpoints detected |
| INJ-07 | **HTTP header injection (CRLF)** — Test for CRLF injection in headers by injecting %0d%0a sequences in URL parameters, Host header, and redirect targets. | `custom curl` | Always |
| INJ-08 | **NoSQL injection** — Test JSON operator injection ({"$gt":""}), JavaScript injection in $where clauses, and regex DoS in NoSQL queries. | `custom curl` | MongoDB, CouchDB, or other NoSQL databases suspected |

### PROTO

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| PROTO-01 | **HTTP request smuggling** — Test for CL.TE and TE.CL request smuggling by sending ambiguous Content-Length and Transfer-Encoding headers. Check for desync between frontend proxy and backend. | `test_http_smuggling` | Always |
| PROTO-02 | **WebSocket security** — Test WebSocket connection authentication, message injection, cross-site WebSocket hijacking (CSWSH), and origin validation. | `test_websocket` | WebSocket endpoints discovered |
| PROTO-03 | **Cache poisoning** — Test for web cache poisoning by injecting unkeyed headers (X-Forwarded-Host, X-Original-URL) and checking if poisoned responses are cached and served to other users. | `test_cache_poisoning` | Always |

### RECON

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| RECON-01 | **Port scan primary target** — Scan top 1000 ports on the primary target | `scan_ports` | Always |
| RECON-02 | **Subdomain enumeration** — Enumerate subdomains for all in-scope domains | `enumerate_subdomains` | Always |
| RECON-03 | **Service fingerprinting** — Fingerprint services on open ports (80, 443 at minimum) | `fingerprint_services` | Always |
| RECON-04 | **Web technology scan** — Identify CDN, framework, server, security headers | `web_technology_scan` | Always |
| RECON-05 | **DNS record enumeration** — Enumerate A, AAAA, MX, TXT, NS, CNAME, SOA records for all in-scope domains | `check_dns_records` | Always |
| RECON-06 | **Zone transfer attempt** — Attempt AXFR zone transfer against all discovered nameservers | `test_zone_transfer` | Always |

### SSRF

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| SSRF-01 | **Internal IP access** — Test URL-accepting parameters for access to internal IPs (127.0.0.1, 10.x, 172.16.x, 192.168.x). Try various bypass encodings. | `test_ssrf` | Always |
| SSRF-02 | **Cloud metadata access** — Probe URL parameters for access to cloud metadata endpoint 169.254.169.254. Test AWS, GCP, and Azure metadata URLs. | `test_ssrf / test_cloud_metadata` | Always |
| SSRF-03 | **DNS rebinding** — Test DNS rebinding to bypass SSRF allowlist filters. Use domains that resolve to internal IPs after initial resolution. | `test_ssrf` | Always |

### TLS

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| TLS-01 | **SSL/TLS protocol analysis** — Test for weak protocols (SSLv3, TLS 1.0, TLS 1.1). Only TLS 1.2+ should be accepted. | `scan_ssl_tls` | Always |
| TLS-02 | **Certificate chain validation** — Verify certificate chain integrity, expiry date, signing algorithm strength, and hostname match | `check_certificate` | Always |
| TLS-03 | **Cipher suite analysis** — Enumerate and grade all supported cipher suites. Flag weak ciphers (RC4, DES, NULL, export-grade). | `scan_ssl_ciphers` | Always |
| TLS-04 | **Known SSL vulnerabilities** — Check for Heartbleed, ROBOT, POODLE, BEAST, CRIME, DROWN, FREAK, Logjam vulnerabilities | `scan_ssl_tls` | Always |

### UPLOAD

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| UPLOAD-01 | **Extension bypass** — Attempt to bypass file extension restrictions using double extensions (.php.jpg), case variation (.pHp), null byte injection (file.php%00.jpg), and alternate extensions (.phtml, .php5). | `test_file_upload` | Always |
| UPLOAD-02 | **Content-Type manipulation** — Upload files with manipulated MIME types. Send a PHP/JSP file with Content-Type: image/jpeg to bypass server-side type checks. | `test_file_upload` | Always |
| UPLOAD-03 | **Path traversal in filename** — Use path traversal sequences in the filename field (../../etc/passwd, ..\..\web.config) to write files outside the upload directory. | `test_file_upload` | Always |

### VSCAN

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| VSCAN-01 | **Nuclei CVE scanning** — Run Nuclei with medium,high,critical severity templates | `run_nuclei` | Always |
| VSCAN-02 | **CSRF protection check** — Determine if CSRF tokens are used. If Bearer auth only, document as architecturally mitigated. | `manual analysis` | Always |
| VSCAN-03 | **Nikto web server scanning** — Run Nikto against all discovered web servers to check for known server misconfigurations, dangerous files, and outdated software. | `run_nikto` | Always |

## Code (SAST)

### SAST

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| SAST-01 | **Semgrep OWASP Top 10 scan** — Run Semgrep with p/owasp-top-ten ruleset | `scan_semgrep` | Always |
| SAST-02 | **Secrets scanning** — Run Gitleaks on full repository | `scan_secrets` | Always |
| SAST-03 | **Dependency vulnerability scan** — Check all package managers for known vulnerable dependencies | `scan_dependencies` | Always |
| SAST-04 | **Entry point mapping** — Map all HTTP routes, API endpoints, and entry points | `map_entry_points` | Always |
| SAST-05 | **Defense analysis** — Check for auth middleware, CSRF, rate limiting, input validation, output encoding, security headers | `analyze_defenses` | Always |
| SAST-06 | **IaC scanning** — Scan infrastructure-as-code for misconfigurations | `scan_iac` | Dockerfiles, Terraform, K8s manifests detected |
| SAST-07 | **Security audit ruleset** — Run Semgrep with p/security-audit ruleset for broader coverage beyond OWASP Top 10 (crypto issues, race conditions, insecure defaults). | `scan_semgrep` | Always |
| SAST-08 | **Language-specific scanning** — Run language-specific scanners: Bandit for Python, njsscan for JavaScript/Node.js. Auto-detect language and select appropriate scanner. | `scan_bandit / scan_njsscan` | Always |
| SAST-09 | **Dangerous function detection** — Scan for use of dangerous functions: eval(), exec(), system(), popen(), child_process.exec(), innerHTML, dangerouslySetInnerHTML, pickle.loads(), yaml.load(). | `scan_semgrep` | Always |
| SAST-10 | **Configuration secrets in code (git history)** — Scan git history for secrets that may have been committed and later removed. Use gitleaks with --include-git-history flag. | `scan_secrets` | Always |
| SAST-DEF-01 | **Authentication middleware coverage** — Verify all HTTP endpoints have authentication middleware applied. Flag any unprotected routes that should require auth. | `analyze_defenses` | Always |
| SAST-DEF-02 | **Input validation coverage** — Check that all user-facing inputs have validation (type checking, length limits, format validation). Flag endpoints accepting raw unvalidated input. | `analyze_defenses` | Always |
| SAST-DEF-03 | **CSRF protection coverage** — Verify all state-changing operations (POST, PUT, DELETE) have CSRF protection via tokens, SameSite cookies, or origin checking. | `analyze_defenses` | Always |
| SAST-DEF-04 | **Output encoding coverage** — Check that all dynamic output is properly encoded for its context (HTML, JavaScript, URL, CSS). Flag raw interpolation in templates. | `analyze_defenses` | Always |
| SAST-DEF-05 | **SQL parameterization coverage** — Verify all database queries use parameterized queries or ORM methods. Flag any string concatenation in SQL construction. | `analyze_defenses` | Always |
| SAST-DF-01 | **SQL injection data flows** — Trace user input from HTTP request parameters through the application to SQL query construction. Flag unparameterized queries. | `trace_data_flows` | Always |
| SAST-DF-02 | **XSS data flows** — Trace user input from HTTP request parameters to HTML/template output. Flag unencoded output in response rendering. | `trace_data_flows` | Always |
| SAST-DF-03 | **RCE data flows** — Trace user input to command execution sinks (exec, spawn, system, popen). Flag any unvalidated input reaching shell commands. | `trace_data_flows` | Always |
| SAST-DF-04 | **SSRF data flows** — Trace user input to outbound HTTP request construction (fetch, axios, requests, HttpClient). Flag URLs built from user input without allowlist validation. | `trace_data_flows` | Always |
| SAST-DF-05 | **File system access flows** — Trace user input to file system operations (readFile, writeFile, open, path.join). Flag path traversal risks from unvalidated file paths. | `trace_data_flows` | Always |
| SAST-SC-01 | **Critical dependency vulnerabilities** — Scan all dependencies for CRITICAL severity CVEs. Any critical vulnerability in a direct dependency is an automatic finding. | `scan_dependencies` | Always |
| SAST-SC-02 | **High dependency vulnerabilities** — Scan all dependencies for HIGH severity CVEs. Document affected packages, CVE IDs, and available fix versions. | `scan_dependencies` | Always |
| SAST-SC-03 | **License compliance** — Check for copyleft (GPL, AGPL) or restrictive licenses in dependencies that may conflict with project licensing requirements. | `scan_dependencies` | Always |
| SAST-SC-04 | **Dependency confusion risk** — Check for private package names that could be squatted on public registries. Verify .npmrc / pip.conf scoping and registry configuration. | `scan_dependencies` | Always |

## Cross-Validation

### XVAL

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| XVAL-01 | **Validate SAST XSS findings against live endpoints** — For each SAST XSS finding, determine if the vulnerable code path is reachable from external endpoints | orchestrated | Always |
| XVAL-02 | **Validate SAST injection findings against live endpoints** — For each SAST injection finding, test the corresponding live endpoint | orchestrated | Always |
| XVAL-03 | **Confirm token storage matches code** — Verify localStorage/cookie storage from SAST matches DAST observation | orchestrated | Always |
| XVAL-04 | **Confirm security header gaps match code** — Verify missing headers from SAST defense analysis match DAST header check | orchestrated | Always |
| XVAL-05 | **Validate SAST SSRF findings against live endpoints** — For each SAST SSRF finding (user input to HTTP client), test the corresponding live endpoint with internal IP and cloud metadata payloads | orchestrated | Always |
| XVAL-06 | **Validate SAST RCE findings against live endpoints** — For each SAST command injection finding (user input to exec/system), test the corresponding live endpoint with command injection payloads | orchestrated | Always |
| XVAL-07 | **Validate SAST auth bypass findings against live endpoints** — For each SAST auth gap (unprotected routes), confirm the live endpoint allows unauthenticated access | orchestrated | Always |
| XVAL-08 | **Validate SAST deserialization findings** — For each SAST deserialization finding, test the corresponding live endpoint with serialized payloads and out-of-band callbacks | orchestrated | Always |
| XVAL-09 | **Validate SAST rate limiting gaps against live API** — For SAST-identified endpoints missing rate limiting middleware, confirm with rapid request bursts against the live API | orchestrated | Always |
| XVAL-10 | **Validate SAST path traversal findings against live endpoints** — For each SAST file access finding (user input to fs operations), test the corresponding live endpoint with path traversal sequences | orchestrated | Always |
| XVAL-11 | **Validate SAST secrets exposure in deployed environment** — For secrets found in code (API keys, tokens), check if they are active in the deployed environment by testing against their respective services | orchestrated | Always |
| XVAL-12 | **Cloud posture vs exploitation validation** — Validate cloud posture findings with actual exploitation attempts | orchestrated | Always |
| XVAL-13 | **IaC vs live cloud config validation** — Cross-validate IaC scanning results against live cloud configuration | orchestrated | Always |
| XVAL-14 | **Identity recon vs exploitation validation** — Validate identity recon findings via exploitation — cracked-hash / forged-token proof (Kerberoast candidate → cracked cred, CA gap → bypassed token) | orchestrated | Always |
| XVAL-15 | **SAST domain-creds vs live AD foothold** — Cross-validate domain credentials surfaced by SAST (secret in config) against a live AD foothold (CHAIN-47 cross-domain bridge) | orchestrated | Always |

## Chain Analysis

### CHAIN

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| CHAIN-01 | **Grants/requires capability tagging** — Tag every finding with capabilities it grants and requires. Verify all findings have been analyzed. | `chain-analysis-agent` | Always |
| CHAIN-02 | **Catalog pattern matching** — Match tagged findings against the 30 chain patterns in chain-patterns.yml. Document matches and near-misses. | `chain-analysis-agent` | Always |
| CHAIN-03 | **Emergent chain discovery** — Identify novel attack chains not in the catalog by analyzing capability flows between findings. | `chain-analysis-agent` | Always |
| CHAIN-04 | **Multi-step exploit hypothesis generation** — Generate testable hypotheses for each chain with specific required tests and expected outcomes. | `chain-analysis-agent` | Always |
| CHAIN-05 | **Chain exploitation validation** — Validate chain hypotheses against exploit agent results. Classify each as confirmed, refuted, or untested. | `chain-analysis-agent` | Always |
| CHAIN-06 | **Combined severity calculation** — Calculate combined severity for each chain (highest step + chain bonus, capped at critical). | `chain-analysis-agent` | Always |
| CHAIN-07 | **Defense-in-depth analysis** — For refuted chains, document which defensive control broke the chain. Rank controls by chain-breaking impact. | `chain-analysis-agent` | Always |
| CHAIN-08 | **Chain remediation prioritization** — Recommend which chain links to break first, considering ease of fix and number of chains disrupted. | `chain-analysis-agent` | Always |

## Cloud

### CLOUD

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| CLOUD-01 | **Cloud account enumeration** — Enumerate all resources in authorized cloud accounts using ScoutSuite | `enum_cloud_account` | cloud_accounts defined in scope.yml |
| CLOUD-02 | **Public cloud asset discovery** — External discovery of cloud-hosted assets by company name | `discover_cloud_assets_external` | cloud_accounts defined in scope.yml |
| CLOUD-03 | **Cloud network mapping** — Map VPCs, security groups, peering, public IPs, load balancers | `enum_cloud_networking` | cloud_accounts defined in scope.yml |
| CLOUD-04 | **Cloud endpoint discovery** — Discover public API Gateways, CloudFront, ALB/ELB, CDN endpoints | `enum_cloud_endpoints` | cloud_accounts defined in scope.yml |
| CLOUD-05 | **IAM policy analysis** — Analyze IAM policies for wildcards, admin-equivalent, dangerous combos | `enum_iam_policies` | cloud_accounts defined in scope.yml |
| CLOUD-06 | **IAM privilege escalation** — Identify and attempt privesc: PassRole, AssumeRole, Lambda injection | `test_iam_privesc` | cloud_accounts defined in scope.yml |
| CLOUD-07 | **Cross-account trust analysis** — Test trust policies for confused deputy, overpermissive principals | `test_cross_account_trust` | cloud_accounts defined in scope.yml |
| CLOUD-08 | **Service account permissions** — Test EC2 profiles, Lambda roles, ECS task roles for excess permissions | `test_service_account_permissions` | cloud_accounts defined in scope.yml |
| CLOUD-09 | **MFA enforcement** — Verify MFA required for console, privileged API calls, role assumption | `enum_iam_policies` | cloud_accounts defined in scope.yml |
| CLOUD-10 | **Credential exposure and rotation** — Check stale/unrotated keys, keys in env vars, keys in user-data | `test_credential_exposure` | cloud_accounts defined in scope.yml |
| CLOUD-11 | **Storage bucket exploitation** — Test all storage buckets for policy conditions, cross-account, versioning | `exploit_storage_misconfig` | cloud_accounts defined in scope.yml |
| CLOUD-12 | **Public snapshot exposure** — Find publicly shared RDS/EBS/disk snapshots | `test_public_snapshots` | cloud_accounts defined in scope.yml |
| CLOUD-13 | **Encryption at rest verification** — Verify encryption on storage, databases, volumes, snapshots | `audit_cloud_posture` | cloud_accounts defined in scope.yml |
| CLOUD-14 | **Secrets management exploitation** — Enumerate and read Secrets Manager, Parameter Store, Key Vault | `test_secrets_manager` | cloud_accounts defined in scope.yml |
| CLOUD-15 | **Sensitive data in storage** — Scan accessible buckets for PII, credentials, config, dumps | `scan_storage_sensitive_data` | cloud_accounts defined in scope.yml |
| CLOUD-16 | **Instance metadata exploitation** — Userdata secrets, instance profile permissions, credential harvesting | `test_instance_metadata` | cloud_accounts defined in scope.yml |
| CLOUD-17 | **Serverless function security** — Env var leakage, event injection, layer analysis, execution role abuse | `test_lambda_security` | cloud_accounts defined in scope.yml |
| CLOUD-18 | **API Gateway bypass** — Direct Lambda invocation, missing authorizer, throttling bypass | `test_api_gateway_security` | cloud_accounts defined in scope.yml |
| CLOUD-19 | **Container registry exposure** — Pull images without auth, extract secrets from layers, scan CVEs | `test_container_registry` | cloud_accounts defined in scope.yml |
| CLOUD-20 | **Compute network exposure** — Security group analysis: admin ports open to 0.0.0.0/0 | `enum_cloud_networking` | cloud_accounts defined in scope.yml |
| CLOUD-21 | **K8s RBAC analysis** — Overprivileged SAs, cluster-admin bindings, wildcard permissions | `test_k8s_rbac` | kubernetes clusters defined in scope.yml |
| CLOUD-22 | **K8s secrets extraction** — Extract secrets from K8s: Secret resources, env vars, mounted volumes | `test_k8s_secrets` | kubernetes clusters defined in scope.yml |
| CLOUD-23 | **Container escape testing** — Privileged pods, hostPID/hostNetwork, Docker socket, SYS_ADMIN caps | `test_k8s_escape` | kubernetes clusters defined in scope.yml |
| CLOUD-24 | **K8s network segmentation** — Cross-namespace connectivity, missing network policies | `test_k8s_network_policy` | kubernetes clusters defined in scope.yml |
| CLOUD-25 | **K8s API server security** — Anonymous auth, exposed dashboard, metrics endpoint info disclosure | `test_k8s_api_server` | kubernetes clusters defined in scope.yml |
| CLOUD-26 | **Container image CVEs** — Scan running container images for critical/high vulnerabilities | `scan_container_image` | kubernetes clusters defined in scope.yml |
| CLOUD-27 | **Security logging verification** — Verify CloudTrail/Azure Monitor/GCP Audit, multi-region, S3 logging | `enum_cloud_logging` | cloud_accounts defined in scope.yml |
| CLOUD-28 | **Alert configuration** — Check alerts for root usage, privesc, config changes, anomalies | `audit_cloud_posture` | cloud_accounts defined in scope.yml |
| CLOUD-29 | **Log tampering test** — Test if current credentials can disable/modify logging | `enum_cloud_logging` | cloud_accounts defined in scope.yml |

## Identity / IDP

### IDENTITY

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| IDENTITY-01 | **AD domain enumeration** — bloodhound-python + ldapdomaindump full domain collection (users, groups, computers, trusts, ACLs) | `enum_ad_domain` | active_directory target in scope |
| IDENTITY-02 | **BloodHound graph collection** — Collect the BloodHound graph (collection_method All) for attack-path analysis | `enum_ad_domain` | active_directory target in scope |
| IDENTITY-03 | **Kerberoast/AS-REP candidate enumeration** — List Kerberoastable SPNs (GetUserSPNs) and AS-REP-roastable users (GetNPUsers) — candidates only, no cracking | `enum_ad_kerberos_targets` | active_directory target in scope |
| IDENTITY-04 | **ADCS vulnerable template enumeration** — certipy find -vulnerable — enumerate ADCS CAs and ESC1-ESC13 vulnerable templates (no exploitation) | `enum_adcs_templates` | active_directory target in scope |
| IDENTITY-05 | **AD trust enumeration** — Enumerate domain/forest trusts and trust direction from the BloodHound collection | `enum_ad_domain` | active_directory target in scope |
| IDENTITY-06 | **Kerberoasting + crack** — GetUserSPNs -request → extract TGS hashes → crack with hashcat (mode 13100); report cracked service-account creds | `kerberoast` | active_directory target in scope |
| IDENTITY-07 | **AS-REP roasting + crack** — GetNPUsers → extract AS-REP hashes (mode 18200) → crack | `asrep_roast` | active_directory target in scope |
| IDENTITY-08 | **AD password spray** — kerbrute/NetExec lockout-aware spray (<= threshold-margin, jitter, abort-on-lockout). LOCKOUT MANDATE applies. | `password_spray_ad` | active_directory target in scope |
| IDENTITY-09 | **ACL abuse (GenericAll/WriteDACL)** — Exploit a discovered ACL edge via impacket/bloodyAD. Password-reset / group-add writes = user-confirm protocol. | `abuse_ad_acl` | active_directory target in scope |
| IDENTITY-10 | **DCSync** — secretsdump -just-dc using replication rights — pull krbtgt/target hashes to prove DA-equivalent (read-only) | `dcsync` | active_directory target in scope |
| IDENTITY-11 | **Delegation abuse (unconstrained/constrained/RBCD)** — getST/rbcd to impersonate a target user to a service via a delegation edge | `abuse_delegation` | active_directory target in scope |
| IDENTITY-12 | **ADCS ESC1-13 exploitation** — Certipy ESC1-ESC8/ESC11/ESC13 — request a privileged cert, auth with it (PKINIT → TGT → secretsdump). ESC8 relay = user-confirm. | `exploit_adcs` | active_directory target in scope |
| IDENTITY-13 | **LAPS password read** — NetExec/bloodyAD --laps — read LAPS local-admin passwords the current identity is entitled to (read-only) | `read_laps` | active_directory target in scope |
| IDENTITY-14 | **NTLM/SMB relay** — impacket ntlmrelayx (+ mitm6/Responder) — relay coerced auth to LDAP/SMB/ADCS-HTTP. Multi-step, always user-confirm. | `ntlm_relay` | active_directory target in scope AND MITM position |
| IDENTITY-15 | **Golden/Silver ticket forge** — Forge a Golden/Silver TGT from the krbtgt hash (post-DCSync) to prove persistence (forge + use, no account change) | `golden_ticket` | active_directory target in scope AND krbtgt obtained |
| IDENTITY-16 | **Tenant fingerprint (unauthenticated)** — Unauthenticated tenant fingerprint: federation (getuserrealm), .well-known OIDC config, tenant ID, branding | `enum_entra_tenant` | entra_id target in scope |
| IDENTITY-17 | **User/email enumeration** — o365spray / AADInternals user-existence enumeration against a name/email list | `enum_entra_users` | entra_id target in scope |
| IDENTITY-18 | **Directory enumeration** — roadrecon gather + analyze: users, groups, SPs, app registrations, roles, owners | `enum_entra_directory` | entra_id target in scope |
| IDENTITY-19 | **Conditional Access enumeration** — Enumerate CA policies (named locations, device/MFA conditions, app exclusions) — finds the gaps spray/replay exploit | `enum_conditional_access` | entra_id target in scope |
| IDENTITY-20 | **OAuth app/SP grant enumeration** — List app registrations + service principals + delegated/application permission grants (illicit-consent candidates) | `enum_oauth_apps` | entra_id target in scope |
| IDENTITY-21 | **Entra password spray** — MSOLSpray/o365spray lockout-aware spray respecting Smart Lockout (1 attempt/user/window, jitter, abort-on-lockout). LOCKOUT MANDATE applies. | `password_spray_entra` | entra_id target in scope |
| IDENTITY-22 | **Illicit consent grant abuse** — GraphRunner OAuth-app inject / illicit consent — register/abuse an app to obtain delegated Graph scopes. User-confirm (creates a registration). | `abuse_consent_grant` | entra_id target in scope |
| IDENTITY-23 | **Device-code phishing** — TokenTactics/GraphRunner device-code flow — emulate phishing token-acquisition. User-confirm (involves a victim). | `device_code_phish` | entra_id target in scope |
| IDENTITY-24 | **Token theft/replay** — roadtx — replay a stolen/issued access+refresh token against Graph; test CAE and refresh rotation (read-only by default) | `replay_entra_token` | entra_id target in scope |
| IDENTITY-25 | **Conditional Access bypass** — Pivot UA / device-compliance / location to slip a held token past a CA gap found in enum_conditional_access | `test_ca_bypass` | entra_id target in scope |
| IDENTITY-26 | **Service principal abuse** — Add a client secret/cert to an owned SP, or abuse SP owner rights to escalate. User-confirm (adds a credential). | `abuse_service_principal` | entra_id target in scope |
| IDENTITY-27 | **Primary Refresh Token abuse** — roadtx/AADInternals PRT request/abuse — derive a PRT to mint tokens as the user. User-confirm (multi-step). | `forge_prt` | entra_id target in scope |
| IDENTITY-28 | **Cross-tenant/guest abuse** — Guest/B2B abuse — enumerate and access cross-tenant resources reachable from an in-scope guest identity (read-only) | `test_cross_tenant` | entra_id target in scope |
| IDENTITY-29 | **Mailbox access (Graph)** — GraphRunner Get-Inbox/Invoke-SearchMailbox — read/search an in-scope mailbox via Graph (proves Mail.Read blast radius, read-only) | `access_mailbox` | m365 target in scope |
| IDENTITY-30 | **SharePoint/OneDrive exfil** — GraphRunner Invoke-SearchSharePointAndOneDrive — keyword-search tenant SharePoint/OneDrive for secrets/PII (read-only) | `search_sharepoint_onedrive` | m365 target in scope |
| IDENTITY-31 | **Teams data access** — GraphRunner Get-TeamsChat/channel messages — read Teams data (read-only) | `access_teams` | m365 target in scope |
| IDENTITY-32 | **eDiscovery abuse** — Tenant-wide Compliance Center / eDiscovery search (the 'search everyone's mail' power). User-confirm (tenant-wide reach). | `abuse_ediscovery` | m365 target in scope |
| IDENTITY-33 | **App-registration persistence** — GraphRunner/AADInternals — plant a hidden app-registration persistence (consent-free Graph access). User-confirm (persistence). | `abuse_app_registration` | m365 target in scope |
| IDENTITY-34 | **AADInternals Golden SAML / sync abuse** — AADInternals Golden SAML / immutableID / AD-Connect-sync abuse — the deepest M365 tenant-takeover primitives. User-confirm (multi-step, highest impact). | `aadinternals_attack` | m365 target in scope |
| IDENTITY-35 | **MFA coverage sweep** — MFASweep — per-protocol MFA coverage check across the M365/Entra auth surface | `enum_m365_surface` | entra_id target in scope |
| IDENTITY-36 | **Legacy auth protocol exposure** — Identify legacy/basic-auth protocol endpoints (IMAP/POP/SMTP/EWS) reachable without modern-auth/MFA | `enum_m365_surface` | m365 target in scope |
| IDENTITY-37 | **Stale/over-privileged roles** — Surface stale and over-privileged directory-role assignments (e.g. standing Global Admin) from the directory enumeration | `enum_entra_directory` | entra_id target in scope |
| IDENTITY-38 | **AD Connect / sync account abuse** — Abuse the AD Connect / directory-sync service account to pivot between on-prem AD and Entra (the hybrid-identity bridge) | `aadinternals_attack` | active_directory AND entra_id in scope |
| IDENTITY-39 | **On-prem DA → Entra GA (Golden SAML)** — From on-prem Domain Admin, forge a Golden SAML token to assume Entra Global Admin (CHAIN-48 hybrid bridge) | `aadinternals_attack` | active_directory AND entra_id in scope |
| IDENTITY-40 | **Secret-in-code → AD foothold (cross-domain)** — Use domain creds surfaced by SAST (secret in config) to establish an AD foothold, then Kerberoast (CHAIN-47 cross-domain bridge) | `kerberoast` | active_directory in scope AND repo_paths provided |
| IDENTITY-41 | **Okta org fingerprint (unauthenticated)** — Unauth Okta org fingerprint via .well-known OIDC/org metadata + sign-in widget config (no auth) | `enum_okta_org` | okta target in scope |
| IDENTITY-42 | **Okta user enumeration** — Username/login existence via the Users API (with SSWS token) or the /api/v1/authn behavior oracle | `enum_okta_users` | okta target in scope |
| IDENTITY-43 | **Okta OAuth app + scope enumeration** — Enumerate OAuth/API-service apps + their grants/scopes (the consent-abuse surface) | `enum_okta_apps` | okta target in scope |
| IDENTITY-44 | **Okta privileged role enumeration** — Enumerate Super Admin / Org Admin and other privileged role assignments | `enum_okta_admin_roles` | okta target in scope |
| IDENTITY-45 | **Okta policy gap analysis** — Sign-on / MFA / password / network-zone policy gaps (the conditional-access analog) | `enum_okta_policies` | okta target in scope |
| IDENTITY-46 | **Okta password spray (lockout-aware)** — Lockout-aware spray against /api/v1/authn — fail-closed per the Lockout Mandate (caps at threshold-1, aborts on lockout) | `spray_okta` | okta target in scope |
| IDENTITY-47 | **Okta MFA factor analysis** — Enrolled-factor enumeration + weak-factor / push-fatigue / downgrade analysis | `test_okta_mfa` | okta target in scope |
| IDENTITY-48 | **Okta OAuth consent abuse** — OAuth consent-grant / app abuse path (analysis by default; attempt_grant gated) | `abuse_okta_consent` | okta target in scope |
| IDENTITY-49 | **Okta token replay** — Read-only session / OAuth token replay | `test_okta_token_replay` | okta target in scope |
| IDENTITY-50 | **Okta SAML/OIDC weakness analysis** — SAML/OIDC signature/validation (golden-SAML class) analysis | `test_okta_saml` | okta target in scope |
| IDENTITY-51 | **Google Workspace domain fingerprint (unauthenticated)** — Unauth domain fingerprint: MX/SPF/DKIM/DMARC, GHS, accounts.google realm + OIDC config (no auth) | `enum_gworkspace_domain` | google_workspace target in scope |
| IDENTITY-52 | **Google Workspace user enumeration** — Directory enum via the Admin SDK (SA key + delegated subject) or email-validity oracle | `enum_gworkspace_users` | google_workspace target in scope |
| IDENTITY-53 | **Google Workspace privileged role enumeration** — Super Admin / delegated-admin / privileged-role enumeration | `enum_gworkspace_admin_roles` | google_workspace target in scope |
| IDENTITY-54 | **Google Workspace OAuth + domain-wide delegation abuse** — Domain-wide-delegation + OAuth-app abuse analysis (the high-impact GWS path; attempt_impersonate gated) | `abuse_gworkspace_oauth` | google_workspace target in scope |
| IDENTITY-55 | **Google Workspace SAML/SSO weakness analysis** — SAML/SSO config + golden-SAML-class signature analysis | `test_gworkspace_saml` | google_workspace target in scope |
| IDENTITY-56 | **Google Workspace token replay** — Read-only OAuth refresh/access token replay (attempt_refresh gated) | `test_gworkspace_token` | google_workspace target in scope |
| IDENTITY-57 | **Ping org fingerprint (unauthenticated)** — PingOne/PingFederate fingerprint via OIDC .well-known + auth/token endpoints + SAML metadata (no auth) | `enum_ping_org` | ping target in scope |
| IDENTITY-58 | **Ping user enumeration** — User enum via the PingOne Management API (worker token) or auth-flow oracle | `enum_ping_users` | ping target in scope |
| IDENTITY-59 | **Ping OAuth app/consent abuse** — OAuth application + worker-app/role-assignment abuse analysis (attempt_grant gated) | `abuse_ping_oauth` | ping target in scope |
| IDENTITY-60 | **Ping SAML/OIDC weakness analysis** — SAML/OIDC signature posture + golden-SAML/XSW class analysis | `test_ping_saml` | ping target in scope |

## AI / LLM

### AI

| ID | Attack | Backing tool | Applies when |
|---|---|---|---|
| AI-DOS-01 | **Unbounded consumption probe** — Short proof that a rate / token / cost limit is absent — probe-only, never a sustained flood (AI Safety Mandate §10.1) (OWASP LLM10) | `ai_consumption_probe` | ai_targets defined in scope.yml |
| AI-EA-01 | **Excessive agency / tool-call coercion** — Coerce the agent into firing a dangerous tool. CAPTURE the tool call + arguments and STOP before real side effects (AI Safety Mandate §10.3) (OWASP LLM06) | `ai_test_excessive_agency` | ai_targets with kind agent or mcp_server in scope (declared or detected — AI-RECON-05) |
| AI-EA-02 | **Multi-tool chain escalation** — Coerce a chain of tool calls (read → act) that escalates beyond intended scope; capture each call without executing real side effects (OWASP LLM06) | `ai_test_excessive_agency` | ai_targets with kind agent in scope (declared or detected — AI-RECON-05) |
| AI-EXT-01 | **Training-data / membership-inference extraction** — Bounded susceptibility probe: does the model echo memorized/training data verbatim or show a membership-inference signal (asymmetric confidence between a planted member string and a control)? (ATLAS AML.T0024) | `ai_test_model_extraction` | ai_targets defined in scope.yml |
| AI-EXT-02 | **Model-parameter / fingerprint extraction susceptibility** — Bounded susceptibility probe: does the model leak its exact name/version/parameter count/provider, and is there NO rate limit during the bounded query burst (extraction feasible)? (ATLAS AML.T0044) | `ai_test_model_extraction` | ai_targets defined in scope.yml |
| AI-GB-01 | **Guardrail bypass** — Bypass the declared/observed input-output guardrails (encoding, multilingual, splitting) | `ai_probe_injection` | ai_targets defined in scope.yml |
| AI-MCP-01 | **MCP tool-description poisoning** — An MCP server's tool descriptions enter the connecting client's context — probe for embedded instructions / indirect injection in advertised tools | `ai_test_mcp_server` | ai_targets with kind mcp_server in scope (declared or detected — AI-RECON-05) |
| AI-MCP-02 | **MCP confused-deputy** — Can a low-privilege caller invoke a tool the MCP server runs with its own higher privileges? (confused-deputy) | `ai_test_mcp_server` | ai_targets with kind mcp_server in scope (declared or detected — AI-RECON-05) |
| AI-MIS-01 | **Misinformation / overreliance probe** — Probe for confidently-wrong / fabricated output in a security-relevant context (OWASP LLM09) | `ai_test_info_disclosure` | ai_targets with kind chat_app in scope |
| AI-OH-01 | **Improper output handling → downstream sink** — Drive model output that is rendered as HTML / concatenated into SQL / passed to a shell, and prove the downstream sink itself (OWASP LLM05). ai-redteam owns the sink end-to-end — no hand-off. | `ai_test_output_handling` | ai_targets with kind chat_app or agent in scope (agent: declared or detected — AI-RECON-05) |
| AI-OH-02 | **Markdown / link injection in output** — Drive model output containing an active markdown image/link (data-exfil or javascript: URI) that the UI renders unsanitized (OWASP LLM05) | `ai_test_output_handling` | ai_targets with kind chat_app or agent in scope (agent: declared or detected — AI-RECON-05) |
| AI-PI-01 | **Direct prompt injection** — Direct instruction-override injection in user input (OWASP LLM01) | `ai_probe_injection` | ai_targets defined in scope.yml |
| AI-PI-02 | **Indirect prompt injection (via sources / tool outputs)** — Injection via retrieved documents, tool outputs, or fetched web content (OWASP LLM01 indirect) | `ai_probe_injection` | ai_targets with kind agent or rag_app or mcp_server in scope (declared or detected — AI-RECON-05) |
| AI-PI-03 | **Jailbreak battery** — Run the promptfoo/garak jailbreak corpora against the target (OWASP LLM01) | `ai_probe_injection` | ai_targets defined in scope.yml |
| AI-POI-01 | **Retrieval / data-poisoning influence (non-persistent)** — Does attacker-controlled retrieval content steer later answers? Non-persistent probe — never writes the customer's production index (AI Safety Mandate §10.2) (OWASP LLM04) | `ai_test_data_poisoning` | ai_targets with kind rag_app in scope (declared or detected — AI-RECON-05) |
| AI-RAG-01 | **RAG tenant-isolation / retrieval leak** — Can a query surface another tenant's or out-of-scope documents from the vector store? (OWASP LLM08) | `ai_test_rag_isolation` | ai_targets with kind rag_app in scope (declared or detected — AI-RECON-05) |
| AI-RECON-01 | **Model / provider / framework fingerprint** — Fingerprint the model, provider, and framework (LangChain/LlamaIndex/raw) behind the endpoint | `ai_fingerprint_target` | ai_targets defined in scope.yml |
| AI-RECON-02 | **Exposed tool / function enumeration** — Enumerate the tools/functions the agent can call (the excessive-agency blast radius) | `ai_fingerprint_target` | ai_targets with kind agent or mcp_server in scope (declared or detected — AI-RECON-05) |
| AI-RECON-03 | **Untrusted-input surface map** — Map every place attacker-controlled data enters the context window (direct input, retrieved docs, tool outputs, fetched web content) — the input to everything downstream | `ai_fingerprint_target` | ai_targets defined in scope.yml |
| AI-RECON-04 | **Guardrail detection** — Detect declared/observed input and output filters (the controls AI-PI/AI-OH must bypass) | `ai_fingerprint_target` | ai_targets defined in scope.yml |
| AI-RECON-05 | **Cross-kind capability auto-detection** — Probe the target's TRUE nature regardless of declared kind — does it tool-call (agent), retrieve+cite (rag_app), or expose an MCP tools/list (mcp_server)? Sets detected_capabilities; any capability NOT declared is an undeclared-surface finding AND promotes that kind's tests into the active run (coverage only expands). Honors a target's cross_kind_probe:false opt-out. | `ai_fingerprint_target` | ai_targets defined in scope.yml |
| AI-SID-01 | **Sensitive information disclosure** — Coax training-data / other-tenant / backend-secret disclosure (OWASP LLM02) | `ai_test_info_disclosure` | ai_targets with kind chat_app or agent or rag_app in scope (agent/rag: declared or detected — AI-RECON-05) |
| AI-SID-02 | **PII leakage in output** — Probe for PII (emails, tokens, account data) surfaced in model output that the user shouldn't reach (OWASP LLM02) | `ai_test_info_disclosure` | ai_targets with kind chat_app or agent or rag_app in scope (agent/rag: declared or detected — AI-RECON-05) |
| AI-SPL-01 | **System-prompt extraction** — Extract the system prompt / instructions / tool schema (OWASP LLM07) | `ai_extract_system_prompt` | ai_targets defined in scope.yml |
| AI-SPL-02 | **Tool-schema / function-definition leakage** — Extract the exposed tool/function schema (names, args, descriptions) — the excessive-agency recon an attacker needs (OWASP LLM07) | `ai_extract_system_prompt` | ai_targets with kind agent or mcp_server in scope (declared or detected — AI-RECON-05) |

