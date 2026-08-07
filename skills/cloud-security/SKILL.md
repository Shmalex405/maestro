# Cloud Security Agent Skill

## Purpose

Cloud infrastructure red team testing — goes beyond posture scanning (Wiz/Orca style) to prove exploitability with real evidence. Split across two agents:

- **cloud-recon**: Asset discovery, IAM enumeration, network mapping, posture auditing (Phase 2a, parallel)
- **cloud-exploit**: Privilege escalation, storage abuse, K8s attacks, serverless exploitation (Phase 3, parallel)

## Scope Validation

Cloud tools MUST validate against `scope.yml` before executing:

1. **cloud_account_id** must exist in `scope.yml → cloud_accounts[].id`
2. **cluster_id** must exist in `scope.yml → kubernetes[].id`
3. Namespaces must be in `namespaces_in_scope` and NOT in `namespaces_excluded`
4. ARN patterns must not match `cloud_accounts[].exclusions`
5. Tools that enumerate (ScoutSuite, Prowler) only scan services listed in `services_in_scope`

If no `cloud_accounts` defined in scope.yml, all CLOUD-* tests should be marked N_A.

## Tools Available

### Cloud Reconnaissance (7 tools)
| Tool | Description |
|------|-------------|
| `enum_cloud_account` | Full account enumeration via ScoutSuite (EC2, S3, Lambda, RDS, IAM, EKS) |
| `audit_cloud_posture` | Prowler security audit with CIS Benchmark mappings |
| `enum_cloud_networking` | VPC, security group, NACL, peering, public IP mapping |
| `discover_cloud_assets_external` | External bucket/blob/storage discovery by keyword |
| `enum_cloud_endpoints` | API Gateway, CloudFront, ALB, Azure Front Door discovery |
| `enum_cloud_logging` | CloudTrail, Azure Monitor, GCP Audit logging gaps |
| `check_cloud_storage_public` | Enumerate all buckets and test public access |

### IAM & Identity Exploitation (5 tools)
| Tool | Description |
|------|-------------|
| `enum_iam_policies` | Policy analysis: wildcards, admin-equivalent, dangerous combos |
| `test_iam_privesc` | PMapper + Pacu privesc path identification and exploitation |
| `test_cross_account_trust` | Confused deputy, overpermissive trust, external principals |
| `test_service_account_permissions` | EC2 profiles, Lambda roles, ECS task roles analysis |
| `test_credential_exposure` | Stale keys, env var secrets, user-data credentials |

### Storage & Data Exploitation (5 tools)
| Tool | Description |
|------|-------------|
| `exploit_storage_misconfig` | Authenticated bucket exploitation: policies, ACLs, versioning |
| `test_public_snapshots` | Public RDS/EBS/disk snapshot discovery |
| `test_secrets_manager` | Secrets Manager/SSM/Key Vault/Secret Manager enumeration and read |
| `test_database_exposure` | RDS/Aurora public access, firewall rules, default creds |
| `scan_storage_sensitive_data` | PII, credentials, configs in accessible storage |

### Compute & Serverless Exploitation (6 tools)
| Tool | Description |
|------|-------------|
| `test_instance_metadata` | Enhanced IMDS: userdata, profiles, credential harvesting |
| `test_lambda_security` | Env vars, event injection, layers, function URL auth |
| `test_api_gateway_security` | Missing auth, direct invocation, throttling bypass |
| `test_container_registry` | ECR/ACR/GCR public access, layer secrets, image CVEs |
| `scan_container_image` | Trivy CVE scanning for container images |
| `test_messaging_exposure` | SQS/SNS/EventBridge public access and message injection |

### Kubernetes Red Team (7 tools)
| Tool | Description |
|------|-------------|
| `enum_k8s_cluster` | Namespace, pod, service, RBAC, ingress, netpol enumeration |
| `test_k8s_rbac` | Overprivileged SAs, cluster-admin bindings, privesc paths |
| `test_k8s_secrets` | Secret resources, env vars, mounted volumes, etcd access |
| `test_k8s_escape` | Privileged pods, hostPID/Net, Docker socket, SYS_ADMIN caps |
| `test_k8s_network_policy` | Cross-namespace connectivity, missing network policies |
| `test_k8s_api_server` | Anonymous auth, dashboard, metrics, kubelet exposure |
| `test_k8s_admission` | Admission controller bypass with test pods (dry-run) |

### Existing Tools (retained)
| Tool | Description |
|------|-------------|
| `test_cloud_metadata` | SSRF-based IMDS probing (AWS/Azure/GCP) |
| `check_s3_bucket` | S3 bucket permission testing (unauthenticated) |

## Workflow

### Cloud Recon Agent (Phase 2a — parallel with recon-infra + sast-scan)

```
1. Validate cloud_accounts exist in scope.yml → if none, mark all CLOUD-* as N_A
2. For each cloud account:
   a. Run enum_cloud_account (ScoutSuite) for full inventory
   b. Run audit_cloud_posture (Prowler) for posture findings
   c. Run enum_cloud_networking for VPC/SG mapping
   d. Run enum_cloud_endpoints for public-facing services
   e. Run enum_cloud_logging for audit gap analysis
   f. Run check_cloud_storage_public for storage permissions
3. Run discover_cloud_assets_external with company keywords
4. Run enum_iam_policies for IAM analysis
5. Run test_credential_exposure for stale/exposed keys
6. If K8s clusters in scope:
   a. Run enum_k8s_cluster for cluster inventory
   b. Run test_k8s_api_server for API server security
   c. Run scan_container_image for running image CVEs
7. Compile cloud_inventory, iam_findings, network_map → pass to cloud-exploit
```

### Cloud Exploit Agent (Phase 3 — parallel with web-security + api-graphql)

```
1. Receive cloud_inventory, iam_findings, network_map from cloud-recon
2. IAM Exploitation:
   a. Run test_iam_privesc with attempt_exploitation=true
   b. Run test_cross_account_trust for trust abuse
   c. Run test_service_account_permissions for over-privileged SAs
   d. Test MFA enforcement via enum_iam_policies
3. Storage Exploitation:
   a. Run exploit_storage_misconfig on discovered buckets
   b. Run test_public_snapshots
   c. Run test_secrets_manager with attempt_read=true
   d. Run scan_storage_sensitive_data on accessible buckets
4. Compute/Serverless Exploitation:
   a. Run test_instance_metadata with harvest_credentials=true
   b. Run test_lambda_security with test_invocation=true
   c. Run test_api_gateway_security
   d. Run test_container_registry with pull_and_scan=true
   e. Run test_messaging_exposure
5. Kubernetes Exploitation:
   a. Run test_k8s_rbac with attempt_escalation=true
   b. Run test_k8s_secrets
   c. Run test_k8s_escape
   d. Run test_k8s_network_policy
   e. Run test_k8s_admission
6. Test log tampering: enum_cloud_logging → attempt disable
```

## Evidence Standard

Cloud findings follow the same evidence rules as all other findings:

- **Real credentials shown** (AWS key IDs, role ARNs, service account names) — internal report
- **Real API responses** — show actual `aws sts get-caller-identity` output after privesc
- **Real data samples** — if secrets read from Secrets Manager, show the values
- **Attack chain proof** — if SSRF→IMDS→S3, show every hop with requests and responses

## Finding Severity Guidelines

| Finding Type | Severity | Example |
|---|---|---|
| IAM admin-equivalent policy | CRITICAL | Policy allows `*:*` on `*` |
| Public RDS snapshot with data | CRITICAL | `aws rds describe-db-snapshots` shows public=true |
| K8s cluster-admin service account | HIGH | Any pod can become cluster-admin |
| Container escape vector | CRITICAL | Privileged pod + hostPID + Docker socket |
| Stale access key (>90 days) | MEDIUM | Key created 2024-01-15, never rotated |
| Missing encryption at rest | MEDIUM | S3 bucket without SSE-S3/SSE-KMS |
| CloudTrail not multi-region | LOW | Only us-east-1 trail configured |
| Missing network policy | MEDIUM | Namespace allows all ingress/egress |

## Output Format

Each agent saves checkpoint to `reports/{agent-name}-results.json`:

```json
{
  "agent": "cloud-recon",
  "test_results": [
    { "test_id": "CLOUD-01", "status": "PASS", "details": "..." },
    ...
  ],
  "findings": [...],
  "cloud_inventory": { ... },
  "iam_findings": [...],
  "network_map": { ... },
  "k8s_inventory": { ... }
}
```
