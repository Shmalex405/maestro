# Multi-Application Support Guide

This guide explains how to configure and use the Kali MCP Pentest system to test multiple applications across different environments.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Configuration Files](#configuration-files)
4. [Step-by-Step Setup](#step-by-step-setup)
5. [Authentication Types](#authentication-types)
6. [Adding New Applications](#adding-new-applications)
7. [Usage Examples](#usage-examples)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The Kali MCP Pentest system is designed to handle unlimited applications across multiple environments. You configure your targets and credentials once, and the system:

- Automatically validates scope before any test
- Handles authentication for each application
- Selects appropriate tools based on target type
- Generates findings linked to specific applications
- Creates Jira tickets with proper context
- Produces reports filtered by application/environment

### What You Configure Once

| Configuration | Purpose |
|---------------|---------|
| `config/scope.yml` | Defines which targets can be tested |
| `config/credentials.yml` | Stores authentication for each application |
| `.env` | Contains sensitive credential values |

### What the System Handles

| Task | Automated |
|------|-----------|
| Scope validation | ✅ Before every test |
| Authentication | ✅ Token refresh, session management |
| Tool selection | ✅ Based on target type |
| Finding correlation | ✅ Links to applications |
| Report generation | ✅ Filtered by app/environment |

---

## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    CONFIGURATION LAYER                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌──────────────────┐  ┌─────────────────┐    │
│  │ scope.yml   │  │ credentials.yml  │  │     .env        │    │
│  │             │  │                  │  │                 │    │
│  │ - Networks  │  │ - App configs    │  │ - Secrets       │    │
│  │ - Domains   │  │ - Auth types     │  │ - Tokens        │    │
│  │ - Exclusions│  │ - Test accounts  │  │ - API keys      │    │
│  └─────────────┘  └──────────────────┘  └─────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │  App 1  │  │  App 2  │  │  App 3  │  │  App N  │           │
│  │ Bearer  │  │ Session │  │ OAuth2  │  │ API Key │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TESTING LAYER                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Recon → Vuln Scan → Web App Test → Exploit Validation         │
│                              │                                  │
│                              ▼                                  │
│                    Findings Database                            │
│                              │                                  │
│                              ▼                                  │
│              Jira Tickets + Reports + Emails                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration Files

### File 1: `config/scope.yml`

**Purpose:** Defines which network targets and domains are allowed for testing. Any target not in this file will be blocked.

**Location:** `config/scope.yml`

**Structure:**
```yaml
# Network ranges (for IP-based targets)
networks:
  - cidr: "10.0.0.0/8"           # CIDR notation
    environment: "development"   # Environment label
    notes: "Dev network"         # Optional description

# Domain patterns (for web applications)
domains:
  - pattern: "*.staging.company.com"  # Wildcard supported
    environment: "staging"

# Kubernetes clusters (optional)
kubernetes:
  - cluster: "staging-eks"
    namespaces:
      - "app"
      - "api"

# NEVER test these (overrides above)
exclusions:
  - "*.prod.company.com"
  - "10.0.0.1"
```

---

### File 2: `config/credentials.yml`

**Purpose:** Stores authentication configuration for each application. Sensitive values reference environment variables.

**Location:** `config/credentials.yml`

**Structure:**
```yaml
applications:
  - name: "app-identifier"           # Unique name you reference
    environment: "staging"           # Environment label
    base_url: "https://..."          # Base URL for the app
    auth_type: "bearer"              # Auth method (see below)
    credentials:                     # Auth-specific config
      token: "${ENV_VAR_NAME}"       # Reference to .env variable

# Default headers for all requests
default_headers:
  User-Agent: "SecurityScanner/1.0"
  Accept: "application/json"

# Test accounts for authorization testing
test_accounts:
  admin:
    username: "${TEST_ADMIN_USER}"
    password: "${TEST_ADMIN_PASS}"
    role: "administrator"
```

---

### File 3: `.env`

**Purpose:** Contains actual secret values. Never commit this file to version control.

**Location:** Project root `.env`

**Structure:**
```bash
# Application Credentials
APP_NAME_TOKEN=actual-token-value
APP_NAME_PASSWORD=actual-password

# Integration Credentials  
JIRA_API_TOKEN=your-jira-token
SMTP_PASS=your-email-password
```

---

## Step-by-Step Setup

### Step 1: Plan Your Applications

Before configuring, list all applications you need to test:

| App Name | Environment | URL | Auth Type | Credentials Needed |
|----------|-------------|-----|-----------|-------------------|
| frontend | staging | https://app.staging.co | session | username, password |
| api | staging | https://api.staging.co | bearer | token |
| admin | staging | https://admin.staging.co | basic | username, password |

---

### Step 2: Configure Scope (`config/scope.yml`)

Open the file and add your targets:
```yaml
networks:
  # Add your internal network ranges
  - cidr: "10.0.0.0/8"
    environment: "internal"
    notes: "Corporate network"
    
  - cidr: "192.168.100.0/24"
    environment: "staging"
    notes: "Staging environment network"
    
  - cidr: "172.16.0.0/16"
    environment: "development"
    notes: "Development VPC"

domains:
  # Add patterns for each application
  # Use wildcards (*) for subdomains
  
  # Frontend applications
  - pattern: "*.staging.yourcompany.com"
    environment: "staging"
    
  - pattern: "*.dev.yourcompany.com"
    environment: "development"
    
  # API endpoints
  - pattern: "api.staging.yourcompany.com"
    environment: "staging"
    
  - pattern: "api-*.test.yourcompany.com"
    environment: "test"
    
  # Internal tools
  - pattern: "*.internal.yourcompany.com"
    environment: "internal"

# Kubernetes (if applicable)
kubernetes:
  - cluster: "staging-cluster"
    namespaces:
      - "frontend"
      - "backend"
      - "services"

# CRITICAL: Exclude production and sensitive systems
exclusions:
  # Production - NEVER test
  - "*.prod.yourcompany.com"
  - "*.production.yourcompany.com"
  - "api.yourcompany.com"  # Production API
  
  # Infrastructure
  - "10.0.0.1"              # Gateway
  - "10.0.0.2"              # DNS server
  - "*.vault.yourcompany.com"  # Secrets management
  
  # Third-party services
  - "*.stripe.com"
  - "*.auth0.com"
```

---

### Step 3: Configure Credentials (`config/credentials.yml`)

Add authentication for each application:
```yaml
applications:
  # ============================================
  # APPLICATION 1: Frontend (Session-based auth)
  # ============================================
  - name: "frontend-app"
    environment: "staging"
    base_url: "https://app.staging.yourcompany.com"
    auth_type: "session"
    credentials:
      username: "${FRONTEND_USERNAME}"
      password: "${FRONTEND_PASSWORD}"
    # Session configuration
    login_url: "/api/auth/login"
    login_method: "POST"
    login_body:
      email: "${FRONTEND_USERNAME}"
      password: "${FRONTEND_PASSWORD}"
    session_token_location: "cookie"  # cookie, header, or body
    session_token_name: "session_id"

  # ============================================
  # APPLICATION 2: REST API (Bearer token)
  # ============================================
  - name: "backend-api"
    environment: "staging"
    base_url: "https://api.staging.yourcompany.com"
    auth_type: "bearer"
    credentials:
      token: "${BACKEND_API_TOKEN}"
    headers:
      Authorization: "Bearer ${BACKEND_API_TOKEN}"

  # ============================================
  # APPLICATION 3: Admin Panel (Basic auth)
  # ============================================
  - name: "admin-panel"
    environment: "staging"
    base_url: "https://admin.staging.yourcompany.com"
    auth_type: "basic"
    credentials:
      username: "${ADMIN_USERNAME}"
      password: "${ADMIN_PASSWORD}"

  # ============================================
  # APPLICATION 4: Partner API (API Key)
  # ============================================
  - name: "partner-api"
    environment: "staging"
    base_url: "https://partner.staging.yourcompany.com"
    auth_type: "api_key"
    credentials:
      api_key: "${PARTNER_API_KEY}"
    headers:
      X-API-Key: "${PARTNER_API_KEY}"
      X-Partner-ID: "your-partner-id"

  # ============================================
  # APPLICATION 5: Microservice (OAuth2)
  # ============================================
  - name: "oauth-service"
    environment: "staging"
    base_url: "https://service.staging.yourcompany.com"
    auth_type: "oauth2"
    oauth2:
      token_url: "https://auth.yourcompany.com/oauth/token"
      client_id: "${OAUTH_CLIENT_ID}"
      client_secret: "${OAUTH_CLIENT_SECRET}"
      scope: "read write admin"
      grant_type: "client_credentials"

  # ============================================
  # APPLICATION 6: GraphQL API (Custom headers)
  # ============================================
  - name: "graphql-api"
    environment: "staging"
    base_url: "https://graphql.staging.yourcompany.com"
    auth_type: "bearer"
    credentials:
      token: "${GRAPHQL_TOKEN}"
    headers:
      Authorization: "Bearer ${GRAPHQL_TOKEN}"
      X-Request-ID: "security-scan"
      Content-Type: "application/json"

  # ============================================
  # APPLICATION 7: Internal Tool (No auth)
  # ============================================
  - name: "internal-docs"
    environment: "internal"
    base_url: "https://docs.internal.yourcompany.com"
    auth_type: "none"

# Default headers applied to all authenticated requests
default_headers:
  User-Agent: "SecurityScanner/1.0 (Automated Testing)"
  Accept: "application/json, text/html"
  Accept-Language: "en-US,en;q=0.9"

# Test accounts for authorization/privilege testing
test_accounts:
  # Admin account - full privileges
  admin:
    username: "${TEST_ADMIN_USER}"
    password: "${TEST_ADMIN_PASS}"
    role: "administrator"
    description: "Full system access"
  
  # Regular user - standard privileges
  user:
    username: "${TEST_USER_USER}"
    password: "${TEST_USER_PASS}"
    role: "standard_user"
    description: "Normal user access"
  
  # Read-only user - minimal privileges
  readonly:
    username: "${TEST_READONLY_USER}"
    password: "${TEST_READONLY_PASS}"
    role: "read_only"
    description: "View-only access"
  
  # Guest account - unauthenticated baseline
  guest:
    username: ""
    password: ""
    role: "guest"
    description: "No authentication"

# Credential rotation settings (optional)
rotation:
  enabled: false
  interval_hours: 24
  notification_email: "security@yourcompany.com"
```

---

### Step 4: Configure Environment Variables (`.env`)

Add all the secret values referenced in credentials.yml:
```bash
# ===========================================
# KALI MCP PENTEST - ENVIRONMENT CONFIGURATION
# ===========================================
# WARNING: Never commit this file to version control!
# Add .env to your .gitignore

# ===========================================
# APPLICATION 1: Frontend
# ===========================================
FRONTEND_USERNAME=testuser@yourcompany.com
FRONTEND_PASSWORD=SecureTestPassword123!

# ===========================================
# APPLICATION 2: Backend API
# ===========================================
BACKEND_API_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNlY3VyaXR5IFNjYW5uZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# ===========================================
# APPLICATION 3: Admin Panel
# ===========================================
ADMIN_USERNAME=admin
ADMIN_PASSWORD=AdminPassword456!

# ===========================================
# APPLICATION 4: Partner API
# ===========================================
PARTNER_API_KEY=pk_test_51234567890abcdefghijklmnop

# ===========================================
# APPLICATION 5: OAuth Service
# ===========================================
OAUTH_CLIENT_ID=security-scanner-client
OAUTH_CLIENT_SECRET=super-secret-client-secret-value

# ===========================================
# APPLICATION 6: GraphQL API
# ===========================================
GRAPHQL_TOKEN=gql_live_abcdefghijklmnopqrstuvwxyz123456

# ===========================================
# TEST ACCOUNTS (for authorization testing)
# ===========================================
TEST_ADMIN_USER=admin@test.yourcompany.com
TEST_ADMIN_PASS=AdminTestPass789!

TEST_USER_USER=user@test.yourcompany.com
TEST_USER_PASS=UserTestPass789!

TEST_READONLY_USER=readonly@test.yourcompany.com
TEST_READONLY_PASS=ReadonlyTestPass789!

# ===========================================
# JIRA INTEGRATION
# ===========================================
JIRA_BASE_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=security-automation@yourcompany.com
JIRA_API_TOKEN=ATATT3xFfGF0abcdefghijklmnopqrstuvwxyz123456789

# ===========================================
# SHAREPOINT INTEGRATION
# ===========================================
SHAREPOINT_SITE_URL=https://yourcompany.sharepoint.com/sites/Security
SHAREPOINT_CLIENT_ID=12345678-1234-1234-1234-123456789012
SHAREPOINT_CLIENT_SECRET=abcdefghijklmnopqrstuvwxyz123456789
SHAREPOINT_FOLDER_PATH=/SecurityReports/Automated

# ===========================================
# EMAIL (SMTP) INTEGRATION
# ===========================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=security-alerts@yourcompany.com
SMTP_PASS=abcdefghijklmnop
SMTP_FROM=security-scanner@yourcompany.com

# ===========================================
# DATABASE
# ===========================================
DB_PATH=./data/pentest.db

# ===========================================
# SCOPE CONFIGURATION
# ===========================================
SCOPE_CONFIG_PATH=./config/scope.yml
CREDENTIALS_CONFIG_PATH=./config/credentials.yml
```

---

## Authentication Types

### Type 1: Session (Cookie-based)

For traditional web applications with login forms.
```yaml
- name: "web-app"
  auth_type: "session"
  credentials:
    username: "${USERNAME}"
    password: "${PASSWORD}"
  login_url: "/api/login"
  login_method: "POST"
  login_body:
    email: "${USERNAME}"
    password: "${PASSWORD}"
  session_token_location: "cookie"
  session_token_name: "SESSIONID"
```

**How it works:**
1. System POSTs credentials to login_url
2. Extracts session token from response cookie
3. Includes cookie in all subsequent requests
4. Automatically refreshes when expired

---

### Type 2: Bearer Token

For APIs using JWT or static bearer tokens.
```yaml
- name: "api"
  auth_type: "bearer"
  credentials:
    token: "${API_TOKEN}"
```

**How it works:**
1. Adds `Authorization: Bearer <token>` header to all requests

---

### Type 3: Basic Auth

For services using HTTP Basic Authentication.
```yaml
- name: "service"
  auth_type: "basic"
  credentials:
    username: "${USERNAME}"
    password: "${PASSWORD}"
```

**How it works:**
1. Base64 encodes `username:password`
2. Adds `Authorization: Basic <encoded>` header

---

### Type 4: API Key

For services using API key authentication.
```yaml
- name: "api"
  auth_type: "api_key"
  credentials:
    api_key: "${API_KEY}"
  headers:
    X-API-Key: "${API_KEY}"
```

**How it works:**
1. Adds specified header with API key to all requests

---

### Type 5: OAuth2 (Client Credentials)

For services using OAuth2 client credentials flow.
```yaml
- name: "service"
  auth_type: "oauth2"
  oauth2:
    token_url: "https://auth.company.com/oauth/token"
    client_id: "${CLIENT_ID}"
    client_secret: "${CLIENT_SECRET}"
    scope: "read write"
    grant_type: "client_credentials"
```

**How it works:**
1. Requests access token from token_url
2. Caches token until near expiration
3. Adds `Authorization: Bearer <token>` header
4. Automatically refreshes when expired

---

### Type 6: None

For publicly accessible services.
```yaml
- name: "public-api"
  auth_type: "none"
```

---

### Type 7: OTP Email (Interactive)

For applications using email-based one-time passwords. This is an **interactive flow** that will prompt you for the OTP code.

```yaml
- name: "secure-app"
  environment: "staging"
  base_url: "https://secure-app.staging.company.com"
  auth_type: "otp_email"
  interactive: true  # Indicates user prompts will occur
  otp_config:
    # Step 1: Initiate OTP (sends code to email)
    initiate_url: "/auth/login"
    initiate_method: "POST"
    initiate_body:
      email: "${OTP_APP_USERNAME}"

    # User identifier for prompts
    username_field: "email"
    username_value: "${OTP_APP_USERNAME}"

    # Step 2: Verify OTP
    verify_url: "/auth/verify-otp"
    verify_method: "POST"
    verify_body:
      email: "${OTP_APP_USERNAME}"
      code: "{{OTP_CODE}}"  # Placeholder replaced with user input

    # Where to find session token after verification
    session_token_location: "cookie"  # cookie, header, or body
    session_token_name: "session_id"

    # How long to wait for OTP entry (seconds)
    otp_timeout: 300
```

**How it works:**
1. System POSTs to initiate_url to trigger OTP email
2. **Prompts you to enter the OTP code** (via Claude or API)
3. Submits OTP to verify_url
4. Extracts session token from response
5. Caches session for subsequent requests (1 hour default)

**Using OTP via Claude Code:**
When you test an OTP-authenticated app, Claude will automatically:
1. Trigger the OTP email
2. Tell you "OTP sent to user@example.com, please enter the code"
3. Wait for you to provide the code
4. Complete authentication

**Using OTP via API/Frontend:**
```bash
# Step 1: Initiate OTP
curl -X POST http://localhost:3001/api/config/credentials/otp/initiate \
  -H "Content-Type: application/json" \
  -d '{"app_name": "secure-app"}'
# Response: {"success": true, "message": "OTP sent to user@example.com", "username": "user@example.com"}

# Step 2: Check for pending prompts (optional)
curl http://localhost:3001/api/config/prompts
# Response: {"prompts": [{"id": "prompt_123", "type": "otp", "message": "Enter OTP code"}]}

# Step 3: Verify OTP
curl -X POST http://localhost:3001/api/config/credentials/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"app_name": "secure-app", "otp_code": "123456"}'
# Response: {"success": true, "message": "Successfully authenticated", "authenticated": true}
```

**MCP Tools for OTP:**
| Tool | Purpose |
|------|---------|
| `prompt_for_otp` | Interactively request OTP from user |
| `prompt_for_input` | Generic user input prompt |
| `check_pending_prompt` | Check status of pending prompt |
| `respond_to_prompt` | Submit response to pending prompt |

---

## Adding New Applications

### Quick Add Checklist

When adding a new application:

- [ ] 1. Add domain/IP to `config/scope.yml`
- [ ] 2. Add application config to `config/credentials.yml`
- [ ] 3. Add secret values to `.env`
- [ ] 4. Test with Claude: "Test connectivity to [app-name]"

### Example: Adding a New API

**Step 1: scope.yml**
```yaml
domains:
  - pattern: "newapi.staging.company.com"
    environment: "staging"
```

**Step 2: credentials.yml**
```yaml
applications:
  - name: "new-api"
    environment: "staging"
    base_url: "https://newapi.staging.company.com"
    auth_type: "bearer"
    credentials:
      token: "${NEW_API_TOKEN}"
```

**Step 3: .env**
```bash
NEW_API_TOKEN=your-actual-token-here
```

**Step 4: Test**
```
"Run a quick scan on new-api to verify connectivity"
```

---

## Usage Examples

### Test Single Application
```
"Run a full security assessment on frontend-app"
```
```
"Test backend-api for SQL injection vulnerabilities"
```
```
"Scan admin-panel for authentication bypass issues"
```

### Test by Environment
```
"Run vulnerability scans on all staging environment applications"
```
```
"Perform reconnaissance on the development network (172.16.0.0/16)"
```

### Test with Specific Auth
```
"Test frontend-app endpoints using the admin test account, 
then test the same endpoints with the readonly account 
and compare what each can access"
```

### Test Multiple Applications
```
"Run the OWASP Top 10 scan against:
- frontend-app
- backend-api
- admin-panel
Generate a combined report"
```

### Authenticated vs Unauthenticated
```
"For backend-api, first run an unauthenticated scan,
then run an authenticated scan using the configured credentials.
Compare what's exposed without auth vs with auth."
```

### Scan Code + Test Live
```
"Scan the repository at ~/projects/backend for vulnerabilities.
For any critical findings, validate them against the live 
backend-api staging environment."
```

### Generate Targeted Report
```
"Generate a security report for frontend-app only.
Include all findings from the past week.
Create Jira tickets for HIGH and CRITICAL issues in project SEC."
```

---

## Best Practices

### Scope Management

| Do | Don't |
|-----|-------|
| ✅ Use specific CIDR ranges | ❌ Use overly broad ranges like 0.0.0.0/0 |
| ✅ Explicitly list all allowed domains | ❌ Use wildcards like *.* |
| ✅ Add exclusions for production | ❌ Assume production is safe because it's not listed |
| ✅ Include environment labels | ❌ Mix production and staging in same scope |
| ✅ Review scope quarterly | ❌ Set and forget |

### Credential Security

| Do | Don't |
|-----|-------|
| ✅ Use environment variables for secrets | ❌ Hardcode passwords in YAML |
| ✅ Use test/staging credentials only | ❌ Use production credentials |
| ✅ Rotate credentials regularly | ❌ Share credentials across environments |
| ✅ Add .env to .gitignore | ❌ Commit .env to version control |
| ✅ Use least-privilege test accounts | ❌ Use admin accounts for all testing |

### Testing Strategy

| Do | Don't |
|-----|-------|
| ✅ Test one application at a time initially | ❌ Test everything at once |
| ✅ Start with reconnaissance | ❌ Jump straight to exploitation |
| ✅ Verify connectivity before deep scans | ❌ Assume everything is accessible |
| ✅ Review findings before creating tickets | ❌ Auto-create tickets for all findings |
| ✅ Document false positives | ❌ Ignore recurring false positives |

### Organization

| Do | Don't |
|-----|-------|
| ✅ Use consistent naming (app-environment) | ❌ Use random or unclear names |
| ✅ Group applications by team/environment | ❌ Mix unrelated applications |
| ✅ Keep configurations in sync | ❌ Have different scopes per tester |
| ✅ Version control config files (not .env) | ❌ Make undocumented changes |

---

## Troubleshooting

### "Target not in scope"

**Cause:** The target IP or domain isn't in scope.yml

**Fix:**
1. Check `config/scope.yml` for the target
2. Verify CIDR range includes the IP
3. Verify domain pattern matches
4. Check exclusions aren't blocking it
```yaml
# Example: If testing 192.168.50.10
networks:
  - cidr: "192.168.50.0/24"  # Must include .10
    environment: "staging"
```

### "Authentication failed"

**Cause:** Credentials are incorrect or expired

**Fix:**
1. Verify values in `.env` are correct
2. Check token hasn't expired
3. Test credentials manually
4. Verify auth_type matches the application
```bash
# Test bearer token manually
curl -H "Authorization: Bearer $BACKEND_API_TOKEN" \
  https://api.staging.company.com/health
```

### "Application not found"

**Cause:** The app name doesn't match credentials.yml

**Fix:**
1. Check exact spelling of `name` in credentials.yml
2. Names are case-sensitive
3. Use the exact name when referencing

### "Environment variable not set"

**Cause:** Variable in credentials.yml isn't in .env

**Fix:**
1. Check `.env` contains the variable
2. Variable names are case-sensitive
3. Restart MCP server after .env changes

### "OAuth token refresh failed"

**Cause:** OAuth2 configuration issues

**Fix:**
1. Verify token_url is correct
2. Check client_id and client_secret
3. Verify scope is valid
4. Test OAuth flow manually

---

## Quick Reference Card

### File Locations

| File | Purpose |
|------|---------|
| `config/scope.yml` | Allowed targets |
| `config/credentials.yml` | App authentication |
| `.env` | Secret values |
| `config/tools.yml` | Tool settings |

### Auth Type Summary

| Type | Header Added |
|------|--------------|
| session | Cookie from login response |
| bearer | `Authorization: Bearer <token>` |
| basic | `Authorization: Basic <base64>` |
| api_key | Custom header with key |
| oauth2 | `Authorization: Bearer <oauth_token>` |
| otp_email | Session from OTP verification (interactive) |
| none | No authentication |

### Common Commands
```bash
# Rebuild after config changes
cd docker && docker-compose down && docker-compose up -d

# Restart MCP server after .env changes
cd mcp-server && npm start

# Verify scope
cat config/scope.yml

# Check credentials (without secrets)
cat config/credentials.yml | grep -v "password\|token\|secret"
```

### Claude Commands
```
"List all configured applications"
"Test connectivity to [app-name]"
"Run security scan on [app-name]"
"Generate report for [environment]"
"What applications are in scope?"
```

---

## Support

If you encounter issues:

1. Check `STEPS.md` for setup instructions
2. Check `TROUBLESHOOTING` section above
3. Review audit logs: `sqlite3 data/pentest.db "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20"`
4. Check Docker logs: `docker logs kali-pentest`

---

*Last Updated: January 2025*
