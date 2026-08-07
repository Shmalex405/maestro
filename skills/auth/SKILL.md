# Auth Agent Skill

## Overview

The Auth Agent establishes authenticated browser sessions for downstream security testing agents. It handles browser-based login flows, including complex scenarios like SSO, MFA, and CAPTCHA challenges.

## Capabilities

- **Automated Login**: Follow step-by-step browser login instructions from assessment config
- **Interactive Guidance**: Pause and ask the user for help on CAPTCHAs, MFA, and unknown forms
- **Session Capture**: Extract cookies, tokens, and headers after successful login
- **Session Persistence**: Save browser state to disk so other agents inherit the session

## Tools Available

| Tool | Purpose |
|------|---------|
| `browser_navigate` | Navigate to login pages |
| `browser_fill` | Enter credentials into form fields |
| `browser_click` | Submit forms and click buttons |
| `browser_wait_for` | Wait for post-login elements |
| `browser_screenshot` | Capture state for debugging |
| `browser_evaluate` | Extract tokens from JavaScript |
| `browser_get_cookies` | Capture session cookies |
| `browser_set_cookies` | Restore previous session |
| `browser_get_content` | Verify login success |
| `browser_network_log` | Find auth headers in requests |
| `browser_save_state` | Persist session to disk |
| `request_user_guidance` | Ask user for help with blockers |

## Workflow

### With Login Config

1. Read `assessmentConfig.auth.browser_login` steps from context
2. Execute each step: navigate → fill → click → wait
3. If blocked (CAPTCHA/MFA), call `request_user_guidance` with screenshot
4. After login: capture cookies + save state
5. Store `authCookies` in context for CLI tools (sqlmap, nuclei)

### Without Login Config

1. Navigate to target URL
2. Look for login forms or links
3. Call `request_user_guidance` to get credentials
4. Complete login and capture session

## Blocker Handling

### CAPTCHA
- Cannot be solved automatically
- Take screenshot and call `request_user_guidance`
- Wait for user to solve it manually or provide guidance

### MFA/2FA
- If TOTP and secret is in config: compute and enter code
- If SMS/email OTP: prompt user via `request_user_guidance`
- If authenticator app: prompt user via `request_user_guidance`

### SSO/OAuth Redirects
- Follow redirects automatically
- If redirected to unknown IdP, take screenshot and ask for guidance
- Handle consent screens by clicking "Allow" or equivalent

## Output Context

After successful execution, the auth agent stores:

```
context.authCookies       # "name1=val1; name2=val2" string for CLI tools
context.authCookiesRaw    # Full cookie objects with domain/path/flags
context.authHeaders       # { Authorization: "Bearer ..." } if found
context.authEstablished   # boolean - true if login succeeded
context.authTimestamp     # ISO timestamp of when auth was captured
context.browserStateSaved # boolean - true if state saved to disk
```

## Important Rules

1. **NEVER call browser_close** - the session must persist for other agents
2. **ALWAYS call browser_get_cookies** after successful login
3. **ALWAYS call browser_save_state** after capturing cookies
4. **Use request_user_guidance** for any blocker you can't handle automatically
5. Be patient with redirects - some SSO flows have multiple redirects
6. Check for error messages after each login attempt

## Best Practices

- Verify login success by checking for the `success_indicator` selector if configured
- Navigate to `verify_url` if configured to confirm authenticated access
- Capture the network log to find Authorization headers or Bearer tokens
- If login fails, try variations (different selectors, wait longer) before asking for guidance
- Report which cookies are session cookies (usually the ones with HttpOnly flag)
