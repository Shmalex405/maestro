# Browser Automation Skill

## Purpose
The Browser tools enable real browser interaction via Playwright (headless Chromium) running inside the Kali Docker container. This allows testing of Single Page Applications (SPAs), DOM-based XSS validation, SSO/TOTP authentication flows, cookie analysis, and visual evidence capture.

## When to Use Browser Tools vs CLI Tools

### Use Browser Tools When:
- Testing SPAs that require JavaScript execution
- Validating DOM-based XSS (need real JS engine to confirm execution)
- Navigating SSO/OAuth authentication flows
- Handling TOTP/OTP login sequences
- Analyzing client-side validation and logic
- Capturing visual evidence (screenshots) of vulnerabilities
- Discovering hidden API calls in JS-heavy applications (network log)
- Testing cookie security flags (HttpOnly, Secure, SameSite)
- Interacting with forms that require JavaScript

### Use CLI Tools When:
- SQL injection testing (sqlmap is more thorough)
- Directory/endpoint fuzzing (ffuf is faster)
- CVE scanning (nuclei has better template coverage)
- Server-side vulnerability scanning (nikto)
- Network reconnaissance (nmap)
- Any test that doesn't require JavaScript execution

## Available Tools

### browser_navigate
Navigate to a URL. Starts browser if not running.
```
Arguments:
  - url: URL to navigate to
  - wait_for: CSS selector to wait for after navigation (optional)
  - timeout: Navigation timeout in ms (default: 30000)
```

### browser_click
Click an element on the page.
```
Arguments:
  - selector: CSS selector of element to click
  - text: Text content to match (alternative to selector)
  - timeout: Timeout in ms (default: 10000)
```

### browser_fill
Fill a form field with text.
```
Arguments:
  - selector: CSS selector of input field
  - value: Value to fill
  - timeout: Timeout in ms (default: 10000)
```

### browser_screenshot
Take a screenshot. Returns base64-encoded PNG.
```
Arguments:
  - full_page: Capture full scrollable page (default: false)
  - selector: Screenshot a specific element (optional)
```

### browser_evaluate
Execute JavaScript in the browser context.
```
Arguments:
  - script: JavaScript code to evaluate (has access to document, window, etc.)
```

### browser_get_cookies
Get all cookies for the current browser context.

### browser_set_cookies
Set cookies in the browser context.
```
Arguments:
  - cookies: Array of {name, value, domain?, path?} objects
```

### browser_get_content
Get page content as HTML or text.
```
Arguments:
  - format: "html" or "text" (default: "text")
  - selector: Get content of specific element (optional)
```

### browser_wait_for
Wait for a CSS selector state or network idle.
```
Arguments:
  - selector: CSS selector to wait for
  - state: "visible", "hidden", "attached", "detached" (default: "visible")
  - timeout: Timeout in ms (default: 10000)
```

### browser_network_log
Get captured network requests/responses. Reveals hidden API calls.
```
Arguments:
  - filter: URL pattern regex to filter results (optional)
```

### browser_close
Close the browser session and clear all state.

## Workflow Patterns

### DOM XSS Validation
1. `browser_navigate` to the target page
2. `browser_fill` the input field with XSS payload
3. `browser_click` the submit button
4. `browser_evaluate` to check if payload executed (e.g., `window.__xss_fired`)
5. `browser_screenshot` for evidence

### SSO Authentication
1. `browser_navigate` to the login page
2. `browser_fill` username and password fields
3. `browser_click` the login button
4. `browser_wait_for` the redirect/dashboard
5. `browser_get_cookies` to capture session tokens
6. Continue testing with authenticated session

### SPA API Discovery
1. `browser_navigate` to the SPA
2. Interact with UI elements (`browser_click`, `browser_fill`)
3. `browser_network_log` to capture all XHR/fetch calls
4. Use discovered API endpoints for further testing with CLI tools

### Cookie Security Audit
1. `browser_navigate` to the target
2. `browser_get_cookies` to get all cookies
3. Check each cookie for: HttpOnly, Secure, SameSite flags
4. Report cookies with missing security attributes

## Best Practices
- Always call `browser_close` when done with browser testing
- Use `browser_wait_for` after navigation/clicks to ensure page is loaded
- Capture screenshots as evidence for all confirmed vulnerabilities
- Use network logging to discover API endpoints that CLI tools can test
- Browser state persists between calls — cookies and sessions are maintained
- Prefer CSS selectors over text matching for reliability
