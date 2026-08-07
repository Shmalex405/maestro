# Target Credentials

Configure how Maestro logs into the app you're testing, so authenticated endpoints get covered too.

> [!NOTE] At a glance
> - Lives at **Sidebar → Config → Credentials**.
> - Add an **Application** (login method + target) and optional **Test Accounts** (roles for authorization testing).
> - Seven auth types are supported: None, Basic Auth, Bearer Token, API Key, Session/Cookie, OAuth 2.0, and OTP (Email).
> - Each application is pinned to a target you already added to **Scope** — set up Scope first.

Without credentials, Maestro can only reach the parts of your app that are visible before login. Configuring credentials lets it authenticate and exercise the endpoints behind the login wall, which is where most of the real attack surface lives.

## Step 1 — Open the Credentials page

In the left sidebar, open **Config**, then choose **Credentials**. The page header reads **Credentials — Manage application authentication for authenticated testing**, and it has two cards:

- **Applications** — the login method Maestro uses to authenticate to a target.
- **Test Accounts** — extra user accounts (by role) used for authorization-boundary testing.

> [!IMPORTANT] Add your scope first
> The **Target (from Scope)** dropdown is populated from your Scope domains and networks. If your scope is empty, the dialog shows "No targets in scope" with a link to add them. Set up [Scope](./scope.md) before adding an application.

## Step 2 — Add an application

In the **Applications** card, click **Add Application**. A dialog opens with these fields:

- **Application Name** — auto-filled from the target you pick (you can override it). It becomes the key used to reference this app.
- **Environment** — read-only; inherited from the scope target (for example, `staging`).
- **Target (from Scope)** — a dropdown of your scope domains and networks. Each entry shows a **Domain** or **Network** badge, the value, and its environment. Selecting one fills in the base URL and environment, and auto-suggests the name.
- **Authentication Type** — the login method (see Step 3).

Name and Target are required; the **Add Application** button stays disabled until both are set (and at least one scope target exists).

## Step 3 — Pick the authentication type

Choose **Authentication Type** in the dialog. The fields below the selector change to match your choice:

| Type | When to use it | Fields you'll fill in |
|------|----------------|-----------------------|
| **None** | The app (or the part you're testing) needs no login. | none |
| **Basic Auth** | HTTP Basic Authentication (browser credential prompt). | Username, Password |
| **Bearer Token** | You already hold a token sent as `Authorization: Bearer …`. | Bearer Token |
| **API Key** | A key passed in a custom header. | Header Name (defaults to `X-API-Key`), API Key |
| **Session/Cookie** | A standard login form that returns a session cookie. | Login URL, Username / Email, Password |
| **OAuth 2.0** | Machine-to-machine client-credentials flow. | Token URL, Client ID, Client Secret |
| **OTP (Email)** | Login that emails a one-time code (see Step 4). | Login URL, Username / Email |

Secret fields (passwords, tokens, API keys, client secrets) are masked by default; use the eye icon at the right of each field to reveal or hide the value.

> [!TIP] Use the simplest type that works
> If you can obtain a long-lived **Bearer Token** or **API Key**, those are the least fragile to configure. **Session/Cookie** and **OTP (Email)** are best when you need Maestro to drive the real login form the way a user would.

Click **Add Application** to save. The new app appears in the Applications table showing its name, environment badge, auth type (with an icon), and base URL. Use the pencil icon to **Edit** or the trash icon to **Delete** — changes save immediately.

## Step 4 — Handle email OTP logins

When an application uses **OTP (Email)**, you provide the **Login URL** and **Username / Email** here, but not a code — there's no code field, because the code doesn't exist yet at config time.

During an assessment, Maestro initiates the login (triggering the email), then pauses and prompts you to enter the one-time code it just sent. You type the code in, Maestro submits it, and the resulting session is reused for the authenticated tests that follow. Expect a short interactive pause at the start of the run while you fetch the code from your inbox.

> [!WARNING] OTP runs are interactive
> Because someone has to read the emailed code, OTP logins can't run fully unattended. Be ready to enter the code when Maestro asks, or the authenticated portion of the assessment will be blocked.

## Step 5 — Add test accounts (for authorization testing)

The **Test Accounts** card holds multiple user accounts so Maestro can test authorization boundaries — for example, confirming a `user` can't reach `admin`-only data. Click **Add Test Account** and fill in:

- **Role** — a label like `admin`, `user`, or `viewer`. This is the key for the account.
- **Username / Email**
- **Password** — masked, with the same eye-icon reveal toggle.

Role and Username are required. Saved accounts appear in the table with a role badge, the username, and a masked password. Add at least two roles when you want Maestro to compare what different privilege levels can access.

## Where to look next

- [Scope](./scope.md) — define the domains and networks the credential targets are drawn from.
- [Connect your LLM](./connect-your-llm.md) — set up the brain that drives the assessment.
- [Configuration overview](./overview.md) — all the config pages in one place.
- [Run a black-box pentest](../getting-started/black-box-pentest.md) — put your configured credentials to work.
