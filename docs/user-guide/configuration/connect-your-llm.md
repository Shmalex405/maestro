# Connect Your LLM

Authenticate the AI "brain" that runs your assessments — Claude or Codex — before launching your first scan.

> [!NOTE] At a glance
> - Every assessment is driven by an LLM running inside the Kali container. Until you connect one, no scan can start.
> - Maestro supports two brains: **Claude** (Anthropic Claude Code) and **OpenAI Codex**. Pick one — you only need to connect the one you intend to use.
> - Each brain offers the same three credential modes: **Sign in** (personal subscription), **API key** (your own billing), and **Bundled** (included with your Maestro license).
> - You connect a brain from **Sidebar → Config → Claude** or **Sidebar → Config → Codex**.

## Step 1 — Understand why this is required

Maestro doesn't run assessments on its own. Each assessment is orchestrated by an AI model — the "brain" — that runs inside the Kali Linux container and drives the security tools (nmap, nuclei, sqlmap, and the rest) through the MCP server. That brain is either **Claude Code** or the **OpenAI Codex CLI**.

Because the brain needs to authenticate to its provider (Anthropic or OpenAI) before it can think, **you must connect at least one brain before any assessment will run**. If you skip this step, an assessment launch has nothing to drive it.

You only need to connect the brain you plan to use. Many teams connect just one.

## Step 2 — Open the brain's config page

Go to **Sidebar → Config**, then choose either **Claude** or **Codex**.

Each page opens on a **Current Status** card at the top. It shows:

- **Active mode** — the credential mode that will be used on the next launch (one of Sign in / API key / Bundled).
- Three checklist rows with a green check or grey X: a sign-in **session in the container**, an **API key in Keychain**, and **Bundled enabled for org**.

Use the **Refresh** button on that card if you've just signed in elsewhere and the status hasn't caught up — the page also polls automatically every few seconds.

> [!IMPORTANT]
> Only **one mode is active at a time**. Switching modes takes effect on the **next launch of the Terminal / Codex pane** — not retroactively for a session that's already open.

## Step 3 — Choose a credential mode

Below the status card are three mode cards. Each card has a **Use this** button (it reads **Active** with a check once selected). The recommended default — personal sign-in — is marked with a **Recommended** badge.

The two brains mirror each other exactly. Pick the tab for the brain you're connecting.

::: tabs

::: tab Claude

The Claude page header reads **Claude Authentication**.

**Sign in with Claude** (Recommended)
Uses your personal Claude Pro or Max subscription. Best for individual pentesters — each user signs into their own account inside the Kali container. You don't complete this sign-in on the config page itself: open the **Terminal** pane and click **Connect Claude** to start the OAuth flow. When it succeeds, the card shows "Signed in inside the Kali container" and the status card's "OAuth session in container" row turns green.

**API key**
Use an Anthropic Console API key — pay-per-use, no rate limits, ideal when one billing account covers multiple pentesters or for ZDR / compliance requirements. In the **Anthropic API key** field, paste a key (it looks like `sk-ant-...`; use the eye icon to reveal it), then:
- **Test** — validates the key against Anthropic without saving it. A success toast reads "Key works — Anthropic accepted it."
- **Save** — re-validates, stores the key in your **macOS Keychain**, and automatically switches the active mode to API key.
Once saved you'll see "Key saved in Keychain" with a **Clear** button to remove it.

**Bundled (Groovy-managed)**
Included with your Maestro license. Uses your cloud sign-in — no API key required. Token usage is metered per organization against your tier. If Bundled isn't provisioned for your org, the card explains that and tells you to contact your Groovy Security representative. When it is enabled, the card shows **Tokens used this month**, a usage bar, the percentage used, the monthly reset date, and your tier.

::: tab Codex

The Codex page header reads **Codex Authentication** and connects the OpenAI Codex CLI (GPT-5.5).

**Sign in with ChatGPT** (Recommended)
Uses your personal ChatGPT Plus, Pro, or Team plan. Best for individual pentesters — each user signs into their own account inside the Kali container. Open the **Codex** pane and click **Connect Codex** to start the device-code sign-in flow. When it succeeds, the card shows "Signed in inside the Kali container" and the status card's "ChatGPT session in container" row turns green.

**API key**
Use an OpenAI Platform API key — pay-per-use, no rate limits, ideal when one billing account covers multiple pentesters or for ZDR / compliance requirements. In the **OpenAI API key** field, paste a key (it looks like `sk-...`; use the eye icon to reveal it), then:
- **Test** — validates the key against OpenAI without saving it. A success toast reads "Key works — OpenAI accepted it."
- **Save** — re-validates, stores the key in your **macOS Keychain**, and automatically switches the active mode to API key.
Once saved you'll see "Key saved in Keychain" with a **Clear** button to remove it.

**Bundled (Groovy-managed)**
Included with your Maestro license. Uses your cloud sign-in — no API key required. OpenAI tokens are metered per organization against your tier at 1:1 with Claude usage (the same monthly cap). If Bundled isn't provisioned for your org, the card tells you to contact your Groovy Security representative. When enabled, the card shows tokens used this month, a usage bar, the percentage used, the reset date, and your tier.

:::

> [!TIP]
> Not sure which to pick? If you have a personal Claude or ChatGPT subscription, **Sign in** is the simplest and is the recommended default. Choose **API key** when one billing account should cover several pentesters or you have ZDR / compliance requirements. Choose **Bundled** when it's included with your license and provisioned for your org.

## Step 4 — Confirm the brain is connected

Back on the **Current Status** card, confirm the **Active mode** matches the mode you intend to use and that the matching checklist row is green:

- Sign in → "OAuth session in container" / "ChatGPT session in container" is green.
- API key → "API key in Keychain" is green.
- Bundled → "Bundled enabled for org" is green.

Once the status reflects the mode you want, your brain is connected and you're ready to launch an assessment.

> [!WARNING]
> If you select **API key** mode without a saved key, or **Bundled** when it isn't enabled for your org, Maestro blocks the switch and shows an error toast. Save a valid key first, or pick a mode whose checklist row is green.

## Where to look next

- [Getting started overview](../getting-started/overview.md) — run your first assessment now that a brain is connected.
- [Define your scope](./scope.md) — set the targets Maestro is allowed to test.
- [Credentials](./credentials.md) — supply app logins so Maestro can test authenticated flows.
- [Cloud accounts](../cloud-accounts/overview.md) — connect AWS / Azure / GCP / Kubernetes for cloud assessments.
