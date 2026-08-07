# Integrations

Connect Maestro to the tools your team already uses — like GitHub for code scanning and Jira for ticketing.

> [!NOTE] At a glance
> - Find it at **Sidebar → Config → Integrations**.
> - **GitHub** lets Maestro browse and add your private repositories for security scanning.
> - **Jira** lets Maestro create tickets for security findings in a project you choose.
> - Each integration has a toggle, a connection **Test** button, and its own **Save** button — nothing is stored until you save.

## GitHub

Connecting GitHub lets Maestro access your repositories (including private ones) so you can add them for security scanning without cloning by hand.

1. Open **Sidebar → Config → Integrations**.
2. In the **GitHub** card, flip the toggle on (it sits in the top-right of the card header). The setup fields appear once it's enabled.
3. Follow the **Create token on GitHub** link in the blue notice. You need a **Personal Access Token (Classic)** with the `repo` scope so Maestro can read private repositories.
4. Paste the token into the **Personal Access Token** field. Use the eye icon to reveal it if you want to double-check it.
5. Click **Test**. On success you'll see **Connected as @your-username** in green.
6. Once connected, the **Your Repositories** list loads automatically. Use the **Search repositories...** box to filter, and **Refresh** to reload the list.
7. For any repo, click **Add** to register it as a Maestro repository. Repos you've already added show an **Added** badge instead.
8. Click **Save GitHub Settings** to persist the connection.

Each repository row shows whether it's private (lock icon) or public (globe icon), its primary language, and its star and fork counts. Clicking the repo name opens it on GitHub.

> [!TIP] If your token is already saved, Maestro reconnects and reloads your repository list automatically the next time you open this page — you won't need to re-enter it.

> [!WARNING] A token without the `repo` scope can't see private repositories. If your private repos are missing from the list, regenerate the token with `repo` selected and re-test.

When you're done here, your added repositories become available wherever Maestro scans code. Manage the full list from your repositories view.

## Jira

Connecting Jira lets Maestro automatically create tickets for security findings, routed into a project (and visible on its boards) that you select.

1. Open **Sidebar → Config → Integrations**.
2. In the **Jira** card, flip the toggle on in the card header. The credential fields appear once it's enabled.
3. Fill in **Jira URL** (e.g. `https://yourcompany.atlassian.net`) and **Email** (the Atlassian account email, e.g. `you@company.com`).
4. Follow the **Create Jira API token** link to generate a token in your Atlassian account, then paste it into the **API Token** field. The eye icon reveals it for verification.
5. Click **Test**. On success you'll see **Connected as <your name>** in green, and Maestro fetches your projects.
6. Under **Project & Board**, pick a **Default Project** from the dropdown — each entry shows the project key and name. (If projects can't be listed, you can type the key by hand, e.g. `SEC`.)
7. The **Boards** panel fills in automatically for the project you choose, showing each board's name and type. If a project has no boards, Maestro tells you so.
8. Click **Save Jira Settings** to persist the connection.

> [!IMPORTANT] All three of **Jira URL**, **Email**, and **API Token** are required before the **Test** button activates. Use the API token from your Atlassian account — not your Atlassian password.

> [!TIP] If your Jira credentials are already saved, Maestro marks the connection as live and reloads your projects (and the saved project's boards) automatically when you reopen the page.

After saving, the chosen **Default Project** is where Maestro files tickets for security findings, so they land in your team's normal workflow alongside the report.

## Where to look next

- [Configuration overview](./overview.md) — the rest of the Config section.
- [Reports](../reports.md) — what Maestro produces from an assessment, and how findings flow into Jira.
- [Getting started](../getting-started/overview.md) — set up Maestro from the beginning.
