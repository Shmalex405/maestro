# Users

The Users page lets you invite people to your organization, set whether they are an admin or a regular user, resend invite emails, and disable accounts.

> [!NOTE] At a glance
> - Open it from the **Sidebar → Users**.
> - The **Members** list shows every account, sorted by email, with its status and role.
> - **Invite user** sends a welcome email containing a temporary password.
> - You can change anyone's role or disable any account except your own.

## Where to find it

In the app sidebar, click **Users**. The page header reads **Users** with the note "Manage members of your organization. Invitees receive an email with a temporary password and set their own on first login."

The list refreshes automatically about every 30 seconds, so newly accepted invites and status changes appear without a manual reload.

## Read the Members table

The **Members** card lists all accounts. Its description shows the current count (for example, "5 users in your organization"). Each row has four columns:

- **Email** — the member's address. Your own row is marked **(you)**.
- **Status** — a colored badge:
  - **Active** — the account is confirmed and in use.
  - **Invited** — invited but hasn't set a permanent password yet.
  - **Password Reset** — a password reset is required.
  - **Unconfirmed** — sign-up not yet confirmed.
  - **Disabled** — access has been removed.
- **Role** — shows **Admin** (with a shield icon) or **User**.
- **Actions** — the buttons available for that row (see below).

## Invite a user

1. Click **Invite user** (top right of the page).
2. In the **Invite a user** dialog, enter the person's address in the **Email** field.
3. Pick a **Role** — **User** or **Admin**. The dialog notes that "Admins can invite and manage other users."
4. Click **Send invite**. The button stays disabled until you enter an address that contains an `@`.

On success you'll see a "Invite sent to …" confirmation, the dialog closes, and the new account appears in the list as **Invited**.

> [!TIP] The invitee gets a welcome email with a temporary password and is prompted to set a permanent one the first time they sign in.

## Resend an invite

If a member's status is **Invited** and they never received or used the email, a **Resend** button appears in their **Actions** column. Click it to send the invite again. You'll see an "Invite resent" confirmation.

## Change a member's role

For any account other than your own, the **Actions** column shows a role toggle:

- **Make admin** — promotes a regular user to admin.
- **Demote** — drops an admin back to a regular user.

Click it and the role updates immediately, with a "Role updated to …" confirmation.

> [!IMPORTANT] You cannot change your own role from this page — the role and disable controls only appear on other members' rows.

## Disable a member

For any active account other than your own, a red **Disable** button appears in the **Actions** column.

1. Click **Disable**.
2. A confirmation prompt asks: "Disable [email]? They'll lose access immediately." Click OK to proceed.

The account's status changes to **Disabled** and they lose access right away.

> [!WARNING] Disabling is immediate and removes access. Make sure you're disabling the right person before confirming.

## If the list won't load

If members can't be fetched, the card shows "Failed to load users:" followed by the error. Check that you're signed in and connected, then wait for the next automatic refresh or reopen the page.

## Where to look next

- [Getting started](./getting-started/overview.md) — set up the app and sign in.
- [Configuration](./configuration/overview.md) — connect repos, scope, and integrations for your organization.
