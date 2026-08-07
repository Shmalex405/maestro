/**
 * Build a Jira "browse" URL from the org's configured integrations base URL.
 *
 * The base URL comes from integrations config (Config → Integrations → Jira),
 * never a hardcoded host — a hardcoded tenant would leak one customer's Jira
 * into every other customer's build and break deep-links for everyone else.
 *
 * Returns null when no base URL is configured; callers should render the ticket
 * key as plain text rather than a link that 404s.
 */
export function jiraTicketUrl(
  baseUrl: string | null | undefined,
  ticket: string | null | undefined,
): string | null {
  const base = baseUrl?.trim();
  if (!base || !ticket) return null;
  return `${base.replace(/\/+$/, '')}/browse/${ticket}`;
}
