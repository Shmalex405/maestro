import { getCustomerConfig } from '@/lib/customer-registry';

// Public discovery endpoint for the Maestro desktop app.
//
// Called on first launch with the user's work email. Returns the backend URL
// and Cognito settings so the desktop app can auto-configure itself — the user
// never types a URL or Cognito values.
//
// Returns the same shape whether the email resolves or falls through to
// `local` (default backend). Callers decide what to do with a `local` result.
//
// No auth required — this endpoint only returns public configuration data.
// The backend URL is public (it's a DNS name the user is about to hit anyway)
// and the Cognito IDs are safe to expose (that's literally the point of public
// client IDs). License enforcement happens at the backend after login.
//
// CORS: prod desktop fetches from tauri://localhost (Tauri custom scheme,
// CORS-bypassed by the webview). Dev desktop fetches from
// http://localhost:3000 which IS subject to CORS. Since the response carries
// no secrets and no credentials, we return `*` for Allow-Origin and skip
// Allow-Credentials so cookies are not in scope.

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
  'Access-Control-Max-Age': '86400',
} as const;

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const email = url.searchParams.get('email');

  if (!email || !email.includes('@')) {
    return Response.json(
      { error: 'email query parameter is required' },
      { status: 400, headers: CORS_HEADERS }
    );
  }

  const config = await getCustomerConfig(email);

  const cognitoRegion = process.env.COGNITO_REGION || '';
  const cognitoUserPoolId = process.env.COGNITO_USER_POOL_ID || '';
  const cognitoDesktopClientId = process.env.COGNITO_DESKTOP_CLIENT_ID || '';
  // Hosted UI domain host (no scheme), e.g. "login.maestro.groovysec.com".
  // Shared across all orgs (single pool). Empty until the platform enables it;
  // the desktop app falls back to SRP password login while it is empty.
  const cognitoDomain = process.env.COGNITO_DOMAIN || '';

  if (!cognitoRegion || !cognitoUserPoolId || !cognitoDesktopClientId) {
    return Response.json(
      { error: 'Cognito configuration missing on platform' },
      { status: 500, headers: CORS_HEADERS }
    );
  }

  return Response.json(
    {
      orgId: config.orgId,
      customerName: config.customerName,
      backendUrl: config.backendUrl,
      authProvider: 'cognito',
      cognitoRegion,
      cognitoUserPoolId,
      cognitoClientId: cognitoDesktopClientId,
      cognitoDomain,
      // OAST listener for the `oast` verification oracle, when the org has one.
      //
      // SERVER HOSTNAME ONLY — never the polling token. This endpoint is
      // UNAUTHENTICATED (CORS `*`, no credentials): anyone who knows a
      // customer's email can call it. A hostname is org routing, the same class
      // of value as backendUrl. The token is not — it gates polling for
      // interactions that carry target IPs and whatever a blind payload
      // exfiltrated, so it must only ever travel over an authenticated channel.
      // See getOastToken() in lib/desktop-bootstrap.ts for where it comes from.
      ...(config.oast?.server ? { oast: { server: config.oast.server } } : {}),
      // Hint: when orgId is 'local', the email did not match any customer. The
      // desktop app should show a friendly "we don't recognize your email —
      // contact your admin" message rather than using the fallback URL.
      recognized: config.orgId !== 'local',
    },
    { headers: CORS_HEADERS }
  );
}
