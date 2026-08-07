// Cloud account active-switching helper.
//
// Switching the active cloud account is more than flipping a flag on disk
// — the desktop's whole data layer (Dashboard, Findings, Repos, etc.) is
// pinned to bootstrap.backendUrl and to the Cognito tokens currently in
// the auth store. When the user picks a different account on
// /config/cloud, we have to:
//
//   1. Persist the new active_id in the Tauri backend
//   2. Update localStorage `maestro-bootstrap` so cloudRequest() targets
//      the new backendUrl and the cognito-auth helpers use the new pool
//   3. Reset the cloud-session.json persist memo so the in-container MCP
//      server picks up the new URL on its next read
//   4. Invalidate React Query so every cached read re-fetches against
//      the new active backend
//
// For Cognito accounts that share the same User Pool (the Maestro
// pattern — all customers validate against Groovy's central pool), the
// auth-store's existing tokens stay valid and the user doesn't need to
// re-login. For accounts on a *different* pool, cloudRequest will get a
// 401 on the first read after switching and the startup gate will bounce
// the user back to the login screen. Per-account Cognito token caching
// is a follow-up.

import type { QueryClient } from '@tanstack/react-query';
import { api, resetCloudSessionMemo } from './tauri-api';
import { getBootstrap, saveBootstrap, type Bootstrap } from './desktop-bootstrap';

/** Cache keys that depend on the active cloud account and should be
 *  re-fetched after switching. Broad to cover the common read paths
 *  without enumerating every single useQuery in the app. */
const CLOUD_DEPENDENT_QUERY_KEYS: readonly string[] = [
  'cloud-accounts',
  'cloud-config',
  'cloud-status',
  'assessments',
  'findings',
  'repositories',
  'integrations',
  'scope',
  'tools',
  'agents',
  'credentials',
  'audit-logs',
  'dashboard',
  'users',
];

/** Switch the active cloud account. Returns once the backend has been
 *  updated and all React Query caches scheduled for refetch. */
export async function setActiveCloudAccount(
  id: string,
  queryClient: QueryClient,
): Promise<void> {
  // 1. Backend pointer flip
  await api.config.cloud.setActive(id);

  // 2. Refresh bootstrap from the now-active account so cloudRequest()
  //    targets the new backendUrl.
  const account = await api.config.cloud.getAccount(id);
  const existing = getBootstrap();
  const next: Bootstrap = {
    orgId: existing?.orgId ?? id,
    customerName: account.name,
    backendUrl: account.api_url,
    cognitoRegion: account.cognito_region ?? existing?.cognitoRegion ?? '',
    cognitoUserPoolId: account.cognito_user_pool_id ?? existing?.cognitoUserPoolId ?? '',
    cognitoClientId: account.cognito_client_id ?? existing?.cognitoClientId ?? '',
    discoveredAt: new Date().toISOString(),
    email: existing?.email ?? '',
  };
  saveBootstrap(next);

  // 3. Reset the cloud-session persist memo. The next cloudRequest call
  //    will write a fresh cloud-session.json with the new backendUrl so
  //    MCP-driven writes (create_finding, etc.) land in the new org.
  resetCloudSessionMemo();

  // 4. Invalidate cloud-dependent queries — pages re-fetch against the
  //    new active backend on the next render.
  await Promise.all(
    CLOUD_DEPENDENT_QUERY_KEYS.map((key) =>
      queryClient.invalidateQueries({ queryKey: [key] }),
    ),
  );
}
