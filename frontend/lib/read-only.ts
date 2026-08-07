'use client';

/**
 * Read-only role — single source of truth.
 *
 * A user is "read-only" when their Cognito groups include a read-only group
 * and they are NOT also an admin (admin always wins). Read-only users can log
 * in and view everything but cannot perform any mutating action.
 *
 * Enforcement is layered:
 *   1. Data layer — the `invoke` and `cloudRequest` wrappers in tauri-api.ts
 *      hard-block write commands / mutating HTTP verbs for read-only users.
 *   2. UI layer — components use `useIsReadOnly()` to disable/hide write
 *      actions and the terminal input so nothing looks usable that isn't.
 *
 * The Cognito `read_only` group is assigned by the backend
 * (`backend-rs/src/routes/users.rs`). Route-level API enforcement lives in the
 * separate cloud API repo.
 */

import { useAuthStore } from './stores/auth-store';

/** Cognito groups that grant admin. Admin always overrides read-only. */
export const ADMIN_GROUPS = new Set(['admin', 'maestro-admin', 'org-admin']);

/** Cognito groups that restrict a user to view-only access. */
export const READONLY_GROUPS = new Set(['read_only', 'readonly', 'viewer']);

/** Pure predicate over a user's Cognito groups. Admin wins over read-only. */
export function groupsAreReadOnly(groups: string[] | undefined | null): boolean {
  if (!groups || groups.length === 0) return false;
  const lower = groups.map((g) => g.toLowerCase());
  if (lower.some((g) => ADMIN_GROUPS.has(g))) return false; // admin always wins
  return lower.some((g) => READONLY_GROUPS.has(g));
}

/**
 * Non-React accessor — reads the auth store imperatively. Use this in code
 * paths that run outside the React tree (the tauri-api invoke/cloudRequest
 * guards, terminal `onData` handlers, etc.). Components should prefer the
 * `useIsReadOnly()` hook so they re-render when the role changes.
 */
export function isReadOnlyNow(): boolean {
  return groupsAreReadOnly(useAuthStore.getState().user?.groups);
}

/** React hook — subscribes so the component re-renders if the role changes. */
export function useIsReadOnly(): boolean {
  return useAuthStore((s) => groupsAreReadOnly(s.user?.groups));
}

/** True for HTTP verbs that mutate server state. Undefined/GET → read. */
export function isMutatingMethod(method?: string): boolean {
  if (!method) return false;
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase());
}
