// Identity / IDP surface visibility flag.
// ============================================================================
// The Identity surface (Active Directory + Entra ID + M365/O365 red teaming —
// see docs/identity-redteam-plan.md) is now backed end-to-end: the identity
// agents (recon → exploit → analysis) run whenever `identity_targets` is in
// scope, and their findings land in the `identity` category, which the
// /surfaces/identity page renders via the shared surface lens.
//
// Default: ON. Set `NEXT_PUBLIC_IDENTITY_ENABLED=false` at build time to hide
// the Identity nav item + surface (e.g. for a web/cloud-only deployment).
// Mirrors the `codex-enabled.ts` / `deploy-mode.ts` env-flag pattern
// (build-time dead-code friendly).
// ============================================================================

export function isIdentityEnabled(): boolean {
  return process.env.NEXT_PUBLIC_IDENTITY_ENABLED !== 'false';
}
