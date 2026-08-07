// Codex (OpenAI) brain visibility flag.
// ============================================================================
// As of the Workflow-orchestration migration, Claude is the sole *advertised*
// brain. All Codex code — the `codex-terminal-view`, the `api.codex.*` Tauri
// wrappers, the proxy `/openai/*` routes, the container Codex CLI — stays
// intact behind this flag, so Codex can be re-enabled for a customer who wants
// it without re-plumbing anything. This flag ONLY controls frontend visibility.
//
// Default: OFF. Set `NEXT_PUBLIC_CODEX_ENABLED=true` at build time to surface
// the Codex tab, brain picker, and /config/codex card again. Mirrors the
// `deploy-mode.ts` env-flag pattern (build-time dead-code friendly).
// ============================================================================

export function isCodexEnabled(): boolean {
  return process.env.NEXT_PUBLIC_CODEX_ENABLED === 'true';
}
