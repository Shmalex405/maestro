// AI / LLM surface visibility flag.
// ============================================================================
// The AI surface (the standalone AI/LLM security assessment — see
// docs/ai-surface-plan.md) is backed end-to-end: the AI agents
// (ai-recon → ai-redteam → ai-analysis) run whenever `ai_targets` is in scope,
// and their findings land in the `ai` category, which the /surfaces/ai page
// renders via the shared surface lens.
//
// Default: ON. Set `NEXT_PUBLIC_AI_ENABLED=false` at build time to hide the
// AI nav item + surface (e.g. for a deployment that doesn't sell AI testing).
// Mirrors `identity-enabled.ts` (build-time dead-code friendly).
// ============================================================================

export function isAiEnabled(): boolean {
  return process.env.NEXT_PUBLIC_AI_ENABLED !== 'false';
}
