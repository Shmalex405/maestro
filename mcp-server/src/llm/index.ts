/**
 * LLM Provider Module
 *
 * Unified interface for LLM providers, so the orchestration layer doesn't hold a
 * hard dependency on any one vendor's SDK.
 *
 * Anthropic is the only implemented provider. Self-hosted local models (Ollama)
 * were removed — they could not drive a multi-step assessment reliably, and
 * shipping a provider that silently produces worse findings is worse than not
 * offering the choice. The desktop app's two brains (Claude Code and Codex CLI)
 * are selected at the CLI level, not through this factory.
 */

// Types
export * from "./types";

// Provider interface
export { LLMProvider, BaseLLMProvider } from "./provider";

// Provider implementations
export { AnthropicProvider } from "./anthropic-provider";

// Factory functions
export {
  getLLMProvider,
  createProviderByName,
  clearProviderCache,
  getProviderInfo,
  checkProviderHealth,
} from "./factory";
