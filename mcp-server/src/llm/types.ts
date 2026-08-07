/**
 * LLM Provider Types
 *
 * Common types used across all LLM provider implementations, so the
 * orchestration layer stays vendor-neutral at the type level.
 */

// Content block types (normalized from various providers)
export interface TextBlock {
  type: "text";
  text: string;
}

export interface ToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export type ContentBlock = TextBlock | ToolUseBlock;

// Tool result for continuing conversations
export interface ToolResultBlock {
  type: "tool_result";
  tool_use_id: string;
  content: string;
}

// Message types
export interface LLMMessage {
  role: "user" | "assistant";
  content: string | ContentBlock[] | ToolResultBlock[];
}

// Tool definition (matches Claude's format, providers adapt as needed)
export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: {
    type: string;
    properties: Record<string, unknown>;
    required?: string[];
  };
}

// Parsed tool call from response
export interface LLMToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

// Stop reasons
export type StopReason = "end_turn" | "tool_use" | "max_tokens" | "stop_sequence";

// Unified response from any provider
export interface LLMResponse {
  content: ContentBlock[];
  toolCalls: LLMToolCall[];
  textContent: string;
  stopReason: StopReason;
  usage?: {
    inputTokens: number;
    outputTokens: number;
  };
}

// Chat request parameters
export interface ChatParams {
  system: string;
  messages: LLMMessage[];
  tools: ToolDefinition[];
  maxTokens?: number;
  temperature?: number;
  stopSequences?: string[];
}

// Provider configuration
//
// `anthropic` is the only provider with an implementation. `litellm` and
// `openai` remain in the union as declared-but-unimplemented targets — the
// factory throws a clear error for them rather than silently falling back.
export interface ProviderConfig {
  provider: "anthropic" | "litellm" | "openai";
  anthropic?: {
    apiKey?: string; // Falls back to env
    model?: string;
    baseUrl?: string;
  };
  litellm?: {
    url?: string;
    model?: string;
    apiKey?: string;
  };
  openai?: {
    apiKey?: string;
    model?: string;
    baseUrl?: string; // For Azure or compatible APIs
  };
}

// Default configuration values
export const DEFAULT_CONFIG: ProviderConfig = {
  provider: "anthropic",
  anthropic: {
    model: "claude-sonnet-4-20250514",
  },
  litellm: {
    url: "http://localhost:4000",
  },
  openai: {
    model: "gpt-4o",
  },
};
