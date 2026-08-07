/**
 * LLM Provider Interface
 *
 * Abstract interface that all LLM providers must implement. This keeps the
 * orchestration layer off any one vendor's SDK, so a provider can be added
 * without changing agent code.
 *
 * Anthropic is currently the only implementation.
 */

import { ChatParams, LLMResponse } from "./types";

/**
 * Base interface for all LLM providers
 */
export interface LLMProvider {
  /**
   * Provider name for logging/debugging
   */
  readonly name: string;

  /**
   * Model identifier being used
   */
  readonly model: string;

  /**
   * Send a chat request and get a response
   * Handles tool calling natively where supported
   */
  chat(params: ChatParams): Promise<LLMResponse>;

  /**
   * Check if the provider is available/configured
   */
  isAvailable(): Promise<boolean>;

  /**
   * Get provider info for debugging
   */
  getInfo(): {
    name: string;
    model: string;
    endpoint?: string;
  };
}

/**
 * Base class with common functionality
 */
export abstract class BaseLLMProvider implements LLMProvider {
  abstract readonly name: string;
  abstract readonly model: string;

  abstract chat(params: ChatParams): Promise<LLMResponse>;

  async isAvailable(): Promise<boolean> {
    try {
      // Simple health check - override in providers if needed
      await this.chat({
        system: "Respond with OK",
        messages: [{ role: "user", content: "ping" }],
        tools: [],
        maxTokens: 10,
      });
      return true;
    } catch {
      return false;
    }
  }

  getInfo(): { name: string; model: string; endpoint?: string } {
    return {
      name: this.name,
      model: this.model,
    };
  }

  /**
   * Generate a unique tool call ID
   */
  protected generateToolId(): string {
    return `toolu_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
