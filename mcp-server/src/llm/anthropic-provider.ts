/**
 * Anthropic Provider
 *
 * LLM provider implementation for Claude API.
 * This wraps the @anthropic-ai/sdk to conform to our provider interface.
 */

import Anthropic from "@anthropic-ai/sdk";
import { BaseLLMProvider } from "./provider";
import {
  ChatParams,
  LLMResponse,
  ContentBlock,
  LLMToolCall,
  LLMMessage,
  StopReason,
  DEFAULT_CONFIG,
} from "./types";

export interface AnthropicProviderConfig {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
}

export class AnthropicProvider extends BaseLLMProvider {
  readonly name = "anthropic";
  readonly model: string;
  private client: Anthropic;
  private baseUrl?: string;

  constructor(config: AnthropicProviderConfig = {}) {
    super();

    const apiKey = config.apiKey || process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error(
        "Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass apiKey in config."
      );
    }

    this.model = config.model || process.env.ANTHROPIC_MODEL || DEFAULT_CONFIG.anthropic!.model!;
    this.baseUrl = config.baseUrl;

    this.client = new Anthropic({
      apiKey,
      ...(this.baseUrl && { baseURL: this.baseUrl }),
    });
  }

  async chat(params: ChatParams): Promise<LLMResponse> {
    const messages = this.convertMessages(params.messages);

    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: params.maxTokens || 4096,
      system: params.system,
      messages,
      tools: params.tools as Anthropic.Tool[],
      ...(params.temperature !== undefined && { temperature: params.temperature }),
      ...(params.stopSequences && { stop_sequences: params.stopSequences }),
    });

    return this.parseResponse(response);
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Simple API check
      await this.client.messages.create({
        model: this.model,
        max_tokens: 10,
        messages: [{ role: "user", content: "ping" }],
      });
      return true;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`[AnthropicProvider] Health check failed: ${errorMessage}`);
      return false;
    }
  }

  getInfo() {
    return {
      name: this.name,
      model: this.model,
      endpoint: this.baseUrl || "https://api.anthropic.com",
    };
  }

  /**
   * Convert our message format to Anthropic's format
   */
  private convertMessages(messages: LLMMessage[]): Anthropic.MessageParam[] {
    return messages.map((msg) => {
      if (typeof msg.content === "string") {
        return {
          role: msg.role,
          content: msg.content,
        };
      }

      // Handle content blocks (including tool results)
      const content = msg.content.map((block) => {
        if (block.type === "tool_result") {
          return {
            type: "tool_result" as const,
            tool_use_id: block.tool_use_id,
            content: block.content,
          };
        }
        if (block.type === "tool_use") {
          return {
            type: "tool_use" as const,
            id: block.id,
            name: block.name,
            input: block.input,
          };
        }
        // Text block
        return {
          type: "text" as const,
          text: block.text,
        };
      });

      return {
        role: msg.role,
        content,
      };
    }) as Anthropic.MessageParam[];
  }

  /**
   * Parse Anthropic response to our unified format
   */
  private parseResponse(response: Anthropic.Message): LLMResponse {
    const content: ContentBlock[] = [];
    const toolCalls: LLMToolCall[] = [];
    let textContent = "";

    for (const block of response.content) {
      if (block.type === "text") {
        content.push({ type: "text", text: block.text });
        textContent += block.text;
      } else if (block.type === "tool_use") {
        content.push({
          type: "tool_use",
          id: block.id,
          name: block.name,
          input: block.input as Record<string, unknown>,
        });
        toolCalls.push({
          id: block.id,
          name: block.name,
          input: block.input as Record<string, unknown>,
        });
      }
    }

    // Map stop reason
    let stopReason: StopReason = "end_turn";
    if (response.stop_reason === "tool_use") {
      stopReason = "tool_use";
    } else if (response.stop_reason === "max_tokens") {
      stopReason = "max_tokens";
    } else if (response.stop_reason === "stop_sequence") {
      stopReason = "stop_sequence";
    }

    return {
      content,
      toolCalls,
      textContent,
      stopReason,
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      },
    };
  }
}
