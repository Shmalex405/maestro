/**
 * LLM Provider Factory
 *
 * Creates and caches LLM provider instances based on configuration.
 * Supports runtime provider switching via environment variables or config file.
 *
 * Anthropic is the only implemented provider; local self-hosted models were
 * removed. Unimplemented providers throw rather than degrade.
 */

import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { LLMProvider } from "./provider";
import { ProviderConfig, DEFAULT_CONFIG } from "./types";
import { AnthropicProvider } from "./anthropic-provider";

// Cached provider instance
let cachedProvider: LLMProvider | null = null;
let cachedConfigHash: string | null = null;

/**
 * Get the configured LLM provider
 * Creates and caches a provider instance based on config
 */
export function getLLMProvider(): LLMProvider {
  const config = loadConfig();
  const configHash = JSON.stringify(config);

  // Return cached provider if config hasn't changed
  if (cachedProvider && cachedConfigHash === configHash) {
    return cachedProvider;
  }

  cachedProvider = createProvider(config);
  cachedConfigHash = configHash;

  console.log(`[LLM Factory] Using provider: ${cachedProvider.name} (${cachedProvider.model})`);

  return cachedProvider;
}

/**
 * Create a specific provider by name (bypasses config)
 */
export function createProviderByName(
  name: "anthropic",
  options: Record<string, unknown> = {}
): LLMProvider {
  switch (name) {
    case "anthropic":
      return new AnthropicProvider(options);
    default:
      throw new Error(`Unknown provider: ${name}`);
  }
}

/**
 * Clear the cached provider (useful for testing or config changes)
 */
export function clearProviderCache(): void {
  cachedProvider = null;
  cachedConfigHash = null;
}

/**
 * Load configuration from file and environment
 */
function loadConfig(): ProviderConfig {
  // Start with defaults
  let config: ProviderConfig = { ...DEFAULT_CONFIG };

  // Try to load from config file
  const configPaths = [
    path.join(process.cwd(), "config", "llm-config.yml"),
    path.join(process.cwd(), "config", "llm-config.yaml"),
    path.join(__dirname, "..", "..", "..", "config", "llm-config.yml"),
  ];

  for (const configPath of configPaths) {
    if (fs.existsSync(configPath)) {
      try {
        const fileContent = fs.readFileSync(configPath, "utf-8");
        const fileConfig = yaml.load(fileContent) as Partial<ProviderConfig>;
        config = mergeConfig(config, fileConfig);
        console.log(`[LLM Factory] Loaded config from ${configPath}`);
        break;
      } catch (error) {
        console.warn(`[LLM Factory] Failed to load ${configPath}:`, error);
      }
    }
  }

  // Environment variables override file config
  if (process.env.LLM_PROVIDER) {
    config.provider = process.env.LLM_PROVIDER as ProviderConfig["provider"];
  }

  // Provider-specific env overrides
  if (process.env.ANTHROPIC_MODEL) {
    config.anthropic = config.anthropic || {};
    config.anthropic.model = process.env.ANTHROPIC_MODEL;
  }

  return config;
}

/**
 * Deep merge configuration objects
 */
function mergeConfig(base: ProviderConfig, override: Partial<ProviderConfig>): ProviderConfig {
  const result = { ...base };

  if (override.provider) {
    result.provider = override.provider;
  }

  if (override.anthropic) {
    result.anthropic = { ...result.anthropic, ...override.anthropic };
  }

  if (override.litellm) {
    result.litellm = { ...result.litellm, ...override.litellm };
  }

  if (override.openai) {
    result.openai = { ...result.openai, ...override.openai };
  }

  return result;
}

/**
 * Create a provider instance based on configuration
 */
function createProvider(config: ProviderConfig): LLMProvider {
  switch (config.provider) {
    case "anthropic":
      return new AnthropicProvider({
        apiKey: config.anthropic?.apiKey,
        model: config.anthropic?.model,
        baseUrl: config.anthropic?.baseUrl,
      });

    case "litellm":
      // LiteLLM speaks an OpenAI-compatible API, so this would be a thin
      // provider over that. Not implemented — fail loudly rather than
      // silently falling back to Anthropic and billing an unexpected account.
      throw new Error(
        "LiteLLM provider not yet implemented. Set provider: anthropic."
      );

    case "openai":
      // OpenAI provider could be added for GPT models or Azure
      throw new Error(
        "OpenAI provider not yet implemented. " +
        "Contributions welcome!"
      );

    default:
      throw new Error(`Unknown provider: ${config.provider}`);
  }
}

/**
 * Get current provider info without creating a new instance
 */
export function getProviderInfo(): { name: string; model: string; endpoint?: string } | null {
  if (cachedProvider) {
    return cachedProvider.getInfo();
  }
  return null;
}

/**
 * Check if the configured provider is available
 */
export async function checkProviderHealth(): Promise<{
  available: boolean;
  provider: string;
  model: string;
  error?: string;
}> {
  try {
    const provider = getLLMProvider();
    const available = await provider.isAvailable();
    const info = provider.getInfo();

    return {
      available,
      provider: info.name,
      model: info.model,
    };
  } catch (error) {
    return {
      available: false,
      provider: "unknown",
      model: "unknown",
      error: String(error),
    };
  }
}
