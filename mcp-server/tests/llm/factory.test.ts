/**
 * Tests for LLM Provider Factory.
 *
 * Tests provider creation, caching, and configuration loading.
 */

import * as fs from 'fs';
import * as path from 'path';

// Mock dependencies before imports
jest.mock('fs');
jest.mock('../../src/llm/anthropic-provider');

import {
  getLLMProvider,
  createProviderByName,
  clearProviderCache,
  getProviderInfo,
  checkProviderHealth,
} from '../../src/llm/factory';
import { AnthropicProvider } from '../../src/llm/anthropic-provider';

const mockFs = fs as jest.Mocked<typeof fs>;
const MockAnthropicProvider = AnthropicProvider as jest.MockedClass<typeof AnthropicProvider>;

describe('LLM Factory', () => {
  beforeEach(() => {
    // Clear cache before each test
    clearProviderCache();
    jest.clearAllMocks();

    // Default mock for fs.existsSync
    mockFs.existsSync.mockReturnValue(false);

    // Setup default mock implementations
    MockAnthropicProvider.mockImplementation(() => ({
      name: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      chat: jest.fn(),
      isAvailable: jest.fn().mockResolvedValue(true),
      getInfo: jest.fn().mockReturnValue({ name: 'anthropic', model: 'claude-sonnet-4-20250514' }),
    } as unknown as AnthropicProvider));
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.LLM_PROVIDER;
    delete process.env.ANTHROPIC_MODEL;
  });

  describe('getLLMProvider', () => {
    it('should return Anthropic provider by default', () => {
      const provider = getLLMProvider();

      expect(provider.name).toBe('anthropic');
      expect(MockAnthropicProvider).toHaveBeenCalled();
    });

    it('should cache provider instance', () => {
      const provider1 = getLLMProvider();
      const provider2 = getLLMProvider();

      expect(provider1).toBe(provider2);
      expect(MockAnthropicProvider).toHaveBeenCalledTimes(1);
    });

    it('should load config from YAML file when present', () => {
      mockFs.existsSync.mockReturnValue(true);
      mockFs.readFileSync.mockReturnValue(`
provider: anthropic
anthropic:
  model: claude-3-opus
`);

      getLLMProvider();

      expect(MockAnthropicProvider).toHaveBeenCalledWith(
        expect.objectContaining({ model: 'claude-3-opus' })
      );
    });

    it('should override file config with environment variables', () => {
      mockFs.existsSync.mockReturnValue(true);
      mockFs.readFileSync.mockReturnValue(`
provider: anthropic
anthropic:
  model: claude-3-opus
`);
      process.env.ANTHROPIC_MODEL = 'claude-sonnet-4-20250514';

      getLLMProvider();

      expect(MockAnthropicProvider).toHaveBeenCalledWith(
        expect.objectContaining({ model: 'claude-sonnet-4-20250514' })
      );
    });
  });

  describe('createProviderByName', () => {
    it('should create Anthropic provider', () => {
      const provider = createProviderByName('anthropic');

      expect(provider.name).toBe('anthropic');
      expect(MockAnthropicProvider).toHaveBeenCalled();
    });

    it('should pass options to provider constructor', () => {
      createProviderByName('anthropic', { model: 'claude-3-opus' });

      expect(MockAnthropicProvider).toHaveBeenCalledWith({ model: 'claude-3-opus' });
    });

    it('should throw error for unknown provider', () => {
      expect(() => {
        createProviderByName('unknown' as 'anthropic');
      }).toThrow('Unknown provider: unknown');
    });
  });

  describe('clearProviderCache', () => {
    it('should clear cached provider', () => {
      const provider1 = getLLMProvider();
      clearProviderCache();
      const provider2 = getLLMProvider();

      expect(provider1).not.toBe(provider2);
      expect(MockAnthropicProvider).toHaveBeenCalledTimes(2);
    });
  });

  describe('getProviderInfo', () => {
    it('should return null when no provider is cached', () => {
      const info = getProviderInfo();

      expect(info).toBeNull();
    });

    it('should return provider info after provider is created', () => {
      getLLMProvider();
      const info = getProviderInfo();

      expect(info).toEqual({
        name: 'anthropic',
        model: 'claude-sonnet-4-20250514',
      });
    });
  });

  describe('checkProviderHealth', () => {
    it('should return available true when provider is healthy', async () => {
      const health = await checkProviderHealth();

      expect(health.available).toBe(true);
      expect(health.provider).toBe('anthropic');
    });

    it('should return available false when provider check fails', async () => {
      MockAnthropicProvider.mockImplementation(() => ({
        name: 'anthropic',
        model: 'claude-sonnet-4-20250514',
        chat: jest.fn(),
        isAvailable: jest.fn().mockResolvedValue(false),
        getInfo: jest.fn().mockReturnValue({ name: 'anthropic', model: 'claude-sonnet-4-20250514' }),
      } as unknown as AnthropicProvider));

      const health = await checkProviderHealth();

      expect(health.available).toBe(false);
    });

    it('should return error when provider creation fails', async () => {
      MockAnthropicProvider.mockImplementation(() => {
        throw new Error('API key missing');
      });

      const health = await checkProviderHealth();

      expect(health.available).toBe(false);
      expect(health.error).toContain('API key missing');
    });
  });
});

describe('Config Loading', () => {
  beforeEach(() => {
    clearProviderCache();
    jest.clearAllMocks();
    mockFs.existsSync.mockReturnValue(false);

    // Re-setup default mock implementations after clearAllMocks
    MockAnthropicProvider.mockImplementation(() => ({
      name: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      chat: jest.fn(),
      isAvailable: jest.fn().mockResolvedValue(true),
      getInfo: jest.fn().mockReturnValue({ name: 'anthropic', model: 'claude-sonnet-4-20250514' }),
    } as unknown as AnthropicProvider));
  });

  afterEach(() => {
    delete process.env.LLM_PROVIDER;
  });

  it('should use DEFAULT_CONFIG when no config file exists', () => {
    mockFs.existsSync.mockReturnValue(false);

    getLLMProvider();

    expect(MockAnthropicProvider).toHaveBeenCalledWith(
      expect.objectContaining({
        model: 'claude-sonnet-4-20250514',
      })
    );
  });

  it('should handle malformed YAML gracefully', () => {
    mockFs.existsSync.mockReturnValue(true);
    mockFs.readFileSync.mockReturnValue('provider: anthropic');

    // Should not throw
    expect(() => getLLMProvider()).not.toThrow();
  });

  it('should check multiple config file paths', () => {
    getLLMProvider();

    // Should have checked for config files
    expect(mockFs.existsSync).toHaveBeenCalled();
  });
});
