/**
 * Tests for Anthropic LLM Provider.
 *
 * Tests chat completion, message conversion, and availability checking.
 */

// Mock the Anthropic SDK before importing
jest.mock('@anthropic-ai/sdk', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => ({
      messages: {
        create: jest.fn(),
      },
    })),
  };
});

import Anthropic from '@anthropic-ai/sdk';
import { AnthropicProvider } from '../../src/llm/anthropic-provider';
import { ChatParams, LLMMessage, ToolDefinition } from '../../src/llm/types';

const MockAnthropic = Anthropic as jest.MockedClass<typeof Anthropic>;

describe('AnthropicProvider', () => {
  let provider: AnthropicProvider;
  let mockMessagesCreate: jest.Mock;

  beforeEach(() => {
    // Setup mock
    mockMessagesCreate = jest.fn();
    MockAnthropic.mockImplementation(() => ({
      messages: {
        create: mockMessagesCreate,
      },
    } as unknown as Anthropic));

    // Set API key for tests
    process.env.ANTHROPIC_API_KEY = 'test-api-key';

    provider = new AnthropicProvider({});
  });

  afterEach(() => {
    delete process.env.ANTHROPIC_API_KEY;
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create provider with default model', () => {
      const info = provider.getInfo();

      expect(info.name).toBe('anthropic');
      expect(info.model).toBe('claude-sonnet-4-20250514');
    });

    it('should accept custom model', () => {
      const customProvider = new AnthropicProvider({ model: 'claude-3-opus' });
      const info = customProvider.getInfo();

      expect(info.model).toBe('claude-3-opus');
    });

    it('should accept custom API key', () => {
      delete process.env.ANTHROPIC_API_KEY;

      const customProvider = new AnthropicProvider({ apiKey: 'custom-key' });

      expect(customProvider).toBeDefined();
    });
  });

  describe('chat', () => {
    const baseChatParams: ChatParams = {
      system: 'You are a helpful assistant.',
      messages: [{ role: 'user', content: 'Hello' }],
      tools: [],
    };

    it('should send chat request and return response', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Hello! How can I help you?' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 10, output_tokens: 20 },
      });

      const response = await provider.chat(baseChatParams);

      expect(response.textContent).toBe('Hello! How can I help you?');
      expect(response.stopReason).toBe('end_turn');
      expect(response.toolCalls).toEqual([]);
    });

    it('should handle tool use response', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [
          { type: 'text', text: 'I will run a scan.' },
          {
            type: 'tool_use',
            id: 'tool-123',
            name: 'scan_ports',
            input: { target: '192.168.1.1' },
          },
        ],
        stop_reason: 'tool_use',
        usage: { input_tokens: 15, output_tokens: 25 },
      });

      const response = await provider.chat({
        ...baseChatParams,
        tools: [
          {
            name: 'scan_ports',
            description: 'Scan ports on a target',
            input_schema: { type: 'object', properties: { target: { type: 'string' } } },
          },
        ],
      });

      expect(response.stopReason).toBe('tool_use');
      expect(response.toolCalls).toHaveLength(1);
      expect(response.toolCalls[0]).toEqual({
        id: 'tool-123',
        name: 'scan_ports',
        input: { target: '192.168.1.1' },
      });
    });

    it('should pass system message correctly', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Response' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 10, output_tokens: 5 },
      });

      await provider.chat(baseChatParams);

      expect(mockMessagesCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          system: 'You are a helpful assistant.',
        })
      );
    });

    it('should handle API errors', async () => {
      mockMessagesCreate.mockRejectedValue(new Error('API rate limited'));

      await expect(provider.chat(baseChatParams)).rejects.toThrow('API rate limited');
    });

    it('should respect maxTokens parameter', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Response' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 10, output_tokens: 5 },
      });

      await provider.chat({
        ...baseChatParams,
        maxTokens: 1000,
      });

      expect(mockMessagesCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          max_tokens: 1000,
        })
      );
    });

    it('should handle empty response content', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [],
        stop_reason: 'end_turn',
        usage: { input_tokens: 5, output_tokens: 0 },
      });

      const response = await provider.chat(baseChatParams);

      expect(response.textContent).toBe('');
      expect(response.content).toEqual([]);
    });
  });

  describe('isAvailable', () => {
    it('should return true when API key is set', async () => {
      const available = await provider.isAvailable();

      expect(available).toBe(true);
    });

    it('should throw error when API key is missing', () => {
      const originalKey = process.env.ANTHROPIC_API_KEY;
      delete process.env.ANTHROPIC_API_KEY;

      expect(() => new AnthropicProvider({})).toThrow('API key required');

      // Restore env
      if (originalKey) {
        process.env.ANTHROPIC_API_KEY = originalKey;
      }
    });
  });

  describe('getInfo', () => {
    it('should return provider info', () => {
      const info = provider.getInfo();

      expect(info.name).toBe('anthropic');
      expect(info.model).toBe('claude-sonnet-4-20250514');
    });

    it('should include custom endpoint when set', () => {
      const customProvider = new AnthropicProvider({
        baseUrl: 'https://custom.anthropic.com',
      });

      const info = customProvider.getInfo();

      expect(info.endpoint).toBe('https://custom.anthropic.com');
    });
  });

  describe('message conversion', () => {
    it('should convert simple text messages', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Response' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 20, output_tokens: 5 },
      });

      const messages: LLMMessage[] = [
        { role: 'user', content: 'Hello' },
        { role: 'assistant', content: 'Hi there!' },
        { role: 'user', content: 'How are you?' },
      ];

      await provider.chat({
        system: 'System prompt',
        messages,
        tools: [],
      });

      expect(mockMessagesCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({ role: 'user' }),
            expect.objectContaining({ role: 'assistant' }),
          ]),
        })
      );
    });

    it('should handle tool result messages', async () => {
      mockMessagesCreate.mockResolvedValue({
        content: [{ type: 'text', text: 'Response' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 30, output_tokens: 5 },
      });

      const messages: LLMMessage[] = [
        { role: 'user', content: 'Scan the target' },
        {
          role: 'assistant',
          content: [
            { type: 'text', text: 'Running scan...' },
            { type: 'tool_use', id: 'tool-1', name: 'scan_ports', input: {} },
          ],
        },
        {
          role: 'user',
          content: [{ type: 'tool_result', tool_use_id: 'tool-1', content: 'Port 80 open' }],
        },
      ];

      await provider.chat({
        system: 'System prompt',
        messages,
        tools: [],
      });

      expect(mockMessagesCreate).toHaveBeenCalled();
    });
  });
});
