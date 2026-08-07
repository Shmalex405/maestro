/**
 * MCP tool registration smoke test.
 *
 * Asserts that the full MCP tool surface is internally consistent:
 *   - every tool in `allTools` has a name, description, and `inputSchema`
 *   - tool names are unique
 *   - every tool has a matching handler in `allHandlers`
 *   - `LOCAL_ONLY_TOOLS` entries all reference real tools (no stale names)
 *
 * Catches the class of bug where a tool is defined in a module but never
 * registered in the top-level `allTools`/`allHandlers` aggregates, or where
 * a handler is removed but its tool entry lingers.
 */

// `server.ts` imports the MCP SDK (ESM) only to type `setupTools()`, which the
// registration smoke test never calls. Stub the SDK so Jest can load the module.
jest.mock('@modelcontextprotocol/sdk/server/index.js', () => ({ Server: class {} }), { virtual: true });
jest.mock('@modelcontextprotocol/sdk/types.js', () => ({
  CallToolRequestSchema: {},
  ListToolsRequestSchema: {},
}), { virtual: true });

import { allTools, allHandlers, LOCAL_ONLY_TOOLS } from '../src/server';

type ToolDef = {
  name: string;
  description: string;
  inputSchema: { type: string; properties?: Record<string, unknown>; required?: string[] };
};

describe('MCP tool registration', () => {
  it('exports a non-empty `allTools` list', () => {
    expect(Array.isArray(allTools)).toBe(true);
    expect(allTools.length).toBeGreaterThan(0);
  });

  it('every tool has name, description, and `inputSchema`', () => {
    for (const tool of allTools as ToolDef[]) {
      expect(typeof tool.name).toBe('string');
      expect(tool.name.length).toBeGreaterThan(0);
      expect(typeof tool.description).toBe('string');
      expect(tool.description.length).toBeGreaterThan(0);
      expect(tool.inputSchema).toBeDefined();
      expect(tool.inputSchema.type).toBe('object');
    }
  });

  it('tool names are unique', () => {
    const names = (allTools as ToolDef[]).map(t => t.name);
    const dupes = names.filter((n, i) => names.indexOf(n) !== i);
    expect(dupes).toEqual([]);
  });

  it('every tool name has a matching handler in `allHandlers`', () => {
    const missing: string[] = [];
    for (const tool of allTools as ToolDef[]) {
      if (typeof allHandlers[tool.name] !== 'function') {
        missing.push(tool.name);
      }
    }
    expect(missing).toEqual([]);
  });

  it('every handler name has a matching tool entry (no orphan handlers)', () => {
    const toolNames = new Set((allTools as ToolDef[]).map(t => t.name));
    const orphans = Object.keys(allHandlers).filter(name => !toolNames.has(name));
    expect(orphans).toEqual([]);
  });

  it('every `LOCAL_ONLY_TOOLS` entry references a real tool', () => {
    const toolNames = new Set((allTools as ToolDef[]).map(t => t.name));
    const stale = LOCAL_ONLY_TOOLS.filter(name => !toolNames.has(name));
    expect(stale).toEqual([]);
  });

  it('inputSchema.required fields all exist in inputSchema.properties', () => {
    const violations: string[] = [];
    for (const tool of allTools as ToolDef[]) {
      const required = tool.inputSchema.required ?? [];
      const properties = tool.inputSchema.properties ?? {};
      for (const field of required) {
        if (!(field in properties)) {
          violations.push(`${tool.name}: required="${field}" not in properties`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
