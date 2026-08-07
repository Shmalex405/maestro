// Redirect console.log to stderr so it doesn't corrupt the MCP stdio transport.
// stdout is reserved exclusively for JSON-RPC messages in the MCP protocol.
console.log = console.error;

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { setupTools } from "./server";
import { initializeDatabase } from "./logging/log-store";
import { loadScopeConfig } from "./scope/scope-config";

async function main() {
  // Initialize SQLite database
  await initializeDatabase();
  
  // Load scope configuration
  await loadScopeConfig();

  const server = new Server(
    {
      name: "kali-mcp-pentest",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Setup all tools
  await setupTools(server);

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error("Kali MCP Pentest Server running on stdio");
}

main().catch(console.error);
