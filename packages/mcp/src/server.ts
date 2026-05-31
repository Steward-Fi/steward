import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { StewardClient } from "@stwd/sdk";
import type { StewardMcpConfig } from "./config.js";
import { buildTools, type StewardTool } from "./tools.js";

/** Package identity advertised to MCP clients during initialization. */
export const SERVER_NAME = "steward";
export const SERVER_VERSION = "0.1.0";

export interface CreateServerOptions {
  client: StewardClient;
  config: Pick<StewardMcpConfig, "defaultAgentId">;
  name?: string;
  version?: string;
}

export interface CreateServerResult {
  server: McpServer;
  tools: StewardTool[];
}

/**
 * Construct an {@link McpServer} with every Steward tool registered against the
 * supplied client. The server is transport-agnostic - the caller connects it to
 * a stdio (or other) transport. Returns both the server and the resolved tool
 * list so callers/tests can introspect what was registered.
 */
export function createStewardMcpServer(options: CreateServerOptions): CreateServerResult {
  const server = new McpServer({
    name: options.name ?? SERVER_NAME,
    version: options.version ?? SERVER_VERSION,
  });

  const tools = buildTools({ client: options.client, config: options.config });

  for (const tool of tools) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      // The SDK validates args against inputSchema before invoking this; the
      // handler re-parses for defense in depth and returns a structured result.
      async (args: Record<string, unknown>) => {
        const result = await tool.handler(args);
        return {
          content: result.content,
          ...(result.isError ? { isError: true } : {}),
          ...(result.structuredContent ? { structuredContent: result.structuredContent } : {}),
        };
      },
    );
  }

  return { server, tools };
}
