#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createStewardClient, loadConfig, redactConfig } from "./config.js";
import { createStewardMcpServer } from "./server.js";

/**
 * Entrypoint for the `stwd-mcp` binary. Loads config from the environment,
 * builds a Steward-backed MCP server, and serves it over stdio (the transport
 * Claude Code / Cursor spawn).
 *
 * IMPORTANT: stdout is reserved for the MCP JSON-RPC stream. All diagnostics go
 * to stderr, and secrets are redacted before anything is logged.
 */
async function main(): Promise<void> {
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(process.env);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[stwd-mcp] Configuration error: ${message}\n`);
    process.exit(1);
    return;
  }

  const client = createStewardClient(config);
  const { server, tools } = createStewardMcpServer({
    client,
    config: { defaultAgentId: config.defaultAgentId },
  });

  process.stderr.write(
    `[stwd-mcp] Starting Steward MCP server. config=${JSON.stringify(redactConfig(config))} tools=${tools.length}\n`,
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);

  const shutdown = async (signal: string): Promise<void> => {
    process.stderr.write(`[stwd-mcp] Received ${signal}, shutting down.\n`);
    try {
      await server.close();
    } finally {
      process.exit(0);
    }
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[stwd-mcp] Fatal error: ${message}\n`);
  process.exit(1);
});
