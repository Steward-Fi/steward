import { describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createStewardMcpServer, SERVER_NAME } from "../server.js";

/** Minimal recording mock of the StewardClient surface the tools touch. */
function makeMockClient(returns: Record<string, unknown> = {}) {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const record =
    (method: string) =>
    (...args: unknown[]) => {
      calls.push({ method, args });
      return Promise.resolve(returns[method] ?? { ok: true });
    };
  const client = {
    listAgents: record("listAgents"),
    getAgent: record("getAgent"),
    createWallet: record("createWallet"),
    getBalance: record("getBalance"),
    getAddresses: record("getAddresses"),
    signTransaction: record("signTransaction"),
    createTransferAction: record("createTransferAction"),
    getPolicies: record("getPolicies"),
    getPolicyRule: record("getPolicyRule"),
    listApprovals: record("listApprovals"),
    getAuditLog: record("getAuditLog"),
  };
  return { client, calls };
}

async function connectedClient(returns?: Record<string, unknown>) {
  const { client: mockClient, calls } = makeMockClient(returns);
  const { server, tools } = createStewardMcpServer({
    client: mockClient as unknown as Parameters<typeof createStewardMcpServer>[0]["client"],
    config: { defaultAgentId: "default_agent" },
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server, tools, calls };
}

describe("createStewardMcpServer", () => {
  test("advertises the steward server name and tool list", async () => {
    const { client, tools, server } = await connectedClient();
    const listed = await client.listTools();
    expect(listed.tools.length).toBe(tools.length);
    expect(listed.tools.map((t) => t.name).sort()).toEqual(tools.map((t) => t.name).sort());
    await server.close();
  });

  test("exposes JSON Schema for tool inputs", async () => {
    const { client, server } = await connectedClient();
    const listed = await client.listTools();
    const signTx = listed.tools.find((t) => t.name === "sign_transaction");
    expect(signTx).toBeDefined();
    const schema = signTx?.inputSchema as {
      type: string;
      properties: Record<string, unknown>;
      required?: string[];
    };
    expect(schema.type).toBe("object");
    expect(Object.keys(schema.properties)).toContain("to");
    expect(Object.keys(schema.properties)).toContain("value");
    expect(schema.required).toContain("to");
    expect(schema.required).toContain("value");
    await server.close();
  });

  test("SERVER_NAME constant is steward", () => {
    expect(SERVER_NAME).toBe("steward");
  });

  test("calls a tool end-to-end over the transport", async () => {
    const { client, calls, server } = await connectedClient({ listAgents: [{ id: "a1" }] });
    const result = await client.callTool({ name: "list_wallets", arguments: {} });
    expect(calls).toEqual([{ method: "listAgents", args: [] }]);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content[0].text)).toEqual([{ id: "a1" }]);
    await server.close();
  });

  test("uses the configured default agent id when omitted", async () => {
    const { client, calls, server } = await connectedClient();
    await client.callTool({ name: "get_balance", arguments: {} });
    expect(calls[0].args[0]).toBe("default_agent");
    await server.close();
  });

  test("rejects invalid arguments at the protocol layer without calling the SDK", async () => {
    const { client, calls, server } = await connectedClient();
    // The SDK validates against the published JSON Schema and returns a
    // structured error result (-32602) before the handler runs, so the mock
    // client is never called. `to: "bad"` fails the address pattern.
    const result = await client.callTool({
      name: "sign_transaction",
      arguments: { agentId: "a1", to: "bad", value: "1" },
    });
    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0].text).toMatch(/validation/i);
    expect(calls).toHaveLength(0);
    await server.close();
  });

  test("rejects a type-mismatched argument", async () => {
    const { client, calls, server } = await connectedClient();
    // value must be a string; passing a number is rejected by schema validation.
    const result = await client.callTool({
      name: "sign_transaction",
      arguments: { agentId: "a1", to: "0x" + "1".repeat(40), value: 123 },
    });
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
    await server.close();
  });

  test("returns a successful (non-error) result for a valid call", async () => {
    const { client, calls, server } = await connectedClient({ getBalance: { wei: "0" } });
    const result = await client.callTool({
      name: "get_balance",
      arguments: { agentId: "a1", chainId: 8453 },
    });
    expect(result.isError).toBeUndefined();
    expect(calls).toEqual([{ method: "getBalance", args: ["a1", 8453] }]);
    await server.close();
  });
});
