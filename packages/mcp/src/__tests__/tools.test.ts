import { describe, expect, test } from "bun:test";
import { StewardApiError } from "@stwd/sdk";
import { buildTools, type StewardTool, type ToolContext, toErrorResult } from "../tools.js";

/** Record of a single method invocation on the mock client. */
interface Call {
  method: string;
  args: unknown[];
}

/**
 * Build a mock StewardClient that records every call and returns a canned
 * value. Only the methods the tools use are implemented. Cast through unknown
 * because we deliberately implement a narrow slice of the client surface.
 */
function makeMockClient(returns: Record<string, unknown> = {}) {
  const calls: Call[] = [];
  const record =
    (method: string) =>
    (...args: unknown[]) => {
      calls.push({ method, args });
      const value = returns[method];
      if (value instanceof Error) return Promise.reject(value);
      return Promise.resolve(value ?? { ok: true, method });
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

function makeContext(
  returns?: Record<string, unknown>,
  defaultAgentId?: string,
): { ctx: ToolContext; calls: Call[] } {
  const { client, calls } = makeMockClient(returns);
  return {
    ctx: { client: client as unknown as ToolContext["client"], config: { defaultAgentId } },
    calls,
  };
}

function toolMap(tools: StewardTool[]): Map<string, StewardTool> {
  return new Map(tools.map((t) => [t.name, t]));
}

const EXPECTED_TOOLS = [
  "list_wallets",
  "get_wallet",
  "create_wallet",
  "get_balance",
  "get_addresses",
  "sign_transaction",
  "create_transfer",
  "list_policies",
  "get_policy",
  "list_pending_approvals",
  "get_audit_log",
];

describe("tool registration", () => {
  test("registers exactly the expected tool set", () => {
    const { ctx } = makeContext();
    const tools = buildTools(ctx);
    expect(tools.map((t) => t.name).sort()).toEqual([...EXPECTED_TOOLS].sort());
  });

  test("every tool has a description, an input schema, and annotations", () => {
    const { ctx } = makeContext();
    for (const tool of buildTools(ctx)) {
      expect(tool.description.length).toBeGreaterThan(10);
      expect(typeof tool.inputSchema).toBe("object");
      expect(tool.annotations.title.length).toBeGreaterThan(0);
      expect(typeof tool.annotations.readOnlyHint).toBe("boolean");
    }
  });

  test("only state-changing tools are marked destructive; reads are readOnly", () => {
    const { ctx } = makeContext();
    const map = toolMap(buildTools(ctx));
    expect(map.get("sign_transaction")?.annotations.destructiveHint).toBe(true);
    expect(map.get("create_transfer")?.annotations.destructiveHint).toBe(true);
    expect(map.get("create_wallet")?.annotations.readOnlyHint).toBe(false);
    expect(map.get("list_wallets")?.annotations.readOnlyHint).toBe(true);
    expect(map.get("get_balance")?.annotations.readOnlyHint).toBe(true);
    expect(map.get("list_wallets")?.annotations.destructiveHint).toBeUndefined();
  });
});

describe("tool dispatch", () => {
  test("list_wallets calls listAgents and returns JSON content", async () => {
    const { ctx, calls } = makeContext({ listAgents: [{ id: "a1" }] });
    const map = toolMap(buildTools(ctx));
    const result = await map.get("list_wallets")!.handler({});
    expect(calls).toEqual([{ method: "listAgents", args: [] }]);
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0].text)).toEqual([{ id: "a1" }]);
  });

  test("get_wallet forwards the explicit agentId", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map.get("get_wallet")!.handler({ agentId: "agent_42" });
    expect(calls).toEqual([{ method: "getAgent", args: ["agent_42"] }]);
  });

  test("create_wallet passes id, name, and platformId through", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map
      .get("create_wallet")!
      .handler({ agentId: "new_agent", name: "My Bot", platformId: "ext-1" });
    expect(calls).toEqual([{ method: "createWallet", args: ["new_agent", "My Bot", "ext-1"] }]);
  });

  test("get_balance forwards an optional chainId", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map.get("get_balance")!.handler({ agentId: "a1", chainId: 8453 });
    expect(calls).toEqual([{ method: "getBalance", args: ["a1", 8453] }]);
  });

  test("sign_transaction routes the full tx through the SDK", async () => {
    const { ctx, calls } = makeContext({ signTransaction: { txHash: "0xabc" } });
    const map = toolMap(buildTools(ctx));
    const result = await map.get("sign_transaction")!.handler({
      agentId: "a1",
      to: "0x" + "1".repeat(40),
      value: "1000000000000000000",
      chainId: 8453,
      broadcast: false,
    });
    expect(calls[0].method).toBe("signTransaction");
    expect(calls[0].args[0]).toBe("a1");
    expect(calls[0].args[1]).toEqual({
      to: "0x" + "1".repeat(40),
      value: "1000000000000000000",
      data: undefined,
      chainId: 8453,
      broadcast: false,
    });
    expect(JSON.parse(result.content[0].text)).toEqual({ txHash: "0xabc" });
  });

  test("create_transfer strips agentId before forwarding the action body", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map.get("create_transfer")!.handler({
      agentId: "a1",
      to: "0x" + "2".repeat(40),
      token: "native",
      value: "500",
      sponsor: true,
    });
    expect(calls[0].method).toBe("createTransferAction");
    expect(calls[0].args[0]).toBe("a1");
    expect(calls[0].args[1]).toEqual({
      to: "0x" + "2".repeat(40),
      token: "native",
      value: "500",
      sponsor: true,
    });
    // agentId must not leak into the SDK action payload.
    expect((calls[0].args[1] as Record<string, unknown>).agentId).toBeUndefined();
  });

  test("list_pending_approvals defaults status to pending", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map.get("list_pending_approvals")!.handler({});
    expect(calls[0]).toEqual({
      method: "listApprovals",
      args: [{ status: "pending", limit: undefined, offset: undefined }],
    });
  });

  test("list_pending_approvals honors an explicit status", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map.get("list_pending_approvals")!.handler({ status: "approved", limit: 10 });
    expect(calls[0].args[0]).toEqual({ status: "approved", limit: 10, offset: undefined });
  });

  test("get_audit_log forwards filter params", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    await map.get("get_audit_log")!.handler({ agentId: "a1", action: "sign", limit: 25 });
    expect(calls[0]).toEqual({
      method: "getAuditLog",
      args: [{ agentId: "a1", action: "sign", limit: 25 }],
    });
  });
});

describe("agent id resolution", () => {
  test("falls back to the configured default agent id", async () => {
    const { ctx, calls } = makeContext(undefined, "default_agent");
    const map = toolMap(buildTools(ctx));
    await map.get("get_balance")!.handler({});
    expect(calls[0].args[0]).toBe("default_agent");
  });

  test("explicit agentId overrides the default", async () => {
    const { ctx, calls } = makeContext(undefined, "default_agent");
    const map = toolMap(buildTools(ctx));
    await map.get("get_balance")!.handler({ agentId: "explicit" });
    expect(calls[0].args[0]).toBe("explicit");
  });

  test("errors when no agentId is available and none is configured", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    const result = await map.get("get_balance")!.handler({});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/No agent id provided/);
    expect(calls).toHaveLength(0);
  });
});

describe("input validation", () => {
  test("rejects an invalid EVM address before calling the SDK", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    const result = await map
      .get("sign_transaction")!
      .handler({ agentId: "a1", to: "0xnothex", value: "1" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/Invalid tool input/);
    expect(result.content[0].text).toMatch(/to:/);
    expect(calls).toHaveLength(0);
  });

  test("rejects a non-integer wei value", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    const result = await map
      .get("sign_transaction")!
      .handler({ agentId: "a1", to: "0x" + "1".repeat(40), value: "1.5" });
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });

  test("rejects unknown extra properties (strict schemas)", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    const result = await map.get("get_wallet")!.handler({ agentId: "a1", evil: "payload" });
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });

  test("rejects missing required fields for create_wallet", async () => {
    const { ctx, calls } = makeContext();
    const map = toolMap(buildTools(ctx));
    const result = await map.get("create_wallet")!.handler({ agentId: "a1" });
    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });

  test("rejects non-object arguments", async () => {
    const { ctx } = makeContext();
    const map = toolMap(buildTools(ctx));
    const result = await map.get("get_balance")!.handler("not an object");
    expect(result.isError).toBe(true);
  });
});

describe("error mapping", () => {
  test("surfaces StewardApiError status and policy results", async () => {
    const apiError = new StewardApiError("Policy denied", 403, {
      results: [{ rule: "spend_limit", passed: false }],
    });
    const { ctx } = makeContext({ signTransaction: apiError });
    const map = toolMap(buildTools(ctx));
    const result = await map
      .get("sign_transaction")!
      .handler({ agentId: "a1", to: "0x" + "1".repeat(40), value: "1" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/HTTP 403/);
    expect(result.content[0].text).toMatch(/spend_limit/);
    expect(result.content[0].text).toMatch(/policyResults/);
  });

  test("toErrorResult maps a generic Error to its message", () => {
    const result = toErrorResult(new Error("boom"));
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("boom");
  });

  test("toErrorResult maps a non-Error throw to a string", () => {
    const result = toErrorResult("weird");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("weird");
  });

  test("a rejected SDK call becomes an error result", async () => {
    const { ctx } = makeContext({ listAgents: new Error("network down") });
    const map = toolMap(buildTools(ctx));
    const result = await map.get("list_wallets")!.handler({});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("network down");
  });
});
