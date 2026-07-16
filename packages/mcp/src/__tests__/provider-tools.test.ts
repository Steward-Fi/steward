import { describe, expect, test } from "bun:test";
import type { StewardClient } from "@stwd/sdk";
import { type ProviderApi, ProviderApiError, sanitizeProviderPayload } from "../provider-api.js";
import { buildTools, type StewardTool } from "../tools.js";

const ACTION_ID = `pa_12345678-1234-1234-1234-123456789abc`;

function harness(responses: Record<string, unknown | Error>) {
  const calls: Array<{ path: string; init?: RequestInit }> = [];
  const providerApi: ProviderApi = {
    async request(path, init) {
      calls.push({ path, init });
      const response = responses[path];
      if (response instanceof Error) throw response;
      return response;
    },
  };
  const tools = buildTools({
    client: {} as StewardClient,
    providerApi,
    config: {},
  });
  return { calls, tools: new Map(tools.map((tool: StewardTool) => [tool.name, tool])) };
}

const validInvoke = {
  workspaceId: "ws_main",
  providerAccountId: "pa_github",
  operationKey: "issue.create",
  arguments: { repository: "owner/repo", title: "bounded action" },
  idempotencyKey: "invoke-00000001",
};

describe("governed provider action tools", () => {
  test("invokes the fixed v2 route and surfaces an allowed result", async () => {
    const allowed = { id: ACTION_ID, status: "executed", result: { outcome: "allowed" } };
    const { tools, calls } = harness({ "/v2/provider-actions": allowed });
    const result = await tools.get("provider_action_invoke")!.handler(validInvoke);
    expect(result.structuredContent).toEqual(allowed);
    expect(calls).toHaveLength(1);
    expect(calls[0].path).toBe("/v2/provider-actions");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual(validInvoke);
  });

  test("preserves pending approval and policy reasons as structured content", async () => {
    const pending = {
      id: ACTION_ID,
      status: "pending_approval",
      policy: { results: [{ rule: "human_review", reason: "approval threshold" }] },
    };
    const { tools } = harness({ "/v2/provider-actions": pending });
    const result = await tools.get("provider_action_invoke")!.handler(validInvoke);
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toEqual(pending);
  });

  test("surfaces denial clearly with the complete sanitized policy payload", async () => {
    const denied = new ProviderApiError("POLICY_DENIED", 403, {
      error: "POLICY_DENIED",
      results: [{ rule: "repository_allowlist", reason: "repository denied" }],
    });
    const { tools } = harness({ "/v2/provider-actions": denied });
    const result = await tools.get("provider_action_invoke")!.handler(validInvoke);
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      status: 403,
      data: { error: "POLICY_DENIED" },
    });
    expect(result.content[0].text).toContain("repository denied");
  });

  test("uses only fixed status, approval, case, and evidence routes", async () => {
    const routes = {
      [`/intents/${ACTION_ID}`]: { status: "authorized" },
      [`/v2/provider-actions/${ACTION_ID}/approval`]: { status: "pending" },
      [`/v2/provider-actions/${ACTION_ID}/case`]: { kind: "case" },
      [`/v2/provider-actions/${ACTION_ID}/evidence`]: { kind: "evidence" },
    };
    const { tools, calls } = harness(routes);
    for (const name of ["status", "approval", "case", "evidence"]) {
      const result = await tools.get(`provider_action_${name}`)!.handler({ actionId: ACTION_ID });
      expect(result.isError).toBeUndefined();
    }
    expect(calls.map((call) => call.path)).toEqual(Object.keys(routes));
  });

  test("rejects tenant, workspace substitution, host injection, and unknown keys", async () => {
    const { tools, calls } = harness({});
    for (const input of [
      { ...validInvoke, tenantId: "foreign" },
      { actionId: ACTION_ID, workspaceId: "foreign" },
      { actionId: ACTION_ID, host: "http://169.254.169.254" },
    ]) {
      const tool = "operationKey" in input ? "provider_action_invoke" : "provider_action_status";
      const result = await tools.get(tool)!.handler(input);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid tool input");
    }
    expect(calls).toHaveLength(0);
  });

  test("rejects malformed action ids, operation keys, and idempotency keys", async () => {
    const { tools, calls } = harness({});
    expect(
      (await tools.get("provider_action_status")!.handler({ actionId: "../../secret" })).isError,
    ).toBe(true);
    expect(
      (
        await tools
          .get("provider_action_invoke")!
          .handler({ ...validInvoke, operationKey: "x".repeat(129) })
      ).isError,
    ).toBe(true);
    expect(
      (
        await tools
          .get("provider_action_invoke")!
          .handler({ ...validInvoke, idempotencyKey: "short" })
      ).isError,
    ).toBe(true);
    expect(calls).toHaveLength(0);
  });

  test("reports an upstream timeout honestly without claiming an outcome", async () => {
    const timeout = new ProviderApiError("Provider API request failed: The operation timed out", 0);
    const { tools } = harness({ "/v2/provider-actions": timeout });
    const result = await tools.get("provider_action_invoke")!.handler(validInvoke);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("timed out");
    expect(result.content[0].text).not.toMatch(/executed|allowed|succeeded/);
  });
});

describe("credential redaction", () => {
  test("removes credential canaries from nested returned and error payloads", () => {
    const canary = "credential-canary-7e132";
    const clean = JSON.stringify(
      sanitizeProviderPayload({
        authorization: `Bearer ${canary}`,
        nested: { providerToken: canary, message: `token=${canary}` },
      }),
    );
    expect(clean).not.toContain(canary);
    expect(clean).toContain("[redacted]");
  });
});
