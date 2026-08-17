import { afterEach, describe, expect, test } from "bun:test";
import type { StewardClient } from "@stwd/sdk";
import {
  createProviderApi,
  type ProviderApi,
  ProviderApiError,
  sanitizeProviderPayload,
} from "../provider-api.js";
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
      [`/v2/provider-actions/${ACTION_ID}`]: { status: "authorized" },
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

  test("status uses the agent-scoped route and preserves its least-privilege DTO", async () => {
    const status = {
      ok: true,
      data: {
        id: ACTION_ID,
        status: "pending_approval",
        version: 1,
        workspaceId: "20000000-0000-4000-8000-000000000001",
        providerAccountId: "30000000-0000-4000-8000-000000000001",
        operationId: "40000000-0000-4000-8000-000000000001",
        operationRevision: 1,
      },
    };
    const path = `/v2/provider-actions/${ACTION_ID}`;
    const { tools, calls } = harness({ [path]: status });

    const result = await tools.get("provider_action_status")!.handler({ actionId: ACTION_ID });

    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toEqual(status);
    expect(calls).toEqual([{ path, init: undefined }]);
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

describe("createProviderApi HTTP transport", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function stubFetch(
    status: number,
    body: unknown,
  ): { seen: Array<{ url: string; init?: RequestInit }> } {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      seen.push({ url: String(url), init });
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    return { seen };
  }

  test("throws ProviderApiError (never a success value) on an upstream 5xx", async () => {
    stubFetch(503, { error: "UPSTREAM_UNAVAILABLE" });
    const api = createProviderApi({
      baseUrl: "https://steward.example",
      bearerToken: "agent-jwt",
    });
    let thrown: unknown;
    try {
      await api.request("/v2/provider-actions", { method: "POST", body: "{}" });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ProviderApiError);
    expect((thrown as ProviderApiError).status).toBe(503);
    expect((thrown as ProviderApiError).message).toBe("UPSTREAM_UNAVAILABLE");
  });

  test("builds auth + tenant headers from config only, never from the path", async () => {
    const { seen } = stubFetch(200, { ok: true });
    const api = createProviderApi({
      baseUrl: "https://steward.example/",
      bearerToken: "agent-jwt",
      tenantId: "tenant-a",
    });
    await api.request("/v2/provider-actions", { method: "POST", body: "{}" });
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("https://steward.example/v2/provider-actions");
    const headers = new Headers(seen[0].init?.headers);
    expect(headers.get("authorization")).toBe("Bearer agent-jwt");
    expect(headers.get("x-steward-tenant")).toBe("tenant-a");
  });

  test("redacts secrets in a real non-ok error body before throwing", async () => {
    const canary = "canary-http-5xx-9a1";
    stubFetch(403, {
      error: "POLICY_DENIED",
      authorization: `Bearer ${canary}`,
      detail: `token=${canary}`,
    });
    const api = createProviderApi({ baseUrl: "https://steward.example", bearerToken: "agent-jwt" });
    let thrown: unknown;
    try {
      await api.request("/v2/provider-actions", { method: "POST", body: "{}" });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ProviderApiError);
    expect(JSON.stringify((thrown as ProviderApiError).data)).not.toContain(canary);
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

  test("redacts password/private-key/jwt/signature keyed fields", () => {
    const canary = "keyed-canary-b51f0";
    const clean = JSON.stringify(
      sanitizeProviderPayload({
        password: canary,
        passphrase: canary,
        private_key: canary,
        clientJwt: canary,
        signature: canary,
        nested: { sessionPassword: canary },
      }),
    );
    expect(clean).not.toContain(canary);
  });

  test("redacts secret shapes embedded in free-text error messages", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sigcanary01";
    const apiKey = "sk-livecanary123456789";
    const ghToken = "ghp_canarytoken123456";
    const slackToken = "xoxb-canary-123456789";
    const password = "free-text-passwd-canary";
    const clean = sanitizeProviderPayload(
      `upstream 500: jwt=${jwt} key=${apiKey} gh=${ghToken} slack=${slackToken} password: ${password}`,
    ) as string;
    for (const canary of [jwt, apiKey, ghToken, slackToken, password]) {
      expect(clean).not.toContain(canary);
    }
    expect(clean).toContain("[redacted]");
  });

  test("leaves non-secret free text and identifiers intact", () => {
    const text = "order oid_123 failed: insufficient balance for 0.01 BTC; tx 0x" + "a".repeat(64);
    expect(sanitizeProviderPayload(text)).toBe(text);
  });
});
