import { afterEach, describe, expect, test } from "bun:test";
import { StewardApiError, StewardClient } from "../client";

const ACTION_ID = "pa_00000000-0000-4000-8000-000000000001";
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function client() {
  return new StewardClient({
    baseUrl: "https://steward.example",
    bearerToken: "agent-jwt-canary",
    tenantId: "tenant-a",
  });
}

function mock(body: unknown, status = 200) {
  const calls: Array<{ url: string; method: string; headers: Headers; body?: string }> = [];
  globalThis.fetch = async (input, init) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: init?.body as string | undefined,
    });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return calls;
}

describe("provider-action lifecycle", () => {
  test("invokes with only the public typed request and agent credentials in headers", async () => {
    const result = {
      id: ACTION_ID,
      status: "pending_approval" as const,
      requestHash: `sha256:${"a".repeat(64)}`,
      actionDigest: `sha256:${"b".repeat(64)}`,
    };
    const calls = mock(result, 202);
    expect(
      await client().providerActions.invoke({
        workspaceId: "workspace-a",
        providerAccountId: "account-a",
        operationKey: "github.issue.list",
        arguments: { owner: "octo", repo: "hello" },
        idempotencyKey: "retry-key-0001",
      }),
    ).toEqual(result);
    expect(calls[0]?.url).toBe("https://steward.example/v2/provider-actions");
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.headers.get("authorization")).toBe("Bearer agent-jwt-canary");
    expect(calls[0]?.headers.get("x-steward-tenant")).toBe("tenant-a");
    expect(JSON.parse(calls[0]?.body ?? "{}")).toEqual({
      workspaceId: "workspace-a",
      providerAccountId: "account-a",
      operationKey: "github.issue.list",
      arguments: { owner: "octo", repo: "hello" },
      idempotencyKey: "retry-key-0001",
    });
  });

  test("polls agent status through the scoped route", async () => {
    const status = {
      id: ACTION_ID,
      status: "pending_approval",
      version: 2,
      workspaceId: "workspace-a",
      providerAccountId: "account-a",
      operationId: "github.issue.list",
      operationRevision: 1,
      actionDigest: `sha256:${"b".repeat(64)}`,
      requestHash: `sha256:${"a".repeat(64)}`,
      expiresAt: null,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:01:00.000Z",
    };
    const calls = mock({ ok: true, data: status });
    expect(await client().providerActions.get(ACTION_ID)).toEqual(status);
    expect(calls[0]?.url).toBe(`https://steward.example/v2/provider-actions/${ACTION_ID}`);
  });

  test("maps the human approval, execution, case, and evidence routes exactly", async () => {
    const c = client();
    let calls = mock({ ok: true, data: { id: ACTION_ID, status: "pending_approval" } });
    await c.providerActions.getApproval(ACTION_ID);
    expect(calls[0]?.url).toEndWith(`/v2/provider-actions/${ACTION_ID}/approval`);
    expect(calls[0]?.method).toBe("GET");

    calls = mock({ id: ACTION_ID, status: "approved", version: 2 });
    await c.providerActions.decideApproval(ACTION_ID, {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: `sha256:${"a".repeat(64)}`,
      expectedActionDigest: `sha256:${"b".repeat(64)}`,
      idempotencyKey: "approval-retry-1",
    });
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toEndWith(`/v2/provider-actions/${ACTION_ID}/approval`);

    calls = mock({ id: ACTION_ID, status: "executing", version: 3 });
    await c.providerActions.execute(ACTION_ID);
    expect(calls[0]?.url).toEndWith(`/v2/provider-actions/${ACTION_ID}/execute`);
    expect(calls[0]?.body).toBeUndefined();

    calls = mock({ schemaVersion: "steward.provider-case-manifest.v1", caseId: ACTION_ID });
    await c.providerActions.getCase(ACTION_ID);
    expect(calls[0]?.url).toEndWith(`/v2/provider-actions/${ACTION_ID}/case`);

    calls = mock({ version: 1, caseId: ACTION_ID, manifest: {}, bundle: {} });
    await c.providerActions.getEvidence(ACTION_ID);
    expect(calls[0]?.url).toEndWith(`/v2/provider-actions/${ACTION_ID}/evidence`);
  });

  test("preserves structured human/MFA failures without treating them as data", async () => {
    mock(
      {
        ok: false,
        error: { code: "APPROVAL_MFA_REQUIRED", message: "recent MFA required" },
      },
      403,
    );
    await expect(client().providerActions.getApproval(ACTION_ID)).rejects.toMatchObject({
      name: "StewardApiError",
      message: "APPROVAL_MFA_REQUIRED",
      status: 403,
    } satisfies Partial<StewardApiError>);
  });

  test("returns a typed persisted denial and preserves non-persisted failures", async () => {
    mock(
      {
        ok: false,
        error: "PROVIDER_ACCESS_DENIED",
        data: {
          id: ACTION_ID,
          status: "denied_access",
          requestHash: `sha256:${"a".repeat(64)}`,
          actionDigest: `sha256:${"b".repeat(64)}`,
        },
      },
      403,
    );
    await expect(
      client().providerActions.invoke({
        workspaceId: "workspace-a",
        providerAccountId: "account-a",
        operationKey: "github.issue.list",
        arguments: {},
        idempotencyKey: "stable-retry-1",
      }),
    ).resolves.toMatchObject({
      id: ACTION_ID,
      status: "denied_access",
      reasonCode: "PROVIDER_ACCESS_DENIED",
      persisted: true,
    });

    mock({ ok: false, error: "BACKEND_UNAVAILABLE" }, 503);
    await expect(
      client().providerActions.invoke({
        workspaceId: "workspace-a",
        providerAccountId: "account-a",
        operationKey: "github.issue.list",
        arguments: {},
        idempotencyKey: "stable-retry-1",
      }),
    ).rejects.toMatchObject({ status: 503, message: "BACKEND_UNAVAILABLE" });
  });
});
