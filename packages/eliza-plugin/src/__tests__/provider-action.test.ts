import { describe, expect, it, vi } from "vitest";
import { providerAction } from "../actions/provider-action.js";
import { providerActionsProvider } from "../providers/provider-actions.js";

const ACTION_ID = "pa_00000000-0000-4000-8000-000000000001";

function runtime(service: Record<string, unknown>) {
  return {
    getService: (name: string) => (name === "steward" ? service : null),
  } as any;
}

describe("STEWARD_PROVIDER_ACTION", () => {
  it("invokes the first-class lifecycle and surfaces pending as blocked, not executed", async () => {
    const invokeProviderAction = vi.fn().mockResolvedValue({
      id: ACTION_ID,
      status: "pending_approval",
      requestHash: `sha256:${"a".repeat(64)}`,
      actionDigest: `sha256:${"b".repeat(64)}`,
    });
    const service = { isConnected: () => true, invokeProviderAction };
    const result = await providerAction.handler(runtime(service), {} as any, undefined, {
      parameters: {
        workspaceId: "workspace-a",
        providerAccountId: "account-a",
        operationKey: "github.issue.list",
        arguments: { owner: "octo", repo: "hello" },
        idempotencyKey: "provider-action-retry",
        tenantId: "forged-tenant",
        actorAgentId: "forged-agent",
        credential: "must-not-forward",
      },
    });

    expect(result.success).toBe(true);
    expect(result.text).toContain("blocked pending human approval");
    expect(result.text).toContain("has not executed");
    expect(result.data).toMatchObject({
      id: ACTION_ID,
      caseId: ACTION_ID,
      blocked: true,
      approvalRequired: true,
    });
    expect(invokeProviderAction).toHaveBeenCalledWith({
      workspaceId: "workspace-a",
      providerAccountId: "account-a",
      operationKey: "github.issue.list",
      arguments: { owner: "octo", repo: "hello" },
      idempotencyKey: "provider-action-retry",
    });
  });

  it("rejects incomplete public parameters before calling Steward", async () => {
    const invokeProviderAction = vi.fn();
    const result = await providerAction.handler(
      runtime({ isConnected: () => true, invokeProviderAction }),
      {} as any,
      undefined,
      { parameters: { operationKey: "github.issue.list" } },
    );
    expect(result.success).toBe(false);
    expect(invokeProviderAction).not.toHaveBeenCalled();
  });

  it("rejects nested credential-shaped arguments client-side", async () => {
    const invokeProviderAction = vi.fn();
    const result = await providerAction.handler(
      runtime({ isConnected: () => true, invokeProviderAction }),
      {} as any,
      undefined,
      {
        parameters: {
          workspaceId: "workspace-a",
          providerAccountId: "account-a",
          operationKey: "github.issue.list",
          arguments: { owner: "octo", auth: { accessToken: "must-not-forward" } },
        },
      },
    );
    expect(result.success).toBe(false);
    expect(result.error).toContain("credentials");
    expect(invokeProviderAction).not.toHaveBeenCalled();
  });

  it("derives stable retry identity from message and canonical public parameters", async () => {
    const invokeProviderAction = vi.fn().mockResolvedValue({
      id: ACTION_ID,
      status: "stub_succeeded",
      requestHash: `sha256:${"a".repeat(64)}`,
      actionDigest: `sha256:${"b".repeat(64)}`,
    });
    const parameters = {
      workspaceId: "workspace-a",
      providerAccountId: "account-a",
      operationKey: "github.issue.list",
      arguments: { repo: "hello", owner: "octo" },
    };
    const service = { isConnected: () => true, invokeProviderAction };
    await providerAction.handler(runtime(service), { id: "message-1" } as any, undefined, {
      parameters,
    });
    await providerAction.handler(runtime(service), { id: "message-1" } as any, undefined, {
      parameters: { ...parameters, arguments: { owner: "octo", repo: "hello" } },
    });
    expect(invokeProviderAction.mock.calls[0][0].idempotencyKey).toBe(
      invokeProviderAction.mock.calls[1][0].idempotencyKey,
    );
    expect(invokeProviderAction.mock.calls[0][0].idempotencyKey).toMatch(/^eliza-[0-9a-f]{64}$/);
  });

  it("fails closed without a stable message id and reports persisted denial honestly", async () => {
    const invokeProviderAction = vi.fn().mockResolvedValue({
      id: ACTION_ID,
      status: "denied_policy",
      reasonCode: "PROVIDER_POLICY_DENIED",
      requestHash: `sha256:${"a".repeat(64)}`,
      actionDigest: `sha256:${"b".repeat(64)}`,
      persisted: true,
    });
    const service = { isConnected: () => true, invokeProviderAction };
    const parameters = {
      workspaceId: "workspace-a",
      providerAccountId: "account-a",
      operationKey: "github.issue.list",
      arguments: {},
    };
    const missing = await providerAction.handler(runtime(service), {} as any, undefined, {
      parameters,
    });
    expect(missing.success).toBe(false);
    expect(missing.text).toContain("not submitted");
    expect(invokeProviderAction).not.toHaveBeenCalled();

    const denied = await providerAction.handler(
      runtime(service),
      { id: "message-2" } as any,
      undefined,
      { parameters },
    );
    expect(denied.success).toBe(false);
    expect(denied.text).toContain("denied and persisted");
    expect(denied.text).not.toContain("not submitted");
  });

  it("fails closed when runtime arguments cannot be canonically serialized", async () => {
    const invokeProviderAction = vi.fn();
    const result = await providerAction.handler(
      runtime({ isConnected: () => true, invokeProviderAction }),
      { id: "message-cyclic" } as any,
      undefined,
      {
        parameters: {
          workspaceId: "workspace-a",
          providerAccountId: "account-a",
          operationKey: "github.issue.list",
          arguments: { unsupportedRuntimeValue: 1n },
        },
      },
    );
    expect(result.success).toBe(false);
    expect(result.error).toContain("stable message id");
    expect(invokeProviderAction).not.toHaveBeenCalled();
  });
});

describe("stewardProviderActions provider", () => {
  it("surfaces agent-readable status and case ids without requesting protected case evidence", async () => {
    const listTrackedProviderActions = vi.fn().mockResolvedValue([
      {
        polling: "ok",
        action: {
          id: ACTION_ID,
          status: "pending_approval",
          version: 2,
          operationId: "github.issue.list",
        },
      },
      {
        polling: "error",
        id: "pa_outage",
        lastKnown: { status: "executing", version: 3, operationId: "x.post.create" },
        error: { message: "gateway timeout", retryable: true },
      },
    ]);
    const result = await providerActionsProvider.get(
      runtime({ isConnected: () => true, listTrackedProviderActions }),
      {} as any,
      {} as any,
    );
    expect(result.text).toContain(`${ACTION_ID}: pending_approval (binding v2)`);
    expect(result.text).toContain(
      "pa_outage: status unavailable (polling error; last known executing",
    );
    expect(result.data?.bindingStates).toEqual([
      {
        id: ACTION_ID,
        status: "pending_approval",
        version: 2,
        operationId: "github.issue.list",
        polling: "ok",
      },
      {
        id: "pa_outage",
        status: "executing",
        version: 3,
        operationId: "x.post.create",
        polling: "error",
      },
    ]);
    expect(listTrackedProviderActions).toHaveBeenCalledOnce();
  });
});
