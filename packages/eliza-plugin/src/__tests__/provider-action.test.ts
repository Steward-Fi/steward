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
});

describe("stewardProviderActions provider", () => {
  it("surfaces agent-readable status and case ids without requesting protected case evidence", async () => {
    const listTrackedProviderActions = vi
      .fn()
      .mockResolvedValue([{ id: ACTION_ID, intentType: "provider-action", status: "pending" }]);
    const result = await providerActionsProvider.get(
      runtime({ isConnected: () => true, listTrackedProviderActions }),
      {} as any,
      {} as any,
    );
    expect(result.text).toContain(`${ACTION_ID}: pending`);
    expect(result.data?.caseStates).toEqual([{ caseId: ACTION_ID, status: "pending" }]);
    expect(listTrackedProviderActions).toHaveBeenCalledOnce();
  });
});
