import { describe, expect, it, vi } from "vitest";
import { assertSecureApiUrl, StewardService } from "../services/StewardService.js";

const ACTION_A = "pa_00000000-0000-4000-8000-000000000001";
const ACTION_B = "pa_00000000-0000-4000-8000-000000000002";

describe("StewardService provider-action polling", () => {
  it("rejects credential-bearing, public plaintext, and non-HTTP API URLs", () => {
    expect(() => assertSecureApiUrl("https://user:secret@api.example.test")).toThrow(
      "must not contain embedded credentials",
    );
    expect(() => assertSecureApiUrl("http://api.example.test")).toThrow(
      "only allowed for localhost",
    );
    expect(() => assertSecureApiUrl("ftp://api.example.test")).toThrow("must use https://");
    expect(() => assertSecureApiUrl("http://127.0.0.1:3200")).not.toThrow();
  });

  it("retains one visible result per binding when a later poll fails", async () => {
    const status = {
      id: ACTION_A,
      status: "executing",
      version: 3,
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
    const get = vi.fn(async (id: string) => {
      if (id === ACTION_A) return status;
      throw new Error("gateway timeout with token-canary");
    });
    const service = new StewardService({} as any);
    Object.assign(service as any, {
      client: { providerActions: { get } },
      _connected: true,
      trackedProviderActionIds: new Set([ACTION_A, ACTION_B]),
      providerActionLastKnown: new Map([
        [ACTION_B, { ...status, id: ACTION_B, status: "approved" }],
      ]),
    });

    const results = await service.listTrackedProviderActions();
    expect(results).toHaveLength(2);
    expect(results[0]).toEqual({ polling: "ok", action: status });
    expect(results[1]).toMatchObject({
      polling: "error",
      id: ACTION_B,
      lastKnown: { id: ACTION_B, status: "approved", version: 3 },
      error: { message: "provider action status is temporarily unavailable", retryable: true },
    });
    expect(JSON.stringify(results)).not.toContain("token-canary");
  });
});
