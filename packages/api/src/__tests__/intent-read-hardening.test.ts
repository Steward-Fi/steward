import { describe, expect, it } from "bun:test";
import {
  redactSignedTransactions,
  toIntentResponse,
  toProviderActionStatusResponse,
} from "../services/intent-response";

describe("intent response hardening", () => {
  it("preserves benign generic intent data while redacting signed transactions", () => {
    const value = {
      tokenAddress: "0xabc",
      prose: [
        "token price is rising",
        "authorization required by policy",
        "secret sauce recipe",
        "cookie policy accepted",
      ],
      cookiePolicy: "accepted",
      authorizationStatus: "required",
      privateKeyRequired: false,
      nested: [
        { signedTx: "0xsigned", txHash: "0xhash" },
        { signed_tx: "0xsigned-snake", status: "complete" },
      ],
    };
    expect(redactSignedTransactions(value)).toEqual({
      ...value,
      nested: [
        { signedTx: "[redacted]", txHash: "0xhash" },
        { signed_tx: "[redacted]", status: "complete" },
      ],
    });
  });

  it("redacts signed transactions without removing benign response fields", () => {
    const authorizationDetails = { authorizationStatus: "required", cookiePolicy: "accepted" };
    const payload = { prose: "token price is rising", privateKeyRequired: false };
    const response = toIntentResponse({
      id: "intent-1",
      authorizationDetails,
      payload,
      executionResult: { signedTx: "0xsigned", prose: "secret sauce recipe" },
      createdAt: new Date("2026-08-16T00:00:00.000Z"),
    } as Parameters<typeof toIntentResponse>[0]);
    expect(response.authorizationDetails).toBe(authorizationDetails);
    expect(response.payload).toBe(payload);
    expect(response.executionResult).toEqual({
      signedTx: "[redacted]",
      prose: "secret sauce recipe",
    });
  });

  it("returns provider-action status through an explicit scalar allowlist", () => {
    const canary = "provider-status-canary";
    const hostileInput = {
      id: "pa_00000000-0000-4000-8000-000000000001",
      status: "pending_approval",
      version: 1,
      workspaceId: "20000000-0000-4000-8000-000000000001",
      providerAccountId: "30000000-0000-4000-8000-000000000001",
      operationId: "40000000-0000-4000-8000-000000000001",
      operationRevision: 1,
      actionDigest: `sha256:${"a".repeat(64)}`,
      requestHash: `sha256:${"b".repeat(64)}`,
      expiresAt: null,
      createdAt: new Date("2026-08-16T00:00:00.000Z"),
      updatedAt: new Date("2026-08-16T00:00:01.000Z"),
      payload: { password: canary },
      safeSummary: { auth: canary },
    };
    const status = toProviderActionStatusResponse(hostileInput);
    expect(Object.keys(status).sort()).toEqual(
      [
        "actionDigest",
        "createdAt",
        "expiresAt",
        "id",
        "operationId",
        "operationRevision",
        "providerAccountId",
        "requestHash",
        "status",
        "updatedAt",
        "version",
        "workspaceId",
      ].sort(),
    );
    expect(JSON.stringify(status)).not.toContain(canary);
  });
});
