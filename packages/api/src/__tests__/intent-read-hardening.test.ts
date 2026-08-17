import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  redactSignedTransactions,
  toIntentResponse,
  toProviderActionStatusResponse,
} from "../services/intent-response";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "intents.ts"), "utf8");

describe("intent read hardening", () => {
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

  it("keeps generic GET, webhook, and persistence on the signedTx-only contract", () => {
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

    const webhookStart = routeSource.indexOf("function dispatchIntentWebhook");
    const webhookEnd = routeSource.indexOf(
      "function dispatchWalletActionSuccessWebhook",
      webhookStart,
    );
    const webhookBody = routeSource.slice(webhookStart, webhookEnd);
    expect(webhookBody).toContain("authorization_details: row.authorizationDetails");
    expect(webhookBody).toContain(
      "execution_result: redactSignedTransactions(row.executionResult)",
    );
    expect(routeSource).toContain(
      "const storedExecutionResult = redactSignedTransactions(executionResult)",
    );
  });

  it("provider-action status DTO is an explicit scalar allowlist", () => {
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

  it("attributes intent audits to the actual auth type and writes lifecycle authorization audit first", () => {
    const auditStart = routeSource.indexOf("async function writeIntentAudit");
    expect(auditStart).toBeGreaterThanOrEqual(0);
    const auditBody = routeSource.slice(
      auditStart,
      routeSource.indexOf("function dispatchIntentWebhook", auditStart),
    );
    expect(auditBody).toContain("actorType: auditActorType(c)");
    expect(auditBody).not.toContain('actorType: "user"');

    const lifecycleUpdateStart = routeSource.indexOf("const lifecycleStatus = status as");
    expect(lifecycleUpdateStart).toBeGreaterThanOrEqual(0);
    const authorizedAudit = routeSource.indexOf(
      "writeIntentAudit(c, `intent.${lifecycleStatus}.authorized`",
      lifecycleUpdateStart,
    );
    const mutation = routeSource.indexOf(".update(intents)", lifecycleUpdateStart);
    expect(authorizedAudit).toBeGreaterThan(lifecycleUpdateStart);
    expect(mutation).toBeGreaterThan(lifecycleUpdateStart);
    expect(authorizedAudit).toBeLessThan(mutation);
  });

  it("does not allow intent resourceId to choose the transaction primary key", () => {
    const transferStart = routeSource.indexOf("async function executeTransferIntent");
    expect(transferStart).toBeGreaterThanOrEqual(0);
    const transferBody = routeSource.slice(
      transferStart,
      routeSource.indexOf("async function executeSendCallsIntent", transferStart),
    );
    expect(transferBody).toContain("const txId = row.id");
    expect(transferBody).not.toContain("row.resourceId || row.id");
  });
});
