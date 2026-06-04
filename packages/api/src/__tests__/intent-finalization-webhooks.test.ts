import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "intents.ts"), "utf8");

describe("intent finalization webhook hardening", () => {
  it("marks intent responses as non-cacheable because execution can return signed material", () => {
    expect(routeSource).toContain("setNoStoreHeaders");
    expect(routeSource).toContain('intentRoutes.use("*"');
    expect(routeSource).toContain("setNoStoreHeaders(c)");
  });

  it("emits wallet-action success webhooks only after final intent audit succeeds", () => {
    const transferStart = routeSource.indexOf("async function executeTransferIntent");
    const sendCallsStart = routeSource.indexOf("async function executeSendCallsIntent");
    const rpcStart = routeSource.indexOf("async function executeRpcIntent");
    expect(transferStart).toBeGreaterThanOrEqual(0);
    expect(sendCallsStart).toBeGreaterThanOrEqual(0);
    expect(rpcStart).toBeGreaterThan(sendCallsStart);

    const transferExecutor = routeSource.slice(transferStart, sendCallsStart);
    const sendCallsExecutor = routeSource.slice(sendCallsStart, rpcStart);
    expect(transferExecutor).not.toContain('"wallet_action.transfer.succeeded"');
    expect(sendCallsExecutor).not.toContain('"wallet_action.send_calls.succeeded"');

    expect(routeSource).toContain("function dispatchWalletActionSuccessWebhook");
    const finalizationStart = routeSource.indexOf('writeIntentAudit(c, "intent.executed"');
    expect(finalizationStart).toBeGreaterThanOrEqual(0);
    const finalizationRoute = routeSource.slice(finalizationStart);
    expect(finalizationRoute.indexOf('writeIntentAudit(c, "intent.executed"')).toBeLessThan(
      finalizationRoute.indexOf("dispatchWalletActionSuccessWebhook"),
    );
    expect(finalizationRoute.indexOf("dispatchWalletActionSuccessWebhook")).toBeLessThan(
      finalizationRoute.indexOf('dispatchIntentWebhook(tenantId, row.agentId, "intent.executed"'),
    );
  });

  it("repairs missing final intent audits before returning an idempotent final status", () => {
    expect(routeSource).toContain("function finalIntentAuditAction");
    expect(routeSource).toContain("async function hasIntentAudit");
    expect(routeSource).toContain("function dispatchFinalIntentWebhooks");

    const repairStart = routeSource.indexOf("if (existing.status === status)");
    const firstConflict = routeSource.indexOf(
      'return c.json<ApiResponse>({ ok: false, error: "Intent is no longer pending" }',
    );
    expect(repairStart).toBeGreaterThanOrEqual(0);
    expect(firstConflict).toBeGreaterThan(repairStart);
    const repairBlock = routeSource.slice(repairStart, firstConflict);
    expect(repairBlock).toContain("hasIntentAudit(tenantId, existing.id, finalAuditAction)");
    expect(repairBlock).toContain("writeIntentAudit(c, finalAuditAction");
    expect(repairBlock).toContain("repaired: true");
    expect(repairBlock).toContain("dispatchFinalIntentWebhooks(tenantId, existing)");
    expect(repairBlock).toContain("return c.json<ApiResponse>({ ok: true");
  });
});
