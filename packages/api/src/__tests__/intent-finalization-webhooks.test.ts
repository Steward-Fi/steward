import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "intents.ts"), "utf8");

describe("intent finalization webhook hardening", () => {
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
});
