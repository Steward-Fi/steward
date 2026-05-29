import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");

describe("wallet_sendCalls spend hardening", () => {
  it("prevents referenceId replay from creating duplicate transfer or send-calls actions", () => {
    expect(vaultSource).toContain("function findActionByReferenceId");
    expect(vaultSource).toContain(
      'findActionByReferenceId(agentId, "transfer", transfer.referenceId)',
    );
    expect(vaultSource).toContain(
      'findActionByReferenceId(agentId, "send_calls", parsed.referenceId)',
    );
    expect(vaultSource).toContain("function requireBroadcastActionIdempotency");
    expect(vaultSource).toContain('"Broadcast transfer actions"');
    expect(vaultSource).toContain('"Broadcast send-calls actions"');
    expect(vaultSource).toContain("require an Idempotency-Key header");

    const transferStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    const transferLookup = vaultSource.indexOf(
      'findActionByReferenceId(agentId, "transfer", transfer.referenceId)',
      transferStart,
    );
    expect(transferLookup).toBeGreaterThan(transferStart);
    expect(transferLookup).toBeLessThan(
      vaultSource.indexOf("const actionId = crypto.randomUUID()", transferLookup),
    );
    const transferLock = vaultSource.indexOf("return withAgentSpendLock(agentId", transferLookup);
    const transferLockedLookup = vaultSource.indexOf(
      'findActionByReferenceId(\n      agentId,\n      "transfer",\n      transfer.referenceId',
      transferLock,
    );
    expect(transferLockedLookup).toBeGreaterThan(transferLock);
    expect(transferLockedLookup).toBeLessThan(
      vaultSource.indexOf("const actionId = crypto.randomUUID()", transferLockedLookup),
    );

    const sendCallsStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/send-calls"');
    const sendCallsLookup = vaultSource.indexOf(
      'findActionByReferenceId(agentId, "send_calls", parsed.referenceId)',
      sendCallsStart,
    );
    expect(sendCallsLookup).toBeGreaterThan(sendCallsStart);
    expect(sendCallsLookup).toBeLessThan(
      vaultSource.indexOf("const actionId = crypto.randomUUID()", sendCallsLookup),
    );
    const sendCallsLock = vaultSource.indexOf("return withAgentSpendLock(agentId", sendCallsLookup);
    const sendCallsLockedLookup = vaultSource.indexOf(
      'findActionByReferenceId(\n      agentId,\n      "send_calls",\n      parsed.referenceId',
      sendCallsLock,
    );
    expect(sendCallsLockedLookup).toBeGreaterThan(sendCallsLock);
    expect(sendCallsLockedLookup).toBeLessThan(
      vaultSource.indexOf("const actionId = crypto.randomUUID()", sendCallsLockedLookup),
    );
  });

  it("fails closed for ERC20 transfer actions until token spend is accounted", () => {
    const transferStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    expect(transferStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf(
      'vaultRoutes.get("/:agentId/actions/:actionId"',
      transferStart,
    );
    const routeSource = vaultSource.slice(transferStart, routeEnd);
    const tokenCheck = routeSource.indexOf('const isTokenTransfer = transfer.token !== "native"');
    const failClosed = routeSource.indexOf(
      "ERC20 transfer actions require token-aware spend accounting",
    );

    expect(tokenCheck).toBeGreaterThanOrEqual(0);
    expect(failClosed).toBeGreaterThan(tokenCheck);
    expect(failClosed).toBeLessThan(routeSource.indexOf("vault.signTransaction(signRequest"));
    expect(failClosed).toBeLessThan(routeSource.indexOf("recordVaultSpend"));
  });

  it("fails closed for native transfer actions to contract recipients", () => {
    const transferStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    expect(transferStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf(
      'vaultRoutes.get("/:agentId/actions/:actionId"',
      transferStart,
    );
    const routeSource = vaultSource.slice(transferStart, routeEnd);
    const nativeGuard = routeSource.indexOf("nativeTransferGasAccountingGuard");
    const policyEvaluation = routeSource.indexOf("await policyEngine.evaluate");
    const signCall = routeSource.indexOf("vault.signTransaction(signRequest");

    expect(vaultSource).toContain('method: "eth_getCode"');
    expect(vaultSource).toContain("Native transfers to contract recipients");
    expect(nativeGuard).toBeGreaterThanOrEqual(0);
    expect(policyEvaluation).toBeGreaterThan(nativeGuard);
    expect(signCall).toBeGreaterThan(nativeGuard);
  });

  it("evaluates cumulative spend with a running per-batch total", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/send-calls"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf(
      'vaultRoutes.post("/:agentId/actions/transfer"',
      routeStart,
    );
    const routeSource = vaultSource.slice(routeStart, routeEnd);

    const statsRead = routeSource.indexOf("const stats = await getTransactionStats(agentId)");
    const runningToday = routeSource.indexOf("let runningSpentToday = stats.spentToday", statsRead);
    const evaluation = routeSource.indexOf("await policyEngine.evaluate", runningToday);
    const runningContext = routeSource.indexOf("spentToday: runningSpentToday", evaluation);
    const increment = routeSource.indexOf("runningSpentToday += callValue", runningContext);

    expect(statsRead).toBeGreaterThanOrEqual(0);
    expect(runningToday).toBeGreaterThan(statsRead);
    expect(runningContext).toBeGreaterThan(evaluation);
    expect(increment).toBeGreaterThan(runningContext);
  });
});
