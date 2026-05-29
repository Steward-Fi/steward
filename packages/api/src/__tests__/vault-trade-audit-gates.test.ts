import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");
const tradeSource = readFileSync(join(import.meta.dir, "..", "routes", "trade.ts"), "utf8");
const vaultPackageSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "vault", "src", "vault.ts"),
  "utf8",
);
const solanaSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "vault", "src", "solana.ts"),
  "utf8",
);

describe("vault and trade audit gates", () => {
  it("requires human MFA for manual vault approval and rejection", () => {
    const markers = [
      'vaultRoutes.post("/:agentId/approve/:txId"',
      'vaultRoutes.post("/:agentId/reject/:txId"',
      'vaultRoutes.post("/:agentId/transactions/:txId/lifecycle"',
      'vaultRoutes.post("/:agentId/transactions/:txId/replace"',
      'vaultRoutes.post("/:agentId/sign-message"',
      'vaultRoutes.post("/:agentId/sign-user-operation"',
      'vaultRoutes.post("/:agentId/sign-authorization"',
    ];
    for (const marker of markers) {
      const start = vaultSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextStart = vaultSource.indexOf("vaultRoutes.", start + marker.length);
      const source = vaultSource.slice(start, nextStart > start ? nextStart : undefined);
      expect(source).toContain("hasTenantAdminSession(c)");
      expect(source).toContain("hasRecentSessionMfa(c)");
    }
    const transferStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    const nextStart = vaultSource.indexOf("vaultRoutes.", transferStart + 1);
    const transferRoute = vaultSource.slice(transferStart, nextStart);
    expect(transferRoute).toContain("requireSignerPermission");
    expect(transferRoute).toContain('"wallet_action_transfer"');
  });

  it("writes blocking audit events before signing or submitting irreversible actions", () => {
    expect(vaultSource.indexOf('action: "vault.sign.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signTransaction(signRequest"),
    );
    const transferRouteStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    const transferRouteEnd = vaultSource.indexOf("vaultRoutes.", transferRouteStart + 1);
    const transferRoute = vaultSource.slice(transferRouteStart, transferRouteEnd);
    expect(transferRoute.indexOf('action: "wallet_action.transfer.authorized"')).toBeLessThan(
      transferRoute.indexOf("vault.signTransaction(signRequest"),
    );
    expect(vaultSource.indexOf('action: "transaction.lifecycle.authorized"')).toBeLessThan(
      vaultSource.indexOf(
        ".update(transactions)",
        vaultSource.indexOf("transactions/:txId/lifecycle"),
      ),
    );
    expect(vaultSource.indexOf('action: "vault.message.sign.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signMessage"),
    );
    expect(vaultSource.indexOf('action: "vault.sign.user_operation.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signUserOperation"),
    );
    expect(vaultSource.indexOf('action: "vault.sign.authorization.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signAuthorization"),
    );
    expect(tradeSource.indexOf('"trade.order.submit.authorized"')).toBeLessThan(
      tradeSource.indexOf("adapter.signOrder(order)"),
    );
    expect(tradeSource.indexOf('"trade.session.create.authorized"')).toBeLessThan(
      tradeSource.indexOf("sessionManager.createSession"),
    );
    expect(tradeSource.indexOf('"trade.session.revoke.authorized"')).toBeLessThan(
      tradeSource.indexOf("getSessionManager().revokeSession"),
    );
    expect(tradeSource).toContain('c.get("authType") === "session-jwt"');
  });

  it("requires recent MFA for trade session management", () => {
    expect(tradeSource).toContain("function requireRecentTradeSessionMfa");
    for (const marker of [
      'tradeRoutes.post("/sessions"',
      'tradeRoutes.get("/sessions/:id"',
      'tradeRoutes.post("/sessions/:id/revoke"',
    ]) {
      const start = tradeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const routeSource = tradeSource.slice(start, tradeSource.indexOf("tradeRoutes.", start + 1));
      expect(routeSource).toContain("canManageTradeSession(c");
      expect(routeSource).toContain("requireRecentTradeSessionMfa(c)");
    }
  });

  it("attributes human trade session control-plane audits to the session user", () => {
    expect(tradeSource).toContain("function tradeAuditActor");
    expect(tradeSource).toContain('authType === "session-jwt" && userId');
    expect(tradeSource).toContain('return { actorType: "user", actorId: userId }');

    const sessionCreateStart = tradeSource.indexOf('tradeRoutes.post("/sessions"');
    expect(sessionCreateStart).toBeGreaterThanOrEqual(0);
    const sessionCreateRoute = tradeSource.slice(
      sessionCreateStart,
      tradeSource.indexOf('tradeRoutes.get("/sessions/:id"', sessionCreateStart),
    );
    expect(sessionCreateRoute).toContain("const actor = tradeAuditActor(c, agentId)");
    expect(sessionCreateRoute).toContain('"trade.session.create.authorized"');
    expect(sessionCreateRoute).toContain('"trade.session.created"');

    const revokeStart = tradeSource.indexOf('tradeRoutes.post("/sessions/:id/revoke"');
    expect(revokeStart).toBeGreaterThanOrEqual(0);
    const revokeRoute = tradeSource.slice(
      revokeStart,
      tradeSource.indexOf('tradeRoutes.post("/hyperliquid/order"', revokeStart),
    );
    expect(revokeRoute).toContain("tradeAuditActor(c, existing.agentId)");
    expect(revokeRoute).toContain("tradeAuditActor(c, revoked.agentId)");
  });

  it("preserves legacy sign broadcast intent through manual approval", () => {
    const pendingInsert = vaultSource.indexOf('status: "pending"');
    expect(pendingInsert).toBeGreaterThanOrEqual(0);
    expect(vaultSource.indexOf("transactionActionPayload", pendingInsert)).toBeGreaterThan(
      pendingInsert,
    );

    const approvalStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"');
    expect(approvalStart).toBeGreaterThanOrEqual(0);
    const approvalRoute = vaultSource.slice(
      approvalStart,
      vaultSource.indexOf('vaultRoutes.post("/:agentId/reject/:txId"', approvalStart),
    );
    expect(approvalRoute).toContain("getTransactionActionPayload");
    expect(approvalRoute).toContain("transactionPayload.broadcast");
    expect(approvalRoute).toContain("const shouldBroadcast");
    expect(approvalRoute).toContain("signedTx: shouldBroadcast ? undefined : txHash");
  });

  it("requires replay protection for direct broadcast signing", () => {
    const signStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign"');
    expect(signStart).toBeGreaterThanOrEqual(0);
    const signRoute = vaultSource.slice(
      signStart,
      vaultSource.indexOf('vaultRoutes.post("/:agentId/rpc"', signStart),
    );
    expect(signRoute).toContain('c.req.header("Idempotency-Key")');
    expect(signRoute).toContain("Broadcast signing requires an Idempotency-Key header");
    expect(signRoute).toContain('const txStatus: "broadcast" | "signed"');
    expect(signRoute).toContain("status: txStatus");
  });

  it("revalidates current policy before executing manual approvals", () => {
    const approvalStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"');
    expect(approvalStart).toBeGreaterThanOrEqual(0);
    const approvalRoute = vaultSource.slice(
      approvalStart,
      vaultSource.indexOf('vaultRoutes.post("/:agentId/reject/:txId"', approvalStart),
    );
    expect(approvalRoute).toContain("return withAgentSpendLock(agentId");
    expect(approvalRoute).toContain("const currentPolicySet = await getPolicySet");
    expect(approvalRoute).toContain("await enforceRateLimit(agentId, currentPolicySet)");
    expect(approvalRoute).toContain("const currentEvaluation = await policyEngine.evaluate");
    expect(approvalRoute).toContain("Pending transaction no longer satisfies current policy");
    expect(approvalRoute).toContain("policyResults: currentEvaluation.results");
    expect(approvalRoute.indexOf("const currentEvaluation")).toBeLessThan(
      approvalRoute.indexOf("vault.signTransaction"),
    );
  });

  it("does not broadcast Solana offline signing requests", () => {
    expect(vaultPackageSource).toContain("broadcast: shouldBroadcast");
    expect(solanaSource).toContain("options: { broadcast?: boolean } = {}");
    expect(solanaSource).toContain("const shouldBroadcast = options.broadcast !== false");
    expect(solanaSource.indexOf("if (!shouldBroadcast)")).toBeLessThan(
      solanaSource.indexOf("connection.sendTransaction"),
    );
    expect(solanaSource.indexOf("btoa(Array.from(tx.serialize()")).toBeLessThan(
      solanaSource.indexOf("connection.sendTransaction"),
    );
    const approvalStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"');
    const approvalRoute = vaultSource.slice(
      approvalStart,
      vaultSource.indexOf('vaultRoutes.post("/:agentId/reject/:txId"', approvalStart),
    );
    expect(approvalRoute).toContain("broadcast: shouldBroadcast");
    expect(approvalRoute).not.toContain("broadcast: true");
  });

  it("prevents lifecycle promotion while approval is pending", () => {
    const lifecycleStart = vaultSource.indexOf(
      'vaultRoutes.post("/:agentId/transactions/:txId/lifecycle"',
    );
    expect(lifecycleStart).toBeGreaterThanOrEqual(0);
    const lifecycleRoute = vaultSource.slice(lifecycleStart);
    expect(lifecycleRoute).toContain("Transaction must be broadcast before confirmation");
    expect(lifecycleRoute).toContain(
      "Pending approval must be resolved before lifecycle promotion",
    );
    expect(lifecycleRoute.indexOf("Pending approval must be resolved")).toBeLessThan(
      lifecycleRoute.indexOf('action: "transaction.lifecycle.authorized"'),
    );
  });

  it("exposes a guarded first-class transaction replacement route", () => {
    const replaceStart = vaultSource.indexOf(
      'vaultRoutes.post("/:agentId/transactions/:txId/replace"',
    );
    expect(replaceStart).toBeGreaterThanOrEqual(0);
    const nextRoute = vaultSource.indexOf("vaultRoutes.", replaceStart + 1);
    const replaceRoute = vaultSource.slice(
      replaceStart,
      nextRoute > replaceStart ? nextRoute : undefined,
    );
    expect(replaceRoute).toContain("replacementTxHash is required");
    expect(replaceRoute).toContain("Pending approval must be resolved before replacement");
    expect(replaceRoute).toContain('action: "transaction.replace.authorized"');
    expect(replaceRoute).toContain('action: "transaction.replaced"');
    expect(replaceRoute).toContain("dispatchTransactionLifecycleWebhook");
    expect(replaceRoute).toContain('"transaction.replaced"');
  });

  it("fails venue-rejected trade submissions without retaining spend or success audit", () => {
    const rejectionStart = tradeSource.indexOf('if (result.status === "rejected")');
    expect(rejectionStart).toBeGreaterThanOrEqual(0);
    expect(
      tradeSource.indexOf(
        ".releaseSpend({ tenantId, id: session.id, amountUsd: sizeUsd })",
        rejectionStart,
      ),
    ).toBeGreaterThan(rejectionStart);
    expect(tradeSource.indexOf('"trade.order.canceled"', rejectionStart)).toBeGreaterThan(
      rejectionStart,
    );
    expect(tradeSource.indexOf("return c.json<ApiResponse>", rejectionStart)).toBeLessThan(
      tradeSource.indexOf('"trade.order.submitted"', rejectionStart),
    );
  });

  it("keeps spend and idempotency fenced when venue submit status is unknown", () => {
    const submitStart = tradeSource.indexOf("let submitAttempted = false");
    expect(submitStart).toBeGreaterThanOrEqual(0);
    expect(tradeSource.indexOf("submitAttempted = true", submitStart)).toBeLessThan(
      tradeSource.indexOf("adapter.submitOrder(signed)", submitStart),
    );
    const unknownStart = tradeSource.indexOf("if (submitAttempted)", submitStart);
    expect(unknownStart).toBeGreaterThan(submitStart);
    expect(tradeSource.indexOf("idempotency.complete(envelope)", unknownStart)).toBeGreaterThan(
      unknownStart,
    );
    expect(tradeSource.indexOf("Trade submission status unknown", unknownStart)).toBeGreaterThan(
      unknownStart,
    );
    const releaseStart = tradeSource.indexOf(
      ".releaseSpend({ tenantId, id: session.id, amountUsd: sizeUsd })",
      unknownStart,
    );
    const unknownReturn = tradeSource.indexOf("return c.json<ApiResponse>", unknownStart);
    expect(unknownReturn).toBeGreaterThan(unknownStart);
    expect(releaseStart === -1 || unknownReturn < releaseStart).toBe(true);
  });
});
