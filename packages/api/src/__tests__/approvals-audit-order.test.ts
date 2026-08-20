import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "approvals.ts"), "utf8");

function expectBefore(first: string, second: string) {
  const firstIndex = routeSource.indexOf(first);
  const secondIndex = routeSource.indexOf(second);
  expect(firstIndex).toBeGreaterThanOrEqual(0);
  expect(secondIndex).toBeGreaterThanOrEqual(0);
  expect(firstIndex).toBeLessThan(secondIndex);
}

function routeBody(marker: string): string {
  const start = routeSource.indexOf(marker);
  expect(start).toBeGreaterThanOrEqual(0);
  const nextRoute = routeSource.indexOf("approvalRoutes.", start + marker.length);
  return routeSource.slice(start, nextRoute === -1 ? undefined : nextRoute);
}

describe("approval route audit ordering", () => {
  it("marks approval control-plane responses as non-cacheable", () => {
    expect(routeSource).toContain("setNoStoreHeaders");
    expect(routeSource).toContain('approvalRoutes.use("*"');
    expect(routeSource).toContain("setNoStoreHeaders(c)");
  });

  it("keeps approval queue reads and writes behind a human approver session", () => {
    for (const marker of [
      'approvalRoutes.get("/", async',
      'approvalRoutes.get("/stats", async',
      'approvalRoutes.get("/rules", async',
      'approvalRoutes.post("/:txId/approve", async',
      'approvalRoutes.post("/:txId/deny", async',
      'approvalRoutes.put("/rules", async',
    ]) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      expect(routeSource.indexOf("requireHumanApprover(c)", start)).toBeGreaterThan(start);
    }
  });

  it("requires recent MFA before approval reads, decisions, and approval rule changes", () => {
    for (const marker of [
      'approvalRoutes.get("/", async',
      'approvalRoutes.get("/stats", async',
      'approvalRoutes.get("/rules", async',
      'approvalRoutes.post("/:txId/approve", async',
      'approvalRoutes.post("/:txId/deny", async',
      'approvalRoutes.put("/rules", async',
    ]) {
      const body = routeBody(marker);
      const approverCheck = body.indexOf("requireHumanApprover(c)");
      const mfaCheck = body.indexOf("hasRecentSessionMfa(c)");
      expect(approverCheck).toBeGreaterThanOrEqual(0);
      expect(mfaCheck).toBeGreaterThan(approverCheck);
    }
  });

  it("writes durable authorization audit events before sensitive mutations", () => {
    expectBefore('action: "approval.deny.authorized"', ".update(approvalQueue)");
    expectBefore('action: "approval_rule.update.authorized"', ".update(autoApprovalRules)");
    expectBefore('action: "approval_rule.create.authorized"', ".insert(autoApprovalRules)");
  });

  it("serializes rule upserts and commits each mutation with its completion audit", () => {
    const ruleBody = routeBody('approvalRoutes.put("/rules", async');
    const transactionStart = ruleBody.indexOf("withTenantAuditedTransaction(");
    const lockedRead = ruleBody.indexOf('.for("update")', transactionStart);
    const updateAuthorization = ruleBody.indexOf(
      'action: "approval_rule.update.authorized"',
      lockedRead,
    );
    const update = ruleBody.indexOf(".update(autoApprovalRules)", lockedRead);
    const updateAudit = ruleBody.indexOf('action: "approval_rule.update"', update);
    const createAuthorization = ruleBody.indexOf(
      'action: "approval_rule.create.authorized"',
      lockedRead,
    );
    const create = ruleBody.indexOf(".insert(autoApprovalRules)", lockedRead);
    const createAudit = ruleBody.indexOf('action: "approval_rule.create"', create);

    expect(transactionStart).toBeGreaterThanOrEqual(0);
    expect(lockedRead).toBeGreaterThan(transactionStart);
    expect(updateAuthorization).toBeGreaterThan(lockedRead);
    expect(update).toBeGreaterThan(updateAuthorization);
    expect(updateAudit).toBeGreaterThan(update);
    expect(createAuthorization).toBeGreaterThan(lockedRead);
    expect(create).toBeGreaterThan(createAuthorization);
    expect(createAudit).toBeGreaterThan(create);
    expect(ruleBody).toContain("return await tx.transaction");
    expect(ruleBody).toContain('return { kind: "failed" as const }');
    expect(ruleBody).toContain('mutation.kind === "failed"');
    expect(ruleBody).not.toContain("await db.delete(autoApprovalRules)");
    expect(ruleBody).not.toContain("maxAmountWei: existing.maxAmountWei");
  });

  it("does not let the generic approval route authorize vault-executable transactions", () => {
    const body = routeBody('approvalRoutes.post("/:txId/approve", async');
    expect(body).toContain(
      "Vault transaction approvals must be executed through POST /vault/:agentId/approve/:txId",
    );
    expect(body).not.toContain('status: "approved"');
    expect(body).not.toContain('set({ status: "approved" })');
    expect(body).not.toContain("intent.authorized");
  });

  it("updates denied approval, transaction status, and completion audit in one transaction", () => {
    // The queue+transaction rejection AND the completion `approval.deny` audit
    // event now commit in a single audited transaction (invariant I14). The
    // audit append lives INSIDE the transaction callback, before the return,
    // so state and evidence are both-or-neither.
    const denyBody = routeBody('approvalRoutes.post("/:txId/deny", async');
    expect(denyBody).toContain(
      "withTenantAuditedTransaction(tenantId, async (tx, appendRequiredAudit)",
    );
    expect(denyBody).toContain(".update(transactions)");
    expect(denyBody).toContain('status: "rejected"');
    // The completion audit is appended within the transaction, not after it.
    const txStart = denyBody.indexOf("withTenantAuditedTransaction(tenantId");
    const auditWithinTx = denyBody.indexOf('action: "approval.deny"', txStart);
    const txReturn = denyBody.indexOf("return updatedRows[0];", txStart);
    expect(auditWithinTx).toBeGreaterThan(txStart);
    expect(txReturn).toBeGreaterThan(auditWithinTx);
    // No post-commit best-effort audit + compensating rollback remains.
    expect(denyBody).not.toContain('.set({ status: "pending", resolvedAt: null');
  });

  it("does not resolve stale approval rows for terminal transactions", () => {
    for (const marker of [
      'approvalRoutes.post("/:txId/approve", async',
      'approvalRoutes.post("/:txId/deny", async',
    ]) {
      const body = routeBody(marker);
      expect(body).toContain("transactionStatus: transactions.status");
      expect(body).toContain('entry.transactionStatus !== "pending"');
      if (marker.includes("/deny")) {
        expect(body).toContain('eq(transactions.status, "pending")');
        // A concurrent resolution rolls back the WHOLE audited transaction via
        // the sentinel error, so the queue rejection cannot commit without the
        // transaction rejection (and its audit).
        expect(body).toContain("throw new ApprovalAlreadyResolvedError()");
        expect(body).toContain("instanceof ApprovalAlreadyResolvedError");
      }
    }
  });
});
