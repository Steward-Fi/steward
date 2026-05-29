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
    expectBefore(
      'action: "approval.deny.authorized"',
      '.update(approvalQueue)',
    );
    expectBefore('action: "approval_rule.update.authorized"', ".update(autoApprovalRules)");
    expectBefore('action: "approval_rule.create.authorized"', ".insert(autoApprovalRules)");
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

  it("updates denied approval and transaction status in the same transaction", () => {
    expect(routeSource).toContain("const [updated] = await db");
    expect(routeSource).toContain(".transaction(async (tx) => {");
    expect(routeSource).toContain(".update(transactions)");
    expect(routeSource).toContain('status: "rejected"');
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
        expect(body).toContain("Approval transaction already resolved");
      }
    }
  });
});
