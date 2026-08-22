import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  approvalQueue,
  auditEvents,
  autoApprovalRules,
  closeDb,
  getDb,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

mock.module("../services/webhook-dispatch", () => ({ dispatchWebhook: () => undefined }));

const TENANT_ID = "approval-mounted-audit";
const AGENT_ID = "approval-mounted-agent";
const USER_ID = "11111111-1111-4111-8111-111111111737";
const TX_ID = "approval-mounted-transaction";
const APPROVAL_ID = "approval-mounted-entry";

let app: Hono<{ Variables: AppVariables }>;

function principal(path: string) {
  const value = new URL(path, "http://localhost").searchParams.get("principal");
  return value ?? "fresh";
}

function assertNoStore(response: Response) {
  expect(response.headers.get("cache-control")).toBe("no-store, max-age=0");
  expect(response.headers.get("pragma")).toBe("no-cache");
  expect(response.headers.get("expires")).toBe("0");
}

async function seedPending(txId = TX_ID, approvalId = APPROVAL_ID) {
  await getDb().insert(transactions).values({
    id: txId,
    agentId: AGENT_ID,
    status: "pending",
    toAddress: "0x0000000000000000000000000000000000000001",
    value: "1",
    chainId: 8453,
  });
  await getDb().insert(approvalQueue).values({
    id: approvalId,
    txId,
    agentId: AGENT_ID,
    status: "pending",
  });
}

async function request(
  path: string,
  init: RequestInit = {},
  selectedPrincipal = "fresh",
): Promise<Response> {
  const separator = path.includes("?") ? "&" : "?";
  const response = await app.request(`${path}${separator}principal=${selectedPrincipal}`, {
    ...init,
    headers: { "content-type": "application/json", ...init.headers },
  });
  assertNoStore(response);
  return response;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "approval-mounted-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "approval-mounted-audit-hmac-key-with-enough-entropy";
  __resetAuditHmacKeyCacheForTests();
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb().insert(tenants).values({ id: TENANT_ID, name: TENANT_ID, apiKeyHash: "hash" });
  await getDb().insert(agents).values({
    id: AGENT_ID,
    tenantId: TENANT_ID,
    name: AGENT_ID,
    walletAddress: "0x0000000000000000000000000000000000000737",
  });

  const { approvalRoutes } = await import("../routes/approvals");
  app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    const selected = principal(c.req.url);
    if (selected === "api-key") c.set("authType", "api-key");
    else if (selected === "agent") {
      c.set("authType", "agent-token");
      c.set("agentScope", AGENT_ID);
    } else {
      c.set("authType", "session-jwt");
      c.set("userId", USER_ID);
      c.set("tenantRole", selected === "member" ? "member" : "owner");
      c.set("sessionMfaVerifiedAt", selected === "stale" ? Date.now() - 10 * 60_000 : Date.now());
    }
    await next();
  });
  app.route("/approvals", approvalRoutes);
  app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
});

beforeEach(async () => {
  await getDb().delete(approvalQueue).where(eq(approvalQueue.agentId, AGENT_ID));
  await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  await getDb().delete(autoApprovalRules).where(eq(autoApprovalRules.tenantId, TENANT_ID));
  await seedPending();
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
  __resetAuditHmacKeyCacheForTests();
});

describe("mounted generic approval boundary", () => {
  it("rejects non-human and stale-MFA principals across reads and writes", async () => {
    const operations: Array<[string, RequestInit]> = [
      ["/approvals", {}],
      ["/approvals/stats", {}],
      ["/approvals/rules", {}],
      [`/approvals/${TX_ID}/approve`, { method: "POST", body: "{}" }],
      [`/approvals/${TX_ID}/deny`, { method: "POST", body: JSON.stringify({ reason: "blocked" }) }],
      [
        "/approvals/rules",
        { method: "PUT", body: JSON.stringify({ maxAmountWei: "10", enabled: true }) },
      ],
    ];
    for (const selected of ["api-key", "agent", "member", "stale"]) {
      for (const [path, init] of operations) {
        const response = await request(path, init, selected);
        expect(response.status, `${selected} ${path}`).toBe(403);
      }
    }
  });

  it("serves list, stats, rules, and rule mutations to a fresh human approver", async () => {
    for (const path of ["/approvals", "/approvals/stats", "/approvals/rules"]) {
      const response = await request(path);
      expect(response.status, path).toBe(200);
    }
    const created = await request("/approvals/rules", {
      method: "PUT",
      body: JSON.stringify({ maxAmountWei: "10", autoDenyAfterHours: 2, enabled: true }),
    });
    expect(created.status).toBe(201);
    const updated = await request("/approvals/rules", {
      method: "PUT",
      body: JSON.stringify({ maxAmountWei: "20" }),
    });
    expect(updated.status).toBe(200);
    const [stored] = await getDb()
      .select()
      .from(autoApprovalRules)
      .where(eq(autoApprovalRules.tenantId, TENANT_ID));
    expect(stored?.maxAmountWei).toBe("20");
  });

  it("refuses generic approval of a Vault transaction without mutating state or audit", async () => {
    const beforeAudits = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));
    const response = await request(`/approvals/${TX_ID}/approve`, {
      method: "POST",
      body: JSON.stringify({ comment: "approve" }),
    });
    expect(response.status).toBe(409);
    expect((await response.json()) as { error: string }).toMatchObject({
      error: expect.stringContaining("/vault/:agentId/approve/:txId"),
    });
    const [queue] = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.id, APPROVAL_ID));
    const [transaction] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, TX_ID));
    expect(queue?.status).toBe("pending");
    expect(transaction?.status).toBe("pending");
    const afterAudits = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));
    expect(afterAudits).toEqual(beforeAudits);
  });

  it("rolls back queue and transaction denial when the required completion audit fails", async () => {
    await getDb().execute(sql`
      CREATE FUNCTION reject_approval_deny_completion() RETURNS trigger AS $$
      BEGIN
        IF NEW.action = 'approval.deny' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `);
    await getDb().execute(sql`
      CREATE TRIGGER reject_approval_deny_completion BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_approval_deny_completion()
    `);
    try {
      const response = await request(`/approvals/${TX_ID}/deny`, {
        method: "POST",
        body: JSON.stringify({ reason: "policy denied" }),
      });
      expect(response.status).toBe(500);
      const [queue] = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.id, APPROVAL_ID));
      const [transaction] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, TX_ID));
      expect(queue?.status).toBe("pending");
      expect(transaction?.status).toBe("pending");
      const completion = await getDb()
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "approval.deny")));
      expect(completion).toHaveLength(0);
    } finally {
      await getDb().execute(sql`DROP TRIGGER reject_approval_deny_completion ON audit_events`);
      await getDb().execute(sql`DROP FUNCTION reject_approval_deny_completion()`);
    }
  });

  it("keeps stale terminal transactions and their queue rows unchanged", async () => {
    await getDb()
      .update(transactions)
      .set({ status: "rejected" })
      .where(eq(transactions.id, TX_ID));
    const response = await request(`/approvals/${TX_ID}/deny`, {
      method: "POST",
      body: JSON.stringify({ reason: "too late" }),
    });
    expect(response.status).toBe(409);
    const [queue] = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.id, APPROVAL_ID));
    expect(queue?.status).toBe("pending");
  });

  it("atomically denies a pending transaction with exactly one completion audit", async () => {
    const response = await request(`/approvals/${TX_ID}/deny`, {
      method: "POST",
      body: JSON.stringify({ reason: "operator denied" }),
    });
    expect(response.status).toBe(200);
    const [queue] = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.id, APPROVAL_ID));
    const [transaction] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, TX_ID));
    expect(queue?.status).toBe("rejected");
    expect(transaction?.status).toBe("rejected");
    const completion = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "approval.deny")));
    expect(completion).toHaveLength(1);
  });
});
