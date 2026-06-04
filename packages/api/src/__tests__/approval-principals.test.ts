import { afterAll, beforeAll, describe, expect, it } from "bun:test";

const SKIP = !process.env.DATABASE_URL;

import { signAccessToken } from "@stwd/auth";
import {
  agents,
  approvalQueue,
  getDb,
  policies,
  runMigrations,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";

const unique = crypto.randomUUID();
const TEST_TENANT = `test-4eyes-${unique}`;
const TEST_AGENT = `test-4eyes-agent-${unique}`;
const REQUESTER_USER_ID = crypto.randomUUID();
const APPROVER_USER_ID = crypto.randomUUID();
const POLICY_ID = `test-4eyes-policy-${unique}`;

let app: { request: (input: string | Request, init?: RequestInit) => Promise<Response> };
let requesterToken: string;
let approverToken: string;
let queuedTxId: string;

beforeAll(async () => {
  if (SKIP) return;

  await runMigrations();

  process.env.STEWARD_MASTER_PASSWORD ||= "test-master-password-for-4eyes";

  const [{ Hono }, { tenantAuth }, { approvalRoutes }, { vaultRoutes }] = await Promise.all([
    import("hono"),
    import("../services/context"),
    import("../routes/approvals"),
    import("../routes/vault"),
  ]);
  const testApp = new Hono();
  testApp.use("/vault/*", (c, next) => tenantAuth(c, next));
  testApp.use("/approvals", (c, next) => tenantAuth(c, next));
  testApp.use("/approvals/*", (c, next) => tenantAuth(c, next));
  testApp.route("/vault", vaultRoutes);
  testApp.route("/approvals", approvalRoutes);
  app = testApp;

  const db = getDb();

  await db.insert(tenants).values({
    id: TEST_TENANT,
    name: "4-eyes Test Tenant",
    apiKeyHash: `unused-${unique}`,
  });

  await db.insert(users).values([
    {
      id: REQUESTER_USER_ID,
      email: `requester-${unique}@example.com`,
      walletAddress: "0x0000000000000000000000000000000000000001",
    },
    {
      id: APPROVER_USER_ID,
      email: `approver-${unique}@example.com`,
      walletAddress: "0x0000000000000000000000000000000000000002",
    },
  ]);

  await db.insert(userTenants).values([
    { userId: REQUESTER_USER_ID, tenantId: TEST_TENANT, role: "admin" },
    { userId: APPROVER_USER_ID, tenantId: TEST_TENANT, role: "admin" },
  ]);

  await db.insert(agents).values({
    id: TEST_AGENT,
    tenantId: TEST_TENANT,
    name: "4-eyes Test Agent",
    walletAddress: "0x1234567890123456789012345678901234567890",
  });

  await db.insert(policies).values({
    id: POLICY_ID,
    agentId: TEST_AGENT,
    type: "auto-approve-threshold",
    enabled: true,
    config: { threshold: "0" },
  });

  requesterToken = await signAccessToken({
    address: "0x0000000000000000000000000000000000000001",
    tenantId: TEST_TENANT,
    userId: REQUESTER_USER_ID,
  });
  approverToken = await signAccessToken({
    address: "0x0000000000000000000000000000000000000002",
    tenantId: TEST_TENANT,
    userId: APPROVER_USER_ID,
  });
});

afterAll(async () => {
  if (SKIP) return;

  const db = getDb();
  await db.delete(approvalQueue).where(eq(approvalQueue.agentId, TEST_AGENT));
  await db.delete(transactions).where(eq(transactions.agentId, TEST_AGENT));
  await db.delete(policies).where(eq(policies.agentId, TEST_AGENT));
  await db.delete(agents).where(eq(agents.id, TEST_AGENT));
  await db.delete(userTenants).where(eq(userTenants.tenantId, TEST_TENANT));
  await db.delete(users).where(inArray(users.id, [REQUESTER_USER_ID, APPROVER_USER_ID]));
  await db.delete(tenants).where(eq(tenants.id, TEST_TENANT));
});

function bearer(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

describe.skipIf(SKIP)("approval principal tracking and 4-eyes enforcement", () => {
  it("records the authenticated requester when approval is queued", async () => {
    const res = await app.request(`/vault/${TEST_AGENT}/sign`, {
      method: "POST",
      headers: bearer(requesterToken),
      body: JSON.stringify({
        to: "0x0000000000000000000000000000000000000003",
        value: "1",
        chainId: 84532,
      }),
    });

    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.data.status).toBe("pending_approval");
    queuedTxId = body.data.txId;

    const db = getDb();
    const [approval] = await db
      .select()
      .from(approvalQueue)
      .where(and(eq(approvalQueue.txId, queuedTxId), eq(approvalQueue.agentId, TEST_AGENT)));

    expect(approval.requestedByType).toBe("user");
    expect(approval.requestedById).toBe(REQUESTER_USER_ID);
  });

  it("rejects approval by the same authenticated principal", async () => {
    const res = await app.request(`/approvals/${queuedTxId}/approve`, {
      method: "POST",
      headers: bearer(requesterToken),
      body: JSON.stringify({ approvedBy: APPROVER_USER_ID }),
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("separation of duties");
  });

  it("allows a different authenticated principal and ignores body-supplied approvedBy", async () => {
    const res = await app.request(`/approvals/${queuedTxId}/approve`, {
      method: "POST",
      headers: bearer(approverToken),
      body: JSON.stringify({ approvedBy: "spoofed-approver", comment: "approved" }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.data.status).toBe("approved");
    expect(body.data.resolvedByType).toBe("user");
    expect(body.data.resolvedById).toBe(APPROVER_USER_ID);
    expect(body.data.resolvedBy).toBe(`user:${APPROVER_USER_ID}`);
    expect(body.data.resolvedBy).not.toBe("spoofed-approver");

    const db = getDb();
    const [approval] = await db
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.txId, queuedTxId));

    expect(approval.resolvedByType).toBe("user");
    expect(approval.resolvedById).toBe(APPROVER_USER_ID);
    expect(approval.resolvedBy).toBe(`user:${APPROVER_USER_ID}`);
  });
});
