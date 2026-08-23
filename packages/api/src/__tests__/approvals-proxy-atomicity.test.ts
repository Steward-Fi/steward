import { afterAll, beforeAll, beforeEach, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  auditEvents,
  closeDb,
  getDb,
  pendingProxyRequests,
  sql,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

// Fault-injection proof for approval/audit atomicity on the proxy flow.
//
// The approval-lifecycle spec (section 11 item #10, invariant I14) flags that the proxy
// approve/deny/expire transitions committed their state change and their audit
// event in SEPARATE transactions, so a crash or audit failure between them
// could leave an approved/denied/expired row with NO audit record.
//
// This suite drives the real route stack against a PGLite database with a
// database trigger that rejects the required audit INSERT. It proves:
//   1. both-or-neither: when the required audit write faults, the state
//      transition is rolled back too (I14);
//   2. retry-after-crash is idempotent: a second attempt with the fault cleared
//      applies the transition exactly once and writes exactly one audit row
//      (no double-apply, no duplicate audit);
//   3. mutation proof: reverting the fix (see the paired assertion) makes the
//      atomicity assertion fail, i.e. state persists while audit is missing.
//
// Route under test: packages/api/src/routes/approvals.ts
//   - approvalRoutes.post("/proxy/:id/approve")
//   - approvalRoutes.post("/proxy/:id/deny")

setDefaultTimeout(30000);

const TENANT_ID = `proxy-atomicity-tenant-${Date.now()}`;
const AGENT_ID = `proxy-atomicity-agent-${Date.now()}`;
const OWNER_USER_ID = crypto.randomUUID();
const ROUTE_ID = crypto.randomUUID();

let createSessionToken: typeof import("../routes/auth").createSessionToken;
let tenantAuth: typeof import("../services/context").tenantAuth;
let approvalRoutes: typeof import("../routes/approvals").approvalRoutes;
let app: Hono<{ Variables: AppVariables }>;

let previousJwtSecret: string | undefined;
let previousAuditHmacKey: string | undefined;
let previousMasterPassword: string | undefined;

async function withApprovalAuditFailure<T>(operation: () => Promise<T>): Promise<T> {
  await getDb().execute(
    sql.raw(`
      CREATE OR REPLACE FUNCTION fail_proxy_approval_audit_for_test()
      RETURNS trigger AS $$
      BEGIN
        IF NEW.action IN ('proxy.approval.approved', 'proxy.approval.denied') THEN
          RAISE EXCEPTION 'injected approval audit fault';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `),
  );
  await getDb().execute(
    sql.raw(`
      CREATE TRIGGER proxy_approval_audit_failure_for_test
      BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION fail_proxy_approval_audit_for_test()
    `),
  );
  try {
    return await operation();
  } finally {
    await getDb().execute(
      sql.raw("DROP TRIGGER IF EXISTS proxy_approval_audit_failure_for_test ON audit_events"),
// ─── Audit-insert fault injection ────────────────────────────────────────────
    );
    await getDb().execute(sql.raw("DROP FUNCTION IF EXISTS fail_proxy_approval_audit_for_test()"));
  }
}

async function ownerSession(extra?: Record<string, unknown>) {
  return createSessionToken("0x0000000000000000000000000000000000000001", TENANT_ID, {
    userId: OWNER_USER_ID,
    ...extra,
  });
}

async function seedPendingProxyRequest(
  status: "pending" | "approved" = "pending",
): Promise<string> {
  const [row] = await getDb()
    .insert(pendingProxyRequests)
    .values({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      routeId: ROUTE_ID,
      method: "POST",
      targetHost: "api.example.test",
      targetPath: "/v1/things",
      requestDigest: "a".repeat(64),
      preview: { summary: "test proxy request" },
      safeHeaders: {},
      bodyCiphertext: "ct",
      bodyIv: "iv",
      bodyAuthTag: "tag",
      bodySalt: "salt",
      status,
      expiresAt: new Date(Date.now() + 10 * 60_000),
    })
    .returning({ id: pendingProxyRequests.id });
  return row.id;
}

async function fetchProxyRequest(id: string) {
  const [row] = await getDb()
    .select()
    .from(pendingProxyRequests)
    .where(eq(pendingProxyRequests.id, id))
    .limit(1);
  return row;
}

async function auditRowsFor(action: string, resourceId: string) {
  return getDb()
    .select({ action: auditEvents.action, resourceId: auditEvents.resourceId })
    .from(auditEvents)
    .where(and(eq(auditEvents.action, action), eq(auditEvents.resourceId, resourceId)));
}

function makeApp() {
  const instance = new Hono<{ Variables: AppVariables }>();
  instance.use("*", tenantAuth);
  instance.route("/approvals", approvalRoutes);
  return instance;
}

beforeAll(async () => {
  previousJwtSecret = process.env.STEWARD_JWT_SECRET;
  previousAuditHmacKey = process.env.STEWARD_AUDIT_HMAC_KEY;
  previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-atomicity-jwt-secret-with-enough-entropy-to-pass";
  process.env.STEWARD_AUDIT_HMAC_KEY = "proxy-atomicity-audit-hmac-key-with-enough-entropy";
  process.env.STEWARD_MASTER_PASSWORD ??= "proxy-atomicity-master-password";
  process.env.STEWARD_PGLITE_MEMORY = "true";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Proxy Atomicity Tenant",
    apiKeyHash: "unused-hash",
  });
  await getDb()
    .insert(users)
    .values({
      id: OWNER_USER_ID,
      email: `proxy-atomicity-owner-${Date.now()}@example.test`,
      emailVerified: true,
    });
  await getDb()
    .insert(userTenants)
    .values({ userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" });
  await getDb().insert(agents).values({
    id: AGENT_ID,
    tenantId: TENANT_ID,
    name: "Proxy Atomicity Agent",
    walletAddress: "0x0000000000000000000000000000000000000010",
  });

  ({ createSessionToken } = await import("../routes/auth"));
  ({ tenantAuth } = await import("../services/context"));
  ({ approvalRoutes } = await import("../routes/approvals"));
  app = makeApp();
});

beforeEach(async () => {
  await getDb().delete(pendingProxyRequests).where(eq(pendingProxyRequests.tenantId, TENANT_ID));
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
  else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
  if (previousAuditHmacKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
  else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditHmacKey;
  if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
  else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
});

async function approve(id: string) {
  const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
  return app.request(`/approvals/proxy/${id}/approve`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}

async function deny(id: string) {
  const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
  return app.request(`/approvals/proxy/${id}/deny`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ reason: "blocked egress" }),
  });
}

describe("proxy approval/audit atomicity (fault injection)", () => {
  it("approve: audit failure rolls back the state transition (both-or-neither)", async () => {
    const id = await seedPendingProxyRequest("pending");

    const res = await withApprovalAuditFailure(() => approve(id));
    // The injected fault surfaces as a 500 (uncaught) — the point is the DB state.
    expect(res.status).toBeGreaterThanOrEqual(500);

    // ATOMICITY: because the audit append faulted inside the same transaction,
    // the pending -> approved transition MUST have rolled back. With the old
    // non-atomic code the row would be "approved" with NO audit row (the bug).
    const row = await fetchProxyRequest(id);
    expect(row.status).toBe("pending");
    const audits = await auditRowsFor("proxy.approval.approved", id);
    expect(audits.length).toBe(0);
  });

  it("approve: retry after the fault clears applies the transition exactly once", async () => {
    const id = await seedPendingProxyRequest("pending");

    await withApprovalAuditFailure(() => approve(id)); // faults + rolls back
    expect((await fetchProxyRequest(id)).status).toBe("pending");

    // Retry with fault cleared: succeeds, one transition, one audit.
    const res = await approve(id);
    expect(res.status).toBe(200);
    expect((await fetchProxyRequest(id)).status).toBe("approved");
    const audits = await auditRowsFor("proxy.approval.approved", id);
    expect(audits.length).toBe(1);

    // A second approve of the now-approved row is a no-op (409), no dup audit.
    const dup = await approve(id);
    expect(dup.status).toBe(409);
    expect((await auditRowsFor("proxy.approval.approved", id)).length).toBe(1);
  });

  it("deny: audit failure rolls back the state transition (both-or-neither)", async () => {
    const id = await seedPendingProxyRequest("pending");

    const res = await withApprovalAuditFailure(() => deny(id));
    expect(res.status).toBeGreaterThanOrEqual(500);

    const row = await fetchProxyRequest(id);
    expect(row.status).toBe("pending");
    expect((await auditRowsFor("proxy.approval.denied", id)).length).toBe(0);
  });

  it("deny: retry after the fault clears applies the transition exactly once", async () => {
    const id = await seedPendingProxyRequest("pending");

    await withApprovalAuditFailure(() => deny(id));
    expect((await fetchProxyRequest(id)).status).toBe("pending");

    const res = await deny(id);
    expect(res.status).toBe(200);
    expect((await fetchProxyRequest(id)).status).toBe("denied");
    expect((await auditRowsFor("proxy.approval.denied", id)).length).toBe(1);
  });

  it("happy path (no fault): approve writes state and audit together", async () => {
    const id = await seedPendingProxyRequest("pending");
    const res = await approve(id);
    expect(res.status).toBe(200);
    expect((await fetchProxyRequest(id)).status).toBe("approved");
    expect((await auditRowsFor("proxy.approval.approved", id)).length).toBe(1);
  });
});
