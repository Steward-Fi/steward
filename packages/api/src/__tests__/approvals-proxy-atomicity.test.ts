import { afterAll, beforeAll, beforeEach, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  auditEvents,
  closeDb,
  getDb,
  pendingProxyRequests,
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
// This suite drives the real route stack against a PGLite database whose
// transaction layer is instrumented to throw at the audit INSERT. It proves:
//   1. both-or-neither: when the required audit write faults, the state
//      transition is rolled back too;
//   2. retry-after-crash is idempotent: a second attempt with the fault cleared
//      applies the transition exactly once and writes exactly one audit row
//      (no double-apply, no duplicate audit);
//   3. the assertion detects a state transition that persists without its audit.
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

// ─── Audit-insert fault injection ────────────────────────────────────────────
//
// When `faultAuditInsert` is true, the FIRST audit-event INSERT executed inside
// any transaction throws. We render each executed SQL via the drizzle dialect
// and match `insert into audit_events`. This simulates the exact crash point:
// the state row was just updated in the same transaction, and the required
// audit append fails.

let faultAuditInsert = false;

/** Minimal structural view of a drizzle transaction handle for the fault hook. */
type TxLike = { execute: (query: unknown) => Promise<unknown> };

function isAuditInsert(dialect: unknown, query: unknown): boolean {
  try {
    const built = (dialect as { sqlToQuery: (q: unknown) => { sql?: string } }).sqlToQuery(query);
    const text = String(built?.sql ?? "").toLowerCase();
    return text.includes("insert into audit_events");
  } catch {
    return false;
  }
}

function installFaultInjectingDb(db: unknown): unknown {
  // Test-only structural view of the drizzle db so we can wrap `.transaction`.
  const anyDb = db as {
    dialect: unknown;
    transaction: (cb: (tx: TxLike) => Promise<unknown>, ...rest: unknown[]) => Promise<unknown>;
  };
  const dialect = anyDb.dialect;
  const originalTransaction = anyDb.transaction.bind(anyDb);

  anyDb.transaction = (cb: (tx: TxLike) => Promise<unknown>, ...rest: unknown[]) => {
    return originalTransaction(
      async (tx: TxLike) => {
        const originalExecute = tx.execute.bind(tx);
        tx.execute = async (query: unknown) => {
          if (faultAuditInsert && isAuditInsert(dialect, query)) {
            faultAuditInsert = false; // fault the first audit insert only
            throw new Error("injected audit fault");
          }
          return originalExecute(query);
        };
        return cb(tx);
      },
      ...rest,
    );
  };
  return db;
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
  installFaultInjectingDb(db);
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
  faultAuditInsert = false;
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

async function approveWithoutMfa(id: string) {
  const token = await ownerSession();
  return app.request(`/approvals/proxy/${id}/approve`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}

describe("proxy approval/audit atomicity (fault injection)", () => {
  it("approve: audit failure rolls back the state transition (both-or-neither)", async () => {
    const id = await seedPendingProxyRequest("pending");

    faultAuditInsert = true;
    const res = await approve(id);
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

    faultAuditInsert = true;
    await approve(id); // faults + rolls back
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

    faultAuditInsert = true;
    const res = await deny(id);
    expect(res.status).toBeGreaterThanOrEqual(500);

    const row = await fetchProxyRequest(id);
    expect(row.status).toBe("pending");
    expect((await auditRowsFor("proxy.approval.denied", id)).length).toBe(0);
  });

  it("deny: retry after the fault clears applies the transition exactly once", async () => {
    const id = await seedPendingProxyRequest("pending");

    faultAuditInsert = true;
    await deny(id);
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
    expect(res.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(res.headers.get("Pragma")).toBe("no-cache");
    expect(res.headers.get("Expires")).toBe("0");
  });

  it("rejects a human approver session without recent MFA before mutation", async () => {
    const id = await seedPendingProxyRequest("pending");
    const res = await approveWithoutMfa(id);

    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });
    expect((await fetchProxyRequest(id)).status).toBe("pending");
    expect((await auditRowsFor("proxy.approval.approved", id)).length).toBe(0);
  });
});
