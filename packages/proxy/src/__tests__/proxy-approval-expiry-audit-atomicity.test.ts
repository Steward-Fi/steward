import { afterAll, afterEach, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  and,
  auditEvents,
  closeDb,
  eq,
  getDb,
  pendingProxyRequests,
  proxyAuditLog,
  sql,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

// Fault-injection proof for proxy-side APPROVAL-EXPIRY audit ATOMICITY.
//
// The round-1 review flagged that the proxy release handler's two expiry paths
// (poll-time pending|approved -> expired, and claim-time approved -> expired)
// flipped the row to `expired` in a bare UPDATE and then wrote ONLY a
// `proxy_audit_log` operational row via `recordRequiredAudit`. That is NOT the
// tamper-evident `audit_events` chain, so a proxy-side expiry left NO chain
// evidence and the state change + its required record were not both-or-neither
// (invariant I14, spec section 11 item #10).
//
// The fix makes both paths call `expireProxyApprovalWithAudit`, which uses the
// shared `@stwd/db` `withTenantAuditedTransaction` primitive to commit the
// `expired` transition AND a `proxy.approval.expired` chain event in ONE
// transaction. This suite drives the real release handler against a PGLite DB
// whose transaction layer is instrumented to throw at the audit-chain INSERT and
// proves:
//   1. audit-chain event present on the happy path (both poll-time & claim-time);
//   2. both-or-neither: when the chain INSERT faults, the `expired` transition
//      rolls back too (I14) and no chain event exists;
//   3. mutation proof (revert): if the transition is not wrapped with the chain
//      append, the fault would leave `expired` with no chain event — asserted by
//      the both-or-neither test failing under a revert of the fix.
//
// Under test: packages/proxy/src/handlers/release.ts
//   - handlePendingProxyRequest (poll-time JS expiry branch)
//   - handlePendingProxyRequest (claim-time SQL expiry branch, via barrier)

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-expiry-audit-master-password";

let signAgentToken: typeof import("@stwd/auth")["signAgentToken"];
let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handlePendingProxyRequest: typeof import("../handlers/release")["handlePendingProxyRequest"];
let holdProxyApprovalRequest: typeof import("../handlers/approvals")["holdProxyApprovalRequest"];
let setReleaseClaimBarrier: typeof import("../handlers/release")["__setReleaseClaimBarrierForTests"];
let resetReleaseClaimBarrier: typeof import("../handlers/release")["__resetReleaseClaimBarrierForTests"];
let setForwardProxyRequest: typeof import("../handlers/proxy")["__setForwardProxyRequestForTests"];
let proxyMod: typeof import("../handlers/proxy");

// ─── Audit-chain-insert fault injection ───────────────────────────────────────
//
// A real database trigger rejects the targeted audit-chain INSERT. This
// simulates the exact crash point after the row is flipped to `expired` in the
// same transaction, without depending on Drizzle's internal execution methods.

const AUDIT_FAULT_TRIGGER = "proxy_expiry_audit_failure";
const AUDIT_FAULT_FUNCTION = "fail_proxy_expiry_audit";

async function installAuditInsertFault(): Promise<void> {
  await getDb().execute(
    sql.raw(`
      CREATE OR REPLACE FUNCTION ${AUDIT_FAULT_FUNCTION}()
      RETURNS trigger AS $$
      BEGIN
        IF NEW.action = 'proxy.approval.expired' THEN
          RAISE EXCEPTION 'injected audit-chain fault';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `),
  );
  await getDb().execute(
    sql.raw(`
      CREATE TRIGGER ${AUDIT_FAULT_TRIGGER}
      BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION ${AUDIT_FAULT_FUNCTION}()
    `),
  );
}

async function removeAuditInsertFault(): Promise<void> {
  await getDb().execute(sql.raw(`DROP TRIGGER IF EXISTS ${AUDIT_FAULT_TRIGGER} ON audit_events`));
  await getDb().execute(sql.raw(`DROP FUNCTION IF EXISTS ${AUDIT_FAULT_FUNCTION}()`));
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-expiry-audit-jwt-secret-with-enough-bytes-here";
  process.env.STEWARD_AUDIT_HMAC_KEY = "proxy-expiry-audit-hmac-key-with-enough-entropy-x";
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.example.com";
  process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS = "api.example.com";
  process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = "true";
  process.env.NODE_ENV = "test";
  process.env.STEWARD_PROXY_DEV_MODE = "true";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ signAgentToken } = await import("@stwd/auth"));
  ({ authMiddleware } = await import("../middleware/auth"));
  ({
    handlePendingProxyRequest,
    __setReleaseClaimBarrierForTests: setReleaseClaimBarrier,
    __resetReleaseClaimBarrierForTests: resetReleaseClaimBarrier,
  } = await import("../handlers/release"));
  ({ holdProxyApprovalRequest } = await import("../handlers/approvals"));
  proxyMod = await import("../handlers/proxy");
  ({ __setForwardProxyRequestForTests: setForwardProxyRequest } = proxyMod);
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  proxyMod.__setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
});

afterEach(() => {
  resetReleaseClaimBarrier();
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
  delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
  delete process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS;
  delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
  delete process.env.NODE_ENV;
  delete process.env.STEWARD_PROXY_DEV_MODE;
});

function buildApp() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.get("/approvals/proxy/:id", handlePendingProxyRequest);
  return app;
}

async function ensureTenant(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
}

async function ensureAgent(tenantId: string, agentId: string) {
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"1".repeat(40)}` })
    .onConflictDoNothing();
}

async function ensureApprovalRoute(tenantId: string, agentId: string): Promise<string> {
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "example", "sk-live-upstream");
  const route = await vault.createRoute(tenantId, secret.id, {
    agentId,
    hostPattern: "api.example.com",
    pathPattern: "/*",
    method: "*",
    injectAs: "header",
    injectKey: "authorization",
    injectFormat: "Bearer {value}",
    requiresApproval: true,
  });
  return route.id;
}

async function holdRequest(tenantId: string, agentId: string) {
  const request = new Request("https://steward-proxy.local/proxy/api.example.com/v1/charges", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  });
  return holdProxyApprovalRequest({
    tenantId,
    agentId,
    route: { id: await ensureApprovalRoute(tenantId, agentId), approvalConfig: {} } as never,
    method: "POST",
    targetHost: "api.example.com",
    targetPath: "/v1/charges",
    request,
  });
}

async function tokenFor(agentId: string, tenantId: string): Promise<string> {
  return signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
}

async function poll(id: string, token: string): Promise<Response> {
  return buildApp().request(`/approvals/proxy/${id}`, {
    headers: { authorization: `Bearer ${token}` },
  });
}

async function pollWithAuditInsertFault(id: string, token: string): Promise<Response> {
  await installAuditInsertFault();
  try {
    return await poll(id, token);
  } finally {
    await removeAuditInsertFault();
  }
}

async function fetchRow(id: string) {
  const [row] = await getDb()
    .select()
    .from(pendingProxyRequests)
    .where(eq(pendingProxyRequests.id, id))
    .limit(1);
  return row;
}

async function expiredChainEvents(tenantId: string, resourceId: string) {
  return getDb()
    .select({ action: auditEvents.action, actorType: auditEvents.actorType })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.tenantId, tenantId),
        eq(auditEvents.action, "proxy.approval.expired"),
        eq(auditEvents.resourceId, resourceId),
      ),
    );
}

async function expiredOperationalLogs(tenantId: string) {
  return getDb()
    .select()
    .from(proxyAuditLog)
    .where(
      and(eq(proxyAuditLog.tenantId, tenantId), eq(proxyAuditLog.reason, "proxy-approval-expired")),
    );
}

function installCountedForwarder() {
  setForwardProxyRequest(async () => {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
}

describe("proxy approval-expiry audit atomicity (fault injection)", () => {
  it("poll-time expiry writes the tamper-evident audit_events chain event (happy path)", async () => {
    const tenantId = `t-pollexp-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Pending + already past deadline -> the poll-time JS expiry branch fires.
    await getDb()
      .update(pendingProxyRequests)
      .set({ expiresAt: new Date(Date.now() - 60_000), updatedAt: new Date() })
      .where(eq(pendingProxyRequests.id, held.id));

    const res = await poll(held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { status: string } };
    expect(body.data.status).toBe("expired");

    expect((await fetchRow(held.id)).status).toBe("expired");
    // The tamper-evident chain event exists...
    const chain = await expiredChainEvents(tenantId, held.id);
    expect(chain).toHaveLength(1);
    expect(chain[0]?.actorType).toBe("system");
    // ...and the operational proxy_audit_log breadcrumb is still written too.
    expect((await expiredOperationalLogs(tenantId)).length).toBeGreaterThan(0);
  });

  it("poll-time expiry: audit-chain fault rolls back the expired transition (both-or-neither)", async () => {
    const tenantId = `t-pollexp-fault-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    await getDb()
      .update(pendingProxyRequests)
      .set({ expiresAt: new Date(Date.now() - 60_000), updatedAt: new Date() })
      .where(eq(pendingProxyRequests.id, held.id));

    const res = await pollWithAuditInsertFault(held.id, await tokenFor(agentId, tenantId));
    // The injected fault propagates out of the release handler as a 5xx.
    expect(res.status).toBeGreaterThanOrEqual(500);

    // ATOMICITY: because the chain append faulted inside the same transaction,
    // the pending -> expired transition MUST have rolled back. Reverting the fix
    // (bare UPDATE + separate proxy_audit_log write) makes this fail: the row
    // would be `expired` with NO chain event.
    expect((await fetchRow(held.id)).status).toBe("pending");
    expect(await expiredChainEvents(tenantId, held.id)).toHaveLength(0);
  });

  it("claim-time expiry writes the audit_events chain event (happy path, TOCTOU barrier)", async () => {
    const tenantId = `t-claimexp-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Approve with an UNEXPIRED deadline so the poll-time branch does NOT fire;
    // only the SQL claim-time guard can catch it.
    await getDb()
      .update(pendingProxyRequests)
      .set({
        status: "approved",
        approvedAt: new Date(),
        approvedBy: "operator",
        expiresAt: new Date(Date.now() + 60_000),
      })
      .where(eq(pendingProxyRequests.id, held.id));

    // Move the deadline into the past AFTER read+digest, BEFORE the atomic claim.
    setReleaseClaimBarrier(async (row) => {
      await getDb()
        .update(pendingProxyRequests)
        .set({ expiresAt: new Date(Date.now() - 60_000), updatedAt: new Date() })
        .where(eq(pendingProxyRequests.id, row.id));
    });
    installCountedForwarder();

    const res = await poll(held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { status: string } };
    expect(body.data.status).toBe("expired");

    expect((await fetchRow(held.id)).status).toBe("expired");
    const chain = await expiredChainEvents(tenantId, held.id);
    expect(chain).toHaveLength(1);
    expect(chain[0]?.actorType).toBe("system");
    expect((await expiredOperationalLogs(tenantId)).length).toBeGreaterThan(0);
  });

  it("claim-time expiry: audit-chain fault rolls back the expired transition (both-or-neither)", async () => {
    const tenantId = `t-claimexp-fault-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    await getDb()
      .update(pendingProxyRequests)
      .set({
        status: "approved",
        approvedAt: new Date(),
        approvedBy: "operator",
        expiresAt: new Date(Date.now() + 60_000),
      })
      .where(eq(pendingProxyRequests.id, held.id));

    setReleaseClaimBarrier(async (row) => {
      await getDb()
        .update(pendingProxyRequests)
        .set({ expiresAt: new Date(Date.now() - 60_000), updatedAt: new Date() })
        .where(eq(pendingProxyRequests.id, row.id));
    });
    installCountedForwarder();

    const res = await pollWithAuditInsertFault(held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBeGreaterThanOrEqual(500);

    // ATOMICITY: the approved -> expired transition rolls back with the faulted
    // chain append. The row stays `approved` (deadline in the past, but never
    // transitioned) and no chain event was written.
    expect((await fetchRow(held.id)).status).toBe("approved");
    expect(await expiredChainEvents(tenantId, held.id)).toHaveLength(0);
  });
});
