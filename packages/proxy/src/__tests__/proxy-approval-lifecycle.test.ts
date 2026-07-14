import { afterAll, afterEach, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import {
  agents,
  and,
  closeDb,
  eq,
  getDb,
  inArray,
  pendingProxyRequests,
  proxyAuditLog,
  sql,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-approval-lifecycle-master";
// A recognizable credential string we assert never appears in stored rows or
// audit events, regardless of the JSON key it is hidden under.
const CREDENTIAL = "sk-live-LIFECYCLE-SUPER-SECRET-DEADBEEF";

let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handlePendingProxyRequest: typeof import("../handlers/release")["handlePendingProxyRequest"];
let holdProxyApprovalRequest: typeof import("../handlers/approvals")["holdProxyApprovalRequest"];
let setReleaseClaimBarrier: typeof import("../handlers/release")["__setReleaseClaimBarrierForTests"];
let resetReleaseClaimBarrier: typeof import("../handlers/release")["__resetReleaseClaimBarrierForTests"];
let setForwardProxyRequest: typeof import("../handlers/proxy")["__setForwardProxyRequestForTests"];
let proxyMod: typeof import("../handlers/proxy");

// A counted, successful stub upstream. Tests that must prove whether (and how
// many times) execution actually reached the wire install this and read
// `executions`. It returns a clean JSON body that never reflects the injected
// credential, so the proxy's credential-reflection response guards pass.
let executions = 0;
function installCountedForwarder(opts: { delayMs?: number } = {}) {
  executions = 0;
  setForwardProxyRequest(async () => {
    executions += 1;
    if (opts.delayMs) await new Promise((resolve) => setTimeout(resolve, opts.delayMs));
    return new Response(JSON.stringify({ ok: true, echoed: "harmless" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-approval-lifecycle-jwt-secret-with-enough-bytes";
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.example.com";
  process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS = "api.example.com";
  process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = "true";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ authMiddleware } = await import("../middleware/auth"));
  ({
    handlePendingProxyRequest,
    __setReleaseClaimBarrierForTests: setReleaseClaimBarrier,
    __resetReleaseClaimBarrierForTests: resetReleaseClaimBarrier,
  } = await import("../handlers/release"));
  ({ holdProxyApprovalRequest } = await import("../handlers/approvals"));
  proxyMod = await import("../handlers/proxy");
  ({ __setForwardProxyRequestForTests: setForwardProxyRequest } = proxyMod);

  // Pin the release-side execution preconditions so a claimed request can
  // actually reach the (stubbed) forwarder: a public DNS answer clears the
  // SSRF guard, and an allow-all rate limiter clears the per-host cap. Neither
  // hook changes the security behavior under test (single-use claim, expiry,
  // denial) — they only remove unrelated network/limiter friction so the
  // counted forwarder can observe real execution.
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  proxyMod.__setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
});

afterEach(() => {
  // Never let a barrier stub leak between tests.
  resetReleaseClaimBarrier();
  executions = 0;
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
  delete process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS;
  delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
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

/** Register a credential route that requires approval and return its id. */
async function ensureApprovalRoute(tenantId: string, agentId: string): Promise<string> {
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "example", "sk-live-upstream");
  const route = await vault.createRoute(tenantId, secret.id, {
    agentId,
    hostPattern: "api.example.com",
    pathPattern: "/*",
    // Match any verb: the lifecycle uses POST, and createRoute defaults method
    // to GET, which would otherwise miss on execution and 403 before the wire.
    method: "*",
    injectAs: "header",
    injectKey: "authorization",
    injectFormat: "Bearer {value}",
    requiresApproval: true,
  });
  return route.id;
}

/**
 * Create a held (pending) proxy request through the real hold path so the row
 * carries genuine encrypted body + structural preview + canonical digest. The
 * body embeds a credential under an innocuous key to prove it never leaks.
 */
async function holdRequest(tenantId: string, agentId: string) {
  const request = new Request("https://steward-proxy.local/proxy/api.example.com/v1/charges", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ label: CREDENTIAL, amount: 100, meta: { note: CREDENTIAL } }),
  });
  return holdProxyApprovalRequest({
    tenantId,
    agentId,
    // createRoute returns a SecretRoute; re-fetch shape is not needed here since
    // holdProxyApprovalRequest only reads route.id and route.approvalConfig.
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

async function poll(app: Hono, id: string, token: string): Promise<Response> {
  return app.request(`/approvals/proxy/${id}`, {
    headers: { authorization: `Bearer ${token}` },
  });
}

describe("proxy approval lifecycle enforcement (PGLite)", () => {
  it("does not execute a request denied through the operator deny guard", async () => {
    const tenantId = `t-deny-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // First APPROVE the request so we exercise the dangerous case: a live,
    // approved row that the release handler could otherwise race to execute.
    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "approved", approvedAt: new Date(), approvedBy: "operator" })
      .where(eq(pendingProxyRequests.id, held.id));

    // Deny via the EXACT guard the operator deny route ships in this PR:
    //   status IN (pending, approved) AND expiresAt > now()
    // and terminal fields (deniedAt/deniedBy/denialReason). Applying the real
    // guard (rather than a bare status write) means the denial only lands on a
    // genuinely deniable row; we assert it MATCHED so the test is not vacuous.
    // The operator session + MFA gating that fronts this UPDATE lives in the
    // api package and is covered by the api approval-route suite; here we prove
    // the proxy-side release enforcement never executes the resulting row.
    const denied = await getDb()
      .update(pendingProxyRequests)
      .set({
        status: "denied",
        deniedAt: new Date(),
        deniedBy: "operator",
        denialReason: "operator rejected",
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(pendingProxyRequests.id, held.id),
          eq(pendingProxyRequests.tenantId, tenantId),
          inArray(pendingProxyRequests.status, ["pending", "approved"]),
          sql`${pendingProxyRequests.expiresAt} > now()`,
        ),
      )
      .returning();
    // Non-vacuous: the guarded deny actually transitioned a live approved row.
    expect(denied.length).toBe(1);
    expect(denied[0].status).toBe("denied");

    // Counted forwarder proves execution never reaches the wire (counter stays 0).
    installCountedForwarder();
    const res = await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { status: string } };
    expect(body.data.status).toBe("denied");
    expect(executions).toBe(0);

    // Nothing executed: no executed/executing transition, no execution audit.
    const [row] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, held.id));
    expect(row.status).toBe("denied");
    expect(row.executedAt).toBeNull();
    const executedAudits = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(
        and(
          eq(proxyAuditLog.tenantId, tenantId),
          eq(proxyAuditLog.reason, "proxy-approval-executed"),
        ),
      );
    expect(executedAudits.length).toBe(0);
  });

  it("enforces the SQL claim-time expiry guard when a row expires mid-release (TOCTOU)", async () => {
    const tenantId = `t-expire-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Approve with an UNEXPIRED deadline. The initial JS expiry branch
    // (release.ts) therefore does NOT fire on the first read/digest pass, so
    // this test cannot pass through that earlier guard — it can only be caught
    // by the SQL claim-time guard inside the atomic UPDATE.
    await getDb()
      .update(pendingProxyRequests)
      .set({
        status: "approved",
        approvedAt: new Date(),
        approvedBy: "operator",
        expiresAt: new Date(Date.now() + 60_000),
      })
      .where(eq(pendingProxyRequests.id, held.id));

    // Deterministic TOCTOU: pause AFTER the read + digest verification and
    // BEFORE the atomic claim, move expiresAt into the past via a direct
    // UPDATE, then resume. No millisecond sleeps — the barrier fires exactly
    // once at the window we care about. If the SQL claim-time guard were
    // removed, the claim would still succeed here and the row would execute.
    let barrierHits = 0;
    setReleaseClaimBarrier(async (row) => {
      barrierHits += 1;
      await getDb()
        .update(pendingProxyRequests)
        .set({ expiresAt: new Date(Date.now() - 60_000), updatedAt: new Date() })
        .where(eq(pendingProxyRequests.id, row.id));
    });

    // Counted forwarder proves the row is never executed once it expires.
    installCountedForwarder();
    const res = await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));
    expect(barrierHits).toBe(1);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { status: string } };
    expect(body.data.status).toBe("expired");
    expect(executions).toBe(0);

    const [row] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, held.id));
    expect(row.status).toBe("expired");
    expect(row.executedAt).toBeNull();

    const expiredAudits = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(
        and(
          eq(proxyAuditLog.tenantId, tenantId),
          eq(proxyAuditLog.reason, "proxy-approval-expired"),
        ),
      );
    expect(expiredAudits.length).toBeGreaterThan(0);
  });

  it("fails an approved request whose stored digest no longer matches", async () => {
    const tenantId = `t-digest-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Approve, but tamper with a canonical-digest input (targetPath) AFTER the
    // request was bound. The stored requestDigest still covers the original
    // path, so the digest recomputed at release time will no longer match. We
    // tamper targetPath rather than requestDigest itself because the stored
    // digest is also bound into the body-encryption AAD — mutating it would
    // break decryption before the digest comparison could run.
    await getDb()
      .update(pendingProxyRequests)
      .set({
        status: "approved",
        approvedAt: new Date(),
        approvedBy: "operator",
        targetPath: "/v1/charges-tampered",
      })
      .where(eq(pendingProxyRequests.id, held.id));

    const res = await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBe(409);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("digest mismatch");

    const [row] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, held.id));
    expect(row.status).toBe("failed");
    expect(row.executedAt).toBeNull();
  });

  it("executes an approved request exactly once under two concurrent pollers", async () => {
    const tenantId = `t-concurrent-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "approved", approvedAt: new Date(), approvedBy: "operator" })
      .where(eq(pendingProxyRequests.id, held.id));

    // Counted, SUCCESSFUL, slightly-delayed forwarder. The delay widens the
    // execution window so a broken single-use claim would let BOTH pollers
    // forward; the counter then catches the double execution. A successful
    // (not unreachable) upstream is essential: with an unreachable upstream a
    // double-execution would still show zero successful hits, making the old
    // "at most one upstream" assertion vacuous.
    installCountedForwarder({ delayMs: 40 });

    const app = buildApp();
    const token = await tokenFor(agentId, tenantId);
    const [a, b] = await Promise.all([poll(app, held.id, token), poll(app, held.id, token)]);
    const bodies = (await Promise.all([a.json(), b.json()])) as Array<{
      ok?: boolean;
      upstream?: { status?: number };
      data?: { status?: string };
    }>;

    // The claim is single-use: exactly one poller forwarded to the wire.
    expect(executions).toBe(1);

    // Exactly one poller carries the fresh upstream success result; the other
    // reports an in-flight/terminal status WITHOUT its own upstream execution.
    const winners = bodies.filter((body) => body.upstream !== undefined);
    expect(winners.length).toBe(1);
    expect(winners[0].upstream?.status).toBe(200);
    const loser = bodies.find((body) => body.upstream === undefined);
    expect(loser).toBeDefined();
    expect(loser?.data?.status).not.toBe("approved");

    // Terminal row is executed once; never left approved, never executed twice.
    const [row] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, held.id));
    expect(row.status).toBe("executed");
    expect(row.executionStatusCode).toBe(200);

    // And the single execution produced exactly one execution audit row.
    const executedAudits = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(
        and(
          eq(proxyAuditLog.tenantId, tenantId),
          eq(proxyAuditLog.reason, "proxy-approval-executed"),
        ),
      );
    expect(executedAudits.length).toBe(1);
  });

  it("never stores credentials in the pending row or audit log", async () => {
    const tenantId = `t-nocreds-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Inspect the freshly held row: the preview and every plaintext column must
    // be free of the embedded credential (only the encrypted body may carry it).
    const [row] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, held.id));

    expect(JSON.stringify(row.preview)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(row.preview)).not.toContain("sk-live");
    expect(JSON.stringify(row.safeHeaders)).not.toContain(CREDENTIAL);
    // The digest is a hash and the ciphertext is opaque; neither is the secret.
    expect(row.requestDigest).not.toContain(CREDENTIAL);
    expect(row.bodyCiphertext).not.toContain(CREDENTIAL);

    // Preview still carries useful STRUCTURE (field names + value types).
    expect(row.preview).toMatchObject({
      contentType: "application/json",
      schema: { label: "string", amount: "number", meta: { note: "string" } },
    });

    // Drive it through approval + a SUCCESSFUL execution so real lifecycle
    // audit rows are actually written, then confirm none leaked the credential.
    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "approved", approvedAt: new Date(), approvedBy: "operator" })
      .where(eq(pendingProxyRequests.id, held.id));
    installCountedForwarder();
    await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));
    expect(executions).toBe(1);

    const audits = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(eq(proxyAuditLog.tenantId, tenantId));

    // Guard against a vacuous pass: the credential-absence loop below is only
    // meaningful if lifecycle audit rows actually exist. Assert the set is
    // NONEMPTY and carries the executed lifecycle reason for this row.
    expect(audits.length).toBeGreaterThan(0);
    const reasons = new Set(audits.map((audit) => audit.reason));
    expect(reasons.has("proxy-approval-executed")).toBe(true);

    for (const audit of audits) {
      expect(JSON.stringify(audit)).not.toContain(CREDENTIAL);
      expect(JSON.stringify(audit)).not.toContain("sk-live");
    }
  });
});
