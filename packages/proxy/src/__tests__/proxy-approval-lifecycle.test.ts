import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import {
  agents,
  and,
  closeDb,
  eq,
  getDb,
  pendingProxyRequests,
  proxyAuditLog,
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
  ({ handlePendingProxyRequest } = await import("../handlers/release"));
  ({ holdProxyApprovalRequest } = await import("../handlers/approvals"));
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
  it("does not execute a denied request", async () => {
    const tenantId = `t-deny-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Operator denies (modeled as the terminal state the deny endpoint sets).
    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "denied", deniedAt: new Date(), deniedBy: "operator" })
      .where(eq(pendingProxyRequests.id, held.id));

    const res = await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { status: string } };
    expect(body.data.status).toBe("denied");

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

  it("expires an approved-but-past-deadline request server-side instead of executing", async () => {
    const tenantId = `t-expire-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    // Approve the request but set the deadline into the past. The initial read
    // in the handler will see status "approved"; the atomic claim must re-check
    // expiry server-side and refuse to execute (closes the TOCTOU window).
    await getDb()
      .update(pendingProxyRequests)
      .set({
        status: "approved",
        approvedAt: new Date(),
        approvedBy: "operator",
        expiresAt: new Date(Date.now() - 60_000),
      })
      .where(eq(pendingProxyRequests.id, held.id));

    const res = await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { status: string } };
    expect(body.data.status).toBe("expired");

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

  it("lets at most one of two concurrent pollers claim an approved request", async () => {
    const tenantId = `t-concurrent-${crypto.randomUUID()}`;
    const agentId = `a-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const held = await holdRequest(tenantId, agentId);

    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "approved", approvedAt: new Date(), approvedBy: "operator" })
      .where(eq(pendingProxyRequests.id, held.id));

    const app = buildApp();
    const token = await tokenFor(agentId, tenantId);
    const [a, b] = await Promise.all([poll(app, held.id, token), poll(app, held.id, token)]);
    const bodies = (await Promise.all([a.json(), b.json()])) as Array<{
      upstream?: unknown;
      data?: { status?: string };
    }>;

    // Exactly one poller wins the single-use approved->executing claim. The
    // winner proceeds to execution (which may fail at the unreachable upstream,
    // leaving the row "failed"); the loser gets a non-executing status back.
    // Either way the row must never end in "approved" and must never be
    // executed twice.
    const [row] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, held.id));
    expect(["executed", "failed", "executing"]).toContain(row.status);
    expect(row.status).not.toBe("approved");

    // Only one poller can ever have observed itself as the executing claimant;
    // the other must report a non-owning terminal/in-flight status. We assert
    // the two responses did not BOTH carry a fresh upstream execution result.
    const upstreamHits = bodies.filter((body) => body.upstream !== undefined).length;
    expect(upstreamHits).toBeLessThanOrEqual(1);
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

    // Drive it through approval + poll, then confirm no audit row leaked it.
    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "approved", approvedAt: new Date(), approvedBy: "operator" })
      .where(eq(pendingProxyRequests.id, held.id));
    await poll(buildApp(), held.id, await tokenFor(agentId, tenantId));

    const audits = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(eq(proxyAuditLog.tenantId, tenantId));
    for (const audit of audits) {
      expect(JSON.stringify(audit)).not.toContain(CREDENTIAL);
      expect(JSON.stringify(audit)).not.toContain("sk-live");
    }
  });
});
