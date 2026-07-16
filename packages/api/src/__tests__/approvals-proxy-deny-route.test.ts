import { afterAll, afterEach, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
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
import { and, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

// Behavioral coverage for the route guard on POST /approvals/proxy/:id/deny.
// The DB-level guard is exercised elsewhere; this suite drives the real route
// stack (tenantAuth + approvalRoutes) against a PGLite database and asserts the
// full session / MFA / role enforcement matrix plus the status transition,
// audit trail, and terminality of a deny.
//
// Route under test: packages/api/src/routes/approvals.ts
//   - requireProxyOperator() (owner/admin + recent-MFA guard)
//   - approvalRoutes.post("/proxy/:id/deny")

setDefaultTimeout(30000);

const TENANT_ID = `proxy-deny-tenant-${Date.now()}`;
const AGENT_ID = `proxy-deny-agent-${Date.now()}`;
const OWNER_USER_ID = crypto.randomUUID();
const MEMBER_USER_ID = crypto.randomUUID();
const ROUTE_ID = crypto.randomUUID();

let apiKey = "";
let createSessionToken: typeof import("../routes/auth").createSessionToken;
let tenantAuth: typeof import("../services/context").tenantAuth;
let approvalRoutes: typeof import("../routes/approvals").approvalRoutes;
let app: Hono<{ Variables: AppVariables }>;

let previousJwtSecret: string | undefined;
let previousAuditHmacKey: string | undefined;
let previousMasterPassword: string | undefined;

function makeApp() {
  const instance = new Hono<{ Variables: AppVariables }>();
  instance.use("*", tenantAuth);
  instance.route("/approvals", approvalRoutes);
  return instance;
}

async function ownerSession(extra?: Record<string, unknown>) {
  return createSessionToken("0x0000000000000000000000000000000000000001", TENANT_ID, {
    userId: OWNER_USER_ID,
    ...extra,
  });
}

async function memberSession(extra?: Record<string, unknown>) {
  return createSessionToken("0x0000000000000000000000000000000000000002", TENANT_ID, {
    userId: MEMBER_USER_ID,
    ...extra,
  });
}

/** Seed a fresh pending proxy request and return its id. */
async function seedPendingProxyRequest(overrides?: {
  status?: "pending" | "approved" | "denied";
  expiresInMs?: number;
}): Promise<string> {
  const expiresAt = new Date(Date.now() + (overrides?.expiresInMs ?? 10 * 60_000));
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
      status: overrides?.status ?? "pending",
      expiresAt,
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

async function denyAuditRowsFor(resourceId: string) {
  return getDb()
    .select({
      action: auditEvents.action,
      actorType: auditEvents.actorType,
      resourceType: auditEvents.resourceType,
      resourceId: auditEvents.resourceId,
      metadata: auditEvents.metadata,
    })
    .from(auditEvents)
    .where(
      and(eq(auditEvents.action, "proxy.approval.denied"), eq(auditEvents.resourceId, resourceId)),
    );
}

async function approvedAuditRowsFor(resourceId: string) {
  return getDb()
    .select({
      action: auditEvents.action,
      actorType: auditEvents.actorType,
      resourceType: auditEvents.resourceType,
      resourceId: auditEvents.resourceId,
      metadata: auditEvents.metadata,
    })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.action, "proxy.approval.approved"),
        eq(auditEvents.resourceId, resourceId),
      ),
    );
}

async function revokedAuditRowsFor(resourceId: string) {
  return getDb()
    .select({
      action: auditEvents.action,
      actorType: auditEvents.actorType,
      resourceType: auditEvents.resourceType,
      resourceId: auditEvents.resourceId,
      metadata: auditEvents.metadata,
    })
    .from(auditEvents)
    .where(
      and(eq(auditEvents.action, "proxy.approval.revoked"), eq(auditEvents.resourceId, resourceId)),
    );
}

/** Every decision-class audit event (approved | denied | revoked) for a row. */
async function decisionAuditRowsFor(resourceId: string) {
  return getDb()
    .select({ action: auditEvents.action })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.resourceId, resourceId),
        inArray(auditEvents.action, [
          "proxy.approval.approved",
          "proxy.approval.denied",
          "proxy.approval.revoked",
        ]),
      ),
    );
}

beforeAll(async () => {
  previousJwtSecret = process.env.STEWARD_JWT_SECRET;
  previousAuditHmacKey = process.env.STEWARD_AUDIT_HMAC_KEY;
  previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-deny-route-jwt-secret-with-enough-entropy-to-pass";
  process.env.STEWARD_AUDIT_HMAC_KEY = "proxy-deny-route-audit-hmac-key-with-enough-entropy";
  // context.ts requires STEWARD_MASTER_PASSWORD at module-init time; seed it
  // before the dynamic import below so the file is self-contained under the
  // isolated runner (mirrors vault-mfa-sensitive-actions.test.ts).
  process.env.STEWARD_MASTER_PASSWORD ??= "proxy-deny-route-master-password";
  process.env.STEWARD_PGLITE_MEMORY = "true";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const keyPair = generateApiKey();
  apiKey = keyPair.key;

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Proxy Deny Tenant",
    apiKeyHash: keyPair.hash,
  });
  await getDb()
    .insert(users)
    .values([
      {
        id: OWNER_USER_ID,
        email: `proxy-deny-owner-${Date.now()}@example.test`,
        emailVerified: true,
      },
      {
        id: MEMBER_USER_ID,
        email: `proxy-deny-member-${Date.now()}@example.test`,
        emailVerified: true,
      },
    ]);
  await getDb()
    .insert(userTenants)
    .values([
      { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
    ]);
  await getDb().insert(agents).values({
    id: AGENT_ID,
    tenantId: TENANT_ID,
    name: "Proxy Deny Agent",
    walletAddress: "0x0000000000000000000000000000000000000010",
  });

  ({ createSessionToken } = await import("../routes/auth"));
  ({ tenantAuth } = await import("../services/context"));
  ({ approvalRoutes } = await import("../routes/approvals"));
  app = makeApp();
});

afterEach(async () => {
  await getDb().delete(pendingProxyRequests).where(eq(pendingProxyRequests.tenantId, TENANT_ID));
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  if (previousJwtSecret === undefined) {
    delete process.env.STEWARD_JWT_SECRET;
  } else {
    process.env.STEWARD_JWT_SECRET = previousJwtSecret;
  }
  if (previousAuditHmacKey === undefined) {
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  } else {
    process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditHmacKey;
  }
  if (previousMasterPassword === undefined) {
    delete process.env.STEWARD_MASTER_PASSWORD;
  } else {
    process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
  }
});

describe("POST /approvals/proxy/:id/deny — session/MFA route enforcement", () => {
  it("allows an owner session with recent MFA to deny a pending proxy request", async () => {
    const id = await seedPendingProxyRequest();
    const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "suspicious egress target" }),
    });
    const body = (await res.json()) as {
      ok: boolean;
      data?: { id: string; status: string };
      error?: string;
    };

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.data?.id).toBe(id);
    expect(body.data?.status).toBe("denied");

    // Status transition + denial metadata persisted.
    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("denied");
    expect(row?.deniedAt).not.toBeNull();
    expect(row?.deniedBy).toBe(OWNER_USER_ID);
    expect(row?.denialReason).toBe("suspicious egress target");

    // Audit trail written.
    const audits = await denyAuditRowsFor(id);
    expect(audits.length).toBe(1);
    expect(audits[0]?.actorType).toBe("user");
    expect(audits[0]?.resourceType).toBe("pending_proxy_request");
    expect((audits[0]?.metadata as { agentId?: string }).agentId).toBe(AGENT_ID);
    expect((audits[0]?.metadata as { reason?: string }).reason).toBe("suspicious egress target");
  });

  it("rejects an unauthenticated request (no session, no key) without mutating", async () => {
    const id = await seedPendingProxyRequest();

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "no auth" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    // The route mounts tenantAuth: an unauthenticated caller never establishes a
    // principal, so tenantAuth denies before the operator guard runs. On this
    // stack that surfaces as 403 Forbidden (the default-tenant fallback fails the
    // API-key check), not 401.
    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);

    // No mutation.
    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("rejects an invalid/expired bearer token without mutating", async () => {
    const id = await seedPendingProxyRequest();

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: {
        Authorization: "Bearer not-a-real-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ reason: "bad token" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);

    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("returns 403 for an authenticated non-operator (member role) without mutating", async () => {
    const id = await seedPendingProxyRequest();
    const token = await memberSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "member should not be able to deny" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin user session");

    // No mutation.
    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(row?.deniedBy).toBeNull();
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("returns 403 for an owner session with STALE MFA without mutating", async () => {
    const id = await seedPendingProxyRequest();
    // MFA verified 10 minutes ago; guard window is 5 minutes.
    const token = await ownerSession({
      mfaVerifiedAt: Date.now() - 10 * 60_000,
      mfaMethod: "totp",
    });

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "stale mfa should be rejected" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA");

    // No mutation.
    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(row?.deniedBy).toBeNull();
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("returns 403 for an owner session with NO MFA claim without mutating", async () => {
    const id = await seedPendingProxyRequest();
    const token = await ownerSession();

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "no mfa claim" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA");

    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("rejects an agent/service token and does not deny", async () => {
    const id = await seedPendingProxyRequest();
    const agentToken = await signAgentToken({ agentId: AGENT_ID, tenantId: TENANT_ID }, "30d");

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${agentToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "agent should not deny" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin user session");

    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("rejects an API-key (tenant) principal and does not deny", async () => {
    const id = await seedPendingProxyRequest();

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ reason: "api key should not deny" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    // API-key auth passes requireTenantLevel but fails requireHumanApprover.
    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin user session");

    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("pending");
    expect(await denyAuditRowsFor(id)).toHaveLength(0);
  });

  it("deny is terminal: a second deny after a deny fails cleanly (409) without a new audit", async () => {
    const id = await seedPendingProxyRequest();
    const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });

    const first = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "first deny" }),
    });
    expect(first.status).toBe(200);

    const second = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "second deny" }),
    });
    const secondBody = (await second.json()) as { ok: boolean; error?: string };

    expect(second.status).toBe(409);
    expect(secondBody.ok).toBe(false);
    expect(secondBody.error).toContain("already resolved");

    // Original denial reason preserved; no double-audit.
    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("denied");
    expect(row?.denialReason).toBe("first deny");
    expect(await denyAuditRowsFor(id)).toHaveLength(1);
  });

  it("deny is terminal: approve after deny fails cleanly (409) and preserves denied state", async () => {
    const id = await seedPendingProxyRequest();
    const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });

    const deny = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "deny then attempt approve" }),
    });
    expect(deny.status).toBe(200);

    const approve = await app.request(`/approvals/proxy/${id}/approve`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const approveBody = (await approve.json()) as { ok: boolean; error?: string };

    expect(approve.status).toBe(409);
    expect(approveBody.ok).toBe(false);

    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("denied");
    expect(row?.denialReason).toBe("deny then attempt approve");

    // Audit hygiene: the rejected approve must not emit an approved event, and
    // the single original denial audit must remain intact.
    expect(await approvedAuditRowsFor(id)).toHaveLength(0);
    expect(await denyAuditRowsFor(id)).toHaveLength(1);
  });

  // ─── Finding 1: concurrent approve/deny race + revoke-of-approved ────────────

  it("deny of an already-approved request is a distinct REVOKE (proxy.approval.revoked, no denied event)", async () => {
    const id = await seedPendingProxyRequest({ status: "approved" });
    const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });

    const res = await app.request(`/approvals/proxy/${id}/deny`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "revoke a live approval before it is claimed" }),
    });
    const body = (await res.json()) as { ok: boolean; data?: { status: string } };

    // Deny-of-approved is a load-bearing admin action (revoke-before-consumption,
    // #181): it succeeds and the row lands terminal `denied`.
    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.data?.status).toBe("denied");

    const row = await fetchProxyRequest(id);
    expect(row?.status).toBe("denied");
    expect(row?.denialReason).toBe("revoke a live approval before it is claimed");

    // The audit trail records a DISTINCT revoke event, NOT a `denied` decision
    // (which is reserved for denying a still-pending request).
    const revoked = await revokedAuditRowsFor(id);
    expect(revoked).toHaveLength(1);
    expect((revoked[0]?.metadata as { revokedFrom?: string }).revokedFrom).toBe("approved");
    expect(await denyAuditRowsFor(id)).toHaveLength(0);

    // Exactly one decision-class event total.
    expect(await decisionAuditRowsFor(id)).toHaveLength(1);
  });

  it("concurrent approve+deny on a pending row resolves deterministically (never two conflicting DENIED+APPROVED decisions)", async () => {
    // The reviewer's P1: the old deny guard `status IN ('pending','approved')`
    // let a serialized approve-then-deny yield TWO 200s AND two SAME-CLASS
    // decision events (`proxy.approval.approved` AND `proxy.approval.denied`) on
    // one row — an incoherent double-decision.
    //
    // The fix splits deny into two exclusive CAS transitions (pending-only deny,
    // approved-only revoke), each per-tenant-serialized by the audited
    // transaction. The race now resolves into exactly ONE of two coherent
    // orderings:
    //   A) deny wins the pending-CAS first  -> deny 200 (denied), approve 409;
    //      exactly one decision event (`denied`), NO approved event.
    //   B) approve wins first               -> approve 200 (approved), then deny
    //      sees `approved`, takes the approved-CAS REVOKE branch -> deny 200,
    //      emitting a DISTINCT `proxy.approval.revoked` (a deliberate
    //      revoke-before-consumption, NOT a second `denied` decision). Row ends
    //      `denied`; audit trail is the coherent sequence approved -> revoked.
    // In NEITHER ordering do `approved` and `denied` coexist on the row.
    const id = await seedPendingProxyRequest();
    const token = await ownerSession({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });

    const doApprove = () =>
      app.request(`/approvals/proxy/${id}/approve`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
    const doDeny = () =>
      app.request(`/approvals/proxy/${id}/deny`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "race deny" }),
      });

    const [approveRes, denyRes] = await Promise.all([doApprove(), doDeny()]);

    const approvedEvents = await approvedAuditRowsFor(id);
    const deniedEvents = await denyAuditRowsFor(id);
    const revokedEvents = await revokedAuditRowsFor(id);
    const row = await fetchProxyRequest(id);

    if (approveRes.status === 200 && denyRes.status === 200) {
      // Ordering B: approve then revoke. Coherent sequence, distinct events.
      expect(row?.status).toBe("denied");
      expect(approvedEvents).toHaveLength(1);
      expect(revokedEvents).toHaveLength(1);
      // Crucially: NO `denied`-class decision on an approved row.
      expect(deniedEvents).toHaveLength(0);
    } else {
      // Ordering A: exactly one 200 (deny) + one 409 (approve). One decision.
      expect([approveRes.status, denyRes.status].sort()).toEqual([200, 409]);
      expect(row?.status).toBe("denied");
      expect(deniedEvents).toHaveLength(1);
      expect(approvedEvents).toHaveLength(0);
      expect(revokedEvents).toHaveLength(0);
    }

    // The invariant that must ALWAYS hold: `approved` and `denied` never coexist
    // as competing decisions on the same row (the exact double-decision the
    // reviewer flagged). Approved may coexist only with the distinct `revoked`.
    expect(!(approvedEvents.length > 0 && deniedEvents.length > 0)).toBe(true);
  });
});
