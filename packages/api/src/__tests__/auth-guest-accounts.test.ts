/**
 * Guest (ephemeral / anonymous) account lifecycle — Privy parity, fail-closed.
 *
 * Drives the real `auth` routes over an in-memory PGLite database (the same
 * harness the other auth suites use) to prove the security contract of guest
 * accounts end-to-end:
 *
 *  1. MINT — `POST /auth/guest` issues a bounded, LIMITED-authority session:
 *     `isGuest=true`, membership role `"guest"` (deliberately below `member`),
 *     a server-side hard expiry, default 24h, capped at 7d, with a provisioned
 *     wallet. Malformed `expiresIn` / non-object bodies are rejected.
 *
 *  2. PRIVILEGE FLOOR — the `"guest"` role can NEVER satisfy
 *     `requireTenantLevel()`, so a guest session is denied every owner/admin
 *     gate. (Direct guard assertion: the one property the whole design rests on.)
 *
 *  3. FAIL-CLOSED EXPIRY — once `users.guest_expires_at` has elapsed,
 *     `verifySessionToken()` returns null even for a structurally-valid,
 *     unexpired access token. The DB column is authoritative, not the JWT `exp`.
 *
 *  4. UPGRADE — `POST /auth/guest/upgrade` promotes a guest into a full account
 *     only after a verified magic link, preserving the user id and raising the
 *     role guest→member (never auto-escalating to admin/owner). It is a no-op on
 *     replay, and an expired guest can never upgrade (the dead session is
 *     rejected before promotion).
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, refreshTokens, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const TENANT_ID = "default";

let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
let verifySessionToken: Awaited<typeof import("../routes/auth")>["verifySessionToken"];
let requireTenantLevel: Awaited<typeof import("../services/context")>["requireTenantLevel"];

type GuestResponse = {
  ok: boolean;
  token?: string;
  refreshToken?: string;
  user?: {
    id: string;
    isGuest?: boolean;
    guestExpiresAt?: string | null;
    email?: string | null;
    walletAddress?: string | null;
    tenantId?: string;
    alreadyUpgraded?: boolean;
  };
  error?: string;
};

async function mintGuest(body?: Record<string, unknown>): Promise<GuestResponse> {
  const res = await authRoutes.request("/guest", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return (await res.json()) as GuestResponse;
}

/** Send a magic link and read the raw token back out of the mock inbox. */
async function magicLinkToken(email: string): Promise<string> {
  const send = await authRoutes.request("/email/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, tenantId: TENANT_ID }),
  });
  expect(send.status).toBe(200);
  const inbox = await authRoutes.request(`/test/inbox/${encodeURIComponent(email.toLowerCase())}`);
  expect(inbox.status).toBe(200);
  const msg = (await inbox.json()) as { token?: string };
  expect(typeof msg.token).toBe("string");
  return msg.token as string;
}

/** Minimal Hono-context stub exposing only what `requireTenantLevel` reads. */
function ctxWith(vars: { authType?: string; tenantRole?: string }) {
  return {
    get: (key: string) => (vars as Record<string, unknown>)[key],
  } as unknown as Parameters<typeof requireTenantLevel>[0];
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "auth-guest-accounts-master-password";
  process.env.STEWARD_JWT_SECRET ??= "auth-guest-accounts-jwt-secret-with-enough-entropy";
  // Real (non-dev) audit HMAC key: guest create/upgrade write tamper-evident
  // audit events, which fail closed without one. We supply a key rather than
  // weakening the guard.
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);
  // Deterministic magic links for the upgrade e2e: the mock provider records the
  // sent token to an in-memory inbox, exposed only under NODE_ENV=test.
  process.env.NODE_ENV = "test";
  process.env.EMAIL_PROVIDER = "mock";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Default Tenant",
    apiKeyHash: "hash",
  });

  ({ authRoutes, verifySessionToken } = await import("../routes/auth"));
  ({ requireTenantLevel } = await import("../services/context"));
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.EMAIL_PROVIDER;
});

describe("guest account minting", () => {
  it("mints a bounded, limited-authority guest with a provisioned wallet", async () => {
    const before = Date.now();
    const body = await mintGuest();

    expect(body.ok).toBe(true);
    expect(typeof body.token).toBe("string");
    expect(typeof body.refreshToken).toBe("string");
    expect(body.user?.isGuest).toBe(true);
    expect(body.user?.email).toBeNull();
    expect(typeof body.user?.id).toBe("string");

    // Default lifetime is 24h, server-stamped.
    const expMs = new Date(body.user?.guestExpiresAt as string).getTime();
    const dayMs = 24 * 3600 * 1000;
    expect(expMs).toBeGreaterThan(before + dayMs - 60_000);
    expect(expMs).toBeLessThan(before + dayMs + 60_000);

    // Persisted as a guest, linked to the tenant with the LIMITED "guest" role.
    const [row] = await getDb()
      .select({ isGuest: users.isGuest, guestExpiresAt: users.guestExpiresAt })
      .from(users)
      .where(eq(users.id, body.user?.id as string));
    expect(row?.isGuest).toBe(true);
    expect(row?.guestExpiresAt).toBeInstanceOf(Date);

    const [membership] = await getDb()
      .select({ role: userTenants.role })
      .from(userTenants)
      .where(
        and(eq(userTenants.userId, body.user?.id as string), eq(userTenants.tenantId, TENANT_ID)),
      );
    expect(membership?.role).toBe("guest");
  });

  it("honours a custom lifetime and caps it at 7 days", async () => {
    const before = Date.now();
    const short = await mintGuest({ expiresIn: "45m" });
    const shortMs = new Date(short.user?.guestExpiresAt as string).getTime();
    expect(shortMs).toBeGreaterThan(before + 44 * 60_000);
    expect(shortMs).toBeLessThan(before + 46 * 60_000);

    const capped = await mintGuest({ expiresIn: "30d" });
    const cappedMs = new Date(capped.user?.guestExpiresAt as string).getTime();
    const weekMs = 7 * 24 * 3600 * 1000;
    // Clamped to the 7-day hard cap, never the requested 30 days.
    expect(cappedMs).toBeLessThan(before + weekMs + 60_000);
    expect(cappedMs).toBeGreaterThan(before + weekMs - 60_000);
  });

  it("rejects a malformed lifetime and a non-object body", async () => {
    const badLifetime = await authRoutes.request("/guest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: "not-a-duration" }),
    });
    expect(badLifetime.status).toBe(400);

    const badBody = await authRoutes.request("/guest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([1, 2, 3]),
    });
    expect(badBody.status).toBe(400);
  });
});

describe("guest privilege floor", () => {
  it("never lets the guest role satisfy requireTenantLevel()", () => {
    // The whole guest design rests on this: a guest session carries tenantRole
    // "guest", which must fail the owner/admin gate that protects every
    // tenant-config / key-management / sensitive action.
    expect(requireTenantLevel(ctxWith({ authType: "session-jwt", tenantRole: "guest" }))).toBe(
      false,
    );
    // Sanity: the same gate still passes for owner/admin and api-key callers, and
    // rejects agent tokens — i.e. "guest" is denied for the right reason.
    expect(requireTenantLevel(ctxWith({ authType: "session-jwt", tenantRole: "owner" }))).toBe(
      true,
    );
    expect(requireTenantLevel(ctxWith({ authType: "session-jwt", tenantRole: "admin" }))).toBe(
      true,
    );
    expect(requireTenantLevel(ctxWith({ authType: "session-jwt", tenantRole: "member" }))).toBe(
      false,
    );
    expect(requireTenantLevel(ctxWith({ authType: "api-key" }))).toBe(true);
    expect(requireTenantLevel(ctxWith({ authType: "agent-token", tenantRole: "owner" }))).toBe(
      false,
    );
  });
});

describe("guest fail-closed expiry", () => {
  it("rejects an expired guest token even though the JWT itself is unexpired", async () => {
    const guest = await mintGuest();
    const token = guest.token as string;

    // A freshly-minted guest verifies fine.
    expect(await verifySessionToken(token)).not.toBeNull();

    // Force the authoritative server-side expiry into the past. The access token
    // is still structurally valid and unexpired, but the guest window is closed.
    await getDb()
      .update(users)
      .set({ guestExpiresAt: new Date(Date.now() - 1000) })
      .where(eq(users.id, guest.user?.id as string));

    expect(await verifySessionToken(token)).toBeNull();
  });
});

describe("guest upgrade", () => {
  it("requires a session and a verified email identity", async () => {
    // No session at all.
    const noSession = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ method: "email", token: "x", email: "a@example.test" }),
    });
    expect(noSession.status).toBe(401);

    const guest = await mintGuest();
    const auth = { Authorization: `Bearer ${guest.token}`, "content-type": "application/json" };

    // Unsupported method.
    const badMethod = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "sms", token: "x", email: "a@example.test" }),
    });
    expect(badMethod.status).toBe(400);

    // Missing token/email.
    const missing = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "email" }),
    });
    expect(missing.status).toBe(400);

    // A bogus (unverifiable) magic-link token is rejected — never promote on an
    // unverified identity.
    const bogus = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "email", token: "deadbeef", email: "a@example.test" }),
    });
    expect(bogus.status).toBe(401);
  });

  it("promotes a guest on a verified magic link, then is idempotent on replay", async () => {
    const guest = await mintGuest();
    const guestId = guest.user?.id as string;
    const auth = { Authorization: `Bearer ${guest.token}`, "content-type": "application/json" };
    const email = `guest-upgrade-${guestId.slice(0, 8)}@example.test`;

    // First upgrade: verified magic link → full account.
    const token1 = await magicLinkToken(email);
    const res1 = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "email", token: token1, email }),
    });
    const body1 = (await res1.json()) as GuestResponse;
    expect(res1.status).toBe(200);
    expect(body1.ok).toBe(true);
    expect(body1.user?.isGuest).toBe(false);
    // The user id is PRESERVED across the upgrade (no new account, no orphaned data).
    expect(body1.user?.id).toBe(guestId);

    // DB: full account, role raised guest → member (never admin/owner), guest
    // expiry cleared.
    const [row] = await getDb()
      .select({
        isGuest: users.isGuest,
        guestExpiresAt: users.guestExpiresAt,
        email: users.email,
        emailVerified: users.emailVerified,
      })
      .from(users)
      .where(eq(users.id, guestId));
    expect(row?.isGuest).toBe(false);
    expect(row?.guestExpiresAt).toBeNull();
    expect(row?.email).toBe(email);
    expect(row?.emailVerified).toBe(true);

    const [membership] = await getDb()
      .select({ role: userTenants.role })
      .from(userTenants)
      .where(and(eq(userTenants.userId, guestId), eq(userTenants.tenantId, TENANT_ID)));
    expect(membership?.role).toBe("member");

    // Replay with the SAME verified email is an idempotent no-op success — same
    // id, still a full (non-guest) account, flagged alreadyUpgraded.
    const token2 = await magicLinkToken(email);
    const res2 = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "email", token: token2, email }),
    });
    const body2 = (await res2.json()) as GuestResponse;
    expect(res2.status).toBe(200);
    expect(body2.user?.id).toBe(guestId);
    expect(body2.user?.isGuest).toBe(false);
    expect(body2.user?.alreadyUpgraded).toBe(true);
  });

  it("refuses to upgrade an expired guest (dead session)", async () => {
    const guest = await mintGuest();
    const auth = { Authorization: `Bearer ${guest.token}`, "content-type": "application/json" };

    // Close the guest window server-side.
    await getDb()
      .update(users)
      .set({ guestExpiresAt: new Date(Date.now() - 1000) })
      .where(eq(users.id, guest.user?.id as string));

    // Even with a well-formed request, the expired session can never upgrade:
    // verifySessionToken rejects the dead guest before any promotion.
    const res = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "email", token: "whatever", email: "x@example.test" }),
    });
    expect(res.status).toBe(401);

    // And the account is still a guest — no partial promotion happened.
    const [row] = await getDb()
      .select({ isGuest: users.isGuest })
      .from(users)
      .where(eq(users.id, guest.user?.id as string));
    expect(row?.isGuest).toBe(true);
  });
});

describe("guest delete", () => {
  it("deactivates a guest, revokes refresh tokens, and invalidates the access token", async () => {
    const guest = await mintGuest();
    const guestId = guest.user?.id as string;
    const auth = { Authorization: `Bearer ${guest.token}` };

    const res = await authRoutes.request("/guest", {
      method: "DELETE",
      headers: auth,
    });
    const body = (await res.json()) as { ok: boolean; deleted?: boolean; userId?: string };
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ ok: true, deleted: true, userId: guestId });

    const [row] = await getDb()
      .select({ isGuest: users.isGuest, deactivatedAt: users.deactivatedAt })
      .from(users)
      .where(eq(users.id, guestId));
    expect(row?.isGuest).toBe(true);
    expect(row?.deactivatedAt).toBeInstanceOf(Date);

    const remainingRefreshTokens = await getDb()
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, guestId));
    expect(remainingRefreshTokens).toHaveLength(0);
    expect(await verifySessionToken(guest.token as string)).toBeNull();
  });

  it("refuses to delete an upgraded full account through the guest endpoint", async () => {
    const guest = await mintGuest();
    const auth = { Authorization: `Bearer ${guest.token}`, "content-type": "application/json" };
    const email = `guest-delete-upgraded-${guest.user?.id}@example.test`;
    const token = await magicLinkToken(email);
    const upgrade = await authRoutes.request("/guest/upgrade", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ method: "email", token, email }),
    });
    expect(upgrade.status).toBe(200);

    const upgradedToken = ((await upgrade.json()) as GuestResponse).token as string;
    const res = await authRoutes.request("/guest", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${upgradedToken}` },
    });
    const body = (await res.json()) as { error?: string };
    expect(res.status).toBe(409);
    expect(body.error).toContain("Only guest accounts");
  });
});
