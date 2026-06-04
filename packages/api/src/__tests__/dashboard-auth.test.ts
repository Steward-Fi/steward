import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAccessToken, signAgentToken } from "@stwd/auth";
import { getDb, tenants, users, userTenants } from "@stwd/db";
import { eq } from "drizzle-orm";

setDefaultTimeout(30000);

/**
 * NOTE on test isolation:
 *   This file deliberately uses the ambient `DATABASE_URL` set by the
 *   `Integration Tests (Postgres)` CI job and does NOT swap pglite via
 *   `setPGLiteOverride`. An earlier version of this file replaced the
 *   global db handle in `beforeAll` and closed it in `afterAll`, which
 *   broke every subsequent test in `bun test packages/api` with
 *   `error: PGlite is closed`. We use a unique tenant id and clean up
 *   the row instead of swapping the connection.
 */

const TENANT_ID = "test-dashboard-auth";
const OWNER_USER_ID = crypto.randomUUID();
const MEMBER_USER_ID = crypto.randomUUID();
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

let app: typeof import("../app")["app"];

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  ({ app } = await import("../app"));

  await getDb()
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Dashboard Auth Tenant",
      apiKeyHash: "hash",
    })
    .onConflictDoNothing();
  await getDb()
    .insert(users)
    .values([
      { id: OWNER_USER_ID, email: `dashboard-owner-${OWNER_USER_ID}@example.test` },
      { id: MEMBER_USER_ID, email: `dashboard-member-${MEMBER_USER_ID}@example.test` },
    ])
    .onConflictDoNothing();
  await getDb()
    .insert(userTenants)
    .values([
      { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
    ])
    .onConflictDoNothing();
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;
  await getDb()
    .delete(userTenants)
    .where(eq(userTenants.tenantId, TENANT_ID))
    .catch(() => {});
  await getDb()
    .delete(users)
    .where(eq(users.id, OWNER_USER_ID))
    .catch(() => {});
  await getDb()
    .delete(users)
    .where(eq(users.id, MEMBER_USER_ID))
    .catch(() => {});
  await getDb()
    .delete(tenants)
    .where(eq(tenants.id, TENANT_ID))
    .catch(() => {});
});

describeWithDatabase("dashboardAuthMiddleware", () => {
  it("explicitly rejects agent tokens", async () => {
    const token = await signAgentToken({ agentId: "agent-1", tenantId: TENANT_ID }, "1h");

    const res = await app.request("/dashboard/nonexistent-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("agent tokens");
  });

  it("rejects owner sessions without recent MFA before returning dashboard data", async () => {
    const token = await signAccessToken(
      {
        address: `0x${"1".repeat(40)}`,
        tenantId: TENANT_ID,
        userId: OWNER_USER_ID,
      },
      "1h",
    );

    const res = await app.request("/dashboard/nonexistent-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA");
  });

  it("allows owner sessions with recent MFA to reach the dashboard route", async () => {
    const token = await signAccessToken(
      {
        address: `0x${"1".repeat(40)}`,
        tenantId: TENANT_ID,
        userId: OWNER_USER_ID,
        mfaVerifiedAt: Date.now(),
      },
      "1h",
    );

    const res = await app.request("/dashboard/nonexistent-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(res.headers.get("Pragma")).toBe("no-cache");
    expect(res.headers.get("Expires")).toBe("0");
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Agent not found");
  });

  it("rejects member sessions before returning dashboard data", async () => {
    const token = await signAccessToken(
      {
        address: `0x${"2".repeat(40)}`,
        tenantId: TENANT_ID,
        userId: MEMBER_USER_ID,
      },
      "1h",
    );

    const res = await app.request("/dashboard/nonexistent-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Tenant-level auth");
  });
});
