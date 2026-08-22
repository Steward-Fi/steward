import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";

const TENANT_ID = "tenant-config-partial-mounted";
const USER_ID = crypto.randomUUID();
let adminToken = "";
let staleMfaToken = "";
let app: Hono;

const seeded = {
  policyExposure: { mode: "allowlist" as const },
  policyTemplates: [],
  secretRoutePresets: [],
  approvalConfig: { defaultRequired: 2 },
  featureFlags: { embeddedWallets: { enabled: true, createOnLogin: false } },
  theme: { primaryColor: "#112233", colorScheme: "dark" as const },
  gasSponsorshipConfig: { enabled: false },
};

describe("tenant config partial update hardening", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "tenant-config-partial-master";
    process.env.STEWARD_JWT_SECRET = "tenant-config-partial-jwt-secret-value";
    process.env.STEWARD_AUDIT_HMAC_KEY = "tenant-config-partial-audit-key-value";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Tenant Config Partial Mounted",
      apiKeyHash: "tenant-config-partial-key-hash",
    });
    await getDb()
      .insert(users)
      .values({ id: USER_ID, email: `${USER_ID}@example.test` });
    await getDb()
      .insert(userTenants)
      .values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });
    await getDb()
      .insert(tenantConfigs)
      .values({ tenantId: TENANT_ID, ...seeded });
    const { createSessionToken } = await import("../routes/auth");
    adminToken = await createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
      userId: USER_ID,
      tenantId: TENANT_ID,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    staleMfaToken = await createSessionToken(
      "0x0000000000000000000000000000000000000000",
      TENANT_ID,
      { userId: USER_ID, tenantId: TENANT_ID },
    );
    const { tenantConfigRoutes } = await import("../routes/tenant-config");
    app = new Hono();
    app.use("*", correlationId);
    app.route("/tenants", tenantConfigRoutes);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  const request = (path: string, method: string, body: unknown, token = adminToken) =>
    app.request(`/tenants/${TENANT_ID}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

  it("preserves every omitted control-plane field on a mounted partial PUT", async () => {
    const response = await request("/config", "PUT", { displayName: "Updated display" });
    expect(response.status).toBe(200);
    const [stored] = await getDb()
      .select()
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored).toMatchObject({ displayName: "Updated display", ...seeded });
  });

  it("keeps every alias mutation behind a recent owner/admin MFA session", async () => {
    for (const [path, method, body] of [
      ["/app-origins", "POST", { origin: "https://app.example" }],
      ["/app-origins", "DELETE", { origin: "https://app.example" }],
      ["/redirect-urls", "POST", { url: "https://app.example/callback" }],
      ["/redirect-urls", "DELETE", { url: "https://app.example/callback" }],
      ["/access-allowlist", "POST", { type: "email", value: "user@example.com" }],
      ["/access-allowlist", "DELETE", { type: "email", value: "user@example.com" }],
      ["/gas-sponsorship", "PATCH", { gasSponsorshipConfig: { enabled: false } }],
    ] as const) {
      const response = await request(path, method, body, staleMfaToken);
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ ok: false });
    }
  });

  it("normalizes and persists app-origin, redirect-url, and access-allowlist aliases", async () => {
    const origin = await request("/app-origins", "POST", {
      origin: "  https://APP.Example.COM  ",
    });
    expect(origin.status).toBe(200);
    expect(await origin.json()).toMatchObject({ data: { entries: ["https://app.example.com"] } });

    const redirect = await request("/redirect-urls", "POST", {
      url: "  https://APP.Example.COM/callback  ",
    });
    expect(redirect.status).toBe(200);
    expect(await redirect.json()).toMatchObject({
      data: { entries: ["https://app.example.com/callback"] },
    });

    const allowlist = await request("/access-allowlist", "POST", {
      type: "email",
      value: "  USER@Example.COM  ",
    });
    expect(allowlist.status).toBe(200);
    expect(await allowlist.json()).toMatchObject({
      data: { entries: [{ type: "email", value: "user@example.com" }] },
    });
  });

  it("rejects invalid gas sponsorship without mutating the stored config", async () => {
    const response = await request("/gas-sponsorship", "PATCH", {
      gasSponsorshipConfig: { enabled: true },
    });
    expect(response.status).toBe(400);
    const [stored] = await getDb()
      .select({ gasSponsorshipConfig: tenantConfigs.gasSponsorshipConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored?.gasSponsorshipConfig).toEqual({ enabled: false });
  });
});
