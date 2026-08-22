import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

const TENANT_ID = "secret-cache-contract";
const USER_ID = crypto.randomUUID();
const USER_ADDRESS = "0x1234567890123456789012345678901234567890";
const PLATFORM_KEY = "secret-cache-contract-platform-key";

type RouteGroup =
  | "app-client"
  | "invitation-user"
  | "invitation-platform"
  | "vault"
  | "user-wallet"
  | "global-wallet"
  | "audit"
  | "dashboard"
  | "auth";

/** Explicit inventory of response families that can expose sensitive data. */
const SECRET_BEARING_RESPONSE_INVENTORY = [
  { family: "app-client secret rotation", group: "app-client" },
  { family: "user invitation token", group: "invitation-user" },
  { family: "platform invitation token", group: "invitation-platform" },
  { family: "vault message signature", group: "vault" },
  { family: "vault raw-hash signature", group: "vault" },
  { family: "vault raw-digest signature", group: "vault" },
  { family: "vault typed-data signature", group: "vault" },
  { family: "vault user-operation signature", group: "vault" },
  { family: "vault authorization signature", group: "vault" },
  { family: "vault Solana signature", group: "vault" },
  { family: "user-wallet message and transaction signatures", group: "user-wallet" },
  { family: "global-wallet personal and typed-data signatures", group: "global-wallet" },
  { family: "MFA-gated audit reads", group: "audit" },
  { family: "MFA-gated dashboard reads", group: "dashboard" },
  { family: "identity token", group: "auth" },
  { family: "refresh token rotation", group: "auth" },
  { family: "OAuth exchange token", group: "auth" },
  { family: "OAuth provider token", group: "auth" },
] as const satisfies ReadonlyArray<{ family: string; group: RouteGroup }>;

type Probe = () => Promise<Response>;
let probes: Record<RouteGroup, Probe>;

function expectNoStore(response: Response, family: string): void {
  expect(response.headers.get("Cache-Control"), family).toBe("no-store, max-age=0");
  expect(response.headers.get("Pragma"), family).toBe("no-cache");
  expect(response.headers.get("Expires"), family).toBe("0");
}

beforeAll(async () => {
  process.env.NODE_ENV = "test";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "secret-cache-contract-master-password";
  process.env.STEWARD_JWT_SECRET = "secret-cache-contract-jwt-secret-32chars";
  process.env.STEWARD_AUDIT_HMAC_KEY = "secret-cache-contract-audit-key-32chars";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({ [PLATFORM_KEY]: ["platform:*"] });

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb().insert(tenants).values({ id: TENANT_ID, name: "Cache Contract", apiKeyHash: "x" });
  await getDb().insert(users).values({ id: USER_ID, walletAddress: USER_ADDRESS });
  await getDb().insert(userTenants).values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });

  const [
    { tenantConfigRoutes },
    { platformRoutes },
    { vaultRoutes },
    { userRoutes },
    { globalWalletRoutes },
    { auditRoutes },
    { dashboardRoutes },
    { authRoutes, createSessionToken },
  ] = await Promise.all([
    import("../routes/tenant-config"),
    import("../routes/platform"),
    import("../routes/vault"),
    import("../routes/user"),
    import("../routes/global-wallet"),
    import("../routes/audit"),
    import("../routes/dashboard"),
    import("../routes/auth"),
  ]);

  const sessionToken = await createSessionToken(USER_ADDRESS, TENANT_ID, {
    userId: USER_ID,
    tenantId: TENANT_ID,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  const sessionHeaders = { Authorization: `Bearer ${sessionToken}` };

  const authorized = (mounted: Hono): Hono => {
    const app = new Hono();
    app.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("userId", USER_ID);
      await next();
    });
    app.route("/", mounted);
    return app;
  };

  const tenant = authorized(tenantConfigRoutes);
  const vault = authorized(vaultRoutes);
  const audit = authorized(auditRoutes);
  const dashboard = authorized(dashboardRoutes);

  probes = {
    "app-client": () => tenant.request("/__cache-contract-probe__"),
    "invitation-user": () =>
      userRoutes.request("/__cache-contract-probe__", { headers: sessionHeaders }),
    "invitation-platform": () =>
      platformRoutes.request("/__cache-contract-probe__", {
        headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
      }),
    vault: () => vault.request("/__cache-contract-probe__"),
    "user-wallet": () =>
      userRoutes.request("/__cache-contract-probe__", { headers: sessionHeaders }),
    "global-wallet": () =>
      globalWalletRoutes.request("/__cache-contract-probe__", { headers: sessionHeaders }),
    audit: () => audit.request("/events?limit=1"),
    dashboard: () => dashboard.request("/missing-agent"),
    auth: () => authRoutes.request("/identity-token"),
  };
}, 120_000);

afterAll(async () => {
  await closeDb();
  for (const name of [
    "NODE_ENV",
    "STEWARD_PGLITE_MEMORY",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_JWT_SECRET",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_PLATFORM_KEYS",
    "STEWARD_PLATFORM_KEY_SCOPES",
  ]) {
    delete process.env[name];
  }
});

describe("secret-bearing response cache contract", () => {
  for (const entry of SECRET_BEARING_RESPONSE_INVENTORY) {
    it(`${entry.family} is non-cacheable after its authorization boundary`, async () => {
      const response = await probes[entry.group]();
      expect(response.status, entry.family).toBeGreaterThanOrEqual(200);
      expectNoStore(response, entry.family);
    });
  }

  it("keeps the inventory complete and uniquely named", () => {
    expect(SECRET_BEARING_RESPONSE_INVENTORY).toHaveLength(18);
    expect(new Set(SECRET_BEARING_RESPONSE_INVENTORY.map(({ family }) => family)).size).toBe(18);
    expect(new Set(SECRET_BEARING_RESPONSE_INVENTORY.map(({ group }) => group))).toEqual(
      new Set<RouteGroup>([
        "app-client",
        "invitation-user",
        "invitation-platform",
        "vault",
        "user-wallet",
        "global-wallet",
        "audit",
        "dashboard",
        "auth",
      ]),
    );
  });
});
