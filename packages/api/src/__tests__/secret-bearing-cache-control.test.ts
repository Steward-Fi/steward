import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { readFileSync } from "node:fs";
import { closeDb, getDb, tenantAppClients, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = "secret-cache-runtime";
const USER_ID = "11111111-1111-4111-8111-111111111111";
const CLIENT_ID = "runtime-client";
setDefaultTimeout(30_000);

function expectNoStore(response: Response): void {
  expect(response.headers.get("Cache-Control")).toBe("no-store, max-age=0");
  expect(response.headers.get("Pragma")).toBe("no-cache");
  expect(response.headers.get("Expires")).toBe("0");
}

const SECRET_RESPONSE_INVENTORY = [
  [
    "app-client-secret",
    "/:tenantId/app-clients/:clientId/secrets",
    "secret-bearing-cache-control.test.ts",
    true,
  ],
  [
    "user-invitation-token",
    "/me/tenants/:tenantId/invitations",
    "secret-bearing-cache-control.test.ts",
    true,
  ],
  [
    "platform-invitation-token",
    "/tenants/:tenantId/invitations",
    "secret-bearing-cache-control.test.ts",
    true,
  ],
  ["vault-message", "/:agentId/sign-message", "vault-raw-signing.test.ts", true],
  ["vault-raw-hash", "/:agentId/sign-raw-hash", "vault-raw-signing.test.ts", true],
  ["vault-raw-digest", "/:agentId/sign-raw-digest", "vault-raw-digest-signing.test.ts", true],
  ["vault-typed-data", "/:agentId/sign-typed-data", "vault-raw-signing.test.ts", true],
  [
    "vault-user-operation",
    "/:agentId/sign-user-operation",
    "secret-bearing-cache-control.test.ts",
    false,
  ],
  [
    "vault-authorization",
    "/:agentId/sign-authorization",
    "secret-bearing-cache-control.test.ts",
    false,
  ],
  ["vault-solana", "/:agentId/sign-solana", "sign-solana-priority-fee.test.ts", true],
  ["user-wallet-signing", "/me/wallet/sign", "user-wallet-signers.test.ts", true],
  ["global-wallet-personal-sign", "personal_sign", "global-wallet.test.ts", true],
  ["global-wallet-typed-data", "eth_signTypedData_v4", "global-wallet.test.ts", true],
  ["audit-read", "/events", "audit-events-filters.test.ts", true],
  ["dashboard-read", "/dashboard/:agentId", "dashboard-auth.test.ts", true],
  ["auth-identity-token", "/identity-token", "identity-discovery.test.ts", true],
  ["auth-refresh", "/refresh", "session-revocation.test.ts", true],
  ["auth-oauth-exchange", "/oauth/exchange", "auth-oauth-nonce-exchange.test.ts", true],
  ["auth-provider-token", "/oauth/:provider/token", "auth-oauth-token-encryption.test.ts", true],
] as const satisfies ReadonlyArray<
  readonly [id: string, route: string, evidenceFile: string, secretSuccessReachable: boolean]
>;

let tenantConfigApp: Hono<{ Variables: AppVariables }>;
let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];
let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];
let vaultRoutes: Awaited<typeof import("../routes/vault")>["vaultRoutes"];
let vaultApp: Hono<{ Variables: AppVariables }>;
let globalWalletRoutes: Awaited<typeof import("../routes/global-wallet")>["globalWalletRoutes"];
let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
let sessionToken: string;
let personalSessionToken: string;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "secret-cache-runtime-master-password-32chars";
  process.env.STEWARD_JWT_SECRET = "secret-cache-runtime-jwt-key-32chars";
  process.env.STEWARD_AUDIT_HMAC_KEY = "secret-cache-runtime-audit-key-32chars";
  process.env.STEWARD_PLATFORM_KEYS = "secret-cache-platform-key";
  process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
    "secret-cache-platform-key": [
      "platform:read",
      "platform:write",
      "platform:tenant-member:write",
    ],
  });
  process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING = "true";
  process.env.STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING = "true";
  process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING = "true";
  process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING = "true";
  process.env.STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING = "true";
  process.env.STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb()
    .insert(tenants)
    .values([
      { id: TENANT_ID, name: "Secret cache runtime", apiKeyHash: "hash-runtime" },
      { id: `personal-${USER_ID}`, name: "Personal", apiKeyHash: "hash-personal" },
    ]);
  await getDb().insert(users).values({ id: USER_ID, email: "secret-cache@example.test" });
  await getDb()
    .insert(userTenants)
    .values([
      { userId: USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: USER_ID, tenantId: `personal-${USER_ID}`, role: "owner" },
    ]);
  await getDb().insert(tenantAppClients).values({
    tenantId: TENANT_ID,
    id: CLIENT_ID,
    name: "Runtime client",
    enabled: true,
    isDefault: true,
  });

  const tenantConfig = await import("../routes/tenant-config");
  tenantConfigApp = new Hono<{ Variables: AppVariables }>();
  tenantConfigApp.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", USER_ID);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  tenantConfigApp.route("/", tenantConfig.tenantConfigRoutes);

  ({ userRoutes } = await import("../routes/user"));
  ({ platformRoutes } = await import("../routes/platform"));
  ({ vaultRoutes } = await import("../routes/vault"));
  ({ globalWalletRoutes } = await import("../routes/global-wallet"));
  const auth = await import("../routes/auth");
  authRoutes = auth.authRoutes;
  sessionToken = await auth.createSessionToken(
    "0x1111111111111111111111111111111111111111",
    TENANT_ID,
    { userId: USER_ID, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
  );
  personalSessionToken = await auth.createSessionToken(
    "0x1111111111111111111111111111111111111111",
    `personal-${USER_ID}`,
    { userId: USER_ID, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
  );
  vaultApp = new Hono<{ Variables: AppVariables }>();
  vaultApp.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", USER_ID);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  vaultApp.route("/", vaultRoutes);
});

afterAll(async () => {
  await closeDb();
  for (const name of [
    "STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING",
    "STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING",
    "STEWARD_ALLOW_UNSAFE_RAW_SIGNING",
    "STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING",
    "STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING",
    "STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING",
  ]) {
    delete process.env[name];
  }
});

describe("secret-bearing response cache control", () => {
  it("keeps every family bound to explicit mounted evidence and honest reachability", () => {
    expect(SECRET_RESPONSE_INVENTORY).toHaveLength(19);
    expect(new Set(SECRET_RESPONSE_INVENTORY.map(([id]) => id)).size).toBe(19);
    for (const [id, _route, evidenceFile, secretSuccessReachable] of SECRET_RESPONSE_INVENTORY) {
      const evidence = readFileSync(new URL(evidenceFile, import.meta.url), "utf8");
      if (secretSuccessReachable) {
        expect(evidence, `${id}: missing mounted success status assertion`).toMatch(
          /\.status\)?\.toBe\((?:200|201)\)|status\)\.toBe\((?:200|201)\)/,
        );
      } else {
        expect(evidence, `${id}: missing mounted fail-closed response assertion`).toContain(
          "toBeGreaterThanOrEqual(400)",
        );
      }
      expect(evidence, `${id}: Cache-Control`).toContain('"Cache-Control"');
      expect(evidence, `${id}: Pragma`).toContain('"Pragma"');
      expect(evidence, `${id}: Expires`).toContain('"Expires"');
      expect(typeof secretSuccessReachable).toBe("boolean");
    }
    expect(
      SECRET_RESPONSE_INVENTORY.filter(([, , , reachable]) => !reachable).map(([id]) => id),
    ).toEqual(["vault-user-operation", "vault-authorization"]);
  });

  it("returns an app-client secret and protects its post-auth missing-client error", async () => {
    const appSecret = await tenantConfigApp.request(
      `/${TENANT_ID}/app-clients/${CLIENT_ID}/secrets`,
      { method: "POST", headers: { Authorization: `Bearer ${sessionToken}` } },
    );
    expect(appSecret.status).toBe(201);
    expectNoStore(appSecret);
    expect((await appSecret.json()) as object).toHaveProperty("data.appSecret");
    const missing = await tenantConfigApp.request(`/${TENANT_ID}/app-clients/missing/secrets`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    expect(missing.status).toBe(404);
    expectNoStore(missing);
  });

  it("returns a user invitation token and protects its post-auth validation error", async () => {
    const userInvitation = await userRoutes.request(`/me/tenants/${TENANT_ID}/invitations`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user-invite@example.test" }),
    });
    expect(userInvitation.status).toBe(201);
    expectNoStore(userInvitation);
    expect((await userInvitation.json()) as object).toHaveProperty("data.token");
    const invalid = await userRoutes.request(`/me/tenants/${TENANT_ID}/invitations`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email: "invalid" }),
    });
    expect(invalid.status).toBe(400);
    expectNoStore(invalid);
  });

  it("returns a platform invitation token and protects its post-auth validation error", async () => {
    const platformInvitation = await platformRoutes.request(`/tenants/${TENANT_ID}/invitations`, {
      method: "POST",
      headers: {
        "X-Steward-Platform-Key": "secret-cache-platform-key",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email: "platform-invite@example.test" }),
    });
    expect(platformInvitation.status).toBe(201);
    expectNoStore(platformInvitation);
    expect((await platformInvitation.json()) as object).toHaveProperty("data.token");
    const invalid = await platformRoutes.request(`/tenants/${TENANT_ID}/invitations`, {
      method: "POST",
      headers: {
        "X-Steward-Platform-Key": "secret-cache-platform-key",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email: "invalid" }),
    });
    expect(invalid.status).toBe(400);
    expectNoStore(invalid);
  });

  for (const [family, path, body] of [
    ["vault-message", "/missing/sign-message", { message: "hello" }],
    ["vault-raw-hash", "/missing/sign-raw-hash", { hash: `0x${"11".repeat(32)}` }],
    [
      "vault-raw-digest",
      "/missing/sign-raw-digest",
      { chain: "sui", curve: "ed25519", payloadHex: `0x${"11".repeat(32)}` },
    ],
    ["vault-typed-data", "/missing/sign-typed-data", {}],
    ["vault-user-operation", "/missing/sign-user-operation", {}],
    ["vault-authorization", "/missing/sign-authorization", {}],
    ["vault-solana", "/missing/sign-solana", {}],
  ] as const) {
    it(`${family} protects its mounted post-auth error branch`, async () => {
      const response = await vaultApp.request(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      expect(response.status).toBeGreaterThanOrEqual(400);
      expectNoStore(response);
    });
  }

  it("user-wallet signing protects each authenticated validation error", async () => {
    for (const path of ["/me/wallet/sign", "/me/wallet/sign-message"] as const) {
      const response = await userRoutes.request(path, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${personalSessionToken}`,
          "Content-Type": "application/json",
        },
        body: path.endsWith("sign-message") ? JSON.stringify({ message: "hello" }) : "{}",
      });
      expect(response.status).toBeGreaterThanOrEqual(400);
      expectNoStore(response);
    }
  });

  for (const method of ["personal_sign", "eth_signTypedData_v4"] as const) {
    it(`global-wallet ${method} protects its authenticated validation error`, async () => {
      const response = await globalWalletRoutes.request("/rpc", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${personalSessionToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ method }),
      });
      expect(response.status).toBeGreaterThanOrEqual(400);
      expectNoStore(response);
    });
  }

  it("audit read protects its mounted successful response", async () => {
    const { auditRoutes } = await import("../routes/audit");
    const auditApp = new Hono<{ Variables: AppVariables }>();
    auditApp.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    auditApp.route("/", auditRoutes);
    const response = await auditApp.request("/events");
    expect(response.status).toBe(200);
    expectNoStore(response);
    const invalid = await auditApp.request("/events?limit=not-a-number");
    expect(invalid.status).toBe(400);
    expectNoStore(invalid);
  });

  for (const [family, path, init] of [
    ["auth-identity-token", "/identity-token", { method: "GET" }],
    ["auth-refresh", "/refresh", { method: "POST", body: "{}" }],
    ["auth-oauth-exchange", "/oauth/exchange", { method: "POST", body: "{}" }],
    ["auth-provider-token", "/oauth/google/token", { method: "POST", body: "{}" }],
  ] as const) {
    it(`${family} protects its mounted validation or authorization error`, async () => {
      const response = await authRoutes.request(path, {
        ...init,
        headers: { "Content-Type": "application/json" },
      });
      expect(response.status).toBeGreaterThanOrEqual(400);
      expectNoStore(response);
    });
  }
});
