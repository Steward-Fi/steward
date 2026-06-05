import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenantAppClients, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const TENANT_ID = "auth-device-flow-tenant";
const OTHER_TENANT_ID = "auth-device-flow-other-tenant";
const CLIENT_ID = "device-cli";
const USER_ID = "11111111-1111-4111-8111-111111111111";
const USER_ADDRESS = `0x${"d".repeat(40)}`;

describe("OAuth device authorization flow", () => {
  let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
  let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "auth-device-flow-master";
    process.env.STEWARD_JWT_SECRET = "auth-device-flow-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "auth-device-flow-audit-hmac-key-with-enough-entropy";
    process.env.STEWARD_KDF_SALT =
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    process.env.APP_URL = "https://app.steward.test";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Device Flow Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(tenants).values({
      id: OTHER_TENANT_ID,
      name: "Other Device Flow Tenant",
      apiKeyHash: "other-hash",
    });
    await getDb()
      .insert(tenantAppClients)
      .values({
        id: CLIENT_ID,
        tenantId: TENANT_ID,
        name: "Device CLI",
        enabled: true,
        allowedBundleIds: ["com.example.device"],
        allowedPackageNames: ["com.example.device"],
      });
    await getDb().insert(users).values({
      id: USER_ID,
      email: "device-flow@example.test",
      emailVerified: true,
      walletAddress: USER_ADDRESS,
      walletChain: "ethereum",
    });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: TENANT_ID,
      role: "member",
    });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: OTHER_TENANT_ID,
      role: "member",
    });

    const auth = await import("../routes/auth");
    authRoutes = auth.authRoutes;
    createSessionToken = auth.createSessionToken;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_KDF_SALT;
    delete process.env.APP_URL;
  });

  async function userAuthHeader() {
    const token = await createSessionToken(USER_ADDRESS, TENANT_ID, {
      userId: USER_ID,
      email: "device-flow@example.test",
      authMethod: "email",
    });
    return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  }

  async function otherTenantUserAuthHeader() {
    const token = await createSessionToken(USER_ADDRESS, OTHER_TENANT_ID, {
      userId: USER_ID,
      email: "device-flow@example.test",
      authMethod: "email",
    });
    return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  }

  async function issueDeviceCode() {
    const response = await authRoutes.request("/device/code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_ID, client_id: CLIENT_ID }),
    });
    expect(response.status).toBe(200);
    return (await response.json()) as {
      device_code: string;
      user_code: string;
      verification_uri: string;
      interval: number;
      expires_in: number;
      client_id: string;
    };
  }

  it("issues app-client-bound device codes", async () => {
    const body = await issueDeviceCode();
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(body.verification_uri).toBe("https://app.steward.test/auth/device");
    expect(body.interval).toBe(5);
    expect(body.expires_in).toBe(600);
    expect(body.client_id).toBe(CLIENT_ID);
  });

  it("binds supplied native identifiers to enabled app-client allowlists", async () => {
    const issuedResponse = await authRoutes.request("/device/code", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Native-Bundle-Id": "com.example.device",
      },
      body: JSON.stringify({ tenantId: TENANT_ID, client_id: CLIENT_ID }),
    });
    expect(issuedResponse.status).toBe(200);
    const issued = (await issuedResponse.json()) as {
      device_code: string;
      user_code: string;
      native_bundle_id: string;
    };
    expect(issued.native_bundle_id).toBe("com.example.device");

    const approve = await authRoutes.request("/device/verify", {
      method: "POST",
      headers: await userAuthHeader(),
      body: JSON.stringify({ user_code: issued.user_code, action: "approve" }),
    });
    expect(approve.status).toBe(200);

    const wrongNativePoll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Native-Bundle-Id": "com.attacker.device",
      },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(wrongNativePoll.status).toBe(401);
    expect(await wrongNativePoll.json()).toMatchObject({ ok: false, error: "invalid_client" });

    const token = await authRoutes.request("/device/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Native-Bundle-Id": "com.example.device",
      },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(token.status).toBe(200);
    const tokenBody = (await token.json()) as { access_token: string };
    expect(tokenBody.access_token).toBeTruthy();
  });

  it("rejects malformed or unbound native identifiers during token polling", async () => {
    const issued = await issueDeviceCode();
    const approve = await authRoutes.request("/device/verify", {
      method: "POST",
      headers: await userAuthHeader(),
      body: JSON.stringify({ user_code: issued.user_code, action: "approve" }),
    });
    expect(approve.status).toBe(200);

    const malformedNativePoll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Native-Package-Name": "*",
      },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(malformedNativePoll.status).toBe(401);
    expect(await malformedNativePoll.json()).toMatchObject({
      ok: false,
      error: "invalid_client",
    });

    const unboundNativePoll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Native-Bundle-Id": "com.example.device",
      },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(unboundNativePoll.status).toBe(401);
    expect(await unboundNativePoll.json()).toMatchObject({
      ok: false,
      error: "invalid_client",
    });

    const token = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(token.status).toBe(200);
    expect(await token.json()).toMatchObject({ ok: true });
  });

  it("rejects malformed and unallowlisted native identifiers at device-code issuance", async () => {
    const malformed = await authRoutes.request("/device/code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        client_id: CLIENT_ID,
        native_bundle_id: "*",
      }),
    });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({
      ok: false,
      error: "native bundle id is invalid",
    });

    const unallowed = await authRoutes.request("/device/code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        client_id: CLIENT_ID,
        native_package_name: "com.attacker.device",
      }),
    });
    expect(unallowed.status).toBe(400);
    expect(await unallowed.json()).toMatchObject({
      ok: false,
      error: "native package name is not allowed for this app client",
    });
  });

  it("returns authorization_pending then slow_down while unapproved", async () => {
    const issued = await issueDeviceCode();
    const first = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(first.status).toBe(400);
    expect(await first.json()).toMatchObject({ ok: false, error: "authorization_pending" });

    const second = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(second.status).toBe(400);
    expect(await second.json()).toMatchObject({ ok: false, error: "slow_down", interval: 10 });
  });

  it("approves a user code and consumes it for a session token", async () => {
    const issued = await issueDeviceCode();
    const approve = await authRoutes.request("/device/verify", {
      method: "POST",
      headers: await userAuthHeader(),
      body: JSON.stringify({ user_code: issued.user_code, action: "approve" }),
    });
    expect(approve.status).toBe(200);
    expect(await approve.json()).toMatchObject({ ok: true, status: "approved" });

    const token = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(token.status).toBe(200);
    const tokenBody = (await token.json()) as {
      token: string;
      access_token: string;
      refreshToken: string;
      user: { id: string; email: string };
    };
    expect(tokenBody.token).toBe(tokenBody.access_token);
    expect(tokenBody.refreshToken).toBeTruthy();
    expect(tokenBody.user.id).toBe(USER_ID);

    const replay = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ ok: false, error: "expired_token" });
  });

  it("returns access_denied for denied device codes", async () => {
    const issued = await issueDeviceCode();
    const deny = await authRoutes.request("/device/verify", {
      method: "POST",
      headers: await userAuthHeader(),
      body: JSON.stringify({ userCode: issued.user_code, action: "deny" }),
    });
    expect(deny.status).toBe(200);

    const poll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(poll.status).toBe(400);
    expect(await poll.json()).toMatchObject({ ok: false, error: "access_denied" });
  });

  it("enforces app-client binding on token polling", async () => {
    const issued = await issueDeviceCode();
    const poll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: "other-client",
      }),
    });
    expect(poll.status).toBe(401);
    expect(await poll.json()).toMatchObject({ ok: false, error: "invalid_client" });
  });

  it("requires the bound client id instead of allowing anonymous polling for client-bound codes", async () => {
    const issued = await issueDeviceCode();
    const poll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
      }),
    });

    expect(poll.status).toBe(401);
    expect(await poll.json()).toMatchObject({ ok: false, error: "invalid_client" });
  });

  it("rejects approval from a browser session in a different tenant", async () => {
    const issued = await issueDeviceCode();
    const approve = await authRoutes.request("/device/verify", {
      method: "POST",
      headers: await otherTenantUserAuthHeader(),
      body: JSON.stringify({ user_code: issued.user_code, action: "approve" }),
    });

    expect(approve.status).toBe(403);
    expect(await approve.json()).toMatchObject({
      ok: false,
      error: "Device code tenant mismatch",
    });

    const poll = await authRoutes.request("/device/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: issued.device_code,
        client_id: CLIENT_ID,
      }),
    });
    expect(poll.status).toBe(400);
    expect(await poll.json()).toMatchObject({ ok: false, error: "authorization_pending" });
  });
});
