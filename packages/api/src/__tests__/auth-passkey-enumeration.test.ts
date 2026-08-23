import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { authenticators, closeDb, getDb, tenantConfigs, tenants, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

setDefaultTimeout(120_000);

const ENABLED_TENANT_ID = "passkey-enumeration-enabled";
const DISABLED_TENANT_ID = "passkey-enumeration-disabled";
const KNOWN_EMAIL = "passkey-known@example.test";
const NO_PASSKEY_EMAIL = "passkey-without-credential@example.test";
const UNKNOWN_EMAIL = "passkey-unknown@example.test";
const SECRET_CREDENTIAL_ID = "credential-id-must-never-leave-options-route";

type LoginOptions = {
  challenge: string;
  challengeId: string;
  rpId: string;
  timeout: number;
  userVerification: string;
  allowCredentials: Array<{ id: string }>;
  [key: string]: unknown;
};

describe("passkey login options privacy", () => {
  let app: Hono;
  let getAuthChallengeStore: Awaited<typeof import("../routes/auth")>["getAuthChallengeStore"];
  let knownUserId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    process.env.STEWARD_JWT_SECRET = "passkey-enumeration-jwt-secret-with-enough-entropy";
    process.env.STEWARD_MASTER_PASSWORD = "passkey-enumeration-master-password";
    process.env.STEWARD_KDF_SALT = "dGVzdC1zYWx0LXRlc3Qtc2FsdA==";
    process.env.PASSKEY_RP_ID = "steward.fi";
    process.env.PASSKEY_ORIGIN = "https://steward.fi";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    await getDb()
      .insert(tenants)
      .values([
        { id: ENABLED_TENANT_ID, name: "Passkey enabled", apiKeyHash: "passkey-enabled" },
        { id: DISABLED_TENANT_ID, name: "Passkey disabled", apiKeyHash: "passkey-disabled" },
      ]);
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: DISABLED_TENANT_ID,
        authAbuseConfig: { loginMethods: { passkey: false } },
      });
    const [knownUser] = await getDb()
      .insert(users)
      .values({ email: KNOWN_EMAIL, emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(users).values({ email: NO_PASSKEY_EMAIL, emailVerified: true });
    knownUserId = knownUser.id;
    await getDb()
      .insert(authenticators)
      .values({
        userId: knownUserId,
        credentialId: SECRET_CREDENTIAL_ID,
        credentialPublicKey: "credential-public-key-must-also-remain-private",
        counter: 7,
        credentialDeviceType: "singleDevice",
        credentialBackedUp: false,
        transports: ["internal"],
      });

    const auth = await import("../routes/auth");
    getAuthChallengeStore = auth.getAuthChallengeStore;
    app = new Hono().route("/auth", auth.authRoutes);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_KDF_SALT;
    delete process.env.PASSKEY_RP_ID;
    delete process.env.PASSKEY_ORIGIN;
  });

  async function requestOptions(email: string, tenantId = ENABLED_TENANT_ID) {
    return app.request("/auth/passkey/login/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, tenantId }),
    });
  }

  function assertDiscoverableCredentialShape(options: LoginOptions) {
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(options.challengeId).toBe(options.challenge);
    expect(options.rpId).toBe("steward.fi");
    expect(options.timeout).toBeGreaterThan(0);
    expect(options.userVerification).toBe("required");
    expect(options.allowCredentials).toEqual([]);
  }

  it("returns the same non-enumerating shape for passkey, no-passkey, and unknown emails", async () => {
    const [knownResponse, noPasskeyResponse, unknownResponse] = await Promise.all([
      requestOptions(`  ${KNOWN_EMAIL.toUpperCase()}  `),
      requestOptions(NO_PASSKEY_EMAIL),
      requestOptions(UNKNOWN_EMAIL),
    ]);
    expect(knownResponse.status).toBe(200);
    expect(noPasskeyResponse.status).toBe(200);
    expect(unknownResponse.status).toBe(200);

    const known = (await knownResponse.json()) as LoginOptions;
    const noPasskey = (await noPasskeyResponse.json()) as LoginOptions;
    const unknown = (await unknownResponse.json()) as LoginOptions;
    assertDiscoverableCredentialShape(known);
    assertDiscoverableCredentialShape(noPasskey);
    assertDiscoverableCredentialShape(unknown);
    expect(Object.keys(known).sort()).toEqual(Object.keys(noPasskey).sort());
    expect(Object.keys(known).sort()).toEqual(Object.keys(unknown).sort());

    for (const payload of [known, noPasskey, unknown]) {
      const serialized = JSON.stringify(payload);
      expect(serialized).not.toContain(SECRET_CREDENTIAL_ID);
      expect(serialized).not.toContain("credential-public-key-must-also-remain-private");
      expect(serialized).not.toContain(knownUserId);
    }

    expect(
      await getAuthChallengeStore().get(`passkey-login:${KNOWN_EMAIL}:${known.challengeId}`),
    ).toBe(known.challenge);
    expect(
      await getAuthChallengeStore().get(
        `passkey-login:${NO_PASSKEY_EMAIL}:${noPasskey.challengeId}`,
      ),
    ).toBe(noPasskey.challenge);
    expect(
      await getAuthChallengeStore().get(`passkey-login:${UNKNOWN_EMAIL}:${unknown.challengeId}`),
    ).toBe(unknown.challenge);
  });

  it("honors explicit tenant existence and passkey login-method boundaries", async () => {
    const missingTenant = await requestOptions(KNOWN_EMAIL, "passkey-enumeration-missing");
    expect(missingTenant.status).toBe(404);

    const disabled = await requestOptions(KNOWN_EMAIL, DISABLED_TENANT_ID);
    expect(disabled.status).toBe(403);
    expect(await disabled.json()).toMatchObject({
      ok: false,
      error: "passkey login is disabled for this tenant",
    });
  });
});
