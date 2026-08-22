import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { authenticators, closeDb, getDb, tenantConfigs, tenants, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

setDefaultTimeout(120_000);

const ENABLED_TENANT_ID = "passkey-enumeration-enabled";
const DISABLED_TENANT_ID = "passkey-enumeration-disabled";
const KNOWN_EMAIL = "passkey-known@example.test";
const NO_PASSKEY_EMAIL = "passkey-none@example.test";
const OTHER_EMAIL = "passkey-other@example.test";
const UNKNOWN_EMAIL = "passkey-unknown@example.test";
const KNOWN_CREDENTIAL_ID = "credential-id-for-known-email";
const SECOND_KNOWN_CREDENTIAL_ID = "second-credential-id-for-known-email";
const OTHER_CREDENTIAL_ID = "credential-id-for-other-email";

type LoginOptions = {
  challenge: string;
  challengeId: string;
  rpId: string;
  timeout: number;
  userVerification: string;
  allowCredentials: Array<{ id: string; transports?: string[] }>;
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
    const [knownUser, otherUser] = await getDb()
      .insert(users)
      .values([
        { email: KNOWN_EMAIL, emailVerified: true },
        { email: OTHER_EMAIL, emailVerified: true },
        { email: NO_PASSKEY_EMAIL, emailVerified: true },
      ])
      .returning({ id: users.id });
    knownUserId = knownUser.id;
    await getDb()
      .insert(authenticators)
      .values([
        {
          userId: knownUserId,
          credentialId: KNOWN_CREDENTIAL_ID,
          credentialPublicKey: "known-credential-public-key",
          counter: 7,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
          transports: ["internal"],
        },
        {
          userId: knownUserId,
          credentialId: SECOND_KNOWN_CREDENTIAL_ID,
          credentialPublicKey: "second-known-credential-public-key",
          counter: 0,
          credentialDeviceType: "multiDevice",
          credentialBackedUp: true,
          transports: ["hybrid"],
        },
        {
          userId: otherUser.id,
          credentialId: OTHER_CREDENTIAL_ID,
          credentialPublicKey: "other-credential-public-key",
          counter: 2,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
          transports: ["internal"],
        },
      ]);

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

  function assertAuthenticationOptionsShape(options: LoginOptions) {
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(options.challengeId).toBe(options.challenge);
    expect(options.rpId).toBe("steward.fi");
    expect(options.timeout).toBeGreaterThan(0);
    expect(options.userVerification).toBe("required");
  }

  it("returns only credential ids and transports bound to the normalized typed email", async () => {
    const knownResponse = await requestOptions(`  ${KNOWN_EMAIL.toUpperCase()}  `);
    expect(knownResponse.status).toBe(200);

    const known = (await knownResponse.json()) as LoginOptions;
    assertAuthenticationOptionsShape(known);
    expect(known.allowCredentials).toHaveLength(2);
    expect(known.allowCredentials.map(({ id }) => id).sort()).toEqual(
      [KNOWN_CREDENTIAL_ID, SECOND_KNOWN_CREDENTIAL_ID].sort(),
    );
    expect(known.allowCredentials).toContainEqual({
      id: KNOWN_CREDENTIAL_ID,
      transports: ["internal"],
      type: "public-key",
    });
    expect(known.allowCredentials).toContainEqual({
      id: SECOND_KNOWN_CREDENTIAL_ID,
      transports: ["hybrid"],
      type: "public-key",
    });

    const serialized = JSON.stringify(known);
    expect(serialized).not.toContain(OTHER_CREDENTIAL_ID);
    expect(serialized).not.toContain("known-credential-public-key");
    expect(serialized).not.toContain("other-credential-public-key");
    expect(serialized).not.toContain(knownUserId);

    expect(
      await getAuthChallengeStore().get(`passkey-login:${KNOWN_EMAIL}:${known.challengeId}`),
    ).toBe(known.challenge);
  });

  it("returns one generic unavailable response for unknown and no-passkey emails", async () => {
    const [unknownResponse, noPasskeyResponse] = await Promise.all([
      requestOptions(UNKNOWN_EMAIL),
      requestOptions(NO_PASSKEY_EMAIL),
    ]);

    expect(unknownResponse.status).toBe(404);
    expect(noPasskeyResponse.status).toBe(404);
    const expected = {
      ok: false,
      error: "Passkey sign-in is unavailable for this email",
    };
    expect(await unknownResponse.json()).toEqual(expected);
    expect(await noPasskeyResponse.json()).toEqual(expected);
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
