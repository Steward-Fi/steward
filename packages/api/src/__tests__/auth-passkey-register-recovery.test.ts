import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { authenticators, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

setDefaultTimeout(120_000);

const TENANT_ID = "passkey-register-recovery";
const CURRENT_ORIGIN = "https://steward.fi";
const CURRENT_RP_ID = "steward.fi";
const OTHER_RP_ID = "waifu.fun";
const SAME_RP_EMAIL = "passkey-same-rp@example.test";
const CROSS_RP_EMAIL = "passkey-cross-rp@example.test";
const LEGACY_EMAIL = "passkey-legacy@example.test";
const UNKNOWN_EMAIL = "passkey-unknown@example.test";
const SAME_RP_CREDENTIAL_ID = "same-rp-passkey-credential";
const CROSS_RP_CREDENTIAL_ID = "cross-rp-passkey-credential";
const LEGACY_CREDENTIAL_ID = "legacy-passkey-credential";

type RegistrationOptions = {
  challenge: string;
  rp: { id: string };
  excludeCredentials?: Array<{ id: string; type: "public-key" }>;
  user: { id: string; name: string };
};

describe("passkey verified-email registration recovery", () => {
  let app: Hono;
  let auth: Awaited<typeof import("../routes/auth")>;
  let sameRpUserId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    process.env.STEWARD_JWT_SECRET = "passkey-register-recovery-jwt-secret-with-enough-entropy";
    process.env.STEWARD_MASTER_PASSWORD = "passkey-register-recovery-master-password";
    process.env.STEWARD_KDF_SALT = "dGVzdC1zYWx0LXRlc3Qtc2FsdA==";
    process.env.PASSKEY_RP_ID = CURRENT_RP_ID;
    process.env.PASSKEY_ORIGIN = CURRENT_ORIGIN;
    process.env.PASSKEY_ALLOWED_ORIGINS = `${CURRENT_ORIGIN},https://${OTHER_RP_ID}`;

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Passkey recovery", apiKeyHash: "passkey-recovery" });
    const [sameRpUser, crossRpUser, legacyUser] = await getDb()
      .insert(users)
      .values([
        { email: SAME_RP_EMAIL, emailVerified: true },
        { email: CROSS_RP_EMAIL, emailVerified: true },
        { email: LEGACY_EMAIL, emailVerified: true },
      ])
      .returning({ id: users.id });
    sameRpUserId = sameRpUser.id;
    await getDb()
      .insert(userTenants)
      .values(
        [sameRpUser, crossRpUser, legacyUser].map((user) => ({
          userId: user.id,
          tenantId: TENANT_ID,
          role: "member" as const,
        })),
      );
    await getDb()
      .insert(authenticators)
      .values([
        {
          userId: sameRpUser.id,
          credentialId: SAME_RP_CREDENTIAL_ID,
          credentialPublicKey: "same-rp-passkey-public-key",
          rpId: CURRENT_RP_ID,
          counter: 1,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
          transports: ["internal"],
        },
        {
          userId: crossRpUser.id,
          credentialId: CROSS_RP_CREDENTIAL_ID,
          credentialPublicKey: "cross-rp-passkey-public-key",
          rpId: OTHER_RP_ID,
          counter: 1,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
          transports: ["internal"],
        },
        {
          userId: legacyUser.id,
          credentialId: LEGACY_CREDENTIAL_ID,
          credentialPublicKey: "legacy-passkey-public-key",
          // NULL is the deliberate migration state for pre-0114 rows.
          rpId: null,
          counter: 1,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
          transports: ["internal"],
        },
      ]);

    auth = await import("../routes/auth");
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
    delete process.env.PASSKEY_ALLOWED_ORIGINS;
  });

  async function requestWithGrant(email: string, grant: string) {
    await auth._seedEmailGrantForTests(grant, email, TENANT_ID);
    return app.request("/auth/passkey/register/options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: CURRENT_ORIGIN,
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({ email, emailGrant: grant }),
    });
  }

  it("returns a stable same-RP 409 without consuming the verified-email grant", async () => {
    const grant = "same-rp-email-grant";
    await auth._seedEmailGrantForTests(grant, SAME_RP_EMAIL, TENANT_ID);

    const first = await app.request("/auth/passkey/register/options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: CURRENT_ORIGIN,
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({ email: SAME_RP_EMAIL, emailGrant: grant }),
    });
    expect(first.status).toBe(409);
    expect(await first.json()).toEqual({
      ok: false,
      error: "A passkey already exists for this email. Sign in with it instead.",
      code: "passkey_already_registered",
    });

    // register/options only peeks. A retry reaches the same recovery contract
    // instead of turning the valid grant into an expired-grant error.
    const retry = await app.request("/auth/passkey/register/options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: CURRENT_ORIGIN,
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({ email: SAME_RP_EMAIL, emailGrant: grant }),
    });
    expect(retry.status).toBe(409);
    expect(await retry.json()).toMatchObject({ code: "passkey_already_registered" });
  });

  it("allows cross-RP registration and omits the other RP credential from exclusions", async () => {
    const response = await requestWithGrant(CROSS_RP_EMAIL, "cross-rp-email-grant");
    expect(response.status).toBe(200);
    const options = (await response.json()) as RegistrationOptions;
    expect(options.rp.id).toBe(CURRENT_RP_ID);
    expect(options.excludeCredentials ?? []).toEqual([]);
    expect(JSON.stringify(options)).not.toContain(CROSS_RP_CREDENTIAL_ID);
  });

  it("does not guess legacy RP provenance and lets the browser adjudicate it", async () => {
    const response = await requestWithGrant(LEGACY_EMAIL, "legacy-email-grant");
    expect(response.status).toBe(200);
    const options = (await response.json()) as RegistrationOptions;
    expect(options.rp.id).toBe(CURRENT_RP_ID);
    expect(options.excludeCredentials).toContainEqual({
      id: LEGACY_CREDENTIAL_ID,
      type: "public-key",
    });
  });

  it("returns fresh registration options for an unknown verified account", async () => {
    const response = await requestWithGrant(UNKNOWN_EMAIL, "unknown-email-grant");
    expect(response.status).toBe(200);
    const options = (await response.json()) as RegistrationOptions;
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(options.user.name).toBe(UNKNOWN_EMAIL);
    expect(options.excludeCredentials ?? []).toEqual([]);

    const [created] = await getDb().select().from(users).where(eq(users.email, UNKNOWN_EMAIL));
    expect(created?.email).toBe(UNKNOWN_EMAIL);
  });

  it("keeps authenticated same-RP multi-device enrollment available", async () => {
    const token = await auth.createSessionToken(
      "0x0000000000000000000000000000000000000001",
      TENANT_ID,
      {
        userId: sameRpUserId,
        email: SAME_RP_EMAIL,
        authMethod: "passkey",
        factorEnrollmentVerifiedAt: Date.now(),
      },
    );
    const response = await app.request("/auth/passkey/register/options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: CURRENT_ORIGIN,
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ email: SAME_RP_EMAIL }),
    });

    expect(response.status).toBe(200);
    const options = (await response.json()) as RegistrationOptions;
    expect(options.excludeCredentials).toContainEqual({
      id: SAME_RP_CREDENTIAL_ID,
      type: "public-key",
    });
  });
});
