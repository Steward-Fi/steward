import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { authenticators, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

setDefaultTimeout(120_000);

const TENANT_ID = "passkey-register-recovery";
const EXISTING_EMAIL = "passkey-existing@example.test";
const NEW_EMAIL = "passkey-new@example.test";
const EXISTING_CREDENTIAL_ID = "existing-passkey-credential";
const EXISTING_GRANT = "existing-passkey-email-grant";
const NEW_GRANT = "new-passkey-email-grant";

type RegistrationOptions = {
  challenge: string;
  excludeCredentials?: Array<{ id: string; type: "public-key" }>;
  user: { id: string; name: string };
};

describe("passkey verified-email registration recovery", () => {
  let app: Hono;
  let auth: Awaited<typeof import("../routes/auth")>;
  let existingUserId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    process.env.STEWARD_JWT_SECRET = "passkey-register-recovery-jwt-secret-with-enough-entropy";
    process.env.STEWARD_MASTER_PASSWORD = "passkey-register-recovery-master-password";
    process.env.STEWARD_KDF_SALT = "dGVzdC1zYWx0LXRlc3Qtc2FsdA==";
    process.env.PASSKEY_RP_ID = "steward.fi";
    process.env.PASSKEY_ORIGIN = "https://steward.fi";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Passkey recovery", apiKeyHash: "passkey-recovery" });
    const [existingUser] = await getDb()
      .insert(users)
      .values({ email: EXISTING_EMAIL, emailVerified: true })
      .returning({ id: users.id });
    existingUserId = existingUser.id;
    await getDb().insert(userTenants).values({
      userId: existingUserId,
      tenantId: TENANT_ID,
      role: "member",
    });
    await getDb()
      .insert(authenticators)
      .values({
        userId: existingUserId,
        credentialId: EXISTING_CREDENTIAL_ID,
        credentialPublicKey: "existing-passkey-public-key",
        counter: 1,
        credentialDeviceType: "singleDevice",
        credentialBackedUp: false,
        transports: ["internal"],
      });

    auth = await import("../routes/auth");
    app = new Hono().route("/auth", auth.authRoutes);
    await auth._seedEmailGrantForTests(EXISTING_GRANT, EXISTING_EMAIL, TENANT_ID);
    await auth._seedEmailGrantForTests(NEW_GRANT, NEW_EMAIL, TENANT_ID);
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

  function requestWithGrant(email: string, emailGrant: string) {
    return app.request("/auth/passkey/register/options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({ email, emailGrant }),
    });
  }

  it("returns a stable 409 for a verified-email grant when a passkey already exists", async () => {
    const first = await requestWithGrant(EXISTING_EMAIL, EXISTING_GRANT);
    expect(first.status).toBe(409);
    expect(await first.json()).toEqual({
      ok: false,
      error: "A passkey already exists for this email. Sign in with it instead.",
      code: "passkey_already_registered",
    });

    // register/options must only peek at the grant. A retry still reaches the
    // same conflict rather than failing as an expired/consumed grant.
    const retry = await requestWithGrant(EXISTING_EMAIL, EXISTING_GRANT);
    expect(retry.status).toBe(409);
    expect(await retry.json()).toMatchObject({ code: "passkey_already_registered" });
  });

  it("returns WebAuthn options for a verified new-email enrollment", async () => {
    const response = await requestWithGrant(NEW_EMAIL, NEW_GRANT);
    expect(response.status).toBe(200);
    const options = (await response.json()) as RegistrationOptions;
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(options.user.name).toBe(NEW_EMAIL);
    expect(options.excludeCredentials ?? []).toEqual([]);
  });

  it("keeps authenticated multi-device passkey enrollment available", async () => {
    const token = await auth.createSessionToken(
      "0x0000000000000000000000000000000000000001",
      TENANT_ID,
      {
        userId: existingUserId,
        email: EXISTING_EMAIL,
        authMethod: "passkey",
        factorEnrollmentVerifiedAt: Date.now(),
      },
    );
    const response = await app.request("/auth/passkey/register/options", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ email: EXISTING_EMAIL }),
    });

    expect(response.status).toBe(200);
    const options = (await response.json()) as RegistrationOptions;
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(options.excludeCredentials).toContainEqual({
      id: EXISTING_CREDENTIAL_ID,
      type: "public-key",
    });
  });
});
