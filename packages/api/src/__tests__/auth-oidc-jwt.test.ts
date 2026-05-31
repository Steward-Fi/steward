import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  accounts,
  closeDb,
  getDb,
  tenantConfigs,
  tenantSsoDomains,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const TENANT_A = `oidc-tenant-a-${Date.now()}`;
const TENANT_B = `oidc-tenant-b-${Date.now()}`;
const TENANT_CLOSED = `oidc-tenant-closed-${Date.now()}`;
const TENANT_MIXED_CASE_DISABLED = `oidc-tenant-disabled-${Date.now()}`;
const TENANT_AZP = `oidc-tenant-azp-${Date.now()}`;
const AZP_CLIENT_ID = "azp-client-id";
const ISSUER = "https://issuer.example.test";
const JWKS_URI = "https://issuer.example.test/.well-known/jwks.json";
const PROVIDER_ID = "primary";
const ORIGINAL_FETCH = globalThis.fetch;
const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

describe("OIDC JWT auth", () => {
  let authRoutes: typeof import("../routes/auth").authRoutes;
  let privateKey: CryptoKey | Uint8Array;
  let publicJwk: Record<string, unknown>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.NODE_ENV = "test";
    process.env.STEWARD_MASTER_PASSWORD = "auth-oidc-jwt-master-password";
    process.env.STEWARD_JWT_SECRET = "auth-oidc-jwt-secret-with-enough-entropy";
    process.env.STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH = "true";
    // Audit chain now requires an HMAC key; supply a deterministic test key so
    // writeAuditEvent during OIDC login does not reject the exchange.
    process.env.STEWARD_AUDIT_HMAC_KEY =
      process.env.STEWARD_AUDIT_HMAC_KEY ?? "auth-oidc-jwt-audit-hmac-key-with-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const keyPair = await generateKeyPair("RS256");
    privateKey = keyPair.privateKey;
    publicJwk = await exportJWK(keyPair.publicKey);
    publicJwk.kid = "test-key";
    publicJwk.alg = "RS256";

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === JWKS_URI) return Response.json({ keys: [publicJwk] });
      return ORIGINAL_FETCH(input);
    }) as typeof fetch;

    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_A, name: "OIDC Tenant A", apiKeyHash: "hash-a" },
        { id: TENANT_B, name: "OIDC Tenant B", apiKeyHash: "hash-b" },
        { id: TENANT_CLOSED, name: "OIDC Tenant Closed", apiKeyHash: "hash-closed" },
        {
          id: TENANT_MIXED_CASE_DISABLED,
          name: "OIDC Tenant Mixed Case Disabled",
          apiKeyHash: "hash-disabled",
        },
        { id: TENANT_AZP, name: "OIDC Tenant AZP", apiKeyHash: "hash-azp" },
      ]);
    await getDb()
      .insert(tenantConfigs)
      .values([
        {
          tenantId: TENANT_A,
          joinMode: "open",
          oidcProviders: [
            {
              id: PROVIDER_ID,
              enabled: true,
              issuer: ISSUER,
              audience: ["aud-a"],
              jwksUri: JWKS_URI,
              allowedAlgs: ["RS256"],
            },
          ],
        },
        {
          tenantId: TENANT_B,
          joinMode: "open",
          oidcProviders: [
            {
              id: PROVIDER_ID,
              enabled: true,
              issuer: ISSUER,
              audience: ["aud-b"],
              jwksUri: JWKS_URI,
              allowedAlgs: ["RS256"],
            },
          ],
        },
        {
          tenantId: TENANT_CLOSED,
          joinMode: "closed",
          oidcProviders: [
            {
              id: PROVIDER_ID,
              enabled: true,
              issuer: ISSUER,
              audience: ["aud-closed"],
              jwksUri: JWKS_URI,
              allowedAlgs: ["RS256"],
            },
          ],
        },
        {
          tenantId: TENANT_MIXED_CASE_DISABLED,
          joinMode: "open",
          authAbuseConfig: { loginMethods: { oidc: { acmesso: false } } },
          oidcProviders: [
            {
              id: "AcmeSSO",
              enabled: true,
              issuer: ISSUER,
              audience: ["aud-disabled"],
              jwksUri: JWKS_URI,
              allowedAlgs: ["RS256"],
            },
          ],
        },
        {
          tenantId: TENANT_AZP,
          joinMode: "open",
          // Multi-audience provider with a configured clientId: exercises the
          // OIDC §3.1.3.7 azp (authorized party) enforcement in verifyOidcJwt.
          oidcProviders: [
            {
              id: PROVIDER_ID,
              enabled: true,
              issuer: ISSUER,
              audience: ["aud-azp", "aud-azp-second"],
              clientId: AZP_CLIENT_ID,
              jwksUri: JWKS_URI,
              allowedAlgs: ["RS256"],
            },
          ],
        },
      ]);
    await getDb()
      .insert(tenantSsoDomains)
      .values([
        {
          tenantId: TENANT_A,
          domain: "a.example.test",
          verificationToken: "token-a",
          status: "verified",
          verifiedAt: new Date(),
        },
        {
          tenantId: TENANT_B,
          domain: "b.example.test",
          verificationToken: "token-b",
          status: "verified",
          verifiedAt: new Date(),
        },
        {
          tenantId: TENANT_CLOSED,
          domain: "closed.example.test",
          verificationToken: "token-closed",
          status: "verified",
          verifiedAt: new Date(),
        },
        {
          tenantId: TENANT_AZP,
          domain: "azp.example.test",
          verificationToken: "token-azp",
          status: "verified",
          verifiedAt: new Date(),
        },
      ]);
    ({ authRoutes } = await import("../routes/auth"));
  }, 30_000);

  afterAll(async () => {
    globalThis.fetch = ORIGINAL_FETCH;
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    if (ORIGINAL_NODE_ENV === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = ORIGINAL_NODE_ENV;
    }
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  async function oidcToken(
    subject: string,
    audience: string,
    claims: Record<string, unknown> = {},
  ) {
    const domain =
      audience === "aud-b"
        ? "b.example.test"
        : audience === "aud-closed"
          ? "closed.example.test"
          : "a.example.test";
    return new SignJWT({
      sub: subject,
      email: `${subject}@${domain}`,
      email_verified: true,
      name: subject,
      ...claims,
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .setIssuer(ISSUER)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  }

  it("exchanges a valid tenant OIDC token for a Steward session", async () => {
    const token = await oidcToken("external-user-1", "aud-a");

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_A, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      token: string;
      refreshToken: string;
      expiresIn: number;
      user: { id: string; oidcProviderId: string };
    };
    expect(body.ok).toBe(true);
    expect(body.expiresIn).toBe(900);
    expect(body.refreshToken).toBeTruthy();
    expect(body.user.oidcProviderId).toBe(PROVIDER_ID);
  });

  it("rejects unverified OIDC email before provisioning a Steward session", async () => {
    const token = await oidcToken("unverified-email-user", "aud-a", {
      email: "claimed@a.example.test",
      email_verified: false,
    });

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_A, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("verified email claim");
  });

  it("rejects OIDC JWT emails outside the tenant verified SSO domain", async () => {
    const token = await oidcToken("wrong-domain-user", "aud-a", {
      email: "wrong-domain@evil.example.test",
      email_verified: true,
    });

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_A, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("email domain is not verified");
  });

  it("rejects a token with the wrong audience for the tenant provider", async () => {
    const token = await oidcToken("external-user-2", "aud-a");

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_B, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(401);
  });

  it("enforces disabled OIDC login methods for mixed-case provider ids", async () => {
    const token = await oidcToken("disabled-provider-user", "aud-disabled");

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_MIXED_CASE_DISABLED,
        providerId: "AcmeSSO",
        token,
      }),
    });

    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toBe("OIDC login is disabled for this tenant");
  });

  it("blocks IPv4-mapped IPv6 JWKS destinations", async () => {
    const { assertPublicJwksDestination } = await import("@stwd/auth");
    await expect(assertPublicJwksDestination("https://[::ffff:7f00:1]/jwks.json")).rejects.toThrow(
      "public",
    );
  });

  it("rejects closed-tenant JIT before creating durable identity rows", async () => {
    const beforeUsers = await getDb().select().from(users);
    const beforeAccounts = await getDb().select().from(accounts);
    const token = await oidcToken("closed-tenant-user", "aud-closed");

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_CLOSED, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(403);
    const afterUsers = await getDb().select().from(users);
    const afterAccounts = await getDb().select().from(accounts);
    expect(afterUsers).toHaveLength(beforeUsers.length);
    expect(afterAccounts).toHaveLength(beforeAccounts.length);
  });

  it("keeps the same external subject isolated across tenants", async () => {
    const beforeAccounts = await getDb().select().from(accounts);
    const tokenA = await oidcToken("same-subject", "aud-a");
    const tokenB = await oidcToken("same-subject", "aud-b");

    const responseA = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_A, providerId: PROVIDER_ID, token: tokenA }),
    });
    const responseB = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_B, providerId: PROVIDER_ID, token: tokenB }),
    });

    expect(responseA.status).toBe(200);
    expect(responseB.status).toBe(200);
    const bodyA = (await responseA.json()) as { user: { id: string } };
    const bodyB = (await responseB.json()) as { user: { id: string } };
    expect(bodyA.user.id).not.toBe(bodyB.user.id);

    const oidcAccounts = await getDb().select().from(accounts);
    expect(oidcAccounts.filter((account) => account.provider === "oidc")).toHaveLength(
      beforeAccounts.filter((account) => account.provider === "oidc").length + 2,
    );
    const tenantLinks = await getDb().select().from(userTenants);
    expect(
      tenantLinks.some((link) => link.userId === bodyA.user.id && link.tenantId === TENANT_A),
    ).toBe(true);
    expect(
      tenantLinks.some((link) => link.userId === bodyB.user.id && link.tenantId === TENANT_B),
    ).toBe(true);
  });

  // ─── OIDC §3.1.3.7 azp (authorized party) enforcement ────────────────────
  async function azpToken(subject: string, audience: string | string[], azp?: string) {
    const claims: Record<string, unknown> = {
      sub: subject,
      email: `${subject}@azp.example.test`,
      email_verified: true,
      name: subject,
    };
    if (azp !== undefined) claims.azp = azp;
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .setIssuer(ISSUER)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  }

  it("rejects a token whose azp does not match the configured client_id", async () => {
    const token = await azpToken("azp-mismatch-user", "aud-azp", "wrong-client");

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_AZP, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("azp");
  });

  it("rejects a multi-audience token that lacks an azp claim", async () => {
    const token = await azpToken("multi-aud-no-azp-user", ["aud-azp", "aud-azp-second"]);

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_AZP, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("configured client_id");
  });

  it("accepts a single-audience token whose azp matches the client_id", async () => {
    const token = await azpToken("azp-match-user", "aud-azp", AZP_CLIENT_ID);

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_AZP, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it("rejects a single-audience token that omits the configured client_id", async () => {
    const token = await azpToken("azp-absent-user", "aud-azp");

    const response = await authRoutes.request("/jwt/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_AZP, providerId: PROVIDER_ID, token }),
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.error).toContain("audience does not include the configured client_id");
  });
});
