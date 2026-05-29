import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { generateApiKey } from "@stwd/auth";
import { closeDb, getDb, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const TENANT_ID = "tenant-oidc-providers";

describe("tenant-admin OIDC provider config routes", () => {
  let tenantConfigRoutes: typeof import("../routes/tenant-config").tenantConfigRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let ownerId = "";
  let memberId = "";
  let apiKey = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "tenant-oidc-providers-master-password";
    process.env.STEWARD_JWT_SECRET = "tenant-oidc-providers-jwt-secret";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const keyPair = generateApiKey();
    apiKey = keyPair.key;
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Tenant OIDC Providers",
      apiKeyHash: keyPair.hash,
    });
    const [owner] = await getDb()
      .insert(users)
      .values({ email: "owner@example.test", emailVerified: true })
      .returning({ id: users.id });
    const [member] = await getDb()
      .insert(users)
      .values({ email: "member@example.test", emailVerified: true })
      .returning({ id: users.id });
    ownerId = owner.id;
    memberId = member.id;
    await getDb()
      .insert(userTenants)
      .values([
        { userId: ownerId, tenantId: TENANT_ID, role: "owner" },
        { userId: memberId, tenantId: TENANT_ID, role: "member" },
      ]);

    ({ tenantConfigRoutes } = await import("../routes/tenant-config"));
    ({ createSessionToken } = await import("../routes/auth"));
  }, 30_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
  });

  async function tokenFor(userId: string): Promise<string> {
    return createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
      userId,
      tenantId: TENANT_ID,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
  }

  it("lets tenant owners put and read normalized OIDC provider config", async () => {
    const token = await tokenFor(ownerId);
    const response = await tenantConfigRoutes.request(`/${TENANT_ID}/oidc-providers`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        providers: [
          {
            id: "auth0-prod",
            issuer: "https://tenant.example.com/",
            audience: ["steward-api"],
            jwksUri: "https://tenant.example.com/.well-known/jwks.json",
            clientId: "enterprise-client",
            clientSecretEnv: "ACME_SSO_CLIENT_SECRET",
            authorizationUrl: "https://tenant.example.com/oauth2/v1/authorize",
            tokenUrl: "https://tenant.example.com/oauth2/v1/token",
            scopes: ["openid", "email", "profile"],
            allowedAlgs: ["RS256"],
            allowJitProvisioning: false,
          },
        ],
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: { providers: Array<{ id: string; issuer: string; allowedAlgs: string[] }> };
    };
    expect(body.data.providers).toEqual([
      expect.objectContaining({
        id: "auth0-prod",
        issuer: "https://tenant.example.com",
        clientId: "enterprise-client",
        clientSecretEnv: "ACME_SSO_CLIENT_SECRET",
        authorizationUrl: "https://tenant.example.com/oauth2/v1/authorize",
        tokenUrl: "https://tenant.example.com/oauth2/v1/token",
        scopes: ["openid", "email", "profile"],
        allowedAlgs: ["RS256"],
      }),
    ]);

    const [stored] = await getDb()
      .select({ oidcProviders: tenantConfigs.oidcProviders })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored?.oidcProviders[0]?.id).toBe("auth0-prod");

    const getResponse = await tenantConfigRoutes.request(`/${TENANT_ID}/oidc-providers`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as typeof body;
    expect(getBody.data.providers[0]?.issuer).toBe("https://tenant.example.com");
  });

  it("rejects non-admin members and unsafe provider URLs", async () => {
    const memberToken = await tokenFor(memberId);
    const memberResponse = await tenantConfigRoutes.request(`/${TENANT_ID}/oidc-providers`, {
      headers: { Authorization: `Bearer ${memberToken}` },
    });
    expect(memberResponse.status).toBe(403);

    const ownerToken = await tokenFor(ownerId);
    const unsafeResponse = await tenantConfigRoutes.request(`/${TENANT_ID}/oidc-providers`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${ownerToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        providers: [
          {
            id: "private-jwks",
            issuer: "https://tenant.example.com",
            audience: ["steward-api"],
            jwksUri: "https://127.0.0.1/.well-known/jwks.json",
          },
        ],
      }),
    });
    expect(unsafeResponse.status).toBe(400);
    const unsafeBody = (await unsafeResponse.json()) as { error: string };
    expect(unsafeBody.error).toContain("jwksUri for provider private-jwks");

    const unsafeAuthCodeResponse = await tenantConfigRoutes.request(
      `/${TENANT_ID}/oidc-providers`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${ownerToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          providers: [
            {
              id: "unsafe-code-flow",
              issuer: "https://tenant.example.com",
              audience: ["steward-api"],
              jwksUri: "https://tenant.example.com/.well-known/jwks.json",
              clientId: "enterprise-client",
              authorizationUrl: "https://tenant.example.com/oauth2/v1/authorize",
              tokenUrl: "https://127.0.0.1/oauth2/v1/token",
            },
          ],
        }),
      },
    );
    expect(unsafeAuthCodeResponse.status).toBe(400);
    const unsafeAuthCodeBody = (await unsafeAuthCodeResponse.json()) as { error: string };
    expect(unsafeAuthCodeBody.error).toContain("tokenUrl for provider unsafe-code-flow");
  });

  it("rejects tenant API keys for OIDC provider config changes", async () => {
    const getResponse = await tenantConfigRoutes.request(`/${TENANT_ID}/oidc-providers`, {
      headers: {
        "X-Steward-Key": apiKey,
        "X-Steward-Tenant": TENANT_ID,
      },
    });

    expect(getResponse.status).toBe(403);

    const response = await tenantConfigRoutes.request(`/${TENANT_ID}/oidc-providers`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Key": apiKey,
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({
        providers: [
          {
            id: "api-key-provider",
            issuer: "https://tenant.example.com",
            audience: ["steward-api"],
            jwksUri: "https://tenant.example.com/.well-known/jwks.json",
          },
        ],
      }),
    });

    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("owner or admin session");
  });
});
