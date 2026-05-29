import { afterEach, describe, expect, it } from "bun:test";
import { getIdentityJwks, signIdentityJwtPayload, verifyToken } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { decodeProtectedHeader, exportPKCS8, generateKeyPair, importJWK, jwtVerify } from "jose";
import { identityDiscoveryRoutes } from "../routes/discovery";

const ORIGINAL_ENV = {
  APP_URL: process.env.APP_URL,
  STEWARD_IDENTITY_JWT_PRIVATE_KEY: process.env.STEWARD_IDENTITY_JWT_PRIVATE_KEY,
  STEWARD_IDENTITY_JWT_ALG: process.env.STEWARD_IDENTITY_JWT_ALG,
  STEWARD_IDENTITY_JWT_KID: process.env.STEWARD_IDENTITY_JWT_KID,
  STEWARD_IDENTITY_JWT_ISSUER: process.env.STEWARD_IDENTITY_JWT_ISSUER,
  STEWARD_IDENTITY_JWT_AUDIENCE: process.env.STEWARD_IDENTITY_JWT_AUDIENCE,
  STEWARD_JWT_SECRET: process.env.STEWARD_JWT_SECRET,
};

async function configureRs256IdentityKey() {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  process.env.STEWARD_IDENTITY_JWT_PRIVATE_KEY = await exportPKCS8(privateKey);
  process.env.STEWARD_IDENTITY_JWT_ALG = "RS256";
  process.env.STEWARD_IDENTITY_JWT_KID = "identity-test-key";
  process.env.STEWARD_IDENTITY_JWT_ISSUER = "https://api.example.test";
  process.env.STEWARD_IDENTITY_JWT_AUDIENCE = "steward-identity";
}

afterEach(async () => {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  await closeDb();
});

describe("identity JWKS discovery", () => {
  it("publishes only public key material for configured identity-token signing keys", async () => {
    await configureRs256IdentityKey();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: "acme",
      name: "Acme",
      apiKeyHash: "hash",
      ownerAddress: "0x0000000000000000000000000000000000000000",
    });

    const jwksResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/.well-known/jwks.json",
    );
    expect(jwksResponse.status).toBe(200);
    const jwks = (await jwksResponse.json()) as {
      keys: Array<Record<string, unknown>>;
    };

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      kty: "RSA",
      alg: "RS256",
      kid: "identity-test-key",
      use: "sig",
    });
    expect(jwks.keys[0]?.d).toBeUndefined();

    const configResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/.well-known/openid-configuration",
    );
    const config = (await configResponse.json()) as Record<string, unknown>;
    expect(config).toMatchObject({
      issuer: "https://api.example.test",
      jwks_uri: "https://api.example.test/.well-known/jwks.json",
      id_token_signing_alg_values_supported: ["RS256"],
    });

    const tenantConfigResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/tenants/acme/.well-known/openid-configuration",
    );
    expect(tenantConfigResponse.status).toBe(200);
    const tenantConfig = (await tenantConfigResponse.json()) as Record<string, unknown>;
    expect(tenantConfig).toMatchObject({
      issuer: "https://api.example.test/tenants/acme",
      tenant_id: "acme",
      jwks_uri: "https://api.example.test/tenants/acme/.well-known/jwks.json",
      id_token_signing_alg_values_supported: ["RS256"],
    });

    const otherTenantConfigResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/tenants/other/.well-known/openid-configuration",
    );
    expect(otherTenantConfigResponse.status).toBe(200);
    expect(await otherTenantConfigResponse.json()).toMatchObject({
      issuer: "https://api.example.test/tenants/other",
      tenant_id: "other",
      jwks_uri: "https://api.example.test/tenants/other/.well-known/jwks.json",
    });

    const otherTenantJwksResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/tenants/other/.well-known/jwks.json",
    );
    expect(otherTenantJwksResponse.status).toBe(200);

    const invalidTenantConfigResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/tenants/bad%20tenant/.well-known/openid-configuration",
    );
    expect(invalidTenantConfigResponse.status).toBe(400);
  });

  it("signs identity tokens with the asymmetric key when configured", async () => {
    await configureRs256IdentityKey();
    process.env.STEWARD_JWT_SECRET = "identity-discovery-hs-secret-for-negative-check";

    const token = await signIdentityJwtPayload(
      {
        typ: "identity",
        sub: "user-1",
        userId: "user-1",
        tenantId: "tenant-1",
      },
      "15m",
      "https://api.example.test",
      "custom-audience",
    );
    expect(decodeProtectedHeader(token)).toMatchObject({
      alg: "RS256",
      kid: "identity-test-key",
    });

    const jwks = await getIdentityJwks();
    const publicKey = await importJWK(jwks.keys[0]!, "RS256");
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: "https://api.example.test",
      audience: "custom-audience",
      algorithms: ["RS256"],
    });
    expect(payload).toMatchObject({
      typ: "identity",
      sub: "user-1",
      userId: "user-1",
      tenantId: "tenant-1",
    });
    await expect(verifyToken(token)).rejects.toThrow();
  });
});
