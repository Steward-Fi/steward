import { afterEach, describe, expect, it } from "bun:test";
import { randomUUID } from "node:crypto";
import {
  getIdentityJwks,
  IdentityJwtConfigurationError,
  signIdentityJwtPayload,
  verifyToken,
} from "@stwd/auth";
import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { decodeProtectedHeader, exportPKCS8, generateKeyPair, importJWK, jwtVerify } from "jose";
import { identityDiscoveryRoutes } from "../routes/discovery";
import { hydrateProcessEnv, withWorkerJwtAuthority } from "../worker";

const ORIGINAL_ENV = {
  NODE_ENV: process.env.NODE_ENV,
  APP_URL: process.env.APP_URL,
  STEWARD_IDENTITY_JWT_PRIVATE_KEY: process.env.STEWARD_IDENTITY_JWT_PRIVATE_KEY,
  STEWARD_IDENTITY_JWT_ALG: process.env.STEWARD_IDENTITY_JWT_ALG,
  STEWARD_IDENTITY_JWT_KID: process.env.STEWARD_IDENTITY_JWT_KID,
  STEWARD_IDENTITY_JWT_ISSUER: process.env.STEWARD_IDENTITY_JWT_ISSUER,
  STEWARD_IDENTITY_JWT_AUDIENCE: process.env.STEWARD_IDENTITY_JWT_AUDIENCE,
  STEWARD_JWT_SECRET: process.env.STEWARD_JWT_SECRET,
  STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD,
  STEWARD_PGLITE_MEMORY: process.env.STEWARD_PGLITE_MEMORY,
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
  it("keeps identity-token and discovery routes on each overlapping Worker authority", async () => {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    process.env.STEWARD_MASTER_PASSWORD = "identity-discovery-master-password";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { authRoutes, createSessionToken, verifySessionToken } = await import("../routes/auth");
    const tenantId = "authority-overlap";
    const firstUserId = randomUUID();
    const secondUserId = randomUUID();
    await getDb().insert(tenants).values({
      id: tenantId,
      name: "Authority overlap",
      apiKeyHash: "hash",
      ownerAddress: "0x0000000000000000000000000000000000000000",
    });
    await getDb()
      .insert(users)
      .values([
        { id: firstUserId, email: "authority-a@example.test" },
        { id: secondUserId, email: "authority-b@example.test" },
      ]);
    await getDb()
      .insert(userTenants)
      .values([
        { userId: firstUserId, tenantId },
        { userId: secondUserId, tenantId },
      ]);

    const firstKeys = await generateKeyPair("RS256", { extractable: true });
    const secondKeys = await generateKeyPair("ES256", { extractable: true });
    const firstEnv = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "discovery-first-session-secret-at-least-32-characters",
      STEWARD_IDENTITY_JWT_ALG: "RS256",
      STEWARD_IDENTITY_JWT_PRIVATE_KEY: await exportPKCS8(firstKeys.privateKey),
      STEWARD_IDENTITY_JWT_KID: "discovery-first-rsa",
      STEWARD_IDENTITY_JWT_ISSUER: "https://authority-a.identity.test",
      STEWARD_IDENTITY_JWT_AUDIENCE: "authority-a-audience",
    };
    const secondEnv = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "discovery-second-session-secret-at-least-32-characters",
      STEWARD_IDENTITY_JWT_ALG: "ES256",
      STEWARD_IDENTITY_JWT_PRIVATE_KEY: await exportPKCS8(secondKeys.privateKey),
      STEWARD_IDENTITY_JWT_KID: "discovery-second-ec",
      STEWARD_IDENTITY_JWT_AUDIENCE: "authority-b-audience",
      APP_URL: "https://authority-b.app.test",
    };

    async function exerciseRoutes(userId: string, requestOrigin: string) {
      // Session revocation intentionally uses its in-memory test backend here;
      // JWT and discovery readers must still retain the production authority
      // captured above rather than this hostile compatibility-mirror change.
      process.env.NODE_ENV = "test";
      const sessionToken = await createSessionToken("0xauthority", tenantId, { userId });
      expect(await verifySessionToken(sessionToken)).toMatchObject({ userId, tenantId });
      const identityResponse = await authRoutes.request("/identity-token", {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      expect(identityResponse.status).toBe(200);
      const identity = (await identityResponse.json()) as { token: string };

      const rootJwksResponse = await identityDiscoveryRoutes.request(
        `${requestOrigin}/.well-known/jwks.json`,
      );
      const tenantJwksResponse = await identityDiscoveryRoutes.request(
        `${requestOrigin}/tenants/${tenantId}/.well-known/jwks.json`,
      );
      const rootDiscoveryResponse = await identityDiscoveryRoutes.request(
        `${requestOrigin}/.well-known/openid-configuration`,
      );
      const tenantDiscoveryResponse = await identityDiscoveryRoutes.request(
        `${requestOrigin}/tenants/${tenantId}/.well-known/openid-configuration`,
      );
      expect([
        rootJwksResponse.status,
        tenantJwksResponse.status,
        rootDiscoveryResponse.status,
        tenantDiscoveryResponse.status,
      ]).toEqual([200, 200, 200, 200]);
      return {
        token: identity.token,
        rootJwks: (await rootJwksResponse.json()) as { keys: Array<Record<string, unknown>> },
        tenantJwks: (await tenantJwksResponse.json()) as {
          keys: Array<Record<string, unknown>>;
        },
        rootDiscovery: (await rootDiscoveryResponse.json()) as Record<string, unknown>,
        tenantDiscovery: (await tenantDiscoveryResponse.json()) as Record<string, unknown>,
      };
    }

    let markFirstReady!: () => void;
    let releaseFirst!: () => void;
    const firstReady = new Promise<void>((resolve) => {
      markFirstReady = resolve;
    });
    const firstBarrier = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const firstRun = withWorkerJwtAuthority(firstEnv, async () => {
      hydrateProcessEnv(firstEnv);
      markFirstReady();
      await firstBarrier;
      return exerciseRoutes(firstUserId, "https://request-a.invalid");
    });
    await firstReady;

    const secondRun = withWorkerJwtAuthority(secondEnv, async () => {
      hydrateProcessEnv(secondEnv);
      return exerciseRoutes(secondUserId, "https://request-b.invalid");
    });
    const [secondResult, firstResult] = await Promise.all([
      Promise.resolve(secondRun).finally(releaseFirst),
      firstRun,
    ]);

    const expectations = [
      {
        result: firstResult,
        alg: "RS256",
        kty: "RSA",
        kid: firstEnv.STEWARD_IDENTITY_JWT_KID,
        issuer: firstEnv.STEWARD_IDENTITY_JWT_ISSUER,
        audience: firstEnv.STEWARD_IDENTITY_JWT_AUDIENCE,
        publicKey: firstKeys.publicKey,
      },
      {
        result: secondResult,
        alg: "ES256",
        kty: "EC",
        kid: secondEnv.STEWARD_IDENTITY_JWT_KID,
        issuer: secondEnv.APP_URL,
        audience: secondEnv.STEWARD_IDENTITY_JWT_AUDIENCE,
        publicKey: secondKeys.publicKey,
      },
    ] as const;
    for (const expected of expectations) {
      expect(decodeProtectedHeader(expected.result.token)).toMatchObject({
        alg: expected.alg,
        kid: expected.kid,
      });
      await expect(
        jwtVerify(expected.result.token, expected.publicKey, {
          issuer: `${expected.issuer}/tenants/${tenantId}`,
          audience: expected.audience,
          algorithms: [expected.alg],
        }),
      ).resolves.toBeDefined();
      for (const jwks of [expected.result.rootJwks, expected.result.tenantJwks]) {
        expect(jwks.keys).toHaveLength(1);
        expect(jwks.keys[0]).toMatchObject({
          alg: expected.alg,
          kid: expected.kid,
          kty: expected.kty,
          use: "sig",
        });
        expect(jwks.keys[0]?.d).toBeUndefined();
      }
      expect(expected.result.rootDiscovery).toMatchObject({
        issuer: expected.issuer,
        jwks_uri: `${expected.issuer}/.well-known/jwks.json`,
        id_token_signing_alg_values_supported: [expected.alg],
      });
      expect(expected.result.tenantDiscovery).toMatchObject({
        issuer: `${expected.issuer}/tenants/${tenantId}`,
        jwks_uri: `${expected.issuer}/tenants/${tenantId}/.well-known/jwks.json`,
        id_token_signing_alg_values_supported: [expected.alg],
        tenant_id: tenantId,
      });
    }

    const unavailableIdentityResponse = await withWorkerJwtAuthority(
      {
        ...firstEnv,
        STEWARD_IDENTITY_JWT_ISSUER: undefined,
        APP_URL: "http://insecure.identity.test",
      },
      async () => {
        process.env.NODE_ENV = "test";
        const sessionToken = await createSessionToken("0xauthority", tenantId, {
          userId: firstUserId,
        });
        return authRoutes.request("/identity-token", {
          headers: { Authorization: `Bearer ${sessionToken}` },
        });
      },
    );
    expect(unavailableIdentityResponse.status).toBe(503);
    expect(await unavailableIdentityResponse.json()).toEqual({
      ok: false,
      error: "Identity token unavailable",
    });
  });

  it("treats a Worker with no NODE_ENV or canonical base as production and fails closed", async () => {
    process.env.NODE_ENV = "test";
    process.env.APP_URL = "https://ambient.identity.test";
    const workerEnv = {
      DATABASE_URL: "unused",
      STEWARD_JWT_SECRET: "identity-production-posture-secret-at-least-32-characters",
    };
    const response = await withWorkerJwtAuthority(workerEnv, () =>
      identityDiscoveryRoutes.request(
        "https://attacker-controlled-host.invalid/.well-known/openid-configuration",
      ),
    );
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toEqual({ ok: false, error: "Identity discovery unavailable" });
    expect(JSON.stringify(body)).not.toContain("attacker-controlled-host");
    expect(JSON.stringify(body)).not.toContain("STEWARD_IDENTITY_JWT_ISSUER");
    await expect(
      withWorkerJwtAuthority(workerEnv, () => signIdentityJwtPayload({ sub: "missing-base" })),
    ).rejects.toBeInstanceOf(IdentityJwtConfigurationError);
  });

  it("uses one explicit canonical HTTPS base for Worker token and discovery routes", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const workerEnv = {
      DATABASE_URL: "unused",
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "explicit-base-worker-session-secret-at-least-32-characters",
      STEWARD_IDENTITY_JWT_ALG: "ES256",
      STEWARD_IDENTITY_JWT_PRIVATE_KEY: await exportPKCS8(privateKey),
      STEWARD_IDENTITY_JWT_KID: "explicit-worker-ec",
      STEWARD_IDENTITY_JWT_AUDIENCE: "explicit-worker-audience",
      APP_URL: "https://canonical.worker.test/",
    };
    const result = await withWorkerJwtAuthority(workerEnv, async () => {
      hydrateProcessEnv(workerEnv);
      const token = await signIdentityJwtPayload({ sub: "explicit-base" });
      const response = await identityDiscoveryRoutes.request(
        "https://ignored-request-host.invalid/.well-known/openid-configuration",
      );
      return { token, response };
    });
    expect(result.response.status).toBe(200);
    expect(await result.response.json()).toMatchObject({
      issuer: "https://canonical.worker.test",
      jwks_uri: "https://canonical.worker.test/.well-known/jwks.json",
      id_token_signing_alg_values_supported: ["ES256"],
    });
    await expect(
      jwtVerify(result.token, publicKey, {
        issuer: "https://canonical.worker.test",
        audience: "explicit-worker-audience",
        algorithms: ["ES256"],
      }),
    ).resolves.toBeDefined();

    const insecureResponse = await withWorkerJwtAuthority(
      { ...workerEnv, APP_URL: "http://canonical.worker.test" },
      () =>
        identityDiscoveryRoutes.request(
          "https://ignored-request-host.invalid/.well-known/openid-configuration",
        ),
    );
    expect(insecureResponse.status).toBe(503);
    expect(await insecureResponse.json()).toEqual({
      ok: false,
      error: "Identity discovery unavailable",
    });
  });

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
    expect(otherTenantConfigResponse.status).toBe(404);
    expect(await otherTenantConfigResponse.json()).toMatchObject({
      ok: false,
      error: "Tenant not found",
    });

    const otherTenantJwksResponse = await identityDiscoveryRoutes.request(
      "https://api.example.test/tenants/other/.well-known/jwks.json",
    );
    expect(otherTenantJwksResponse.status).toBe(404);

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

  it("does not fall back to the session JWT secret for identity-token signing", async () => {
    delete process.env.STEWARD_IDENTITY_JWT_PRIVATE_KEY;
    process.env.STEWARD_IDENTITY_JWT_ALG = "RS256";
    process.env.STEWARD_IDENTITY_JWT_ISSUER = "https://api.example.test";
    process.env.STEWARD_IDENTITY_JWT_AUDIENCE = "steward-identity";
    process.env.STEWARD_JWT_SECRET = "identity-discovery-hs-secret-for-negative-check";

    await expect(
      signIdentityJwtPayload(
        {
          typ: "identity",
          sub: "user-1",
          userId: "user-1",
          tenantId: "tenant-1",
        },
        "15m",
        "https://api.example.test",
        "custom-audience",
      ),
    ).rejects.toThrow("Identity JWT private key is not configured");
  });
});
