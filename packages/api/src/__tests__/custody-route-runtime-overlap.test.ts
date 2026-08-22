import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  auditChainHeads,
  auditEvents,
  closeDb,
  getDb,
  secretRoutes as secretRouteRows,
  secrets,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const USER = "79500000-0000-4000-8000-000000000099";
const TENANT = `personal-${USER}`;
const AGENT = "custody-runtime-overlap-agent";
const SECRET_TENANT = "custody-runtime-secret-overlap-tenant";
const SECRET_AGENT = "custody-runtime-secret-overlap-agent";
const MASTER_PASSWORD = "custody-runtime-overlap-master-password";
const KDF_SALT = "79".repeat(16);
const JWT_SECRET = "custody-runtime-overlap-jwt-secret-with-enough-entropy";

type Suspension = {
  started: Promise<void>;
  release: () => void;
  wait: () => Promise<void>;
};

let suspendA: Suspension | null = null;
let app: Hono<{ Variables: AppVariables }>;
let userSessionToken: string;
const previousEnvironment = new Map<string, string | undefined>();
const mutatedEnvironmentKeys = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_KDF_SALT",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_JWT_SECRET",
] as const;

function suspension(): Suspension {
  let signalStarted!: () => void;
  let release!: () => void;
  const started = new Promise<void>((resolve) => {
    signalStarted = resolve;
  });
  const resumed = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    started,
    release,
    wait: async () => {
      signalStarted();
      await resumed;
    },
  };
}

const baseAuthority = {
  NODE_ENV: "test",
  STEWARD_RUNTIME: "workers",
  STEWARD_MASTER_PASSWORD: MASTER_PASSWORD,
  STEWARD_KDF_SALT: KDF_SALT,
  STEWARD_AUDIT_HMAC_KEY: "custody-runtime-overlap-audit-hmac-key-with-enough-entropy",
  STEWARD_JWT_SECRET: JWT_SECRET,
  STEWARD_PGLITE_MEMORY: "true",
};

async function overlap(
  path: string,
  init: RequestInit,
  authorityA: Record<string, string>,
  authorityB: Record<string, string>,
): Promise<{ responseA: Response; responseB: Response }> {
  const gate = suspension();
  suspendA = gate;
  const requestA = withRuntimeEnvironment({ ...baseAuthority, ...authorityA }, () =>
    app.request(path, {
      ...init,
      headers: { ...init.headers, "x-overlap-request": "a" },
    }),
  );
  await gate.started;
  try {
    const responseB = await withRuntimeEnvironment({ ...baseAuthority, ...authorityB }, () =>
      app.request(path, {
        ...init,
        headers: { ...init.headers, "x-overlap-request": "b" },
      }),
    );
    gate.release();
    return { responseA: await requestA, responseB };
  } finally {
    gate.release();
    suspendA = null;
  }
}

setDefaultTimeout(30_000);

describe("mounted custody route request authority", () => {
  beforeAll(async () => {
    for (const key of mutatedEnvironmentKeys) previousEnvironment.set(key, process.env[key]);
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
    process.env.STEWARD_KDF_SALT = KDF_SALT;
    process.env.STEWARD_AUDIT_HMAC_KEY = baseAuthority.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_JWT_SECRET = JWT_SECRET;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    const [{ vaultRoutes }, { secretsRoutes }, { userRoutes }, { createSessionToken }] =
      await Promise.all([
        import("../routes/vault"),
        import("../routes/secrets"),
        import("../routes/user"),
        import("../routes/auth"),
      ]);
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      if (c.req.header("x-overlap-request") === "a" && suspendA) {
        await suspendA.wait();
      }
      c.set("tenantId", c.req.header("x-test-tenant") ?? TENANT);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("userId", USER);
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("requestId", c.req.header("x-overlap-request") ?? crypto.randomUUID());
      await next();
    });
    app.route("/vault", vaultRoutes);
    app.route("/secrets", secretsRoutes);
    app.route("/", userRoutes);
    await db.insert(tenants).values({ id: TENANT, name: "Custody overlap", apiKeyHash: "hash" });
    await db.insert(agents).values({
      id: AGENT,
      tenantId: TENANT,
      name: "Custody overlap agent",
      walletAddress: "0x0000000000000000000000000000000000000795",
    });
    await db.insert(tenants).values({
      id: SECRET_TENANT,
      name: "Secret custody overlap",
      apiKeyHash: "secret-hash",
    });
    await db.insert(agents).values({
      id: SECRET_AGENT,
      tenantId: SECRET_TENANT,
      name: "Secret custody overlap agent",
      walletAddress: "0x0000000000000000000000000000000000000796",
    });
    await db.insert(users).values({
      id: USER,
      walletAddress: "0x0000000000000000000000000000000000000795",
      walletChain: "ethereum",
    });
    await db.insert(userTenants).values({
      userId: USER,
      tenantId: TENANT,
      role: "owner",
    });
    userSessionToken = await createSessionToken(
      "0x0000000000000000000000000000000000000795",
      TENANT,
      { userId: USER, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
    );
  });

  afterAll(async () => {
    await closeDb();
    for (const key of mutatedEnvironmentKeys) {
      const previous = previousEnvironment.get(key);
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    }
  });

  it("does not lend private-key export authority from B to suspended request A", async () => {
    const { responseA, responseB } = await overlap(
      `/vault/${AGENT}/export`,
      { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      {
        STEWARD_ALLOW_KEY_EXPORT: "false",
        STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "false",
        STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT: "false",
      },
      {
        STEWARD_ALLOW_KEY_EXPORT: "true",
        STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "true",
        STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT: "true",
      },
    );
    const bodyA = (await responseA.json()) as { error?: string };
    const bodyB = (await responseB.json()) as { error?: string };
    expect(responseA.status).toBe(403);
    expect(bodyA.error).toContain("Private key export is disabled");
    expect(bodyB.error ?? "").not.toContain("Private key export is disabled");
  });

  it("does not lend the production plaintext-export acknowledgement from B to A", async () => {
    const { responseA, responseB } = await overlap(
      `/vault/${AGENT}/export`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          plaintextExportAcknowledgement:
            "I understand this response contains plaintext private keys",
        }),
      },
      {
        NODE_ENV: "production",
        STEWARD_ACK_LOCAL_CUSTODY: "true",
        STEWARD_ALLOW_KEY_EXPORT: "true",
        STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "true",
        STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT: "true",
        STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION: "false",
      },
      {
        NODE_ENV: "production",
        STEWARD_ACK_LOCAL_CUSTODY: "true",
        STEWARD_ALLOW_KEY_EXPORT: "true",
        STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "true",
        STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT: "true",
        STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION: "true",
      },
    );
    const bodyA = (await responseA.json()) as { error?: string };
    const bodyB = (await responseB.json()) as { error?: string };
    expect(responseA.status).toBe(403);
    expect(bodyA.error).toContain("Plaintext private key export responses are disabled");
    expect(bodyB.error ?? "").not.toContain("Plaintext private key export responses are disabled");
  });

  it("does not lend raw or blind signing authority from B to suspended request A", async () => {
    const raw = await overlap(
      `/vault/${AGENT}/sign-raw-hash`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ hash: `0x${"11".repeat(32)}` }),
      },
      {
        STEWARD_ALLOW_UNSAFE_RAW_SIGNING: "false",
        STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING: "false",
      },
      {
        STEWARD_ALLOW_UNSAFE_RAW_SIGNING: "true",
        STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING: "true",
      },
    );
    const rawA = (await raw.responseA.json()) as { error?: string };
    const rawB = (await raw.responseB.json()) as { error?: string };
    expect(rawA.error).toContain("Raw secp256k1 signing is disabled");
    expect(rawB.error).not.toContain("Raw secp256k1 signing is disabled");

    const blind = await overlap(
      `/vault/${AGENT}/sign-solana`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          transaction: "AQIDBA==",
          chainId: 101,
          to: "11111111111111111111111111111111",
          value: "1",
          broadcast: false,
        }),
      },
      { STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING: "false" },
      { STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING: "true" },
    );
    const blindA = (await blind.responseA.json()) as { error?: string };
    const blindB = (await blind.responseB.json()) as { error?: string };
    expect(blind.responseA.status).toBe(422);
    expect(blindA.error).toContain("could not be decoded");
    expect(blindB.error).not.toContain("could not be decoded for policy evaluation");
  });

  it("does not lend personal-wallet export, import, or message-signing authority to A", async () => {
    const scenarios = [
      {
        path: "/me/wallet/export",
        body: {},
        denied: "Private key export is disabled",
        authorityA: {
          STEWARD_ALLOW_KEY_EXPORT: "false",
          STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "false",
          STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT: "false",
        },
        authorityB: {
          STEWARD_ALLOW_KEY_EXPORT: "true",
          STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "true",
          STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT: "true",
        },
      },
      {
        path: "/me/wallet/import/init",
        body: { chain: "evm", walletIndex: 0 },
        denied: "Private key import is disabled",
        authorityA: {
          STEWARD_ALLOW_PRIVATE_KEY_IMPORT: "false",
          STEWARD_ALLOW_USER_PRIVATE_KEY_IMPORT: "false",
        },
        authorityB: {
          STEWARD_ALLOW_PRIVATE_KEY_IMPORT: "true",
          STEWARD_ALLOW_USER_PRIVATE_KEY_IMPORT: "true",
        },
      },
      {
        path: "/me/wallet/sign-message",
        body: { message: "request-local authority" },
        denied: "Message signing is disabled",
        authorityA: {
          STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING: "false",
          STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING: "false",
        },
        authorityB: {
          STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING: "true",
          STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING: "true",
        },
      },
    ];

    for (const scenario of scenarios) {
      const result = await overlap(
        scenario.path,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${userSessionToken}`,
            "content-type": "application/json",
          },
          body: JSON.stringify(scenario.body),
        },
        scenario.authorityA,
        scenario.authorityB,
      );
      const bodyA = (await result.responseA.json()) as { error?: string };
      const bodyB = (await result.responseB.json()) as { error?: string };
      expect(bodyA.error).toContain(scenario.denied);
      expect(bodyB.error ?? "").not.toContain(scenario.denied);
    }
  });

  it("persists only the production secret route authorized by its own request snapshot", async () => {
    const plaintext = "production-secret-value-for-authority-b";
    const secretAuthorityB = {
      STEWARD_MASTER_PASSWORD: "secret-authority-b-master-password",
      STEWARD_KDF_SALT: "b7".repeat(16),
      STEWARD_ALLOW_BROAD_SECRET_ROUTES: "true",
      STEWARD_ALLOW_COOKIE_INJECTION: "true",
      STEWARD_SECRET_ROUTE_ALLOWED_HOSTS: "partner.example.com",
    };
    const createdResponse = await withRuntimeEnvironment(
      { ...baseAuthority, ...secretAuthorityB },
      () =>
        app.request("/secrets", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-test-tenant": SECRET_TENANT,
          },
          body: JSON.stringify({ name: "overlap-secret", value: plaintext }),
        }),
    );
    expect(createdResponse.status).toBe(201);
    const createdBody = (await createdResponse.json()) as { data?: { id?: string } };
    const secretId = createdBody.data?.id;
    expect(secretId).toBeTruthy();

    const [encryptedRow] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, secretId as string));
    expect(encryptedRow?.ciphertext).not.toBe(plaintext);
    expect(encryptedRow?.ciphertext).toMatch(/^[0-9a-f]+$/);
    const { getConfiguredSecretVault } = await import("../services/vault-factory");
    await expect(
      withRuntimeEnvironment({ ...baseAuthority, ...secretAuthorityB }, () =>
        getConfiguredSecretVault().decryptSecret(SECRET_TENANT, secretId as string),
      ),
    ).resolves.toBe(plaintext);
    await expect(
      withRuntimeEnvironment(
        {
          ...baseAuthority,
          STEWARD_MASTER_PASSWORD: "secret-authority-a-wrong-password",
          STEWARD_KDF_SALT: "a6".repeat(16),
        },
        () => getConfiguredSecretVault().decryptSecret(SECRET_TENANT, secretId as string),
      ),
    ).rejects.toThrow();

    const path = "/secrets/routes";
    const init = {
      method: "POST",
      headers: { "content-type": "application/json", "x-test-tenant": SECRET_TENANT },
      body: JSON.stringify({
        secretId,
        agentId: SECRET_AGENT,
        hostPattern: "partner.example.com",
        pathPattern: "/*",
        method: "GET",
        injectAs: "header",
        injectKey: "cookie",
      }),
    };
    const { responseA, responseB } = await overlap(
      path,
      init,
      {
        STEWARD_ALLOW_BROAD_SECRET_ROUTES: "false",
        STEWARD_ALLOW_COOKIE_INJECTION: "false",
        STEWARD_SECRET_ROUTE_ALLOWED_HOSTS: "",
        STEWARD_MASTER_PASSWORD: "secret-authority-a-wrong-password",
        STEWARD_KDF_SALT: "a6".repeat(16),
      },
      secretAuthorityB,
    );
    const bodyA = await responseA.clone().json();
    const bodyB = await responseB.clone().json();
    expect({ status: responseA.status, body: bodyA }).toMatchObject({ status: 400 });
    expect({ status: responseB.status, body: bodyB }).toMatchObject({ status: 201 });
    const persisted = await getDb()
      .select()
      .from(secretRouteRows)
      .where(eq(secretRouteRows.tenantId, SECRET_TENANT));
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toMatchObject({
      secretId,
      agentId: SECRET_AGENT,
      hostPattern: "partner.example.com",
      pathPattern: "/*",
      method: "GET",
      injectAs: "header",
      injectKey: "cookie",
    });
    const events = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, SECRET_TENANT))
      .orderBy(asc(auditEvents.seq));
    expect(events.map((event) => event.action)).toEqual([
      "secret.create.authorized",
      "secret.create",
      "secret_route.create.authorized",
      "secret_route.create",
    ]);
    expect(events.some((event) => event.requestId === "a")).toBe(false);
    const [head] = await getDb()
      .select()
      .from(auditChainHeads)
      .where(eq(auditChainHeads.tenantId, SECRET_TENANT));
    expect(head).toMatchObject({ expectedSeq: 4, expectedCount: 4 });
    expect(head?.headHmac).toEqual(events.at(-1)?.hmac);
  });
});
