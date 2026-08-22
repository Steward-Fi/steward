import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  secretRoutes as secretRouteRows,
  secrets,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT = "custody-runtime-overlap-tenant";
const AGENT = "custody-runtime-overlap-agent";
const USER = "custody-runtime-overlap-user";
const SECRET = "79500000-0000-4000-8000-000000000001";
const MASTER_PASSWORD = "custody-runtime-overlap-master-password";
const KDF_SALT = "79".repeat(16);

type Suspension = {
  started: Promise<void>;
  release: () => void;
  wait: () => Promise<void>;
};

let suspendA: Suspension | null = null;
let app: Hono<{ Variables: AppVariables }>;
const previousEnvironment = new Map<string, string | undefined>();
const mutatedEnvironmentKeys = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_KDF_SALT",
  "STEWARD_AUDIT_HMAC_KEY",
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
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    const [{ vaultRoutes }, { secretsRoutes }] = await Promise.all([
      import("../routes/vault"),
      import("../routes/secrets"),
    ]);
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      if (c.req.header("x-overlap-request") === "a" && suspendA) {
        await suspendA.wait();
      }
      c.set("tenantId", TENANT);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("userId", USER);
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("requestId", crypto.randomUUID());
      await next();
    });
    app.route("/vault", vaultRoutes);
    app.route("/secrets", secretsRoutes);
    await db.insert(tenants).values({ id: TENANT, name: "Custody overlap", apiKeyHash: "hash" });
    await db.insert(agents).values({
      id: AGENT,
      tenantId: TENANT,
      name: "Custody overlap agent",
      walletAddress: "0x0000000000000000000000000000000000000795",
    });
    await db.insert(secrets).values({
      id: SECRET,
      tenantId: TENANT,
      name: "overlap-secret",
      ciphertext: "ciphertext",
      iv: "iv",
      authTag: "tag",
      salt: "salt",
      version: 1,
    });
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

  it("persists only the production secret route authorized by its own request snapshot", async () => {
    const path = "/secrets/routes";
    const init = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secretId: SECRET,
        agentId: AGENT,
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
      },
      {
        STEWARD_ALLOW_BROAD_SECRET_ROUTES: "true",
        STEWARD_ALLOW_COOKIE_INJECTION: "true",
        STEWARD_SECRET_ROUTE_ALLOWED_HOSTS: "partner.example.com",
      },
    );
    const bodyA = await responseA.clone().json();
    const bodyB = await responseB.clone().json();
    expect({ status: responseA.status, body: bodyA }).toMatchObject({ status: 400 });
    expect({ status: responseB.status, body: bodyB }).toMatchObject({ status: 201 });
    const persisted = await getDb()
      .select()
      .from(secretRouteRows)
      .where(eq(secretRouteRows.tenantId, TENANT));
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toMatchObject({
      secretId: SECRET,
      agentId: AGENT,
      hostPattern: "partner.example.com",
      pathPattern: "/*",
      method: "GET",
      injectAs: "header",
      injectKey: "cookie",
    });
  });
});
