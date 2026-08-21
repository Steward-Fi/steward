import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { randomUUID } from "node:crypto";
import { generateApiKey } from "@stwd/auth";
import { closeDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";

const tenantId = `webhook-runtime-${randomUUID()}`;
const userId = randomUUID();
const masterPassword = "mounted-webhook-runtime-master-password";
const webhookKdfSalt = "ab".repeat(32);
const jwtSecret = "mounted-webhook-runtime-jwt-secret-with-enough-entropy";
const auditKey = "mounted-webhook-runtime-audit-key-with-enough-entropy";
const baseWorkerBindings = {
  STEWARD_RUNTIME: "workers",
  STEWARD_PGLITE_MEMORY: "true",
  STEWARD_MASTER_PASSWORD: masterPassword,
  STEWARD_WEBHOOK_SECRET_KDF_SALT: webhookKdfSalt,
  STEWARD_JWT_SECRET: jwtSecret,
  STEWARD_AUDIT_HMAC_KEY: auditKey,
};

describe("mounted webhook request-local policy", () => {
  let app: Awaited<typeof import("../app")>["app"];
  let sessionToken: string;
  const priorEnvironment = new Map<string, string | undefined>();

  beforeAll(async () => {
    for (const [name, value] of Object.entries(baseWorkerBindings)) {
      priorEnvironment.set(name, process.env[name]);
      process.env[name] = value;
    }

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    const apiKey = generateApiKey();
    await db.insert(tenants).values({
      id: tenantId,
      name: "Mounted webhook runtime policy",
      apiKeyHash: apiKey.hash,
    });
    await db.insert(users).values({
      id: userId,
      email: `${userId}@example.test`,
      emailVerified: true,
    });
    await db.insert(userTenants).values({ userId, tenantId, role: "owner" });

    ({ app } = await import("../app"));
    const { createSessionToken } = await import("../routes/auth");
    sessionToken = await createSessionToken(
      "0x0000000000000000000000000000000000000000",
      tenantId,
      {
        userId,
        email: `${userId}@example.test`,
        mfaVerifiedAt: Date.now(),
        mfaMethod: "totp",
      },
    );
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    for (const [name, value] of priorEnvironment) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  function createWebhook(url: string, bindings: Record<string, string>) {
    return withRuntimeEnvironment(bindings, () =>
      app.request("/webhooks", {
        method: "POST",
        headers: {
          authorization: `Bearer ${sessionToken}`,
          "content-type": "application/json",
          "x-steward-tenant": tenantId,
        },
        body: JSON.stringify({ url, events: ["tx.signed"] }),
      }),
    );
  }

  it("observes an enabled binding and then its removal without remounting the app", async () => {
    const enabled = await createWebhook("http://127.0.0.1:38080/enabled", {
      ...baseWorkerBindings,
      STEWARD_ALLOW_INSECURE_WEBHOOK_URLS: "true",
      STEWARD_ALLOW_PRIVATE_WEBHOOK_NETWORKS: "true",
    });
    expect(enabled.status).toBe(201);

    const insecureRemoved = await createWebhook(
      "http://127.0.0.1:38080/insecure-removed",
      baseWorkerBindings,
    );
    expect(insecureRemoved.status).toBe(400);
    await expect(insecureRemoved.json()).resolves.toMatchObject({ error: "url must use https" });

    const privateRemoved = await createWebhook(
      "https://127.0.0.1:38080/private-removed",
      baseWorkerBindings,
    );
    expect(privateRemoved.status).toBe(400);
    await expect(privateRemoved.json()).resolves.toMatchObject({
      error: "url host must be public",
    });
  });
});
