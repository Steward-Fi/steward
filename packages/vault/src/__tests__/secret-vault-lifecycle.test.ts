import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { closeDb, getDb, secrets, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { SecretVault } from "../secret-vault";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "secret-vault-lifecycle-master";
const vault = new SecretVault(MASTER_PASSWORD);

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
});

async function ensureTenant(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: "hash" })
    .onConflictDoNothing();
}

describe("SecretVault lifecycle semantics", () => {
  it("moves existing routes to the new secret version on rotation", async () => {
    const tenantId = `tenant-rotate-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);

    const secret = await vault.createSecret(tenantId, "openai", "sk-old");
    const route = await vault.createRoute(tenantId, secret.id, {
      hostPattern: "api.openai.com",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const rotated = await vault.rotateSecret(tenantId, "openai", "sk-new");
    const updatedRoute = await vault.getRoute(tenantId, route.id);

    expect(updatedRoute?.secretId).toBe(rotated.id);
    expect(updatedRoute?.id).toBe(route.id);

    const [oldVersion] = await getDb()
      .select({ deletedAt: secrets.deletedAt })
      .from(secrets)
      .where(and(eq(secrets.id, secret.id), eq(secrets.tenantId, tenantId)));
    expect(oldVersion?.deletedAt).toBeInstanceOf(Date);
  });

  it("deletes all dependent routes when deleting a secret family", async () => {
    const tenantId = `tenant-delete-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);

    const secret = await vault.createSecret(tenantId, "anthropic", "sk-live");
    const route = await vault.createRoute(tenantId, secret.id, {
      hostPattern: "api.anthropic.com",
      injectAs: "header",
      injectKey: "x-api-key",
    });

    const deleted = await vault.deleteSecret(tenantId, secret.id);

    expect(deleted).toBe(true);
    expect(await vault.getRoute(tenantId, route.id)).toBeNull();
    expect(await vault.listRoutes(tenantId)).toEqual([]);
  });

  it("rejects creating routes for expired secrets", async () => {
    const tenantId = `tenant-expired-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);

    const expiredSecret = await vault.createSecret(tenantId, "expired", "sk-expired", {
      expiresAt: new Date(Date.now() - 60_000),
    });

    await expect(
      vault.createRoute(tenantId, expiredSecret.id, {
        hostPattern: "api.example.com",
        injectAs: "header",
        injectKey: "authorization",
      }),
    ).rejects.toThrow(/expired/);
  });
});
