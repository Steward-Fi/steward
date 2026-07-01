import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, closeDb, getDb, secrets, tenants } from "@stwd/db";
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
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
}

async function ensureAgent(tenantId: string, agentId: string) {
  await getDb()
    .insert(agents)
    .values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000001",
    })
    .onConflictDoNothing();
}

describe("SecretVault lifecycle semantics", () => {
  it("moves existing routes to the new secret version on rotation", async () => {
    const tenantId = `tenant-rotate-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, "agent-openai");

    const secret = await vault.createSecret(tenantId, "openai", "sk-old");
    const route = await vault.createRoute(tenantId, secret.id, {
      agentId: "agent-openai",
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
    await ensureAgent(tenantId, "agent-anthropic");

    const secret = await vault.createSecret(tenantId, "anthropic", "sk-live");
    const route = await vault.createRoute(tenantId, secret.id, {
      agentId: "agent-anthropic",
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
    await ensureAgent(tenantId, "agent-expired");

    const expiredSecret = await vault.createSecret(tenantId, "expired", "sk-expired", {
      expiresAt: new Date(Date.now() - 60_000),
    });

    await expect(
      vault.createRoute(tenantId, expiredSecret.id, {
        agentId: "agent-expired",
        hostPattern: "api.openai.com",
        injectAs: "header",
        injectKey: "authorization",
      }),
    ).rejects.toThrow(/expired/);
  });

  it("enforces github strict-host rules across the two-pass update flow", async () => {
    const tenantId = `tenant-gh-update-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, "agent-gh-update");
    const secret = await vault.createSecret(tenantId, "gh-pat", "github_pat_example");

    // Create a narrow, compliant github route.
    const route = await vault.createRoute(tenantId, secret.id, {
      agentId: "agent-gh-update",
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/widgets/issues/1/comments",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    // A partial update that keeps the route narrow (e.g. just the injectFormat)
    // must succeed — the partial patch alone omits method/path but the merged
    // config still satisfies the strict-host rules.
    const updated = await vault.updateRoute(tenantId, route.id, {
      injectFormat: "token {value}",
    });
    expect(updated?.injectFormat).toBe("token {value}");

    // A partial update that would BREAK narrowness (shrink the path to a single
    // segment) must be rejected by the merged-config pass.
    await expect(vault.updateRoute(tenantId, route.id, { pathPattern: "/repos" })).rejects.toThrow(
      /at least 2 segments/,
    );
  });

  it("rejects unsafe route configs at the vault boundary", async () => {
    const tenantId = `tenant-route-hardening-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, "agent-route-hardening");
    const secret = await vault.createSecret(tenantId, "openai-hardening", "sk-hardening");

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId: "agent-route-hardening",
        hostPattern: "*",
        pathPattern: "/v1/chat/completions",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
      }),
    ).rejects.toThrow(/hostPattern must be an explicit allowed host/);

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId: "missing-agent",
        hostPattern: "api.openai.com",
        pathPattern: "/v1/chat/completions",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
      }),
    ).rejects.toThrow(/Agent missing-agent not found/);
  });
});
