import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  providerAccounts,
  providerOperations,
  secretRoutes,
  secrets,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
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

async function promoteRoute(tenantId: string, routeId: string): Promise<void> {
  const [user] = await getDb()
    .insert(users)
    .values({ email: `vault-route-${crypto.randomUUID()}@example.test` })
    .returning();
  const [workspace] = await getDb()
    .insert(workspaces)
    .values({
      tenantId,
      key: `vault-${crypto.randomUUID()}`,
      name: "vault route",
      environment: "production",
      createdBy: user.id,
    })
    .returning();
  const [account] = await getDb()
    .insert(providerAccounts)
    .values({
      tenantId,
      workspaceId: workspace.id,
      adapterKey: "github",
      externalRef: crypto.randomUUID(),
      displayName: "vault route",
    })
    .returning();
  const [operation] = await getDb()
    .insert(providerOperations)
    .values({
      tenantId,
      workspaceId: workspace.id,
      providerAccountId: account.id,
      operationKey: `vault.route.${crypto.randomUUID()}`,
      riskClass: "write",
      secretRouteId: routeId,
    })
    .returning();
  await getDb()
    .update(secretRoutes)
    .set({ authorityMode: "governed_v2", providerOperationId: operation.id })
    .where(eq(secretRoutes.id, routeId));
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

  it("requires explicit recovery opt-in to append to a deleted lineage", async () => {
    const tenantId = `tenant-restore-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, "agent-restore");
    const original = await vault.createSecret(tenantId, "provider", "old-token");
    const route = await vault.createRoute(tenantId, original.id, {
      agentId: "agent-restore",
      hostPattern: "api.openai.com",
      injectAs: "header",
      injectKey: "authorization",
    });
    await getDb()
      .update(secrets)
      .set({ deletedAt: new Date() })
      .where(and(eq(secrets.tenantId, tenantId), eq(secrets.id, original.id)));

    await expect(
      getDb().transaction((tx) =>
        vault.rotateSecretWithinTx(tx, tenantId, "provider", "new-token"),
      ),
    ).rejects.toThrow('Secret "provider" not found');
    const replacement = await getDb().transaction((tx) =>
      vault.rotateSecretWithinTx(tx, tenantId, "provider", "new-token", {
        allowDeletedCurrent: true,
      }),
    );
    expect(replacement.version).toBe(2);
    expect(await vault.decryptSecret(tenantId, replacement.id)).toBe("new-token");
    expect((await vault.getRoute(tenantId, route.id))?.secretId).toBe(replacement.id);
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

  it("refuses generic deletion of governed provider authority", async () => {
    const tenantId = `tenant-governed-delete-${crypto.randomUUID()}`;
    const agentId = `agent-governed-delete-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const secret = await vault.createSecret(tenantId, "governed-provider", "provider-token");
    const route = await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/widgets",
      method: "GET",
      injectAs: "header",
      injectKey: "authorization",
    });
    await promoteRoute(tenantId, route.id);

    await expect(vault.deleteRoute(tenantId, route.id)).rejects.toThrow(
      /provider-operation lifecycle/,
    );
    await expect(vault.deleteSecret(tenantId, secret.id)).rejects.toThrow(
      /provider-operation lifecycle/,
    );
    expect(await vault.getRoute(tenantId, route.id)).not.toBeNull();
    expect(await vault.getSecretById(tenantId, secret.id)).not.toBeNull();
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

  it("lets an admin disable a legacy non-compliant strict-host route", async () => {
    const tenantId = `tenant-gh-legacy-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, "agent-gh-legacy");
    const secret = await vault.createSecret(tenantId, "gh-legacy-pat", "github_pat_legacy");

    // Simulate a route created BEFORE the strict-host rules existed: a broad
    // single-segment github path that createRoute would now reject. Insert it
    // directly so we can prove the disable path is not blocked by the new rule.
    const [legacy] = await getDb()
      .insert(secretRoutes)
      .values({
        tenantId,
        agentId: "agent-gh-legacy",
        secretId: secret.id,
        hostPattern: "api.github.com",
        pathPattern: "/",
        method: "GET",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
        priority: 0,
        enabled: true,
      })
      .returning();

    // enabled:false is a safety-REDUCING change and must succeed despite the
    // route being non-compliant with the new strict-host rules.
    const disabled = await vault.updateRoute(tenantId, legacy.id, { enabled: false });
    expect(disabled?.enabled).toBe(false);

    // Re-enabling it (safety-INCREASING risk) must still be blocked by strict
    // rules — you cannot turn an unsafe legacy route back on without fixing it.
    await expect(vault.updateRoute(tenantId, legacy.id, { enabled: true })).rejects.toThrow(
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

  it("enforces governed authority at the public create/update boundary", async () => {
    const tenantId = `tenant-vault-authority-${crypto.randomUUID()}`;
    const agentId = "agent-vault-authority";
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const secret = await vault.createSecret(tenantId, "authority", "secret");
    const governed = await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.openai.com",
      pathPattern: "/v1/chat/completions",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
    });
    await promoteRoute(tenantId, governed.id);

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId,
        hostPattern: "api.openai.com",
        pathPattern: "/v1/chat/completions",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
      }),
    ).rejects.toThrow(/different authority model/);
    await expect(
      vault.updateRoute(tenantId, governed.id, { pathPattern: "/v1/responses" }),
    ).rejects.toThrow(/provider operation authoring/);
    await expect(
      vault.updateRoute(tenantId, governed.id, { injectionStrategy: "sigv4" }),
    ).rejects.toThrow(/provider operation authoring/);
    await expect(
      vault.updateRoute(tenantId, governed.id, {
        injectionConfig: { service: "ec2", region: "us-west-2" },
      }),
    ).rejects.toThrow(/provider operation authoring/);
    expect((await vault.getRoute(tenantId, governed.id))?.pathPattern).toBe("/v1/chat/completions");
  });
});
