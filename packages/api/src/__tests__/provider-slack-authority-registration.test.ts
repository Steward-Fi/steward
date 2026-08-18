import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  providerAccounts,
  providerOperations,
  secretRoutes,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { ProviderAuthorityStore } from "../services/provider-authority-store";

setDefaultTimeout(120_000);

const TENANT = "tenant-slack-authority";
const OWNER = "10000000-0000-4000-8000-000000000091";
const WORKSPACE = "20000000-0000-4000-8000-000000000091";
const AGENT = "agent-slack-authority";
const MASTER = "slack-authority-registration-test-master";

describe("Slack provider authority registration", () => {
  const store = new ProviderAuthorityStore();
  let secretId: string;
  let routeId: string;
  let wrongPathRouteId: string;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = MASTER;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await db.insert(tenants).values({ id: TENANT, name: TENANT, apiKeyHash: `hash-${TENANT}` });
    await db.insert(users).values({ id: OWNER, email: "slack-authority@example.test" });
    await db.insert(userTenants).values({ userId: OWNER, tenantId: TENANT, role: "owner" });
    await db.insert(agents).values({
      id: AGENT,
      tenantId: TENANT,
      name: "Slack authority agent",
      walletAddress: `0x${"9".repeat(40)}`,
    });
    await db.insert(workspaces).values({
      id: WORKSPACE,
      tenantId: TENANT,
      key: "slack-authority",
      name: "Slack Authority",
      environment: "production",
      createdBy: OWNER,
    });
    const vault = new SecretVault(MASTER);
    const secret = await vault.createSecret(TENANT, "slack-authority-token", "xoxb-test-token-123");
    secretId = secret.id;
    const route = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT,
      hostPattern: "slack.com",
      pathPattern: "/api/chat.postMessage",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });
    routeId = route.id;
    const wrongPathRoute = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT,
      hostPattern: "slack.com",
      pathPattern: "/api/admin.users.session.reset",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });
    wrongPathRouteId = wrongPathRoute.id;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  test("registers Slack while rejecting a read-risk downgrade for chat.postMessage", async () => {
    const context = (expectedRevision: number) => ({
      tenantId: TENANT,
      actorUserId: OWNER,
      tenantRole: "owner",
      mfaVerifiedAt: Date.now(),
      idempotencyKey: `idem-${crypto.randomUUID()}`,
      expectedRevision,
      reason: "Slack authority regression",
      audit: async () => {},
    });

    const account = await store.createProviderAccount(context(1), {
      workspaceId: WORKSPACE,
      adapterKey: "slack",
      externalRef: "T01234567",
      displayName: "Slack bot",
      credentialSecretId: secretId,
      credentialVersion: 1,
    });
    expect(account.adapterKey).toBe("slack");

    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "read",
        secretRouteId: routeId,
      }),
    ).rejects.toMatchObject({ code: "bad_request", status: 400 });

    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: wrongPathRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    // The completed audit is part of the same transaction as the account CAS,
    // operation insert, and route promotion. If audit signing fails, all three
    // mutations must roll back together.
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: routeId,
      }),
    ).rejects.toThrow("STEWARD_AUDIT_HMAC_KEY is required");
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    expect(await getDb().select().from(providerOperations)).toHaveLength(0);
    const [rolledBackAccount] = await getDb()
      .select({ revision: providerAccounts.revision })
      .from(providerAccounts)
      .where(eq(providerAccounts.id, account.id));
    expect(rolledBackAccount?.revision).toBe(1);
    const [rolledBackRoute] = await getDb()
      .select({ mode: secretRoutes.authorityMode, operationId: secretRoutes.providerOperationId })
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(rolledBackRoute).toEqual({ mode: "legacy", operationId: null });

    const operation = await store.registerOperation(context(1), account.id, {
      operationKey: "slack.chat.postMessage",
      riskClass: "write",
      secretRouteId: routeId,
    });
    expect(operation).toMatchObject({
      operationKey: "slack.chat.postMessage",
      riskClass: "write",
    });
    expect(await getDb().select().from(providerOperations)).toHaveLength(1);
    const [route] = await getDb()
      .select({ mode: secretRoutes.authorityMode, operationId: secretRoutes.providerOperationId })
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(route).toEqual({ mode: "governed_v2", operationId: operation.id });
  });
});
