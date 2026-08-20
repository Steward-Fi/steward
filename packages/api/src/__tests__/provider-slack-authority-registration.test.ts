import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  auditEvents,
  closeDb,
  getDb,
  providerAccounts,
  providerOperations,
  secretRoutes,
  tenants,
  users,
  userTenants,
  withTenantAuditedTransaction,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { writeAuditEvent } from "../services/audit";
import { ProviderAuthorityStore } from "../services/provider-authority-store";

setDefaultTimeout(120_000);

const TENANT = "tenant-slack-authority";
const OWNER = "10000000-0000-4000-8000-000000000091";
const WORKSPACE = "20000000-0000-4000-8000-000000000091";
const AGENT = "agent-slack-authority";
const AGENT_ALT = "agent-slack-authority-alt";
const AGENT_RACE = "agent-slack-authority-race";
const AGENT_WHITESPACE = "agent-slack-authority-whitespace";
const AGENT_GITHUB = "agent-fixed-provider-github";
const AGENT_X = "agent-fixed-provider-x";
const MASTER = "slack-authority-registration-test-master";

describe("Slack provider authority registration", () => {
  const store = new ProviderAuthorityStore();
  const failingCompletedAuditStore = new ProviderAuthorityStore((tenantId, fn) =>
    withTenantAuditedTransaction(tenantId, async (tx, _appendRequiredAudit) =>
      fn(tx, async () => {
        throw new Error("synthetic completed audit failure");
      }),
    ),
  );
  let vault: SecretVault;
  let secretId: string;
  let routeId: string;
  let wrongPathRouteId: string;
  let wrongHeaderRouteId: string;
  let wrongFormatRouteId: string;
  let whitespaceHeaderRouteId: string;
  let raceRouteId: string;
  let githubSecretId: string;
  let githubRouteId: string;
  let xSecretId: string;
  let xRouteId: string;

  const context = (expectedRevision: number) => ({
    tenantId: TENANT,
    actorUserId: OWNER,
    tenantRole: "owner",
    mfaVerifiedAt: Date.now(),
    idempotencyKey: `idem-${crypto.randomUUID()}`,
    expectedRevision,
    reason: "Fixed provider authority regression",
    audit: async (event: {
      action: string;
      resourceType: string;
      resourceId?: string;
      metadata: Record<string, unknown>;
    }) => {
      await writeAuditEvent({
        tenantId: TENANT,
        actorType: "user",
        actorId: OWNER,
        action: event.action,
        resourceType: event.resourceType,
        resourceId: event.resourceId,
        metadata: event.metadata,
      });
    },
  });

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
    await db.insert(agents).values({
      id: AGENT_ALT,
      tenantId: TENANT,
      name: "Slack authority agent alt",
      walletAddress: `0x${"8".repeat(40)}`,
    });
    await db.insert(agents).values([
      {
        id: AGENT_RACE,
        tenantId: TENANT,
        name: "Slack authority race agent",
        walletAddress: `0x${"7".repeat(40)}`,
      },
      {
        id: AGENT_WHITESPACE,
        tenantId: TENANT,
        name: "Slack authority whitespace agent",
        walletAddress: `0x${"6".repeat(40)}`,
      },
      {
        id: AGENT_GITHUB,
        tenantId: TENANT,
        name: "GitHub fixed-provider agent",
        walletAddress: `0x${"5".repeat(40)}`,
      },
      {
        id: AGENT_X,
        tenantId: TENANT,
        name: "X fixed-provider agent",
        walletAddress: `0x${"4".repeat(40)}`,
      },
    ]);
    await db.insert(workspaces).values({
      id: WORKSPACE,
      tenantId: TENANT,
      key: "slack-authority",
      name: "Slack Authority",
      environment: "production",
      createdBy: OWNER,
    });
    vault = new SecretVault(MASTER);
    const secret = await vault.createSecret(TENANT, "slack-authority-token", "xoxb-test-token-123");
    secretId = secret.id;
    const route = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT,
      hostPattern: "slack.com",
      pathPattern: "/api/chat.postMessage",
      method: "POST",
      injectAs: "header",
      // Header names are semantically case-insensitive. The authority gate
      // accepts casing differences while still rejecting surrounding OWS.
      injectKey: "Authorization",
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
    const wrongHeaderRoute = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT_ALT,
      hostPattern: "slack.com",
      pathPattern: "/api/chat.postMessage",
      method: "POST",
      injectAs: "header",
      injectKey: "x-api-key",
      injectFormat: "Bearer {value}",
    });
    wrongHeaderRouteId = wrongHeaderRoute.id;
    const wrongFormatRoute = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT_ALT,
      hostPattern: "slack.com",
      pathPattern: "/api/chat.postMessage",
      method: "POST",
      injectAs: "header",
      injectKey: "Authorization",
      injectFormat: "Token {value}",
    });
    wrongFormatRouteId = wrongFormatRoute.id;
    const whitespaceHeaderRoute = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT_WHITESPACE,
      hostPattern: "slack.com",
      pathPattern: "/api/chat.postMessage",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });
    whitespaceHeaderRouteId = whitespaceHeaderRoute.id;
    // Simulate a malformed persisted row that bypassed the normal vault writer.
    // The registration boundary must not normalize it into authority.
    await db
      .update(secretRoutes)
      .set({ injectKey: " authorization " })
      .where(eq(secretRoutes.id, whitespaceHeaderRoute.id));
    const raceRoute = await vault.createRoute(TENANT, secret.id, {
      agentId: AGENT_RACE,
      hostPattern: "slack.com",
      pathPattern: "/api/chat.postMessage",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });
    raceRouteId = raceRoute.id;
    const githubSecret = await vault.createSecret(TENANT, "github-authority-token", "ghp_test");
    githubSecretId = githubSecret.id;
    const githubRoute = await vault.createRoute(TENANT, githubSecret.id, {
      agentId: AGENT_GITHUB,
      hostPattern: "api.github.com",
      pathPattern: "/repos/steward-fi/steward/issues",
      method: "GET",
      injectAs: "header",
      injectKey: "AUTHORIZATION",
      injectFormat: "Bearer {value}",
    });
    githubRouteId = githubRoute.id;
    const xSecret = await vault.createSecret(TENANT, "x-authority-token", "x-access-test");
    xSecretId = xSecret.id;
    const xRoute = await vault.createRoute(TENANT, xSecret.id, {
      agentId: AGENT_X,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });
    xRouteId = xRoute.id;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  test("registers Slack while rejecting a read-risk downgrade for chat.postMessage", async () => {
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

    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: whitespaceHeaderRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    // Deterministically mutate a route after the optimistic validation but
    // before the audited transaction. The locked re-read must reject the stale
    // target and leave account/operation authority untouched.
    store.faultHooks.afterOperationRoutePreflight = async () => {
      await vault.updateRoute(TENANT, raceRouteId, { injectFormat: "Token {value}" });
    };
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: raceRouteId,
      }),
    ).rejects.toMatchObject({ code: "revision_conflict", status: 409 });
    store.faultHooks = {};
    expect(await getDb().select().from(providerOperations)).toHaveLength(0);
    const [raceAccount] = await getDb()
      .select({ revision: providerAccounts.revision })
      .from(providerAccounts)
      .where(eq(providerAccounts.id, account.id));
    expect(raceAccount?.revision).toBe(1);
    const [raceRoute] = await getDb()
      .select({ mode: secretRoutes.authorityMode, operationId: secretRoutes.providerOperationId })
      .from(secretRoutes)
      .where(eq(secretRoutes.id, raceRouteId));
    expect(raceRoute).toEqual({ mode: "legacy", operationId: null });

    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: wrongHeaderRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: wrongFormatRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    // The completed audit is part of the same transaction as the account CAS,
    // operation insert, and route promotion. If the final required audit write
    // fails, all three mutations must roll back together.
    await expect(
      failingCompletedAuditStore.registerOperation(context(1), account.id, {
        operationKey: "slack.chat.postMessage",
        riskClass: "write",
        secretRouteId: routeId,
      }),
    ).rejects.toThrow("synthetic completed audit failure");
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
    const rollbackActions = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT));
    expect(rollbackActions.map((row) => row.action)).not.toContain(
      "provider.operation.register.completed",
    );

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
    const persistedActions = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT));
    expect(persistedActions.map((row) => row.action)).toEqual(
      expect.arrayContaining([
        "provider.account.create",
        "provider.operation.register",
        "provider.operation.register.completed",
      ]),
    );
  });

  test("applies the canonical bearer route contract to GitHub and X", async () => {
    const githubAccount = await store.createProviderAccount(context(2), {
      workspaceId: WORKSPACE,
      adapterKey: "github",
      externalRef: "steward-fi",
      displayName: "Steward GitHub",
      credentialSecretId: githubSecretId,
      credentialVersion: 1,
    });
    const xAccount = await store.createProviderAccount(context(3), {
      workspaceId: WORKSPACE,
      adapterKey: "x",
      externalRef: "12345",
      displayName: "@steward",
      credentialSecretId: xSecretId,
      credentialVersion: 1,
    });

    const githubOperation = await store.registerOperation(context(1), githubAccount.id, {
      operationKey: "github.issue.list",
      riskClass: "read",
      secretRouteId: githubRouteId,
    });
    const xOperation = await store.registerOperation(context(1), xAccount.id, {
      operationKey: "x.tweet.create",
      riskClass: "write",
      secretRouteId: xRouteId,
    });

    expect(githubOperation.operationKey).toBe("github.issue.list");
    expect(xOperation.operationKey).toBe("x.tweet.create");
    const promoted = await getDb()
      .select({ id: secretRoutes.id, mode: secretRoutes.authorityMode })
      .from(secretRoutes);
    expect(promoted).toEqual(
      expect.arrayContaining([
        { id: githubRouteId, mode: "governed_v2" },
        { id: xRouteId, mode: "governed_v2" },
      ]),
    );
  });
});
