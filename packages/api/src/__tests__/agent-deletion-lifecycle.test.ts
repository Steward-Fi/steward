import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  getDb,
  intents,
  providerAccounts,
  providerActionBindings,
  providerOperations,
  runPluginMigrations,
  secretRoutes,
  tenants,
  transactions,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
  users,
  workspaces,
} from "@stwd/db";
import { capabilities, capabilityGrants } from "@stwd/plugin-capabilities";
import { and, eq, sql } from "drizzle-orm";
import { migrate as pgliteMigrate } from "drizzle-orm/pglite/migrator";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import {
  cleanupAgentBehaviorTestDatabase,
  setupAgentBehaviorTestDatabase,
  USING_REAL_POSTGRES,
} from "./agent-behavior-test-database";

type Sql = {
  <T extends unknown[]>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T>;
  begin<T>(callback: (tx: Sql) => Promise<T>): Promise<T>;
  end(): Promise<void>;
};

const requireFromDb = createRequire(new URL("../../../db/package.json", import.meta.url));
const postgresModule = requireFromDb("postgres") as { default?: unknown } | unknown;
const postgres = ((postgresModule as { default?: unknown }).default ?? postgresModule) as (
  url: string,
  options: { max: number },
) => Sql;

const TENANT_ID = `agent-deletion-lifecycle-${crypto.randomUUID()}`;
const PLATFORM_KEY = `agent-deletion-platform-${crypto.randomUUID()}`;
const WORKSPACE_ID = crypto.randomUUID();
const WORKSPACE_CREATOR_ID = crypto.randomUUID();
const CAPABILITY_MIGRATIONS = fileURLToPath(
  new URL("../../../plugin-capabilities/drizzle", import.meta.url),
);
const MUTATED_ENV = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_JWT_SECRET",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_PLATFORM_KEYS",
  "STEWARD_PLATFORM_KEY_SCOPES",
] as const;
const originalEnv = new Map(MUTATED_ENV.map((name) => [name, process.env[name]]));

setDefaultTimeout(60_000);

let tenantApp: Hono<{ Variables: AppVariables }>;
let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

async function createAgent(agentId: string): Promise<void> {
  await getDb().insert(agents).values({
    id: agentId,
    tenantId: TENANT_ID,
    name: agentId,
    walletAddress: "0x1234567890123456789012345678901234567890",
  });
}

async function createLease(
  agentId: string,
  status: "active" | "needs_attention" | "revoked" | "expired",
  workspaceId = WORKSPACE_ID,
): Promise<string> {
  const id = crypto.randomUUID();
  const terminal = status === "revoked" || status === "expired";
  await getDb()
    .insert(upstreamCredentialLeases)
    .values({
      id,
      tenantId: TENANT_ID,
      workspaceId,
      agentId,
      grantId: crypto.randomUUID(),
      capabilityId: crypto.randomUUID(),
      issuer: "github-app-installation",
      resource: {},
      resourceHash: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
      authorityDigest: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
      idempotencyKeyHash: crypto.randomUUID().replaceAll("-", "").padEnd(64, "0"),
      tokenHash: terminal ? null : "d".repeat(64),
      tokenCiphertext: terminal ? null : "sealed-token",
      tokenIv: terminal ? null : "sealed-iv",
      tokenAuthTag: terminal ? null : "sealed-tag",
      tokenSalt: terminal ? null : "sealed-salt",
      status,
      revokedAt: status === "revoked" ? new Date() : null,
    });
  await getDb()
    .insert(upstreamCredentialLeaseEvents)
    .values({
      leaseId: id,
      tenantId: TENANT_ID,
      action: terminal ? `lease.${status}` : "lease.issue",
      decision: terminal ? "allow" : "deny",
      metadata: { fixture: true },
    });
  return id;
}

async function createCapability(agentId?: string): Promise<{
  capabilityId: string;
  grantId?: string;
  routeId?: string;
}> {
  const capabilityId = crypto.randomUUID();
  await getDb()
    .insert(capabilities)
    .values({
      id: capabilityId,
      tenantId: TENANT_ID,
      name: `capability-${capabilityId}`,
      secretId: crypto.randomUUID(),
      host: "api.example.test",
      pathPattern: "/v1/*",
      method: "POST",
      injectKey: "Authorization",
    });
  if (!agentId) return { capabilityId };

  const routeId = crypto.randomUUID();
  const grantId = crypto.randomUUID();
  await getDb().insert(secretRoutes).values({
    id: routeId,
    tenantId: TENANT_ID,
    agentId,
    secretId: crypto.randomUUID(),
    hostPattern: "api.example.test",
    pathPattern: "/v1/*",
    method: "POST",
    injectAs: "header",
    injectKey: "Authorization",
  });
  await getDb().insert(capabilityGrants).values({
    id: grantId,
    tenantId: TENANT_ID,
    agentId,
    capabilityId,
    secretRouteId: routeId,
    status: "active",
  });
  return { capabilityId, grantId, routeId };
}

async function createProviderBinding(
  agentId: string,
  status: "denied" | "allowed_stub",
  intentAgentId = agentId,
  insertBinding = true,
): Promise<{
  intentId: string;
  binding: typeof providerActionBindings.$inferInsert;
}> {
  const accountId = crypto.randomUUID();
  const operationId = crypto.randomUUID();
  const intentId = `pa_${crypto.randomUUID()}`;
  await getDb().insert(providerAccounts).values({
    id: accountId,
    tenantId: TENANT_ID,
    workspaceId: WORKSPACE_ID,
    adapterKey: "github",
    externalRef: accountId,
    displayName: accountId,
  });
  await getDb()
    .insert(providerOperations)
    .values({
      id: operationId,
      tenantId: TENANT_ID,
      workspaceId: WORKSPACE_ID,
      providerAccountId: accountId,
      operationKey: `github.test.${operationId}`,
      riskClass: "read",
    });
  await getDb().insert(intents).values({
    id: intentId,
    tenantId: TENANT_ID,
    agentId: intentAgentId,
    intentType: "provider-action",
    status: "authorized",
    createdByType: "agent",
    createdById: intentAgentId,
  });
  const uniqueHash = () => `sha256:${crypto.randomUUID().replaceAll("-", "").padEnd(64, "0")}`;
  const binding: typeof providerActionBindings.$inferInsert = {
    intentId,
    tenantId: TENANT_ID,
    workspaceId: WORKSPACE_ID,
    actorAgentId: agentId,
    providerAccountId: accountId,
    operationId,
    operationRevision: 1,
    canonicalProfile: "github.provider-action.v1",
    canonicalActionBytes: Buffer.from("{}"),
    actionDigest: uniqueHash(),
    requestEnvelope: {},
    requestHash: uniqueHash(),
    idempotencyKeyHash: uniqueHash(),
    safeSummary: {},
    accessDecisionId: crypto.randomUUID(),
    accessEffect: status === "denied" ? "deny" : "allow",
    accessReasonCode: status === "denied" ? "access_denied" : "access_allowed",
    dependencyRevisions: {},
    accessDecision: {},
    accessDecisionHash: `sha256:${"3".repeat(64)}`,
    policyEffect: status === "denied" ? "not_evaluated" : "allow",
    policyDecisionId: status === "allowed_stub" ? crypto.randomUUID() : null,
    policyRevisionHash: status === "allowed_stub" ? `sha256:${"4".repeat(64)}` : null,
    policyDecision: status === "allowed_stub" ? {} : null,
    policyDecisionHash: status === "allowed_stub" ? `sha256:${"5".repeat(64)}` : null,
    status,
  };
  if (insertBinding) await getDb().insert(providerActionBindings).values(binding);
  return { intentId, binding };
}

async function tenantDelete(agentId: string): Promise<Response> {
  return tenantApp.request(`/agents/${agentId}`, { method: "DELETE" });
}

async function platformDelete(agentId: string): Promise<Response> {
  return platformRoutes.request(`/tenants/${TENANT_ID}/agents/${agentId}`, {
    method: "DELETE",
    headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
  });
}

async function expectBlockedDeletion(
  actor: "tenant" | "platform",
  status: "active" | "needs_attention",
): Promise<void> {
  const agentId = `${actor}-blocked-${crypto.randomUUID()}`;
  await createAgent(agentId);
  const leaseId = await createLease(agentId, status);
  const [beforeLease] = await getDb()
    .select()
    .from(upstreamCredentialLeases)
    .where(eq(upstreamCredentialLeases.id, leaseId));

  const response = await (actor === "tenant" ? tenantDelete(agentId) : platformDelete(agentId));
  expect(response.status).toBe(409);
  await expect(response.json()).resolves.toEqual({
    ok: false,
    error: "Agent has unresolved upstream credential leases",
  });
  expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(1);
  expect(
    await getDb()
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, leaseId)),
  ).toEqual([beforeLease]);
  expect(
    await getDb()
      .select({ action: upstreamCredentialLeaseEvents.action })
      .from(upstreamCredentialLeaseEvents)
      .where(eq(upstreamCredentialLeaseEvents.leaseId, leaseId)),
  ).toEqual([{ action: "lease.issue" }]);
}

async function expectTerminalDeletion(
  actor: "tenant" | "platform",
  status: "revoked" | "expired",
): Promise<void> {
  const agentId = `${actor}-terminal-${crypto.randomUUID()}`;
  await createAgent(agentId);
  const leaseId = await createLease(agentId, status);
  const [beforeLease] = await getDb()
    .select()
    .from(upstreamCredentialLeases)
    .where(eq(upstreamCredentialLeases.id, leaseId));

  const response = await (actor === "tenant" ? tenantDelete(agentId) : platformDelete(agentId));
  expect(response.status).toBe(200);
  expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(0);
  expect(
    await getDb()
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, leaseId)),
  ).toEqual([beforeLease]);
  const events = await getDb()
    .select({
      action: upstreamCredentialLeaseEvents.action,
      metadata: upstreamCredentialLeaseEvents.metadata,
    })
    .from(upstreamCredentialLeaseEvents)
    .where(eq(upstreamCredentialLeaseEvents.leaseId, leaseId));
  expect(events).toHaveLength(2);
  expect(events).toContainEqual({ action: `lease.${status}`, metadata: { fixture: true } });
  expect(events).toContainEqual({
    action: "lease.agent_authority_deleted",
    metadata: { terminalStatus: status },
  });
}

beforeAll(async () => {
  process.env.STEWARD_MASTER_PASSWORD = "agent-deletion-lifecycle-master-password";
  process.env.STEWARD_JWT_SECRET = "agent-deletion-lifecycle-jwt-secret-with-enough-entropy";
  process.env.STEWARD_AUDIT_HMAC_KEY = "agent-deletion-lifecycle-audit-key-with-enough-entropy";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({ [PLATFORM_KEY]: ["platform:*"] });
  __resetAuditHmacKeyCacheForTests();
  const pglite = await setupAgentBehaviorTestDatabase();
  await runPluginMigrations(
    { id: "capabilities", migrationsFolder: CAPABILITY_MIGRATIONS },
    pglite
      ? {
          db: pglite.db,
          client: pglite.client,
          useAdvisoryLock: false,
          migrateFn: pgliteMigrate as never,
        }
      : undefined,
  );
  await getDb()
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Agent deletion lifecycle",
      apiKeyHash: `hash-${TENANT_ID}`,
    });
  await getDb()
    .insert(users)
    .values({
      id: WORKSPACE_CREATOR_ID,
      email: `${WORKSPACE_CREATOR_ID}@agent-deletion.test`,
    });
  await getDb()
    .insert(workspaces)
    .values({
      id: WORKSPACE_ID,
      tenantId: TENANT_ID,
      key: `agent-deletion-${WORKSPACE_ID}`,
      name: "Agent deletion lifecycle",
      environment: "production",
      createdBy: WORKSPACE_CREATOR_ID,
    });

  const { agentRoutes } = await import("../routes/agents");
  tenantApp = new Hono<{ Variables: AppVariables }>();
  tenantApp.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "agent-deletion-admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  tenantApp.route("/agents", agentRoutes);
  tenantApp.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
  ({ platformRoutes } = await import("../routes/platform"));
});

afterAll(async () => {
  try {
    await cleanupAgentBehaviorTestDatabase(TENANT_ID);
  } finally {
    for (const [name, value] of originalEnv) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    __resetAuditHmacKeyCacheForTests();
  }
});

describe("agent deletion upstream credential boundary", () => {
  it("refuses tenant-admin deletion while an active sealed lease remains", async () => {
    await expectBlockedDeletion("tenant", "active");
  });

  it("refuses platform deletion while provider revocation needs attention", async () => {
    await expectBlockedDeletion("platform", "needs_attention");
  });

  it("deletes tenant-admin agents only after revoked lease evidence is terminal", async () => {
    await expectTerminalDeletion("tenant", "revoked");
  });

  it("deletes platform agents only after expired lease evidence is terminal", async () => {
    await expectTerminalDeletion("platform", "expired");
  });

  it("retains terminal lease evidence across workspace deletion but blocks unresolved authority", async () => {
    const terminalWorkspaceId = crypto.randomUUID();
    const activeWorkspaceId = crypto.randomUUID();
    await getDb()
      .insert(workspaces)
      .values([
        {
          id: terminalWorkspaceId,
          tenantId: TENANT_ID,
          key: `terminal-${terminalWorkspaceId}`,
          name: "terminal lease evidence",
          environment: "production",
          createdBy: WORKSPACE_CREATOR_ID,
        },
        {
          id: activeWorkspaceId,
          tenantId: TENANT_ID,
          key: `active-${activeWorkspaceId}`,
          name: "active lease authority",
          environment: "production",
          createdBy: WORKSPACE_CREATOR_ID,
        },
      ]);
    const terminalAgentId = `terminal-workspace-${crypto.randomUUID()}`;
    const activeAgentId = `active-workspace-${crypto.randomUUID()}`;
    await createAgent(terminalAgentId);
    await createAgent(activeAgentId);
    const terminalLeaseId = await createLease(terminalAgentId, "revoked", terminalWorkspaceId);
    const activeLeaseId = await createLease(activeAgentId, "active", activeWorkspaceId);

    await getDb().delete(workspaces).where(eq(workspaces.id, terminalWorkspaceId));
    expect(
      await getDb()
        .select({ id: upstreamCredentialLeases.id })
        .from(upstreamCredentialLeases)
        .where(eq(upstreamCredentialLeases.id, terminalLeaseId)),
    ).toEqual([{ id: terminalLeaseId }]);

    let unresolvedDeleteError: unknown;
    try {
      await getDb().delete(workspaces).where(eq(workspaces.id, activeWorkspaceId));
    } catch (error) {
      unresolvedDeleteError = error;
    }
    expect(unresolvedDeleteError).toBeInstanceOf(Error);
    expect((unresolvedDeleteError as { cause?: { code?: string } }).cause?.code).toBe("55000");

    await getDb().transaction(async (tx) => {
      await tx.execute(sql`SET LOCAL session_replication_role = replica`);
      await tx.execute(
        sql`DELETE FROM upstream_credential_lease_events WHERE lease_id = ${activeLeaseId}`,
      );
      await tx.execute(sql`DELETE FROM upstream_credential_leases WHERE id = ${activeLeaseId}`);
    });
    await getDb().delete(workspaces).where(eq(workspaces.id, activeWorkspaceId));
  });

  it("revokes an existing capability grant and disables its route atomically", async () => {
    const agentId = `capability-existing-${crypto.randomUUID()}`;
    await createAgent(agentId);
    const { grantId, routeId } = await createCapability(agentId);

    expect((await tenantDelete(agentId)).status).toBe(200);
    expect(
      await getDb()
        .select()
        .from(capabilityGrants)
        .where(eq(capabilityGrants.id, grantId as string)),
    ).toMatchObject([{ status: "revoked", secretRouteId: routeId }]);
    expect(
      await getDb()
        .select()
        .from(secretRoutes)
        .where(eq(secretRoutes.id, routeId as string)),
    ).toMatchObject([{ enabled: false }]);

    let reactivationError: unknown;
    try {
      await getDb()
        .update(capabilityGrants)
        .set({ status: "active" })
        .where(eq(capabilityGrants.id, grantId as string));
    } catch (error) {
      reactivationError = error;
    }
    expect(reactivationError).toBeInstanceOf(Error);
    expect((reactivationError as { cause?: { code?: string } }).cause?.code).toBe("23503");
    expect(
      await getDb()
        .select({ status: capabilityGrants.status })
        .from(capabilityGrants)
        .where(eq(capabilityGrants.id, grantId as string)),
    ).toEqual([{ status: "revoked" }]);
  });

  it("refuses both routed and direct deletion while signed execution is unresolved", async () => {
    const agentId = `signed-execution-${crypto.randomUUID()}`;
    const transactionId = crypto.randomUUID();
    await createAgent(agentId);
    await getDb().insert(transactions).values({
      id: transactionId,
      agentId,
      status: "signed",
      toAddress: "0x1234567890123456789012345678901234567890",
      value: "0",
      chainId: 1,
    });

    const response = await tenantDelete(agentId);
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      error: "Agent has unresolved execution evidence; reconcile it first",
    });

    if (USING_REAL_POSTGRES) {
      let directDeleteError: unknown;
      try {
        await getDb().delete(agents).where(eq(agents.id, agentId));
      } catch (error) {
        directDeleteError = error;
      }
      expect(directDeleteError).toBeInstanceOf(Error);
      expect((directDeleteError as { cause?: { code?: string } }).cause?.code).toBe("55000");
      expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(1);
    }
    await getDb().delete(transactions).where(eq(transactions.id, transactionId));
    expect((await tenantDelete(agentId)).status).toBe(200);
  });

  it.skipIf(!USING_REAL_POSTGRES)(
    "retains resolved provider evidence and fences post-delete publication or resurrection",
    async () => {
      const agentId = `provider-terminal-${crypto.randomUUID()}`;
      const survivorId = `provider-survivor-${crypto.randomUUID()}`;
      await createAgent(agentId);
      await createAgent(survivorId);
      const { intentId } = await createProviderBinding(agentId, "denied");

      expect((await tenantDelete(agentId)).status).toBe(200);
      expect(
        await getDb()
          .select({ status: providerActionBindings.status })
          .from(providerActionBindings)
          .where(eq(providerActionBindings.intentId, intentId)),
      ).toEqual([{ status: "denied" }]);
      expect(
        await getDb()
          .select({ agentId: intents.agentId })
          .from(intents)
          .where(eq(intents.id, intentId)),
      ).toEqual([{ agentId: null }]);

      let resurrectionError: unknown;
      try {
        await getDb()
          .update(providerActionBindings)
          .set({ status: "allowed_stub" })
          .where(eq(providerActionBindings.intentId, intentId));
      } catch (error) {
        resurrectionError = error;
      }
      expect((resurrectionError as { cause?: { code?: string } }).cause?.code).toBe("23503");

      const { binding } = await createProviderBinding(agentId, "allowed_stub", survivorId, false);
      let publicationError: unknown;
      try {
        await getDb().insert(providerActionBindings).values(binding);
      } catch (error) {
        publicationError = error;
      }
      expect((publicationError as { cause?: { code?: string } }).cause?.code).toBe("23503");
    },
  );

  it.skipIf(!USING_REAL_POSTGRES)(
    "returns 409 while provider dispatch remains unresolved",
    async () => {
      const agentId = `provider-live-${crypto.randomUUID()}`;
      await createAgent(agentId);
      await createProviderBinding(agentId, "allowed_stub");
      const response = await tenantDelete(agentId);
      expect(response.status).toBe(409);
      await expect(response.json()).resolves.toEqual({
        ok: false,
        error: "Agent has unresolved execution evidence; reconcile it first",
      });
      expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(1);
    },
  );

  it.skipIf(!USING_REAL_POSTGRES)(
    "prevents lease publication from racing past the locked deletion decision",
    async () => {
      const agentId = `lease-race-${crypto.randomUUID()}`;
      await createAgent(agentId);
      const blockerLeaseId = await createLease(agentId, "revoked");
      const holder = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const writer = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const observer = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const [writerBackend] = await writer<{ pid: number }[]>`
        select pg_backend_pid()::int as pid
      `;
      const writerPid = writerBackend?.pid ?? 0;
      let releaseHolder!: () => void;
      const release = new Promise<void>((resolve) => {
        releaseHolder = resolve;
      });
      let holderPid = 0;
      let holderReady!: () => void;
      const ready = new Promise<void>((resolve) => {
        holderReady = resolve;
      });
      const holderTransaction = holder.begin(async (tx) => {
        const [backend] = await tx<{ pid: number }[]>`select pg_backend_pid()::int as pid`;
        holderPid = backend?.pid ?? 0;
        await tx`select id from upstream_credential_leases where id = ${blockerLeaseId} for update`;
        holderReady();
        await release;
      });
      await ready;

      let deletion: Promise<Response> | undefined;
      let writerOutcome: Promise<{ ok: boolean; error?: unknown }> | undefined;
      try {
        deletion = tenantDelete(agentId);
        let deletionBlocked = false;
        for (let attempt = 0; attempt < 400 && !deletionBlocked; attempt += 1) {
          const [row] = await observer<{ blocked: boolean }[]>`
            select exists (
              select 1 from pg_stat_activity activity
              where ${holderPid} = any(pg_blocking_pids(activity.pid))
                and activity.query ilike '%upstream_credential_leases%'
            ) as blocked
          `;
          deletionBlocked = row?.blocked === true;
          if (!deletionBlocked) await Bun.sleep(10);
        }
        expect(deletionBlocked).toBe(true);

        const writerQuery = writer`
          insert into upstream_credential_leases (
            tenant_id, workspace_id, agent_id, grant_id, capability_id, issuer,
            resource, resource_hash, authority_digest, idempotency_key_hash,
            token_hash, token_ciphertext, token_iv, token_auth_tag, token_salt, status
          ) values (
            ${TENANT_ID}, ${WORKSPACE_ID}, ${agentId}, ${crypto.randomUUID()},
            ${crypto.randomUUID()}, 'github-app-installation', '{}'::jsonb,
            ${"e".repeat(64)}, ${"f".repeat(64)}, ${"a".repeat(64)},
            ${"b".repeat(64)}, 'late-token', 'late-iv', 'late-tag', 'late-salt', 'active'
          )
        `;
        writerOutcome = writerQuery.then(
          () => ({ ok: true }),
          (error) => ({ ok: false, error }),
        );

        let writerBlocked = false;
        for (let attempt = 0; attempt < 400 && !writerBlocked; attempt += 1) {
          const [row] = await observer<{ blocked: boolean }[]>`
            select exists (
              select 1 from pg_stat_activity activity
              where activity.pid = ${writerPid}
                and activity.wait_event_type = 'Lock'
            ) as blocked
          `;
          writerBlocked = row?.blocked === true;
          if (!writerBlocked) await Bun.sleep(10);
        }
        expect(writerBlocked).toBe(true);

        releaseHolder();
        await holderTransaction;
        expect((await deletion).status).toBe(200);
        expect(await writerOutcome).toMatchObject({
          ok: false,
          error: expect.objectContaining({ code: "23503" }),
        });
        expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(0);
        expect(
          await getDb()
            .select()
            .from(upstreamCredentialLeases)
            .where(
              and(
                eq(upstreamCredentialLeases.agentId, agentId),
                eq(upstreamCredentialLeases.status, "active"),
              ),
            ),
        ).toHaveLength(0);
      } finally {
        releaseHolder();
        await Promise.allSettled([
          holderTransaction,
          deletion ?? Promise.resolve(new Response()),
          writerOutcome ?? Promise.resolve({ ok: false }),
        ]);
        await Promise.all([holder.end(), writer.end(), observer.end()]);
      }
    },
  );

  it.skipIf(!USING_REAL_POSTGRES)(
    "prevents capability grant creation from racing past the locked deletion decision",
    async () => {
      const agentId = `capability-race-${crypto.randomUUID()}`;
      await createAgent(agentId);
      const blockerLeaseId = await createLease(agentId, "revoked");
      const { capabilityId } = await createCapability();
      const holder = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const writer = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const observer = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const [writerBackend] = await writer<{ pid: number }[]>`
        select pg_backend_pid()::int as pid
      `;
      const writerPid = writerBackend?.pid ?? 0;
      let releaseHolder!: () => void;
      const release = new Promise<void>((resolve) => {
        releaseHolder = resolve;
      });
      let holderPid = 0;
      let holderReady!: () => void;
      const ready = new Promise<void>((resolve) => {
        holderReady = resolve;
      });
      const holderTransaction = holder.begin(async (tx) => {
        const [backend] = await tx<{ pid: number }[]>`select pg_backend_pid()::int as pid`;
        holderPid = backend?.pid ?? 0;
        await tx`select id from upstream_credential_leases where id = ${blockerLeaseId} for update`;
        holderReady();
        await release;
      });
      await ready;

      let deletion: Promise<Response> | undefined;
      let writerOutcome: Promise<{ ok: boolean; error?: unknown }> | undefined;
      try {
        deletion = tenantDelete(agentId);
        let deletionBlocked = false;
        for (let attempt = 0; attempt < 400 && !deletionBlocked; attempt += 1) {
          const [row] = await observer<{ blocked: boolean }[]>`
            select exists (
              select 1 from pg_stat_activity activity
              where ${holderPid} = any(pg_blocking_pids(activity.pid))
                and activity.query ilike '%upstream_credential_leases%'
            ) as blocked
          `;
          deletionBlocked = row?.blocked === true;
          if (!deletionBlocked) await Bun.sleep(10);
        }
        expect(deletionBlocked).toBe(true);

        writerOutcome = writer`
          insert into capability_grants (
            id, tenant_id, agent_id, capability_id, status
          ) values (
            ${crypto.randomUUID()}, ${TENANT_ID}, ${agentId}, ${capabilityId}, 'active'
          )
        `.then(
          () => ({ ok: true }),
          (error) => ({ ok: false, error }),
        );

        let writerBlocked = false;
        for (let attempt = 0; attempt < 400 && !writerBlocked; attempt += 1) {
          const [row] = await observer<{ blocked: boolean }[]>`
            select exists (
              select 1 from pg_stat_activity activity
              where activity.pid = ${writerPid}
                and activity.wait_event_type = 'Lock'
            ) as blocked
          `;
          writerBlocked = row?.blocked === true;
          if (!writerBlocked) await Bun.sleep(10);
        }
        expect(writerBlocked).toBe(true);

        releaseHolder();
        await holderTransaction;
        expect((await deletion).status).toBe(200);
        expect(await writerOutcome).toMatchObject({
          ok: false,
          error: expect.objectContaining({ code: "23503" }),
        });
        expect(
          await getDb()
            .select()
            .from(capabilityGrants)
            .where(
              and(eq(capabilityGrants.agentId, agentId), eq(capabilityGrants.status, "active")),
            ),
        ).toHaveLength(0);
      } finally {
        releaseHolder();
        await Promise.allSettled([
          holderTransaction,
          deletion ?? Promise.resolve(new Response()),
          writerOutcome ?? Promise.resolve({ ok: false }),
        ]);
        await Promise.all([holder.end(), writer.end(), observer.end()]);
      }
    },
  );

  it.skipIf(!USING_REAL_POSTGRES)(
    "prevents retained authority rows from being reactivated after agent deletion",
    async () => {
      const agentId = `authority-reactivation-${crypto.randomUUID()}`;
      await createAgent(agentId);
      const leaseId = await createLease(agentId, "revoked");
      const { grantId, routeId } = await createCapability(agentId);
      await getDb()
        .update(capabilityGrants)
        .set({ status: "revoked" })
        .where(eq(capabilityGrants.id, grantId as string));
      await getDb()
        .update(secretRoutes)
        .set({ enabled: false })
        .where(eq(secretRoutes.id, routeId as string));

      const holder = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const leaseWriter = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const routeWriter = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const grantWriter = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const observer = postgres(process.env.DATABASE_URL as string, { max: 1 });
      const writerPids = await Promise.all(
        [leaseWriter, routeWriter, grantWriter].map(async (writer) => {
          const [row] = await writer<{ pid: number }[]>`select pg_backend_pid()::int as pid`;
          return row?.pid ?? 0;
        }),
      );
      const leaseWriterPid = writerPids[0] as number;
      const routeWriterPid = writerPids[1] as number;
      const grantWriterPid = writerPids[2] as number;
      let releaseHolder!: () => void;
      const release = new Promise<void>((resolve) => {
        releaseHolder = resolve;
      });
      let holderReady!: () => void;
      const ready = new Promise<void>((resolve) => {
        holderReady = resolve;
      });
      const holderTransaction = holder.begin(async (tx) => {
        await tx`select id from agents where tenant_id = ${TENANT_ID} and id = ${agentId} for update`;
        holderReady();
        await release;
        await tx`delete from agents where tenant_id = ${TENANT_ID} and id = ${agentId}`;
      });
      await ready;

      const outcomes = [
        leaseWriter`
          update upstream_credential_leases
          set status = 'active', token_hash = ${"e".repeat(64)},
              token_ciphertext = 'late-token', token_iv = 'late-iv',
              token_auth_tag = 'late-tag', token_salt = 'late-salt'
          where id = ${leaseId}
        `,
        routeWriter`
          update secret_routes set enabled = true where id = ${routeId as string}
        `,
        grantWriter`
          update capability_grants set status = 'active' where id = ${grantId as string}
        `,
      ].map((operation) =>
        operation.then(
          () => ({ ok: true }),
          (error) => ({ ok: false, error }),
        ),
      );

      try {
        let allBlocked = false;
        for (let attempt = 0; attempt < 400 && !allBlocked; attempt += 1) {
          const rows = await observer<{ pid: number; blocked: boolean }[]>`
            select activity.pid::int as pid, activity.wait_event_type = 'Lock' as blocked
            from pg_stat_activity activity
            where activity.pid = ${leaseWriterPid}
               or activity.pid = ${routeWriterPid}
               or activity.pid = ${grantWriterPid}
          `;
          allBlocked =
            rows.length === writerPids.length && rows.every((row) => row.blocked === true);
          if (!allBlocked) await Bun.sleep(10);
        }
        expect(allBlocked).toBe(true);

        releaseHolder();
        await holderTransaction;
        expect(await Promise.all(outcomes)).toEqual([
          { ok: false, error: expect.objectContaining({ code: "23503" }) },
          { ok: false, error: expect.objectContaining({ code: "23503" }) },
          { ok: false, error: expect.objectContaining({ code: "23503" }) },
        ]);
        expect(
          await getDb()
            .select()
            .from(upstreamCredentialLeases)
            .where(eq(upstreamCredentialLeases.id, leaseId)),
        ).toMatchObject([{ status: "revoked", tokenCiphertext: null }]);
        expect(
          await getDb()
            .select()
            .from(secretRoutes)
            .where(eq(secretRoutes.id, routeId as string)),
        ).toMatchObject([{ enabled: false }]);
        expect(
          await getDb()
            .select()
            .from(capabilityGrants)
            .where(eq(capabilityGrants.id, grantId as string)),
        ).toMatchObject([{ status: "revoked" }]);
      } finally {
        releaseHolder();
        await Promise.allSettled([holderTransaction, ...outcomes]);
        await Promise.all([
          holder.end(),
          leaseWriter.end(),
          routeWriter.end(),
          grantWriter.end(),
          observer.end(),
        ]);
      }
    },
  );
});
