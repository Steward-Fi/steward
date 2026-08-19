import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { createRequire } from "node:module";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  closeDb,
  getDb,
  tenants,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
  users,
  workspaces,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
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
): Promise<string> {
  const id = crypto.randomUUID();
  const terminal = status === "revoked" || status === "expired";
  await getDb()
    .insert(upstreamCredentialLeases)
    .values({
      id,
      tenantId: TENANT_ID,
      workspaceId: WORKSPACE_ID,
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
  await setupAgentBehaviorTestDatabase();
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
    if (USING_REAL_POSTGRES) {
      // The real-Postgres job owns an ephemeral database. Its append-only lease
      // evidence cannot be deleted without weakening the production trigger.
      await closeDb();
    } else {
      await cleanupAgentBehaviorTestDatabase(TENANT_ID);
    }
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
});
