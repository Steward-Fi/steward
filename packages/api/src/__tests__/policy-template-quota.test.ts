import { afterAll, beforeAll, expect, it } from "bun:test";
import { createRequire } from "node:module";
import {
  auditChainHeads,
  auditCheckpoints,
  auditEvents,
  closeDb,
  getDb,
  policyTemplates,
  tenants,
} from "@stwd/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

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

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;
const tenantId = `policy-quota-${crypto.randomUUID()}`;

async function makeApp() {
  const { policiesStandaloneRoutes } = await import("../routes/policies-standalone");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("userId", "11111111-1111-4111-8111-111111111111");
    await next();
  });
  app.route("/policies", policiesStandaloneRoutes);
  return app;
}

async function waitForAdvisoryWaiters(observer: Sql, holderPid: number, count: number) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const [row] = await observer<[{ waiters: number }]>`
      select count(*)::integer as waiters
      from pg_locks waiting
      join pg_locks held
        on held.locktype = waiting.locktype
       and held.database is not distinct from waiting.database
       and held.classid is not distinct from waiting.classid
       and held.objid is not distinct from waiting.objid
       and held.objsubid is not distinct from waiting.objsubid
      where held.pid = ${holderPid}
        and held.locktype = 'advisory'
        and held.granted
        and not waiting.granted
    `;
    if (row?.waiters === count) return;
    await Bun.sleep(10);
  }
  throw new Error(`Timed out waiting for ${count} policy-template quota lock waiters`);
}

beforeAll(async () => {
  if (!databaseUrl || process.env.STEWARD_PGLITE_MEMORY) return;

  const db = getDb();
  await db.insert(tenants).values({
    id: tenantId,
    name: "Policy Template Quota Test",
    apiKeyHash: `hash-${tenantId}`,
  });
  await db.insert(policyTemplates).values(
    Array.from({ length: 99 }, (_, index) => ({
      tenantId,
      name: `existing-${index}`,
      rules: [],
    })),
  );
});

afterAll(async () => {
  if (!databaseUrl || process.env.STEWARD_PGLITE_MEMORY) return;

  const db = getDb();
  await db.delete(auditCheckpoints).where(eq(auditCheckpoints.tenantId, tenantId));
  await db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
  await db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
  await db.delete(tenants).where(eq(tenants.id, tenantId));
  await closeDb();
});

realPostgresIt("serializes same-tenant creates at the 100-template quota", async () => {
  const holder = postgres(databaseUrl!, { max: 1 });
  const observer = postgres(databaseUrl!, { max: 1 });
  let releaseLock!: () => void;
  let lockAcquired!: (pid: number) => void;
  const release = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });
  const acquired = new Promise<number>((resolve) => {
    lockAcquired = resolve;
  });

  const holdLock = holder.begin(async (tx) => {
    const [row] = await tx<[{ pid: number }]>`select pg_backend_pid()::integer as pid`;
    await tx`select pg_advisory_xact_lock(hashtext(${`policy_templates:${tenantId}`}))`;
    lockAcquired(row.pid);
    await release;
  });

  try {
    const holderPid = await acquired;
    const app = await makeApp();
    const create = (name: string) =>
      app.request("/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, rules: [] }),
      });

    const requests = [create("racer-a"), create("racer-b")];
    // The first request waits on the quota lock while holding the canonical
    // tenant audit lock; the second waits behind it on that tenant lock.
    await waitForAdvisoryWaiters(observer, holderPid, 1);
    releaseLock();

    const responses = await Promise.all(requests);
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409]);
    const conflict = responses.find((response) => response.status === 409);
    expect(await conflict?.json()).toEqual({
      ok: false,
      error: "Tenant cannot have more than 100 policy templates",
    });

    const persisted = await getDb()
      .select({ id: policyTemplates.id })
      .from(policyTemplates)
      .where(eq(policyTemplates.tenantId, tenantId));
    expect(persisted).toHaveLength(100);
  } finally {
    releaseLock();
    await holdLock;
    await Promise.all([holder.end(), observer.end()]);
  }
});
