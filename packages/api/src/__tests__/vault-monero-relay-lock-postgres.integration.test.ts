import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createRequire } from "node:module";
import { agents, getDb, tenants, transactions } from "@stwd/db";
import { eq } from "drizzle-orm";

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
const describePostgres =
  databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;
setDefaultTimeout(120_000);

describePostgres("Monero relay parent/idempotency locks (real Postgres)", () => {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const tenantId = `monero-lock-tenant-${suffix}`;
  let admin: Sql;
  let withMoneroRelayLock: <T>(agentId: string, fn: () => Promise<T>) => Promise<T>;

  beforeAll(async () => {
    admin = postgres(databaseUrl!, { max: 1 });
    ({ __withMoneroRelayLockForTests: withMoneroRelayLock } = await import("../routes/vault"));
    await getDb().insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: tenantId });
  });

  afterAll(async () => {
    await getDb()
      .delete(transactions)
      .where(eq(transactions.agentId, `monero-same-key-${suffix}`));
    await getDb()
      .delete(transactions)
      .where(eq(transactions.agentId, `monero-relay-first-${suffix}`));
    await getDb().delete(agents).where(eq(agents.tenantId, tenantId));
    await getDb().delete(tenants).where(eq(tenants.id, tenantId));
    await admin.end();
  });

  async function waitForExactAdvisoryWaiter(agentId: string) {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const [row] = await admin<{ holders: string; waiters: string }[]>`
        select
          count(*) filter (where granted)::text as holders,
          count(*) filter (where not granted)::text as waiters
        from pg_locks
        where locktype = 'advisory'
          and classid = (((hashtextextended(${agentId}, 0) >> 32) & 4294967295)::text)::oid
          and objid = ((hashtextextended(${agentId}, 0) & 4294967295)::text)::oid
          and objsubid = 1
      `;
      if (row?.holders === "1" && row.waiters === "1") return;
      await Bun.sleep(20);
    }
    throw new Error("exact Monero advisory lock waiter was not observed");
  }

  test("same-key contenders use distinct lock backends and checkpoint exactly one relay", async () => {
    const agentId = `monero-same-key-${suffix}`;
    const keyDigest = `key-${suffix}`;
    await getDb().insert(agents).values({ id: agentId, tenantId, name: agentId });
    let releaseFirst!: () => void;
    let firstEntered!: () => void;
    const release = new Promise<void>((resolve) => (releaseFirst = resolve));
    const entered = new Promise<void>((resolve) => (firstEntered = resolve));
    let relayCount = 0;
    const attempt = () =>
      withMoneroRelayLock(agentId, async () => {
        const [existing] = await getDb()
          .select({ id: transactions.id })
          .from(transactions)
          .where(eq(transactions.id, `monero-checkpoint-${keyDigest}`));
        if (existing) return existing.id;
        relayCount += 1;
        firstEntered();
        await release;
        await getDb()
          .insert(transactions)
          .values({
            id: `monero-checkpoint-${keyDigest}`,
            agentId,
            status: "approved",
            value: "1",
            chainId: 301,
            actionType: "monero_transfer",
            actionPayload: { type: "monero_relay_recovery", idempotencyKeyDigest: keyDigest },
            policyResults: [],
          });
        return `monero-checkpoint-${keyDigest}`;
      });

    const first = attempt();
    await entered;
    const second = attempt();
    await waitForExactAdvisoryWaiter(agentId);
    releaseFirst();
    expect(await Promise.all([first, second])).toEqual([
      `monero-checkpoint-${keyDigest}`,
      `monero-checkpoint-${keyDigest}`,
    ]);
    expect(relayCount).toBe(1);
    const rows = await getDb().select().from(transactions).where(eq(transactions.agentId, agentId));
    expect(rows).toHaveLength(1);
  });

  test("relay-first holds the agent parent; delete-first prevents any relay", async () => {
    const relayFirstAgent = `monero-relay-first-${suffix}`;
    await getDb().insert(agents).values({ id: relayFirstAgent, tenantId, name: relayFirstAgent });
    let releaseRelay!: () => void;
    let relayEntered!: () => void;
    const release = new Promise<void>((resolve) => (releaseRelay = resolve));
    const entered = new Promise<void>((resolve) => (relayEntered = resolve));
    let relays = 0;
    const relay = withMoneroRelayLock(relayFirstAgent, async () => {
      relays += 1;
      relayEntered();
      await release;
      await getDb()
        .insert(transactions)
        .values({
          id: `relay-first-anchor-${suffix}`,
          agentId: relayFirstAgent,
          status: "approved",
          value: "1",
          chainId: 301,
          actionType: "monero_transfer",
          actionPayload: { type: "monero_relay_recovery" },
          policyResults: [],
        });
    });
    await entered;
    const deletion = admin.begin(async (tx) => {
      await tx`delete from agents where id = ${relayFirstAgent}`;
    });
    await Bun.sleep(50);
    expect(relays).toBe(1);
    releaseRelay();
    await relay;
    await expect(deletion).rejects.toThrow();
    expect(await getDb().select().from(agents).where(eq(agents.id, relayFirstAgent))).toHaveLength(
      1,
    );

    const deleteFirstAgent = `monero-delete-first-${suffix}`;
    await getDb().insert(agents).values({ id: deleteFirstAgent, tenantId, name: deleteFirstAgent });
    let releaseDelete!: () => void;
    let deleteHeld!: () => void;
    const deleteRelease = new Promise<void>((resolve) => (releaseDelete = resolve));
    const held = new Promise<void>((resolve) => (deleteHeld = resolve));
    const deleteFirst = admin.begin(async (tx) => {
      await tx`delete from agents where id = ${deleteFirstAgent}`;
      deleteHeld();
      await deleteRelease;
    });
    await held;
    const blockedRelay = withMoneroRelayLock(deleteFirstAgent, async () => {
      relays += 1;
    });
    await Bun.sleep(50);
    expect(relays).toBe(1);
    releaseDelete();
    await deleteFirst;
    await expect(blockedRelay).rejects.toThrow(/Agent disappeared/);
    expect(relays).toBe(1);
  });
});
