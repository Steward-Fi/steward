import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createRequire } from "node:module";
import { agents, getDb, tenants, transactions } from "@stwd/db";
import { eq } from "drizzle-orm";

type Sql = {
  <T extends unknown[]>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T>;
  begin<T>(callback: (tx: Sql) => Promise<T>): Promise<T>;
  end(): Promise<void>;
};

type AgentTuple = { block: number; offset: number; relation: number };

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

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

async function waitForOwnedSignal<T>(
  signal: Promise<T>,
  owner: Promise<unknown>,
  label: string,
  timeoutMs = 5_000,
): Promise<T> {
  let deadline: ReturnType<typeof setTimeout> | undefined;
  const ownerSettled = owner.then(
    () => {
      throw new Error(`${label}: owning operation completed before its signal`);
    },
    (cause) => {
      throw new Error(`${label}: owning operation failed before its signal`, { cause });
    },
  );
  const timedOut = new Promise<never>((_, reject) => {
    deadline = setTimeout(() => reject(new Error(`${label}: signal deadline exceeded`)), timeoutMs);
  });
  try {
    return await Promise.race([signal, ownerSettled, timedOut]);
  } finally {
    if (deadline) clearTimeout(deadline);
  }
}

describePostgres("Monero relay parent/idempotency locks (real Postgres)", () => {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const tenantId = `monero-lock-tenant-${suffix}`;
  let admin: Sql;
  let withMoneroRelayLock: <T>(
    agentId: string,
    fn: () => Promise<T>,
    onBackendForTests?: (pid: number) => void,
  ) => Promise<T>;

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

  async function agentTuple(agentId: string): Promise<AgentTuple> {
    const [row] = await admin<AgentTuple[]>`
      select
        tableoid::oid::integer as relation,
        ((ctid::text::point)[0])::integer as block,
        ((ctid::text::point)[1])::integer as offset
      from agents
      where id = ${agentId}
    `;
    if (!row) throw new Error(`missing agent tuple for ${agentId}`);
    return row;
  }

  async function waitForExactAdvisoryWaiter(agentId: string, holderPid: number, waiterPid: number) {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const rows = await admin<{ granted: boolean; pid: number }[]>`
        select pid, granted
        from pg_locks
        where locktype = 'advisory'
          and classid = (((hashtextextended(${agentId}, 0) >> 32) & 4294967295)::text)::oid
          and objid = ((hashtextextended(${agentId}, 0) & 4294967295)::text)::oid
          and objsubid = 1
          and pid in (${holderPid}, ${waiterPid})
        order by pid
      `;
      if (
        rows.length === 2 &&
        rows.some((row) => row.pid === holderPid && row.granted) &&
        rows.some((row) => row.pid === waiterPid && !row.granted)
      ) {
        return;
      }
      await Bun.sleep(20);
    }
    throw new Error(`expected backend ${waiterPid} did not wait behind ${holderPid}`);
  }

  async function waitForExactAgentTupleWaiter(
    tuple: AgentTuple,
    blockerPid: number,
    waiterPid: number,
  ) {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const [row] = await admin<{ blocked: boolean; tupleLock: boolean; xidWait: boolean }[]>`
        select
          ${blockerPid} = any(pg_blocking_pids(${waiterPid})) as blocked,
          exists (
            select 1 from pg_locks
            where pid = ${waiterPid}
              and locktype = 'tuple'
              and relation = ${tuple.relation}::oid
              and page = ${tuple.block}
              and tuple = ${tuple.offset}
          ) as "tupleLock",
          exists (
            select 1 from pg_locks
            where pid = ${waiterPid}
              and locktype = 'transactionid'
              and not granted
          ) as "xidWait"
      `;
      if (row?.blocked && row.tupleLock && row.xidWait) return;
      await Bun.sleep(20);
    }
    throw new Error(`backend ${waiterPid} did not wait on exact agent tuple behind ${blockerPid}`);
  }

  test("same-key contenders use distinct lock backends and checkpoint exactly one relay", async () => {
    const agentId = `monero-same-key-${suffix}`;
    const keyDigest = `key-${suffix}`;
    await getDb().insert(agents).values({ id: agentId, tenantId, name: agentId });
    const releaseFirst = deferred<void>();
    const firstEntered = deferred<void>();
    const firstBackend = deferred<number>();
    const secondBackend = deferred<number>();
    let relayCount = 0;
    const attempt = (backend: ReturnType<typeof deferred<number>>) =>
      withMoneroRelayLock(
        agentId,
        async () => {
          const [existing] = await getDb()
            .select({ id: transactions.id })
            .from(transactions)
            .where(eq(transactions.id, `monero-checkpoint-${keyDigest}`));
          if (existing) return existing.id;
          relayCount += 1;
          firstEntered.resolve();
          await releaseFirst.promise;
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
        },
        backend.resolve,
      );

    let first: ReturnType<typeof attempt> | undefined;
    let second: ReturnType<typeof attempt> | undefined;
    try {
      first = attempt(firstBackend);
      await waitForOwnedSignal(firstEntered.promise, first, "first relay entry");
      second = attempt(secondBackend);
      const [holderPid, waiterPid] = await Promise.all([
        waitForOwnedSignal(firstBackend.promise, first, "first relay backend"),
        waitForOwnedSignal(secondBackend.promise, second, "second relay backend"),
      ]);
      expect(waiterPid).not.toBe(holderPid);
      await waitForExactAdvisoryWaiter(agentId, holderPid, waiterPid);
      releaseFirst.resolve();
      expect(await Promise.all([first, second])).toEqual([
        `monero-checkpoint-${keyDigest}`,
        `monero-checkpoint-${keyDigest}`,
      ]);
      expect(relayCount).toBe(1);
      const rows = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.agentId, agentId));
      expect(rows).toHaveLength(1);
    } finally {
      releaseFirst.resolve();
      await Promise.allSettled([first ?? Promise.resolve(), second ?? Promise.resolve()]);
    }
  });

  test("relay-first holds the exact agent parent tuple until the anchor exists", async () => {
    const agentId = `monero-relay-first-${suffix}`;
    await getDb().insert(agents).values({ id: agentId, tenantId, name: agentId });
    const tuple = await agentTuple(agentId);
    const deletionClient = postgres(databaseUrl!, { max: 1 });
    const releaseRelay = deferred<void>();
    const relayEntered = deferred<void>();
    const relayBackend = deferred<number>();
    const deletionBackend = deferred<number>();
    let relays = 0;
    let relay: Promise<void> | undefined;
    let deletion: Promise<void> | undefined;
    try {
      relay = withMoneroRelayLock(
        agentId,
        async () => {
          relays += 1;
          relayEntered.resolve();
          await releaseRelay.promise;
          await getDb()
            .insert(transactions)
            .values({
              id: `relay-first-anchor-${suffix}`,
              agentId,
              status: "approved",
              value: "1",
              chainId: 301,
              actionType: "monero_transfer",
              actionPayload: { type: "monero_relay_recovery" },
              policyResults: [],
            });
        },
        relayBackend.resolve,
      );
      await waitForOwnedSignal(relayEntered.promise, relay, "relay-first entry");
      deletion = deletionClient.begin(async (tx) => {
        const [backend] = await tx<{ pid: number }[]>`select pg_backend_pid()::int as pid`;
        if (!backend) throw new Error("delete backend is unavailable");
        deletionBackend.resolve(backend.pid);
        await tx`delete from agents where id = ${agentId}`;
      });
      const [blockerPid, waiterPid] = await Promise.all([
        waitForOwnedSignal(relayBackend.promise, relay, "relay-first backend"),
        waitForOwnedSignal(deletionBackend.promise, deletion, "relay-first delete backend"),
      ]);
      await waitForExactAgentTupleWaiter(tuple, blockerPid, waiterPid);
      expect(relays).toBe(1);
      releaseRelay.resolve();
      await relay;
      await expect(deletion).rejects.toThrow();
      expect(await getDb().select().from(agents).where(eq(agents.id, agentId))).toHaveLength(1);
    } finally {
      releaseRelay.resolve();
      await Promise.allSettled([relay ?? Promise.resolve(), deletion ?? Promise.resolve()]);
      await deletionClient.end();
    }
  });

  test("delete-first blocks the exact relay backend and prevents relay execution", async () => {
    const agentId = `monero-delete-first-${suffix}`;
    await getDb().insert(agents).values({ id: agentId, tenantId, name: agentId });
    const tuple = await agentTuple(agentId);
    const deletionClient = postgres(databaseUrl!, { max: 1 });
    const releaseDelete = deferred<void>();
    const deleteHeld = deferred<void>();
    const deletionBackend = deferred<number>();
    const relayBackend = deferred<number>();
    let relays = 0;
    let deletion: Promise<void> | undefined;
    let relay: Promise<void> | undefined;
    try {
      deletion = deletionClient.begin(async (tx) => {
        const [backend] = await tx<{ pid: number }[]>`select pg_backend_pid()::int as pid`;
        if (!backend) throw new Error("delete backend is unavailable");
        deletionBackend.resolve(backend.pid);
        await tx`delete from agents where id = ${agentId}`;
        deleteHeld.resolve();
        await releaseDelete.promise;
      });
      await waitForOwnedSignal(deleteHeld.promise, deletion, "delete-first parent deletion");
      relay = withMoneroRelayLock(
        agentId,
        async () => {
          relays += 1;
        },
        relayBackend.resolve,
      );
      const [blockerPid, waiterPid] = await Promise.all([
        waitForOwnedSignal(deletionBackend.promise, deletion, "delete-first backend"),
        waitForOwnedSignal(relayBackend.promise, relay, "delete-first relay backend"),
      ]);
      await waitForExactAgentTupleWaiter(tuple, blockerPid, waiterPid);
      expect(relays).toBe(0);
      releaseDelete.resolve();
      await deletion;
      await expect(relay).rejects.toThrow(/Agent disappeared/);
      expect(relays).toBe(0);
    } finally {
      releaseDelete.resolve();
      await Promise.allSettled([deletion ?? Promise.resolve(), relay ?? Promise.resolve()]);
      await deletionClient.end();
    }
  });
});
