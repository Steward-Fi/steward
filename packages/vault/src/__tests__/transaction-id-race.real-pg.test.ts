import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { agents, closeDb, createPostgresClient, eq, getDb, tenants, transactions } from "@stwd/db";
import type { SignRequest } from "@stwd/shared";
import { Vault } from "../vault";

setDefaultTimeout(120_000);

const databaseUrl = process.env.DATABASE_URL;
const suite =
  databaseUrl && !databaseUrl.startsWith("file:") && !process.env.STEWARD_PGLITE_MEMORY
    ? describe
    : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `tx-owner-race-tenant-${suffix}`;
const firstAgentId = `tx-owner-race-first-${suffix}`;
const secondAgentId = `tx-owner-race-second-${suffix}`;
const txId = `tx-owner-race-${suffix}`;
const lockKey = `transaction-owner-race:${suffix}`;
const triggerFunction = `tx_owner_race_fn_${suffix}`;
const triggerName = `tx_owner_race_trigger_${suffix}`;
const blocker = databaseUrl ? createPostgresClient(databaseUrl) : null;
const inspector = databaseUrl ? createPostgresClient(databaseUrl) : null;

type TransactionRecorder = {
  recordSignedTransaction(
    request: SignRequest,
    chainId: number,
    shouldBroadcast: boolean,
    hash: string,
    options: { txId: string; status: "broadcast" },
  ): Promise<void>;
};

function requestFor(agentId: string, value: string): SignRequest {
  return {
    tenantId,
    agentId,
    to: "0x0000000000000000000000000000000000000001",
    value,
    chainId: 1,
    broadcast: true,
  };
}

async function waitForBlockedRecorders(expected: number): Promise<number[]> {
  if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await inspector<{ pid: number }[]>`
      with target as (
        select hashtextextended(${lockKey}, 0)::bigint as key
      )
      select distinct locks.pid
      from pg_locks as locks
      cross join target
      where locks.locktype = 'advisory'
        and locks.granted = false
        and locks.database = (select oid from pg_database where datname = current_database())
        and locks.classid::bigint = ((target.key >> 32) & 4294967295)
        and locks.objid::bigint = (target.key & 4294967295)
        and locks.objsubid = 1
    `;
    if (rows.length >= expected) return rows.map((row) => row.pid);
    await Bun.sleep(10);
  }
  throw new Error(`timed out waiting for ${expected} blocked transaction recorders`);
}

suite("transaction id ownership across real PostgreSQL connections", () => {
  beforeAll(async () => {
    if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_PGLITE_MEMORY;
    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Transaction ownership race tenant",
        apiKeyHash: `hash-${tenantId}`,
      });
    await getDb()
      .insert(agents)
      .values([
        {
          id: firstAgentId,
          tenantId,
          name: "First transaction owner",
          walletAddress: "0x0000000000000000000000000000000000000011",
        },
        {
          id: secondAgentId,
          tenantId,
          name: "Second transaction owner",
          walletAddress: "0x0000000000000000000000000000000000000022",
        },
      ]);
    await inspector.unsafe(`
      create function ${triggerFunction}() returns trigger
      language plpgsql
      as $$
      begin
        perform pg_advisory_xact_lock(hashtextextended('${lockKey}', 0));
        return new;
      end
      $$
    `);
    await inspector.unsafe(`
      create trigger ${triggerName}
      before insert on transactions
      for each row when (new.id = '${txId}')
      execute function ${triggerFunction}()
    `);
  });

  afterAll(async () => {
    await inspector
      ?.unsafe(`drop trigger if exists ${triggerName} on transactions`)
      .catch(() => {});
    await inspector?.unsafe(`drop function if exists ${triggerFunction}()`).catch(() => {});
    await getDb()
      .delete(tenants)
      .where(eq(tenants.id, tenantId))
      .catch(() => {});
    await closeDb();
    await Promise.all([blocker?.end(), inspector?.end()]);
  });

  test("only one agent can create a shared transaction id", async () => {
    if (!blocker) throw new Error("real PostgreSQL blocker is unavailable");
    const recorder = new Vault({
      masterPassword: "transaction-owner-race-test",
    }) as unknown as TransactionRecorder;
    await blocker`select pg_advisory_lock(hashtextextended(${lockKey}, 0))`;

    const first = recorder.recordSignedTransaction(
      requestFor(firstAgentId, "1"),
      1,
      true,
      "0xfirst",
      { txId, status: "broadcast" },
    );
    const second = recorder.recordSignedTransaction(
      requestFor(secondAgentId, "2"),
      1,
      true,
      "0xsecond",
      { txId, status: "broadcast" },
    );
    const resultsPromise = Promise.allSettled([first, second]);
    let blockedPids: number[] = [];
    try {
      blockedPids = await waitForBlockedRecorders(2);
    } finally {
      await blocker`select pg_advisory_unlock(hashtextextended(${lockKey}, 0))`;
    }

    const results = await resultsPromise;
    expect(new Set(blockedPids).size).toBe(2);
    expect(results.map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"]);
    const rejected = results.find(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    expect(String(rejected?.reason)).toContain(
      "Transaction id already belongs to a different agent",
    );

    const [recorded] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
    const winningAgent = results[0]?.status === "fulfilled" ? firstAgentId : secondAgentId;
    expect(recorded?.agentId).toBe(winningAgent);
    expect(recorded?.value).toBe(winningAgent === firstAgentId ? "1" : "2");
  });
});
