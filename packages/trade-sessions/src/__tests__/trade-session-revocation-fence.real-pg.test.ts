import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { agents, createPostgresClient, eq, getDb, tenants, tradeSessions } from "@stwd/db";
import { TradeSessionManager } from "../index";

setDefaultTimeout(120_000);

const databaseUrl = process.env.DATABASE_URL;
const realPostgres =
  databaseUrl && !databaseUrl.startsWith("file:") && !process.env.STEWARD_PGLITE_MEMORY
    ? describe
    : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `session-fence-tenant-${suffix}`;
const agentId = `session-fence-agent-${suffix}`;
const blocker = databaseUrl ? createPostgresClient(databaseUrl) : null;
const inspector = databaseUrl ? createPostgresClient(databaseUrl) : null;

function lockKey(sessionId: string): string {
  return `trade_session_fence_${tenantId}:${sessionId}`;
}

async function seedSession(): Promise<string> {
  const id = `ses_${crypto.randomUUID()}`;
  await getDb()
    .insert(tradeSessions)
    .values({
      id,
      tenantId,
      agentId,
      venue: "hyperliquid",
      walletId: "0x0000000000000000000000000000000000000001",
      status: "active",
      dailySpendUsd: "0",
      dailyCapUsd: "100",
      perOrderCapUsd: "50",
      leverageCap: "5",
      allowedAssets: ["BTC"],
      expiresAt: new Date(Date.now() + 120_000),
    });
  return id;
}

async function waitForBlockedLock(key: string, expected: number): Promise<void> {
  if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await inspector<{ count: number }[]>`
      with target as (
        select hashtextextended(${key}, 0)::bigint as key
      )
      select count(distinct locks.pid)::int as count
      from pg_locks as locks
      cross join target
      where locks.locktype = 'advisory'
        and locks.granted = false
        and locks.database = (select oid from pg_database where datname = current_database())
        and locks.classid::bigint = ((target.key >> 32) & 4294967295)
        and locks.objid::bigint = (target.key & 4294967295)
        and locks.objsubid = 1
    `;
    if ((rows[0]?.count ?? 0) >= expected) return;
    await Bun.sleep(10);
  }
  throw new Error(`timed out waiting for ${expected} blocked session-fence connection(s)`);
}

async function holdFence(key: string): Promise<{ release: () => void; done: Promise<void> }> {
  if (!blocker) throw new Error("real PostgreSQL blocker is unavailable");
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let ready!: () => void;
  const acquired = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const done = blocker.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtextextended(${key}, 0))`;
    ready();
    await released;
  });
  await acquired;
  return { release, done };
}

realPostgres("trade-session final venue fence", () => {
  beforeAll(async () => {
    await getDb()
      .insert(tenants)
      .values({ id: tenantId, name: "Session Fence Tenant", apiKeyHash: `hash-${tenantId}` });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Session Fence Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
  });

  afterAll(async () => {
    await getDb().delete(tradeSessions).where(eq(tradeSessions.tenantId, tenantId));
    await getDb().delete(agents).where(eq(agents.tenantId, tenantId));
    await getDb().delete(tenants).where(eq(tenants.id, tenantId));
    await blocker?.end();
    await inspector?.end();
  });

  test("submit-first holds revocation until the bounded venue call finishes", async () => {
    const sessionId = await seedSession();
    const manager = new TradeSessionManager();
    let releaseSubmit!: () => void;
    const submitBarrier = new Promise<void>((resolve) => {
      releaseSubmit = resolve;
    });
    let entered!: () => void;
    const venueEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const submission = manager.withActiveVenueSubmissionFence(
      { tenantId, id: sessionId },
      async () => {
        entered();
        await submitBarrier;
        return "submitted";
      },
    );
    await venueEntered;

    let revokeSettled = false;
    const revocation = manager
      .revokeSession({ tenantId, id: sessionId, revokedBy: "race-test" })
      .finally(() => {
        revokeSettled = true;
      });
    await waitForBlockedLock(lockKey(sessionId), 1);
    expect(revokeSettled).toBe(false);

    releaseSubmit();
    expect(await submission).toBe("submitted");
    expect((await revocation)?.status).toBe("revoked");
  });

  test("revoke-first prevents the post-sign venue callback from running", async () => {
    const sessionId = await seedSession();
    const key = lockKey(sessionId);
    const held = await holdFence(key);
    const manager = new TradeSessionManager();
    const revocation = manager.revokeSession({
      tenantId,
      id: sessionId,
      revokedBy: "race-test",
    });
    await waitForBlockedLock(key, 1);

    let venueCalls = 0;
    const submission = manager.withActiveVenueSubmissionFence(
      { tenantId, id: sessionId },
      async () => {
        venueCalls += 1;
        return "must-not-submit";
      },
    );
    await waitForBlockedLock(key, 2);
    held.release();
    await held.done;

    expect((await revocation)?.status).toBe("revoked");
    expect(await submission).toBeNull();
    expect(venueCalls).toBe(0);
  });

  test("an aborted venue callback releases the fence for queued revocation", async () => {
    const sessionId = await seedSession();
    const manager = new TradeSessionManager();
    let abort!: () => void;
    const aborted = new Promise<void>((_resolve, reject) => {
      abort = () => reject(new DOMException("venue timeout", "AbortError"));
    });
    let entered!: () => void;
    const venueEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const submission = manager.withActiveVenueSubmissionFence(
      { tenantId, id: sessionId },
      async () => {
        entered();
        await aborted;
        return "unreachable";
      },
    );
    await venueEntered;
    const revocation = manager.revokeSession({
      tenantId,
      id: sessionId,
      revokedBy: "race-test",
    });
    await waitForBlockedLock(lockKey(sessionId), 1);
    abort();

    await expect(submission).rejects.toMatchObject({ name: "AbortError" });
    expect((await revocation)?.status).toBe("revoked");
  });
});
