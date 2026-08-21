import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { revocationStore } from "@stwd/auth";
import {
  agents,
  auditEvents,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
  withTenantAuditedTransaction,
} from "@stwd/db";
import {
  generateMoneroWallet,
  type MoneroBalanceResult,
  type MoneroKeyPayloadV1,
  type MoneroTransferDestination,
  type MoneroWalletBackend,
  type PreparedMoneroTransfer,
  Vault,
} from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

type Sql = {
  <T extends unknown[]>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T>;
  begin<T>(callback: (tx: Sql) => Promise<T>): Promise<T>;
  unsafe(query: string): Promise<unknown>;
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
const originalRouteEnv = {
  jwt: process.env.STEWARD_JWT_SECRET,
  master: process.env.STEWARD_MASTER_PASSWORD,
  audit: process.env.STEWARD_AUDIT_HMAC_KEY,
  wallet: process.env.STEWARD_MONERO_WALLET_RPC_URL,
  daemon: process.env.STEWARD_MONERO_DAEMON_URL,
  network: process.env.STEWARD_MONERO_NETWORK,
  platformKeys: process.env.STEWARD_PLATFORM_KEYS,
  platformScopes: process.env.STEWARD_PLATFORM_KEY_SCOPES,
};
process.env.STEWARD_JWT_SECRET ??= "monero-real-pg-jwt";
process.env.STEWARD_MASTER_PASSWORD ??= "monero-real-pg-master";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "monero-real-pg-audit";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

class SetupMoneroBackend implements MoneroWalletBackend {
  readonly network = "mainnet" as const;
  async getDaemonHeight() {
    return 3_400_000;
  }
  async verifyWalletKeys() {}
  async getBalance(): Promise<MoneroBalanceResult> {
    throw new Error("not used");
  }
  async prepareTransfer(
    _payload: MoneroKeyPayloadV1,
    _context: unknown,
    _request: { destinations: MoneroTransferDestination[] },
  ): Promise<PreparedMoneroTransfer> {
    throw new Error("not used");
  }
  async relayTransfer(): Promise<{ txHash: string }> {
    throw new Error("not used");
  }
  async getTransactionStatus(): Promise<"not_found"> {
    return "not_found";
  }
  async discardPreparedTransfer() {}
}

function installRouteMoneroRpc() {
  const realFetch = globalThis.fetch;
  const walletFiles = new Map<string, string>();
  const txHash = "cd".repeat(32);
  let relayCount = 0;
  let beforeRelay: (() => void | Promise<void>) | undefined;
  let relayMode: "success" | "lost-ack" = "success";
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === "http://monero-route-daemon:18089/get_info") {
      return Response.json({ status: "OK", nettype: "mainnet", mainnet: true, height: 3_400_000 });
    }
    if (url === "http://monero-route-daemon:18089/get_transactions") {
      const body = JSON.parse(String(init?.body)) as { txs_hashes: string[] };
      return Response.json({ status: "OK", txs: [], missed_tx: body.txs_hashes });
    }
    if (!url.startsWith("http://monero-route-wallet:18083")) {
      return realFetch(input as RequestInfo, init);
    }
    const request = JSON.parse(String(init?.body)) as {
      method: string;
      params?: Record<string, unknown>;
    };
    const params = request.params ?? {};
    const rpc = (result: unknown) => Response.json({ jsonrpc: "2.0", id: "0", result });
    switch (request.method) {
      case "open_wallet":
        if (!walletFiles.has(String(params.filename))) {
          return Response.json({
            jsonrpc: "2.0",
            id: "0",
            error: { code: -1, message: "Failed to open wallet" },
          });
        }
        return rpc({});
      case "generate_from_keys":
        walletFiles.set(String(params.filename), String(params.address));
        return rpc({ address: params.address });
      case "get_address":
        return rpc({ address: [...walletFiles.values()].at(-1), addresses: [] });
      case "refresh":
        return rpc({ blocks_fetched: 0 });
      case "transfer":
        return rpc({
          amount: 1_000_000_000,
          fee: 25_000_000,
          tx_hash: txHash,
          tx_metadata: "route-real-pg-metadata",
        });
      case "relay_tx":
        relayCount += 1;
        await beforeRelay?.();
        if (relayMode === "lost-ack") throw new TypeError("lost relay acknowledgement");
        return rpc({ tx_hash: txHash });
      case "close_wallet":
      case "rescan_spent":
        return rpc({});
      default:
        return Response.json({
          jsonrpc: "2.0",
          id: "0",
          error: { code: -32601, message: `unexpected ${request.method}` },
        });
    }
  }) as typeof fetch;
  return {
    txHash,
    relayCount: () => relayCount,
    setBeforeRelay: (callback?: () => void | Promise<void>) => {
      beforeRelay = callback;
    },
    setRelayMode: (mode: typeof relayMode) => {
      relayMode = mode;
    },
    restore: () => {
      globalThis.fetch = realFetch;
    },
  };
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
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
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
              toAddress: "monero-recovery-destination",
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
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000002",
    });
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
              toAddress: "monero-recovery-destination",
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
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000003",
    });
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

describePostgres("mounted Monero recovery boundary (real Postgres)", () => {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const tenantId = `monero-route-tenant-${suffix}`;
  const agentId = `monero-route-agent-${suffix}`;
  const userId = crypto.randomUUID();
  const platformKey = `monero-route-platform-${suffix}`;
  const recipient = generateMoneroWallet("mainnet").address;
  const walletScope = "monero:mainnet:0";
  const requestBody = {
    walletScope,
    destinations: [{ address: recipient, amountPiconero: "1000000000" }],
  };
  let app: Hono<{ Variables: AppVariables }>;
  let token = "";
  let admin: Sql;
  let rpc: ReturnType<typeof installRouteMoneroRpc>;

  async function mountedAgentTuple(): Promise<AgentTuple> {
    const [row] = await admin<AgentTuple[]>`
      select tableoid::oid::integer as relation,
        ((ctid::text::point)[0])::integer as block,
        ((ctid::text::point)[1])::integer as offset
      from agents where id = ${agentId}
    `;
    if (!row) throw new Error("mounted Monero agent tuple is unavailable");
    return row;
  }

  async function waitForMountedAdvisoryPair(lockIdentity = agentId): Promise<{
    holderPid: number;
    waiterPid: number;
  }> {
    for (let attempt = 0; attempt < 250; attempt += 1) {
      const rows = await admin<{ pid: number; granted: boolean; blocker_pids: number[] }[]>`
        select lock.pid, lock.granted, pg_blocking_pids(lock.pid)::int[] as blocker_pids
        from pg_locks lock
        where lock.locktype = 'advisory'
          and lock.classid = (((hashtextextended(${lockIdentity}, 0) >> 32) & 4294967295)::text)::oid
          and lock.objid = ((hashtextextended(${lockIdentity}, 0) & 4294967295)::text)::oid
          and lock.objsubid = 1
        order by lock.granted desc, lock.pid
      `;
      const holder = rows.find((row) => row.granted);
      const waiter = rows.find((row) => !row.granted);
      if (
        holder &&
        waiter &&
        holder.pid !== waiter.pid &&
        waiter.blocker_pids.includes(holder.pid)
      ) {
        return { holderPid: holder.pid, waiterPid: waiter.pid };
      }
      await Bun.sleep(20);
    }
    throw new Error(`mounted request did not wait on the exact ${lockIdentity} advisory lock`);
  }

  async function waitForMountedAdvisoryHolder(lockIdentity: string): Promise<number> {
    for (let attempt = 0; attempt < 250; attempt += 1) {
      const [holder] = await admin<{ pid: number }[]>`
        select lock.pid
        from pg_locks lock
        where lock.locktype = 'advisory'
          and lock.granted
          and lock.classid = (((hashtextextended(${lockIdentity}, 0) >> 32) & 4294967295)::text)::oid
          and lock.objid = ((hashtextextended(${lockIdentity}, 0) & 4294967295)::text)::oid
          and lock.objsubid = 1
      `;
      if (holder) return holder.pid;
      await Bun.sleep(20);
    }
    throw new Error(`mounted request did not hold the exact ${lockIdentity} advisory lock`);
  }

  async function waitForMountedTupleWaiter(
    tuple: AgentTuple,
    expectedWaiterPid: number,
    expectedBlockerPid: number,
  ): Promise<void> {
    for (let attempt = 0; attempt < 250; attempt += 1) {
      const [waiter] = await admin<{ pid: number }[]>`
        select activity.pid
        from pg_stat_activity activity
        where activity.datname = current_database()
          and activity.pid = ${expectedWaiterPid}
          and ${expectedBlockerPid} = any(pg_blocking_pids(activity.pid))
          and exists (
            select 1 from pg_locks xid_lock
            where xid_lock.pid = activity.pid
              and xid_lock.locktype = 'transactionid'
              and not xid_lock.granted
          )
          and (
            exists (
              select 1 from pg_locks tuple_lock
              where tuple_lock.pid = activity.pid
                and tuple_lock.locktype = 'tuple'
                and tuple_lock.relation = ${tuple.relation}::oid
                and tuple_lock.page = ${tuple.block}
                and tuple_lock.tuple = ${tuple.offset}
            )
          )
      `;
      if (waiter?.pid === expectedWaiterPid) return;
      await Bun.sleep(20);
    }
    throw new Error(
      `backend ${expectedWaiterPid} did not wait on the exact agent tuple behind ${expectedBlockerPid}`,
    );
  }

  function transfer(
    key: string,
    body: typeof requestBody = requestBody,
    headers: Record<string, string> = {},
  ) {
    return app.request(`/vault/${agentId}/monero/transfer`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "Idempotency-Key": key,
        ...headers,
      },
      body: JSON.stringify(body),
    });
  }

  function deleteTenant() {
    return app.request(`/platform/tenants/${tenantId}`, {
      method: "DELETE",
      headers: { "X-Steward-Platform-Key": platformKey },
    });
  }

  beforeAll(async () => {
    process.env.STEWARD_JWT_SECRET = `monero-route-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `monero-route-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `monero-route-audit-${suffix}`;
    process.env.STEWARD_MONERO_WALLET_RPC_URL = "http://monero-route-wallet:18083/json_rpc";
    process.env.STEWARD_MONERO_DAEMON_URL = "http://monero-route-daemon:18089";
    process.env.STEWARD_MONERO_NETWORK = "mainnet";
    process.env.STEWARD_PLATFORM_KEYS = platformKey;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [platformKey]: ["platform:*"],
    });
    rpc = installRouteMoneroRpc();
    admin = postgres(databaseUrl!, { max: 1 });

    await getDb().insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: tenantId });
    await getDb()
      .insert(users)
      .values({ id: userId, email: `${suffix}@example.test` });
    await getDb().insert(userTenants).values({ userId, tenantId, role: "owner" });
    const setupVault = new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
      moneroBackend: new SetupMoneroBackend(),
    });
    await setupVault.createAgent(tenantId, agentId, agentId);
    await setupVault.createWallet({ tenantId, agentId, chainType: "monero" });
    await getDb()
      .insert(policies)
      .values([
        {
          id: `${agentId}-raw`,
          agentId,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["monero"], allowedCurves: ["ed25519"] },
        },
        {
          id: `${agentId}-address`,
          agentId,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [recipient], mode: "whitelist" },
        },
        {
          id: `${agentId}-spend`,
          agentId,
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "1500000000", maxPerDay: "1500000000" },
        },
      ]);

    const { createSessionToken } = await import("../routes/auth");
    const { agentRoutes } = await import("../routes/agents");
    const { platformRoutes } = await import("../routes/platform");
    const { vaultRoutes } = await import("../routes/vault");
    const { tenantAuth } = await import("../services/context");
    token = await createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    app = new Hono<{ Variables: AppVariables }>();
    app.use("/vault/*", (c, next) => tenantAuth(c, next));
    app.use("/agents/*", (c, next) => tenantAuth(c, next));
    app.route("/vault", vaultRoutes);
    app.route("/agents", agentRoutes);
    app.route("/platform", platformRoutes);
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  }, 120_000);

  afterAll(async () => {
    rpc.restore();
    await getDb().delete(transactions).where(eq(transactions.agentId, agentId));
    await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await getDb().delete(agents).where(eq(agents.id, agentId));
    await getDb().delete(userTenants).where(eq(userTenants.tenantId, tenantId));
    await getDb().delete(users).where(eq(users.id, userId));
    await getDb().delete(tenants).where(eq(tenants.id, tenantId));
    await admin.end();
    const restore = (key: string, value: string | undefined) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    };
    restore("STEWARD_JWT_SECRET", originalRouteEnv.jwt);
    restore("STEWARD_MASTER_PASSWORD", originalRouteEnv.master);
    restore("STEWARD_AUDIT_HMAC_KEY", originalRouteEnv.audit);
    restore("STEWARD_MONERO_WALLET_RPC_URL", originalRouteEnv.wallet);
    restore("STEWARD_MONERO_DAEMON_URL", originalRouteEnv.daemon);
    restore("STEWARD_MONERO_NETWORK", originalRouteEnv.network);
    restore("STEWARD_PLATFORM_KEYS", originalRouteEnv.platformKeys);
    restore("STEWARD_PLATFORM_KEY_SCOPES", originalRouteEnv.platformScopes);
  });

  test("keeps only the independent checkpoint when its authenticated outer transaction rolls back", async () => {
    const { withAuthenticatedTenantDatabase, withIndependentAuthenticatedTenantDatabase } =
      await import("../services/context");
    const key = `outer-rollback-${suffix}`;
    const keyDigest = createHash("sha256").update(key).digest("hex");
    const transactionId = crypto.randomUUID();
    const baseline = rpc.relayCount();
    const [before] = await admin<{ enabled: boolean }[]>`
      select enabled from policies where id = ${`${agentId}-raw`}
    `;
    expect(before?.enabled).toBe(true);

    await expect(
      withAuthenticatedTenantDatabase(
        tenantId,
        "session-jwt",
        userId,
        async () => {
          await getDb()
            .update(policies)
            .set({ enabled: false })
            .where(eq(policies.id, `${agentId}-raw`));
          await withIndependentAuthenticatedTenantDatabase(
            tenantId,
            "session-jwt",
            userId,
            () =>
              withTenantAuditedTransaction(tenantId, async (rawTx, appendRequiredAudit) => {
                const tx = rawTx as ReturnType<typeof getDb>;
                await tx.insert(transactions).values({
                  id: transactionId,
                  agentId,
                  status: "approved",
                  toAddress: recipient,
                  value: "1025000000",
                  chainId: 301,
                  txHash: rpc.txHash,
                  actionType: "monero_transfer",
                  actionPayload: {
                    type: "monero_transfer",
                    recoveryVersion: 1,
                    idempotencyKeyDigest: keyDigest,
                    requestFingerprint: `outer-rollback-${suffix}`,
                    relayState: "prepared",
                  },
                  policyResults: [],
                });
                await appendRequiredAudit({
                  tenantId,
                  actorType: "user",
                  actorId: userId,
                  action: "vault.monero_transfer.authorized",
                  resourceType: "transaction",
                  resourceId: transactionId,
                  metadata: { idempotencyKeyDigest: keyDigest },
                });
              }),
            userId,
          );
          throw new Error("forced authenticated outer transaction rollback");
        },
        userId,
      ),
    ).rejects.toThrow("forced authenticated outer transaction rollback");

    const [outerState] = await admin<{ enabled: boolean }[]>`
      select enabled from policies where id = ${`${agentId}-raw`}
    `;
    expect(outerState?.enabled).toBe(true);
    const [anchor] = await admin<{ id: string; status: string; key_digest: string }[]>`
      select id, status, action_payload->>'idempotencyKeyDigest' as key_digest
      from transactions where id = ${transactionId}
    `;
    expect(anchor).toEqual({ id: transactionId, status: "approved", key_digest: keyDigest });
    const checkpointAudits = await admin<{ action: string }[]>`
      select action from audit_events where resource_id = ${transactionId} order by seq
    `;
    expect(checkpointAudits).toEqual([{ action: "vault.monero_transfer.authorized" }]);
    expect(rpc.relayCount()).toBe(baseline);
    await getDb()
      .update(transactions)
      .set({ status: "failed" })
      .where(eq(transactions.id, transactionId));
  });

  test("commits the anchor before relay and recovers it before mutable gates", async () => {
    const key = `lost-ack-${suffix}`;
    let visibleTransactionId = "";
    rpc.setRelayMode("lost-ack");
    rpc.setBeforeRelay(async () => {
      const [row] = await admin<{ id: string; status: string; audit_count: string }[]>`
        select t.id, t.status,
          (select count(*)::text from audit_events a
           where a.resource_id = t.id and a.action = 'vault.monero_transfer.authorized') as audit_count
        from transactions t
        where t.agent_id = ${agentId} and t.status = 'approved'
      `;
      expect(row?.status).toBe("approved");
      expect(row?.audit_count).toBe("1");
      visibleTransactionId = row?.id ?? "";
    });
    const first = await transfer(key);
    expect(first.status).toBe(202);
    expect(visibleTransactionId).not.toBe("");
    expect(rpc.relayCount()).toBe(1);

    const deletion = await app.request(`/agents/${agentId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(deletion.status).toBe(409);

    await getDb()
      .update(policies)
      .set({ config: { maxPerTx: "1", maxPerDay: "1" } })
      .where(eq(policies.id, `${agentId}-spend`));
    rpc.setBeforeRelay(undefined);
    rpc.setRelayMode("success");
    const replay = await transfer(key);
    expect(replay.status).toBe(202);
    expect(((await replay.json()) as { data: { transactionId: string } }).data.transactionId).toBe(
      visibleTransactionId,
    );
    expect(rpc.relayCount()).toBe(1);

    const differentKey = await transfer(`different-${suffix}`);
    expect(differentKey.status).toBe(403);
    expect(rpc.relayCount()).toBe(1);
  });

  test("serializes concurrent same-key mounted requests to one relay", async () => {
    await getDb()
      .update(policies)
      // Existing lost-ack reservation + one new transfer fit. Re-evaluating
      // the concurrent duplicate after the first commit would exceed this cap,
      // so both successful responses prove locked exact-key recovery happens
      // before the mutable spend gate.
      .set({ config: { maxPerTx: "1500000000", maxPerDay: "2100000000" } })
      .where(eq(policies.id, `${agentId}-spend`));
    const key = `concurrent-${suffix}`;
    const keyDigest = createHash("sha256").update(key).digest("hex");
    const gateIdentity = `monero-checkpoint-gate-${suffix}`;
    const gateFunction = `steward_monero_checkpoint_gate_${suffix}`;
    const gateTrigger = `steward_monero_checkpoint_gate_${suffix}`;
    const gateClient = postgres(databaseUrl!, { max: 1 });
    const gateReady = deferred<void>();
    const releaseGate = deferred<void>();
    const baseline = rpc.relayCount();
    rpc.setRelayMode("success");
    await admin.unsafe(`
      create function ${gateFunction}() returns trigger language plpgsql as $$
      begin
        if new.agent_id = '${agentId}'
          and new.action_payload->>'idempotencyKeyDigest' = '${keyDigest}'
        then
          perform pg_advisory_xact_lock(hashtextextended('${gateIdentity}', 0));
        end if;
        return new;
      end $$
    `);
    await admin.unsafe(`
      create trigger ${gateTrigger} before insert on transactions
      for each row execute function ${gateFunction}()
    `);
    const gateHolder = gateClient.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${gateIdentity}, 0))`;
      gateReady.resolve();
      await releaseGate.promise;
    });
    let first: Promise<Response> | undefined;
    let second: Promise<Response> | undefined;
    try {
      await waitForOwnedSignal(gateReady.promise, gateHolder, "checkpoint gate holder");
      first = transfer(key);
      await waitForMountedAdvisoryPair(gateIdentity);
      second = transfer(key);
      const { holderPid, waiterPid } = await waitForMountedAdvisoryPair();
      expect(holderPid).not.toBe(waiterPid);
      releaseGate.resolve();
      const [firstResponse, secondResponse] = await Promise.all([first, second]);
      expect(firstResponse.status).toBe(200);
      expect([200, 202]).toContain(secondResponse.status);
      const firstBody = (await firstResponse.json()) as { data: { transactionId: string } };
      const secondBody = (await secondResponse.json()) as { data: { transactionId: string } };
      expect(secondBody.data.transactionId).toBe(firstBody.data.transactionId);
      expect(rpc.relayCount()).toBe(baseline + 1);
    } finally {
      releaseGate.resolve();
      await Promise.allSettled([
        gateHolder,
        first ?? Promise.resolve(new Response()),
        second ?? Promise.resolve(new Response()),
      ]);
      await admin.unsafe(`drop trigger if exists ${gateTrigger} on transactions`);
      await admin.unsafe(`drop function if exists ${gateFunction}()`);
      await gateClient.end();
    }
  });

  test("Monero-first tenant deletion rechecks the durable anchor before side effects", async () => {
    await getDb()
      .update(transactions)
      .set({ status: "failed" })
      .where(eq(transactions.agentId, agentId));
    await getDb()
      .update(policies)
      .set({ config: { maxPerTx: "1500000000", maxPerDay: "1500000000" } })
      .where(eq(policies.id, `${agentId}-spend`));

    const tuple = await mountedAgentTuple();
    const relayEntered = deferred<void>();
    const releaseRelay = deferred<void>();
    const baseline = rpc.relayCount();
    let agentRevocations = 0;
    let userRevocations = 0;
    const originalRevokeAgentTokens = revocationStore.revokeAgentTokens.bind(revocationStore);
    const originalRevokeUserTokens = revocationStore.revokeUserTokens.bind(revocationStore);
    revocationStore.revokeAgentTokens = async () => {
      agentRevocations += 1;
      return Date.now();
    };
    revocationStore.revokeUserTokens = async () => {
      userRevocations += 1;
      return Date.now();
    };
    rpc.setRelayMode("success");
    rpc.setBeforeRelay(async () => {
      relayEntered.resolve();
      await releaseRelay.promise;
    });
    const transferRequest = transfer(`tenant-delete-monero-first-${suffix}`);
    let deletionRequest: Promise<Response> | undefined;
    try {
      await waitForOwnedSignal(relayEntered.promise, transferRequest, "Monero-first relay");
      deletionRequest = deleteTenant();
      const blockerPid = await waitForMountedAdvisoryHolder(agentId);
      const waiterPid = await waitForMountedAdvisoryHolder(`steward_tenant_delete_${tenantId}`);
      expect(waiterPid).not.toBe(blockerPid);
      await waitForMountedTupleWaiter(tuple, waiterPid, blockerPid);
      expect(agentRevocations).toBe(0);
      expect(userRevocations).toBe(0);
      const [prematureAudit] = await admin<{ count: number }[]>`
        select count(*)::int as count from audit_events
        where tenant_id = ${tenantId} and action like 'tenant.delete%'
      `;
      expect(prematureAudit?.count).toBe(0);

      releaseRelay.resolve();
      expect((await transferRequest).status).toBe(200);
      expect((await deletionRequest).status).toBe(409);
      expect(rpc.relayCount()).toBe(baseline + 1);
      expect(agentRevocations).toBe(0);
      expect(userRevocations).toBe(0);
      const [finalAudit] = await admin<{ count: number }[]>`
        select count(*)::int as count from audit_events
        where tenant_id = ${tenantId} and action like 'tenant.delete%'
      `;
      expect(finalAudit?.count).toBe(0);
    } finally {
      releaseRelay.resolve();
      await Promise.allSettled([
        transferRequest,
        deletionRequest ?? Promise.resolve(new Response()),
      ]);
      rpc.setBeforeRelay(undefined);
      revocationStore.revokeAgentTokens = originalRevokeAgentTokens;
      revocationStore.revokeUserTokens = originalRevokeUserTokens;
    }
  });

  test("delete-first blocks the mounted Monero route before relay", async () => {
    await getDb()
      .update(transactions)
      .set({ status: "failed" })
      .where(eq(transactions.agentId, agentId));
    const tuple = await mountedAgentTuple();
    const revocationEntered = deferred<void>();
    const releaseRevocation = deferred<void>();
    const baseline = rpc.relayCount();
    const originalRevokeAgentTokens = revocationStore.revokeAgentTokens.bind(revocationStore);
    const originalRevokeUserTokens = revocationStore.revokeUserTokens.bind(revocationStore);
    revocationStore.revokeAgentTokens = async () => {
      revocationEntered.resolve();
      await releaseRevocation.promise;
      return Date.now();
    };
    revocationStore.revokeUserTokens = async () => Date.now();
    const deletionRequest = deleteTenant();
    let transferRequest: Promise<Response> | undefined;
    try {
      await Promise.race([
        revocationEntered.promise,
        deletionRequest.then(async (response) => {
          throw new Error(
            `delete-first completed before revocation: ${response.status} ${await response.clone().text()}`,
          );
        }),
      ]);
      transferRequest = transfer(`tenant-delete-delete-first-${suffix}`);
      const blockerPid = await waitForMountedAdvisoryHolder(`steward_tenant_delete_${tenantId}`);
      const waiterPid = await waitForMountedAdvisoryHolder(agentId);
      expect(waiterPid).not.toBe(blockerPid);
      await waitForMountedTupleWaiter(tuple, waiterPid, blockerPid);
      expect(rpc.relayCount()).toBe(baseline);

      releaseRevocation.resolve();
      expect((await deletionRequest).status).toBe(200);
      expect((await transferRequest).status).toBeGreaterThanOrEqual(400);
      expect(rpc.relayCount()).toBe(baseline);
      expect(await getDb().select().from(tenants).where(eq(tenants.id, tenantId))).toHaveLength(0);
    } finally {
      releaseRevocation.resolve();
      await Promise.allSettled([
        deletionRequest,
        transferRequest ?? Promise.resolve(new Response()),
      ]);
      revocationStore.revokeAgentTokens = originalRevokeAgentTokens;
      revocationStore.revokeUserTokens = originalRevokeUserTokens;
    }
  });
});
