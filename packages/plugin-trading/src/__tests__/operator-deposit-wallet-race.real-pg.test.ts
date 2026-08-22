import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  agentWallets,
  and,
  auditEvents,
  closeDb,
  createPostgresClient,
  eq,
  getDb,
  tenants,
  writeAuditEvent,
} from "@stwd/db";
import { Hono } from "hono";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { StewardAppContext } from "../context";

setDefaultTimeout(120_000);

const databaseUrl = process.env.DATABASE_URL;
const suite =
  databaseUrl && !databaseUrl.startsWith("file:") && !process.env.STEWARD_PGLITE_MEMORY
    ? describe
    : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `deposit-wallet-race-tenant-${suffix}`;
const agentId = `deposit-wallet-race-agent-${suffix}`;
const MASTER_PASSWORD = "deposit-wallet-race-master-password";
const PLATFORM_KEY = "stw_platform_deposit_wallet_race";
const blocker = databaseUrl ? createPostgresClient(databaseUrl) : null;
const inspector = databaseUrl ? createPostgresClient(databaseUrl) : null;

async function waitForBlockedCustodyLock(lockKey: string): Promise<void> {
  if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await inspector<{ count: number }[]>`
      with target as (select hashtextextended(${lockKey}, 0)::bigint as key)
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
    if ((rows[0]?.count ?? 0) >= 1) return;
    await Bun.sleep(10);
  }
  throw new Error("timed out waiting for the mounted deposit signer to block on custody lock");
}

suite("mounted Hyperliquid deposit wallet rotation on real PostgreSQL", () => {
  let app: Hono;
  let originalAddress: string;

  beforeAll(async () => {
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_PGLITE_MEMORY;
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "operator-deposit-wallet-race-audit-hmac-key-0123456789abcdef";

    const [{ Vault }, { createOperatorRecoveryRoutes }] = await Promise.all([
      import("@stwd/vault"),
      import("../routes/operator-recovery"),
    ]);
    const vault = new Vault({ masterPassword: MASTER_PASSWORD });
    await getDb()
      .insert(tenants)
      .values({ id: tenantId, name: "Deposit wallet race tenant", apiKeyHash: `hash-${suffix}` });
    await vault.createAgent(tenantId, agentId, "Deposit wallet race agent");
    const original = await vault.provisionVenueWallet({
      tenantId,
      agentId,
      venue: "hyperliquid",
      chainFamily: "evm",
      approvedAddresses: [],
    });
    originalAddress = original.address;

    const ctx = {
      db: getDb(),
      vault,
      ensureAgentForTenant: async (requestedTenantId: string, requestedAgentId: string) => {
        const [agent] = await getDb()
          .select()
          .from(agents)
          .where(and(eq(agents.id, requestedAgentId), eq(agents.tenantId, requestedTenantId)));
        return agent;
      },
      getPolicySet: async () => [],
      isValidAnyAddress: () => true,
      policyEngine: { evaluate: async () => ({ approved: true, results: [] }) },
      priceOracle: {
        getNativeUsdPrice: async () => 1,
        weiToUsd: async () => 0,
        usdToWei: async () => "0",
      },
      safeJsonParse: async (c: { req: { json: () => Promise<unknown> } }) => c.req.json(),
      writeAuditEvent,
      verifyAuditChain: async () => ({ valid: true, count: 0 }),
      getRedisClient: () => null,
    } as unknown as StewardAppContext;

    app = new Hono();
    app.use("/v1/trade/*", async (c, next) => {
      c.set("tenantId", c.req.header("X-Steward-Tenant") ?? "");
      if (c.req.header("X-Steward-Platform-Key") !== PLATFORM_KEY) {
        return c.json({ ok: false, error: "Invalid platform key" }, 403);
      }
      c.set("authType", "platform");
      return next();
    });
    app.route("/v1/trade", createOperatorRecoveryRoutes(ctx));
  });

  afterAll(async () => {
    await getDb()
      .delete(tenants)
      .where(eq(tenants.id, tenantId))
      .catch(() => {});
    await closeDb();
    await Promise.all([blocker?.end(), inspector?.end()]);
  });

  test("a queued deposit fails before RPC after the venue wallet rotates", async () => {
    if (!blocker || !inspector) throw new Error("real PostgreSQL clients are unavailable");
    const { KeyStore } = await import("@stwd/vault");
    const replacementPrivateKey = generatePrivateKey();
    const replacementAddress = privateKeyToAccount(replacementPrivateKey).address;
    const replacement = new KeyStore(MASTER_PASSWORD).encrypt(replacementPrivateKey, {
      tenantId,
      agentId,
      chainFamily: "evm",
      venue: "hyperliquid",
    });
    const lockKey = JSON.stringify(["vault-custody-v1", tenantId, agentId, "evm", "hyperliquid"]);
    const idempotencyKey = crypto.randomUUID();
    let rpcCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = ((...args: Parameters<typeof fetch>) => {
      rpcCalls += 1;
      return originalFetch(...args);
    }) as typeof fetch;

    try {
      let request!: Promise<Response>;
      await blocker.begin(async (tx) => {
        await tx`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`;
        request = app.request("/v1/trade/hyperliquid/deposit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Steward-Tenant": tenantId,
            "X-Steward-Platform-Key": PLATFORM_KEY,
            "Idempotency-Key": idempotencyKey,
          },
          body: JSON.stringify({ agentId, amount: "5" }),
        });
        await waitForBlockedCustodyLock(lockKey);
        await tx`
          update encrypted_chain_keys
          set ciphertext = ${replacement.ciphertext}, iv = ${replacement.iv},
              tag = ${replacement.tag}, salt = ${replacement.salt}
          where agent_id = ${agentId} and chain_family = 'evm' and venue = 'hyperliquid'
        `;
        await tx`
          update agent_wallets set address = ${replacementAddress}
          where agent_id = ${agentId} and chain_family = 'evm' and venue = 'hyperliquid'
        `;
      });

      const response = await request;
      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({ ok: false, error: "Failed to submit deposit" });
      expect(rpcCalls).toBe(0);

      const replay = await app.request("/v1/trade/hyperliquid/deposit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Tenant": tenantId,
          "X-Steward-Platform-Key": PLATFORM_KEY,
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({ agentId, amount: "5" }),
      });
      expect(replay.status).toBe(502);
      expect(await replay.json()).toEqual({ ok: false, error: "Failed to submit deposit" });
      expect(rpcCalls).toBe(0);

      const failures = await getDb()
        .select({ metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, tenantId),
            eq(auditEvents.resourceId, agentId),
            eq(auditEvents.action, "trade.recovery.deposit.failed"),
          ),
        );
      expect(failures).toHaveLength(1);
      expect(failures[0]?.metadata).toMatchObject({
        venue: "hyperliquid",
        walletAddress: originalAddress,
      });
      const [currentWallet] = await getDb()
        .select({ address: agentWallets.address })
        .from(agentWallets)
        .where(
          and(
            eq(agentWallets.agentId, agentId),
            eq(agentWallets.chainFamily, "evm"),
            eq(agentWallets.venue, "hyperliquid"),
          ),
        );
      expect(currentWallet?.address.toLowerCase()).toBe(replacementAddress.toLowerCase());
      expect(currentWallet?.address.toLowerCase()).not.toBe(originalAddress.toLowerCase());
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
