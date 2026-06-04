/**
 * Regression for issue #110: getTransactionStats must NOT conflate native
 * `value` across chains.
 *
 * The `transactions.value` column holds raw per-chain base units (wei for EVM,
 * lamports / SPL base units for Solana). Summing it across chains and feeding
 * that single scalar to the spending-limit evaluator caused the cross-chain
 * total to be re-priced at the CURRENT request chain's native USD price (USD
 * path) or compared as one unit against a wei cap (wei fallback) — silently
 * over- or under-counting multi-chain spend caps.
 *
 * This drives the REAL getTransactionStats against an in-memory PGLite DB. It
 * seeds two committed (signed) transactions for one agent on two different
 * chains, then asserts the spend counters are scoped to the requested chain.
 *
 * WITHOUT the fix `getTransactionStats(agentId, chainId)` ignores chainId and
 * returns the cross-chain sum, so `spentToday`/`spentThisWeek` come back as the
 * combined total and the chain-A / chain-B assertions FAIL. WITH the fix each
 * chain's counter is isolated, and the no-arg call still returns the combined
 * total (display behaviour preserved).
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

// context.ts reads required env and touches the DB at module import time, so
// install the PGLite override before importing it.
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_MASTER_PASSWORD ??= "txstats-chain-master-password";
const { db: pgliteDb, client: pgliteClient } = await createPGLiteDb("memory://");
setPGLiteOverride(pgliteDb, async () => {
  await pgliteClient.close();
});

const { getTransactionStats } = await import("../services/context");

const TENANT_ID = `txstats-chain-tenant-${Date.now()}`;
const AGENT_ID = `txstats-chain-agent-${Date.now()}`;
const RECIPIENT = "0x1234567890123456789012345678901234567890";

// Two chains whose native base units are NOT comparable in raw form. We use
// deliberately different magnitudes so a cross-chain sum is obviously wrong:
//   chain ETH_MAINNET: 3 ETH worth of wei (3e18)
//   chain SOLANA:      5 SOL worth of lamports (5e9)
const ETH_MAINNET = 1;
const SOLANA = 1399811149; // Steward's Solana chain id sentinel; any distinct id works
const UNRELATED_CHAIN = 137;

const ETH_SPEND = "3000000000000000000"; // 3e18 wei
const SOL_SPEND = "5000000000"; // 5e9 lamports

async function seedTx(idSuffix: string, chainId: number, value: string) {
  await getDb()
    .insert(transactions)
    .values({
      id: `${AGENT_ID}-${idSuffix}`,
      agentId: AGENT_ID,
      status: "signed",
      toAddress: RECIPIENT,
      value,
      chainId,
      policyResults: [],
      signedAt: new Date(),
    });
}

describe("getTransactionStats chain scoping (issue #110)", () => {
  beforeAll(async () => {
    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "TxStats Chain Tenant", apiKeyHash: `hash-${TENANT_ID}` });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "TxStats Chain Agent",
      walletAddress: RECIPIENT,
    });

    // One committed spend on each chain, both inside the rolling day/week window.
    await seedTx("eth", ETH_MAINNET, ETH_SPEND);
    await seedTx("sol", SOLANA, SOL_SPEND);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  it("scopes spentToday/spentThisWeek to the requested chain (EVM)", async () => {
    const stats = await getTransactionStats(AGENT_ID, ETH_MAINNET);
    // Must be ONLY the ETH-chain wei, not ETH wei + SOL lamports.
    expect(stats.spentToday.toString()).toBe(ETH_SPEND);
    expect(stats.spentThisWeek.toString()).toBe(ETH_SPEND);
  });

  it("scopes spentToday/spentThisWeek to the requested chain (Solana)", async () => {
    const stats = await getTransactionStats(AGENT_ID, SOLANA);
    expect(stats.spentToday.toString()).toBe(SOL_SPEND);
    expect(stats.spentThisWeek.toString()).toBe(SOL_SPEND);
  });

  it("returns zero spend for a chain the agent has not transacted on", async () => {
    const stats = await getTransactionStats(AGENT_ID, UNRELATED_CHAIN);
    expect(stats.spentToday.toString()).toBe("0");
    expect(stats.spentThisWeek.toString()).toBe("0");
  });

  it("preserves the cross-chain total when no chainId is supplied (display path)", async () => {
    const stats = await getTransactionStats(AGENT_ID);
    const combined = (BigInt(ETH_SPEND) + BigInt(SOL_SPEND)).toString();
    expect(stats.spentToday.toString()).toBe(combined);
    expect(stats.spentThisWeek.toString()).toBe(combined);
    // Counts remain agent-wide (chain-agnostic) regardless of chain scoping.
    expect(stats.recentTxCount24h).toBe(2);
  });
});
