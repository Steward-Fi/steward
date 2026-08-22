/**
 * PGLite is single-connection, so the mounted route suite proves state and
 * failure behavior there while this gated test proves the production advisory
 * lock with genuinely concurrent PostgreSQL transactions.
 */
import { expect, it } from "bun:test";
import { agents, getDb, sponsoredGasEvents, tenantConfigs, tenants, transactions } from "@stwd/db";
import { eq, inArray } from "drizzle-orm";
import { reserveSponsoredGasEvent } from "../services/gas-sponsorship";

const realPostgresIt =
  process.env.DATABASE_URL && process.env.STEWARD_PGLITE_MEMORY !== "true" ? it : it.skip;

realPostgresIt(
  "serializes concurrent wallet and tenant cap reservations to one bounded winner",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 12);
    const tenantId = `sponsor-race-${suffix}`;
    const agentId = `sponsor-agent-${suffix}`;
    const txIds = [`sponsor-tx-a-${suffix}`, `sponsor-tx-b-${suffix}`];
    const db = getDb();
    try {
      await db.insert(tenants).values({
        id: tenantId,
        name: tenantId,
        apiKeyHash: `hash-${tenantId}`,
      });
      await db.insert(tenantConfigs).values({
        tenantId,
        gasSponsorshipConfig: {
          enabled: true,
          provider: "mock",
          mode: "erc4337",
          allowClientSponsorship: true,
          maxPerTxUsd: 0.6,
          maxPerWalletDayUsd: 1,
          maxTenantDayUsd: 1,
        },
      });
      await db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: "0x7350000000000000000000000000000000000000",
      });
      await db.insert(transactions).values(
        txIds.map((id) => ({
          id,
          agentId,
          status: "pending" as const,
          toAddress: "0x1234567890123456789012345678901234567890",
          value: "1",
          chainId: 8453,
          actionType: "transfer",
          actionPayload: { type: "transfer", token: "native", broadcast: true },
        })),
      );

      const results = await Promise.all(
        txIds.map((txId) =>
          reserveSponsoredGasEvent({
            tenantId,
            agentId,
            txId,
            chainId: 8453,
            caip2: "eip155:8453",
            provider: "mock",
            mode: "erc4337",
            reservedUsd: 0.6,
            metadata: { actionType: "transfer" },
          }),
        ),
      );

      expect(results.filter((result) => result === undefined)).toHaveLength(1);
      expect(results.filter((result) => typeof result === "string")).toHaveLength(1);
      const rows = await db
        .select()
        .from(sponsoredGasEvents)
        .where(eq(sponsoredGasEvents.tenantId, tenantId));
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        agentId,
        status: "reserved",
        reservedUsd: "0.600000",
      });
    } finally {
      await db.delete(sponsoredGasEvents).where(eq(sponsoredGasEvents.tenantId, tenantId));
      await db.delete(transactions).where(inArray(transactions.id, txIds));
      await db.delete(agents).where(eq(agents.id, agentId));
      await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, tenantId));
      await db.delete(tenants).where(eq(tenants.id, tenantId));
    }
  },
  120_000,
);
