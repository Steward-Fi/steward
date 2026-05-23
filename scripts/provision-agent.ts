#!/usr/bin/env bun
import { createHash } from "node:crypto";
import { getDb, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";
import { createAgentToken, DEFAULT_TENANT_ID, vault } from "../packages/api/src/services/context";
import { TradeSessionManager } from "../packages/trade-sessions/src/index";

const USAGE = `Usage:
  bun run scripts/provision-agent.ts <agentId> <ownerAddress>

Example:
  bun run scripts/provision-agent.ts sol 0x15fc6086064afe50ccf4c70000c55cecb6e17777`;

function requireArg(value: string | undefined, name: string): string {
  if (!value?.trim()) {
    console.error(`Missing ${name}\n\n${USAGE}`);
    process.exit(1);
  }
  return value.trim();
}

async function ensureDefaultTenant(ownerAddress: string) {
  const db = getDb();
  const [existing] = await db
    .select({ id: tenants.id })
    .from(tenants)
    .where(eq(tenants.id, DEFAULT_TENANT_ID));
  if (existing) return;

  await db.insert(tenants).values({
    id: DEFAULT_TENANT_ID,
    name: "Default Steward Tenant",
    apiKeyHash: createHash("sha256").update(`provision-agent:${DEFAULT_TENANT_ID}`).digest("hex"),
    ownerAddress,
  });
}

async function ensureAgent(agentId: string, ownerAddress: string) {
  try {
    const created = await vault.createAgent(
      DEFAULT_TENANT_ID,
      agentId,
      agentId === "sol" ? "Sol" : agentId,
      ownerAddress,
    );
    return { agent: created, created: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!/already exists/i.test(message)) throw err;
    const existing = await vault.getAgent(DEFAULT_TENANT_ID, agentId);
    if (!existing) throw new Error(`Agent ${agentId} already exists but could not be loaded`);
    return { agent: existing, created: false };
  }
}

async function ensureHyperliquidWallet(agentId: string) {
  try {
    const existing = await vault.getWallet({ agentId, venue: "hyperliquid" });
    return { wallet: existing, created: false };
  } catch {
    const created = await vault.createWallet({
      agentId,
      venue: "hyperliquid",
      chainType: "evm",
      purpose: "hyperliquid-deposit",
    });
    return { wallet: created, created: true };
  }
}

async function main() {
  const agentId = requireArg(process.argv[2], "agentId");
  const ownerAddress = requireArg(process.argv[3], "ownerAddress");

  await ensureDefaultTenant(ownerAddress);

  const { agent, created: agentCreated } = await ensureAgent(agentId, ownerAddress);
  const { wallet, created: walletCreated } = await ensureHyperliquidWallet(agentId);

  const sessions = new TradeSessionManager();
  const session = await sessions.createSession({
    agentId,
    tenantId: DEFAULT_TENANT_ID,
    venue: "hyperliquid",
    walletId: wallet.address,
    ttlSeconds: 15 * 60,
    dailyCapUsd: 100,
    perOrderCapUsd: 100,
    leverageCap: 2,
    allowedAssets: ["BTC", "ETH"],
  });

  const jwt = await createAgentToken(agentId, DEFAULT_TENANT_ID, "15m", [
    "trade:read",
    "trade:hyperliquid:write",
  ]);

  console.log("Steward Sol provisioning complete");
  console.log("================================");
  console.log(`Agent ID: ${agent.id} (${agentCreated ? "created" : "existing"})`);
  console.log(`Owner address: ${ownerAddress}`);
  console.log(`HL deposit address: ${wallet.address} (${walletCreated ? "created" : "existing"})`);
  console.log(`Trade session ID: ${session.id}`);
  console.log(`Trade session expires: ${session.expiresAt.toISOString()}`);
  console.log("Policy: $100/day cap, $100/order cap, BTC+ETH only, max 2x leverage");
  console.log("");
  console.log("Set these in Sol's eliza-cloud container env:");
  console.log(`STEWARD_AGENT_ID=${agentId}`);
  console.log("STEWARD_API_URL=https://api.steward.fi");
  console.log(`STEWARD_TRADE_SESSION_ID=${session.id}`);
  console.log(`STEWARD_JWT=${jwt}`);
  console.log("");
  console.log(
    "Manual funding step: bridge/fund the HL deposit address above with $20 USDC on Arbitrum first. Do not submit live orders from automation.",
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack || err.message : err);
  process.exit(1);
});
