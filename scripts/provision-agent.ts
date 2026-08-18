#!/usr/bin/env bun
import { resolve } from "node:path";
import { getDb, tenants } from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { createAgentToken, DEFAULT_TENANT_ID, vault } from "../packages/api/src/services/context";
import { TradeSessionManager } from "../packages/trade-sessions/src/index";
import { type DefaultTenantStore, ensureDefaultTenant } from "./lib/default-tenant";
import { type ProvisionSecrets, writeProvisionSecrets } from "./lib/provision-secrets";

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

// Drizzle-backed store for the default-tenant key logic (SEC-012). The key
// itself is generated inside ensureDefaultTenant and written once to the
// owner-only provisioning output — never logged or stored in the database.
const defaultTenantStore: DefaultTenantStore = {
  async getApiKeyHash(tenantId) {
    const [row] = await getDb()
      .select({ apiKeyHash: tenants.apiKeyHash })
      .from(tenants)
      .where(eq(tenants.id, tenantId));
    return row?.apiKeyHash ?? null;
  },
  async insertTenant(values) {
    await getDb().insert(tenants).values(values);
  },
  async rotateApiKeyHash(tenantId, expectedApiKeyHash, apiKeyHash) {
    const updated = await getDb()
      .update(tenants)
      .set({ apiKeyHash })
      .where(and(eq(tenants.id, tenantId), eq(tenants.apiKeyHash, expectedApiKeyHash)))
      .returning({ id: tenants.id });
    return updated.length === 1;
  },
};

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
      tenantId: DEFAULT_TENANT_ID,
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

  const tenantResult = await ensureDefaultTenant(defaultTenantStore, {
    tenantId: DEFAULT_TENANT_ID,
    tenantName: "Default Steward Tenant",
    ownerAddress,
  });

  const provisionSecrets: ProvisionSecrets = {
    ...(tenantResult.status === "created" || tenantResult.status === "rotated"
      ? { tenantApiKey: tenantResult.apiKey }
      : {}),
  };
  // Persist a newly-created/rotated tenant key immediately. If a later wallet
  // or session step fails, the only usable copy of that one-time key is still
  // recoverable and was never written to terminal scrollback or CI logs.
  const credentialsPath = writeProvisionSecrets(provisionSecrets);
  console.log(`Sensitive provisioning output: ${credentialsPath} (mode 0600)`);

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

  Object.assign(provisionSecrets, {
    agentId,
    apiUrl: "http://localhost:3200",
    tradeSessionId: session.id,
    jwt,
  });
  writeProvisionSecrets(provisionSecrets, credentialsPath);

  console.log("Steward Sol provisioning complete");
  console.log("================================");
  if (tenantResult.status === "created") {
    console.log("Default tenant created. Its one-time API key is in the private output file.");
  } else if (tenantResult.status === "rotated") {
    console.log("⚠  ROTATED the default tenant API key: the previous key was publicly");
    console.log("   derivable (sha256 of a string published in this repo, SEC-012) and is");
    console.log("   now INVALID. Update any client still using it.");
    console.log("   The replacement key is in the private output file.");
  }
  console.log(`Agent ID: ${agent.id} (${agentCreated ? "created" : "existing"})`);
  console.log(`Owner address: ${ownerAddress}`);
  console.log(`HL deposit address: ${wallet.address} (${walletCreated ? "created" : "existing"})`);
  console.log(`Trade session expires: ${session.expiresAt.toISOString()}`);
  console.log("Policy: $100/day cap, $100/order cap, BTC+ETH only, max 2x leverage");
  console.log("");
  console.log("Agent environment credentials were written to the private output file above.");
  console.log("");
  console.log(
    "Manual funding step: bridge/fund the HL deposit address above with $20 USDC on Arbitrum first. Do not submit live orders from automation.",
  );
}

function isMain(): boolean {
  const entry = process.argv[1] ? resolve(process.argv[1]) : "";
  return import.meta.url === new URL(`file://${entry}`).href;
}

if (isMain()) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.stack || err.message : err);
    process.exit(1);
  });
}
