/**
 * WaifuBridge — Steward integration service for waifu.fun
 *
 * waifu.fun is an agent token launchpad on BSC (chain 56) using the Flap Protocol
 * portal contract for swaps. This service bridges waifu's agent lifecycle to Steward's
 * wallet infrastructure, applying sensible default policies for every provisioned agent.
 */

import { eq } from "drizzle-orm";
import { parseEther } from "viem";

import { getDb, policies, toPersistedPolicyRule, type PersistedPolicyRule } from "@stwd/db";
import type { AgentBalance, AgentIdentity, PolicyRule } from "@stwd/shared";
import { Vault } from "@stwd/vault";

const AGENT_ID_RE = /^[a-zA-Z0-9_\-.:]{1,128}$/;

// BSC Mainnet — the chain waifu.fun operates on
export const WAIFU_CHAIN_ID = 56;

/**
 * Default policy set for waifu.fun agents.
 * The portal contract address is injected at runtime via `getDefaultPolicies(portalAddress)`.
 */
function buildDefaultPolicies(portalAddress?: string): PersistedPolicyRule[] {
  const addresses = portalAddress ? [portalAddress] : [];

  return [
    {
      id: "waifu-spend",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("0.1").toString(),  // 0.1 BNB per trade
        maxPerDay: parseEther("1.0").toString(),  // 1 BNB daily
        maxPerWeek: parseEther("5.0").toString(), // 5 BNB weekly
      },
    },
    {
      id: "waifu-approved",
      type: "approved-addresses",
      enabled: true,
      config: {
        mode: "whitelist",
        addresses,  // Portal address injected at runtime
      },
    },
    {
      id: "waifu-rate",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 6,
        maxTxPerDay: 24,
      },
    },
    {
      id: "waifu-auto",
      type: "auto-approve-threshold",
      enabled: true,
      config: {
        threshold: parseEther("0.01").toString(), // auto-approve below 0.01 BNB
      },
    },
  ];
}

export interface ProvisionAgentResult {
  agent: AgentIdentity;
  policies: PolicyRule[];
}

export class WaifuBridge {
  private readonly vault: Vault;
  private readonly tenantId: string;

  constructor(vault: Vault, tenantId: string) {
    this.vault = vault;
    this.tenantId = tenantId;
  }

  /**
   * Provision a new Steward wallet for a waifu.fun agent.
   * Creates the agent wallet and applies the default waifu policy set.
   *
   * @param waifuAgentId  — waifu.fun agent ID (used as Steward agent ID)
   * @param name          — human-readable agent name (e.g. "Milady Trader")
   * @param platformId    — waifu.fun platform identifier (e.g. "waifu.fun:1")
   * @param portalAddress — optional Flap Protocol portal address to whitelist
   * @throws Error if waifuAgentId is invalid or agent already exists
   */
  async provisionAgent(
    waifuAgentId: string,
    name: string,
    platformId: string,
    portalAddress?: string
  ): Promise<ProvisionAgentResult> {
    if (!waifuAgentId || !AGENT_ID_RE.test(waifuAgentId)) {
      throw new Error(`Invalid agent ID "${waifuAgentId}" — must be 1-128 alphanumeric characters (plus _ - . :)`);
    }
    if (!name || name.trim().length === 0) {
      throw new Error("Agent name is required");
    }
    if (!platformId || platformId.trim().length === 0) {
      throw new Error("platformId is required for waifu.fun provisioning");
    }

    console.log(`[WaifuBridge] Provisioning agent "${waifuAgentId}" (${name}) for tenant ${this.tenantId}`);

    // Create the Steward wallet
    let agent: AgentIdentity;
    try {
      agent = await this.vault.createAgent(
        this.tenantId,
        waifuAgentId,
        name,
        platformId
      );
    } catch (err) {
      console.error(`[WaifuBridge] Failed to create agent "${waifuAgentId}":`, err);
      throw err;
    }

    console.log(`[WaifuBridge] Agent "${waifuAgentId}" created — wallet ${agent.walletAddress}`);

    // Apply default waifu policies
    const defaultPolicies = buildDefaultPolicies(portalAddress);
    const db = getDb();

    try {
      const persistedPolicies = defaultPolicies.map(toPersistedPolicyRule);
      await db.delete(policies).where(eq(policies.agentId, waifuAgentId));
      await db.insert(policies).values(
        persistedPolicies.map((policy) => ({
          id: policy.id,
          agentId: waifuAgentId,
          type: policy.type,
          enabled: policy.enabled,
          config: policy.config,
        }))
      );
    } catch (err) {
      console.error(`[WaifuBridge] Failed to apply default policies for agent "${waifuAgentId}":`, err);
      // Agent was created but policies failed — caller should retry policy setup
      throw new Error(`Agent created but policy setup failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    console.log(`[WaifuBridge] Default policies applied for agent "${waifuAgentId}" (${defaultPolicies.length} rules)`);

    return { agent, policies: defaultPolicies };
  }

  /**
   * Return the standard waifu.fun policy set for a given portal address.
   * Useful for previewing or applying policies without full provisioning.
   */
  getDefaultPolicies(portalAddress?: string): PolicyRule[] {
    return buildDefaultPolicies(portalAddress);
  }

  /**
   * Query on-chain native balance (BNB) for a waifu agent on BSC.
   * Accepts an optional `chainId` override for testnet use.
   *
   * @throws Error if the agent doesn't exist or balance fetch fails
   */
  async syncAgentBalance(agentId: string, chainId?: number): Promise<AgentBalance> {
    if (!agentId) {
      throw new Error("agentId is required for balance sync");
    }

    const resolvedChainId = chainId ?? WAIFU_CHAIN_ID;

    try {
      const balance = await this.vault.getBalance(this.tenantId, agentId, resolvedChainId);

      return {
        agentId,
        walletAddress: balance.walletAddress,
        balances: {
          native: balance.native.toString(),
          nativeFormatted: balance.nativeFormatted,
          chainId: balance.chainId,
          symbol: balance.symbol,
        },
      };
    } catch (err) {
      console.error(`[WaifuBridge] Failed to sync balance for agent "${agentId}" on chain ${resolvedChainId}:`, err);
      throw err;
    }
  }
}
