/**
 * Configuration types and loader for the agent-trader service.
 *
 * Config is resolved in this priority order:
 *   1. agent-trader.config.json in cwd (or path from CONFIG_PATH env var)
 *   2. Environment variables (STEWARD_API_URL, STEWARD_TENANT_ID, STEWARD_API_KEY)
 *
 * The `agents` array can only be supplied via JSON config — environment
 * variables are only used to override the top-level `steward` connection block.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { MAX_SLIPPAGE_BPS } from "./trade-builder.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface StewardConnection {
  /** Base URL of the Steward API, e.g. https://api.steward.fi */
  apiUrl: string;
  /** Tenant identifier, e.g. "waifu.fun" */
  tenantId: string;
  /** API key for the X-Steward-Key header */
  apiKey: string;
}

export type StrategyName = "rebalance" | "dca" | "threshold" | "manual";

export interface AgentTraderConfig {
  /** Agent ID registered in Steward (used for vault signing calls) */
  agentId: string;
  /** ERC-20 address of the agent's own token */
  tokenAddress: string;
  /** Which trading strategy to use */
  strategy: StrategyName;
  /** How often (in seconds) the trading loop checks state */
  intervalSeconds: number;
  /** Disabled agents are registered but their loops are never started */
  enabled: boolean;
  /** Chain to submit transactions on (defaults to Base mainnet 8453) */
  chainId?: number;
  /** DEX portal/router address for swap calldata encoding */
  portalAddress?: string;
  /**
   * Acceptable slippage for swaps, in basis points (default 100 = 1%).
   * Bounded to [0, 5000) — the swap builder refuses to build outside this range
   * and never emits an unprotected (amountOutMin = 0) swap.
   */
  slippageBps?: number;
  /** Strategy-specific parameters — typed per strategy in their own files */
  params: Record<string, unknown>;
}

export interface TraderConfig {
  steward: StewardConnection;
  /** Port the webhook receiver listens on (default 4210) */
  webhookPort: number;
  /** Secret used to verify incoming Steward webhook signatures */
  webhookSecret?: string;
  /** When true, decisions are logged but no transactions are submitted */
  dryRun?: boolean;
  /** Public HTTPS URL Steward should deliver webhooks to (informational only) */
  webhookPublicUrl?: string;
  agents: AgentTraderConfig[];
}

// ─── Defaults ────────────────────────────────────────────────────────────────

const CONFIG_DEFAULTS: Pick<TraderConfig, "webhookPort" | "dryRun"> = {
  webhookPort: 4210,
  dryRun: false,
};
/**
 * Whether unsigned webhooks are permitted. Local-dev escape hatch only: the flag
 * is hard-disabled in production (mirrors the proxy's `isRedisRequired` gate), so
 * a stray env var cannot strip signature verification on a live deployment.
 */
function allowUnsignedWebhooks(): boolean {
  if (process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS !== "true") return false;
  if (process.env.NODE_ENV === "production") {
    console.error(
      "[agent-trader] STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS is set but ignored in production; webhookSecret stays required.",
    );
    return false;
  }
  return true;
}

// ─── Loader ──────────────────────────────────────────────────────────────────

function loadJsonConfig(path: string): Partial<TraderConfig> {
  try {
    const raw = readFileSync(path, "utf-8");
    return JSON.parse(raw) as Partial<TraderConfig>;
  } catch {
    return {};
  }
}

export function loadConfig(): TraderConfig {
  const configPath = resolve(process.env.CONFIG_PATH ?? "agent-trader.config.json");
  const file = loadJsonConfig(configPath);

  // Merge: file takes precedence, env vars override the connection block
  const steward: StewardConnection = {
    apiUrl: process.env.STEWARD_API_URL ?? file.steward?.apiUrl ?? "http://localhost:3000",
    tenantId: process.env.STEWARD_TENANT_ID ?? file.steward?.tenantId ?? "default",
    apiKey: process.env.STEWARD_API_KEY ?? file.steward?.apiKey ?? "",
  };

  const config: TraderConfig = {
    ...CONFIG_DEFAULTS,
    ...file,
    steward,
    webhookPort: Number(
      process.env.WEBHOOK_PORT ?? file.webhookPort ?? CONFIG_DEFAULTS.webhookPort,
    ),
    dryRun:
      process.env.DRY_RUN === "true"
        ? true
        : process.env.DRY_RUN === "false"
          ? false
          : (file.dryRun ?? CONFIG_DEFAULTS.dryRun),
    agents: file.agents ?? [],
  };

  validate(config);
  return config;
}

function validate(config: TraderConfig): void {
  if (!config.steward.apiUrl) {
    throw new Error("Config error: steward.apiUrl is required");
  }
  if (!config.steward.tenantId) {
    throw new Error("Config error: steward.tenantId is required");
  }
  if (!config.webhookSecret && !allowUnsignedWebhooks()) {
    throw new Error(
      "Config error: webhookSecret is required. Set STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS=true only for local development.",
    );
  }

  for (const agent of config.agents) {
    if (!agent.agentId) {
      throw new Error("Config error: each agent must have an agentId");
    }
    if (!agent.tokenAddress) {
      throw new Error(`Config error: agent "${agent.agentId}" is missing tokenAddress`);
    }
    const validStrategies: StrategyName[] = ["rebalance", "dca", "threshold", "manual"];
    if (!validStrategies.includes(agent.strategy)) {
      throw new Error(
        `Config error: agent "${agent.agentId}" has unknown strategy "${agent.strategy}"`,
      );
    }
    if (!agent.intervalSeconds || agent.intervalSeconds < 10) {
      throw new Error(`Config error: agent "${agent.agentId}" intervalSeconds must be ≥ 10`);
    }
    if (agent.slippageBps !== undefined) {
      if (
        !Number.isInteger(agent.slippageBps) ||
        agent.slippageBps < 0 ||
        agent.slippageBps >= MAX_SLIPPAGE_BPS
      ) {
        throw new Error(
          `Config error: agent "${agent.agentId}" slippageBps must be an integer in [0, ${MAX_SLIPPAGE_BPS}) — got ${agent.slippageBps}`,
        );
      }
    }
  }
}
