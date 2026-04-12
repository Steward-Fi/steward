import { eq, inArray } from "drizzle-orm";
import type {
  AgentIdentity,
  ChainFamily,
  PolicyResult,
  PolicyRule,
  SignRequest,
  TxRecord,
} from "@stwd/shared";

export {
  closeDb,
  createDb,
  createPostgresClient,
  getDatabaseUrl,
  getDb,
  getSql,
  setPGLiteOverride,
} from "./client";
export { runMigrations } from "./migrate";
export {
  closePGLiteDb,
  createPGLiteDb,
  getDataDir,
  getPGLiteClient,
  getPGLiteDb,
  shouldUsePGLite,
} from "./pglite";
export type { PGLiteDb } from "./pglite";
export * from "./schema";
export * from "./schema-auth";

import { policyTypeEnum } from "./schema";
import type { Agent, Policy, Transaction } from "./schema";

export type DbAgentIdentity = AgentIdentity & {
  tenantId: string;
  updatedAt: Date;
};

export type DbPolicyRule = PolicyRule & {
  agentId: string;
  createdAt: Date;
  updatedAt: Date;
};

export type PersistedPolicyType = (typeof policyTypeEnum.enumValues)[number];
export type PersistedPolicyRule = Omit<PolicyRule, "type"> & {
  type: PersistedPolicyType;
};

export type TransactionRequestFields = Pick<
  Transaction,
  "toAddress" | "value" | "data" | "chainId"
>;

export type DbTxRecord = TxRecord;

export function isPersistedPolicyType(value: string): value is PersistedPolicyType {
  return (policyTypeEnum.enumValues as readonly string[]).includes(value);
}

export function toPersistedPolicyRule(policy: PolicyRule): PersistedPolicyRule {
  if (!isPersistedPolicyType(policy.type)) {
    throw new Error(`Unsupported persisted policy type: ${policy.type}`);
  }
  return policy;
}

export function toAgentIdentity(agent: Agent): DbAgentIdentity {
  return {
    id: agent.id,
    tenantId: agent.tenantId,
    name: agent.name,
    walletAddress: agent.walletAddress,
    platformId: agent.platformId ?? undefined,
    erc8004TokenId: agent.erc8004TokenId ?? undefined,
    createdAt: agent.createdAt,
    updatedAt: agent.updatedAt,
  };
}

/**
 * Query all wallet addresses for a single agent from the `agent_wallets` table.
 * Returns an empty object for legacy agents that pre-date multi-wallet support.
 */
export async function getAgentWalletAddresses(
  agentId: string,
): Promise<{ evm?: string; solana?: string }> {
  const { getDb } = await import("./client");
  const { agentWallets } = await import("./schema");
  const db = getDb();
  const rows = await db
    .select()
    .from(agentWallets)
    .where(eq(agentWallets.agentId, agentId));

  const result: { evm?: string; solana?: string } = {};
  for (const row of rows) {
    if (row.chainFamily === "evm") result.evm = row.address;
    if (row.chainFamily === "solana") result.solana = row.address;
  }
  return result;
}

/**
 * Query wallet addresses for multiple agents in a single DB round-trip.
 * Returns a Map from agentId → { evm?, solana? }.
 */
export async function getAgentWalletAddressesBatch(
  agentIds: string[],
): Promise<Map<string, { evm?: string; solana?: string }>> {
  if (agentIds.length === 0) return new Map();

  const { getDb } = await import("./client");
  const { agentWallets } = await import("./schema");
  const db = getDb();
  const rows = await db
    .select()
    .from(agentWallets)
    .where(inArray(agentWallets.agentId, agentIds));

  const result = new Map<string, { evm?: string; solana?: string }>();
  for (const row of rows) {
    if (!result.has(row.agentId)) result.set(row.agentId, {});
    const entry = result.get(row.agentId)!;
    if (row.chainFamily === "evm") entry.evm = row.address;
    if (row.chainFamily === "solana") entry.solana = row.address;
  }
  return result;
}

export function toPolicyRule(policy: Policy): DbPolicyRule {
  return {
    id: policy.id,
    agentId: policy.agentId,
    type: policy.type,
    enabled: policy.enabled,
    config: policy.config,
    createdAt: policy.createdAt,
    updatedAt: policy.updatedAt,
  };
}

export function toSignRequest(transaction: Transaction): SignRequest {
  return {
    agentId: transaction.agentId,
    tenantId: "",
    to: transaction.toAddress,
    value: transaction.value,
    data: transaction.data ?? undefined,
    chainId: transaction.chainId,
  };
}

export function toTxRecord(transaction: Transaction): DbTxRecord {
  return {
    id: transaction.id,
    agentId: transaction.agentId,
    status: transaction.status,
    request: toSignRequest(transaction),
    txHash: transaction.txHash ?? undefined,
    policyResults: transaction.policyResults ?? [],
    createdAt: transaction.createdAt,
    signedAt: transaction.signedAt ?? undefined,
    confirmedAt: transaction.confirmedAt ?? undefined,
  };
}
