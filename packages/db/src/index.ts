import type {
  AgentIdentity,
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
} from "./client";
export { runMigrations } from "./migrate";
export * from "./schema";

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

export type TransactionRequestFields = Pick<
  Transaction,
  "toAddress" | "value" | "data" | "chainId"
>;

export type DbTxRecord = TxRecord;

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
