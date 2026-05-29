/**
 * Vault routes — transaction signing, approval/rejection, history, key import,
 * multi-wallet addresses, RPC passthrough, Solana signing, EIP-712 typed data.
 *
 * Mount: app.route("/vault", vaultRoutes)
 */

import { type PolicyResult, toCaip2 } from "@stwd/shared";
import {
  ENTRY_POINT_V07,
  getUserOperationHash,
  packUserOperation,
  type UnpackedUserOperationFields,
} from "@stwd/vault";
import { and, desc, eq, type SQL, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { enforceRateLimit, recordVaultSpend } from "../middleware/redis-enforcement";
import { type AuditEventInput, writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  agentKeyQuorums,
  agentSigners,
  approvalQueue,
  db,
  ensureAgentForTenant,
  extractRpcErrorMessage,
  getPolicySet,
  getTransactionStats,
  isNonEmptyString,
  isRpcError,
  isValidAddress,
  isValidAgentId,
  isValidAnyAddress,
  isValidSolanaAddress,
  loadConditionSetsForPolicies,
  policyEngine,
  priceOracle,
  type RpcRequest,
  type RpcResponse,
  requireAgentAccess,
  requireTenantLevel,
  type SignRequest,
  type SignTypedDataRequest,
  safeJsonParse,
  sanitizeErrorMessage,
  toSignRequest,
  toTxRecord,
  transactions,
  vault,
} from "../services/context";
import {
  recordSponsoredGasEvent,
  reserveSponsoredGasEvent,
  resolveGasSponsorshipRequest,
} from "../services/gas-sponsorship";
import { verifySignerCredential } from "../services/signer-credentials";
import { dispatchWebhook } from "../services/webhook-dispatch";

export const vaultRoutes = new Hono<{ Variables: AppVariables }>();

async function writeVaultAudit(
  c: Context<{ Variables: AppVariables }>,
  event: Omit<AuditEventInput, "ipAddress" | "userAgent" | "requestId">,
): Promise<void> {
  await writeAuditEvent({
    ...event,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}
const ALLOW_PRIVATE_KEY_EXPORT = process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT === "true";
const ALLOW_VAULT_PRIVATE_KEY_EXPORT =
  process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT === "true";
const ALLOW_UNSAFE_MESSAGE_SIGNING = process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING === "true";
const ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING =
  process.env.STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING === "true";
const ALLOW_UNSAFE_RAW_SIGNING = process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING === "true";
const ALLOW_VAULT_UNSAFE_RAW_SIGNING =
  process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING === "true";
const ALLOW_UNSAFE_CONTRACT_CALL_SIGNING =
  process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING === "true";
const ALLOW_UNSAFE_USER_OPERATION_SIGNING =
  process.env.STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING === "true";
const ALLOW_UNSAFE_AUTHORIZATION_SIGNING =
  process.env.STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING === "true";
const ALLOW_PRIVATE_KEY_IMPORT = process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT === "true";
const ALLOW_VAULT_PRIVATE_KEY_IMPORT =
  process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT === "true";
const VAULT_RPC_ALLOWLIST = new Set(
  (process.env.STEWARD_VAULT_RPC_ALLOWLIST ?? "eth_chainId,eth_blockNumber,eth_getBalance")
    .split(",")
    .map((method) => method.trim())
    .filter(Boolean),
);
const MAX_VAULT_HISTORY_LIMIT = 200;
const MAX_UINT256_DECIMAL =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const MAX_UINT256_DECIMAL_DIGITS = 78;
const MAX_QUORUM_CREDENTIALS = 32;

function userOperationPolicyModelAvailable(): boolean {
  return false;
}

function authorizationPolicyModelAvailable(): boolean {
  return false;
}

function parseListLimit(value: string | undefined, fallback = 100): number {
  const parsed = value ? Number(value) : fallback;
  if (!Number.isSafeInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, MAX_VAULT_HISTORY_LIMIT);
}

function parseListOffset(value: string | undefined): number {
  const parsed = value ? Number(value) : 0;
  if (!Number.isSafeInteger(parsed) || parsed < 0) return 0;
  return Math.min(parsed, 100_000);
}

function isUint256DecimalString(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
  const normalized = value.replace(/^0+/, "") || "0";
  if (normalized.length > MAX_UINT256_DECIMAL_DIGITS) return false;
  return normalized.length < MAX_UINT256_DECIMAL_DIGITS || normalized <= MAX_UINT256_DECIMAL;
}

type TransferActionInput = {
  to?: unknown;
  token?: unknown;
  value?: unknown;
  amountWei?: unknown;
  chainId?: unknown;
  broadcast?: unknown;
  referenceId?: unknown;
  sponsor?: unknown;
};

type SendCallsActionInput = {
  calls?: unknown;
  chainId?: unknown;
  broadcast?: unknown;
  referenceId?: unknown;
  sponsor?: unknown;
};

type ParsedSendCall = {
  to: string;
  value: string;
  data?: string;
};

function parseReferenceId(value: unknown): string | undefined | null {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) return null;
  return trimmed;
}

function parseTransferActionInput(body: TransferActionInput): {
  to: string;
  token: "native" | string;
  value: string;
  chainId: number;
  broadcast: boolean;
  referenceId?: string;
  sponsor: boolean;
} | null {
  const value = typeof body.value === "string" ? body.value : body.amountWei;
  const token =
    body.token === undefined || body.token === null || body.token === "" ? "native" : body.token;
  const chainId =
    typeof body.chainId === "number" && Number.isInteger(body.chainId)
      ? body.chainId
      : parseInt(process.env.CHAIN_ID || "8453", 10);
  const referenceId = parseReferenceId(body.referenceId);

  if (!isNonEmptyString(body.to) || !isValidAddress(body.to)) return null;
  if (token !== "native" && (!isNonEmptyString(token) || !isValidAddress(token))) return null;
  if (!isNonEmptyString(value) || !isUint256DecimalString(value)) return null;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return null;
  if (referenceId === null) return null;

  return {
    to: body.to,
    token,
    value,
    chainId,
    broadcast: body.broadcast !== false,
    referenceId,
    sponsor: body.sponsor === true,
  };
}

function parseSendCallsActionInput(body: SendCallsActionInput):
  | {
      calls: ParsedSendCall[];
      chainId: number;
      broadcast: boolean;
      totalValue: string;
      referenceId?: string;
      sponsor: boolean;
    }
  | string {
  if (!Array.isArray(body.calls) || body.calls.length === 0) {
    return "calls must be a non-empty array";
  }
  if (body.calls.length > 25) {
    return "calls must contain at most 25 entries";
  }

  const chainId =
    typeof body.chainId === "number" && Number.isInteger(body.chainId)
      ? body.chainId
      : parseInt(process.env.CHAIN_ID || "8453", 10);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return "chainId must be a positive integer";
  const referenceId = parseReferenceId(body.referenceId);
  if (referenceId === null) return "referenceId must be a non-empty string up to 128 characters";

  let totalValue = 0n;
  const calls: ParsedSendCall[] = [];
  for (const [index, rawCall] of body.calls.entries()) {
    if (!rawCall || typeof rawCall !== "object") return `calls[${index}] must be an object`;
    const call = rawCall as Record<string, unknown>;
    if (!isNonEmptyString(call.to) || !isValidAddress(call.to)) {
      return `calls[${index}].to must be an EVM address`;
    }
    const value = call.value === undefined ? "0" : call.value;
    if (!isNonEmptyString(value) || !isUint256DecimalString(value)) {
      return `calls[${index}].value must be a uint256 wei string`;
    }
    const data = call.data;
    if (data !== undefined && !isHex(data)) {
      return `calls[${index}].data must be hex`;
    }
    totalValue += BigInt(value);
    calls.push({
      to: call.to,
      value,
      data: data === "0x" || data === undefined ? undefined : data,
    });
  }

  return {
    calls,
    chainId,
    broadcast: body.broadcast !== false,
    totalValue: totalValue.toString(),
    referenceId,
    sponsor: body.sponsor === true,
  };
}

function transferActionResponse(input: {
  actionId: string;
  status: "pending_approval" | "rejected" | "signed" | "broadcast" | "failed";
  chainId: number;
  to: string;
  value: string;
  token: "native" | string;
  txHash?: string;
  signedTx?: string;
  sponsorship?: Record<string, unknown>;
  policyResults?: unknown;
}) {
  return {
    id: input.actionId,
    type: "transfer" as const,
    status: input.status,
    chainId: input.chainId,
    to: input.to,
    value: input.value,
    token: input.token,
    txHash: input.txHash,
    signedTx: input.signedTx,
    sponsorship: input.sponsorship,
    policyResults: input.policyResults,
  };
}

function transferActionPayload(input: {
  token: "native" | string;
  recipient: string;
  amount: string;
  broadcast: boolean;
  referenceId?: string | null;
  sponsorship?: Record<string, unknown>;
}) {
  return {
    type: "transfer",
    token: input.token,
    recipient: input.recipient,
    amount: input.amount,
    broadcast: input.broadcast,
    ...(input.referenceId ? { referenceId: input.referenceId } : {}),
    ...(input.sponsorship ? { sponsorship: input.sponsorship } : {}),
  };
}

function sendCallsActionPayload(input: {
  calls: ParsedSendCall[];
  broadcast: boolean;
  totalValue: string;
  referenceId?: string;
  sponsorship?: Record<string, unknown>;
}) {
  return {
    type: "send_calls",
    calls: input.calls,
    broadcast: input.broadcast,
    totalValue: input.totalValue,
    ...(input.referenceId ? { referenceId: input.referenceId } : {}),
    ...(input.sponsorship ? { sponsorship: input.sponsorship } : {}),
  };
}

function transactionActionPayload(input: { broadcast: boolean; referenceId?: string | null }) {
  return {
    type: "transaction",
    broadcast: input.broadcast,
    ...(input.referenceId ? { referenceId: input.referenceId } : {}),
  };
}

function getTransferActionPayload(payload: unknown): {
  type: "transfer";
  token: string;
  recipient?: string;
  amount?: string;
  broadcast: boolean;
  referenceId?: string;
  sponsorship?: Record<string, unknown>;
} | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  if (value.type !== "transfer") return null;
  return {
    type: "transfer",
    token: typeof value.token === "string" ? value.token : "native",
    recipient: typeof value.recipient === "string" ? value.recipient : undefined,
    amount: typeof value.amount === "string" ? value.amount : undefined,
    broadcast: value.broadcast !== false,
    referenceId: actionReferenceId(value) ?? undefined,
    sponsorship:
      value.sponsorship && typeof value.sponsorship === "object"
        ? (value.sponsorship as Record<string, unknown>)
        : undefined,
  };
}

async function recordSponsoredActionIfNeeded(input: {
  sponsorship: Record<string, unknown> | undefined;
  tenantId: string;
  agentId: string;
  txId: string;
  chainId: number;
  caip2?: string;
  txHash?: string;
  actionType: string;
  status?: "pending" | "rejected" | "failed" | "reserved" | "signed" | "submitted";
}) {
  if (!input.sponsorship || input.sponsorship.sponsored !== true) return;
  if (input.status === "pending" || input.status === "rejected") {
    return;
  }
  const provider = input.sponsorship.provider;
  const mode = input.sponsorship.mode;
  if (typeof provider !== "string" || typeof mode !== "string") return;
  const estimatedUsd =
    typeof input.sponsorship.estimatedUsd === "number" ? input.sponsorship.estimatedUsd : undefined;
  if (input.status === "reserved") {
    if (estimatedUsd === undefined) return "Gas sponsorship estimate is unavailable";
    return reserveSponsoredGasEvent({
      tenantId: input.tenantId,
      agentId: input.agentId,
      txId: input.txId,
      chainFamily: "evm",
      chainId: input.chainId,
      caip2: input.caip2,
      provider,
      mode,
      reservedUsd: estimatedUsd,
      metadata: { actionType: input.actionType },
    });
  }
  await recordSponsoredGasEvent({
    tenantId: input.tenantId,
    agentId: input.agentId,
    txId: input.txId,
    chainFamily: "evm",
    chainId: input.chainId,
    caip2: input.caip2,
    provider,
    mode,
    status: input.status ?? (input.txHash ? "submitted" : "reserved"),
    reservedUsd: input.status === "failed" ? 0 : estimatedUsd,
    actualUsd: input.status === "failed" ? 0 : undefined,
    txHash: input.txHash,
    metadata: { actionType: input.actionType },
  });
}

function transferResponseStatus(
  status: string,
): "pending_approval" | "rejected" | "signed" | "broadcast" | "failed" {
  if (status === "pending") return "pending_approval";
  if (status === "rejected") return "rejected";
  if (status === "broadcast") return "broadcast";
  if (status === "failed") return "failed";
  return "signed";
}

function transferActionResponseFromTransaction(row: typeof transactions.$inferSelect) {
  const payload = getTransferActionPayload(row.actionPayload);
  return transferActionResponse({
    actionId: row.id,
    status: transferResponseStatus(row.status),
    chainId: row.chainId,
    to: payload?.recipient ?? row.toAddress,
    value: payload?.amount ?? row.value,
    token: payload?.token ?? "native",
    txHash: row.txHash ?? undefined,
    sponsorship: payload?.sponsorship,
    policyResults: row.policyResults ?? undefined,
  });
}

async function findActionByReferenceId(
  agentId: string,
  actionType: string,
  referenceId: string | undefined,
) {
  if (!referenceId) return null;
  const [existing] = await db
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        eq(transactions.actionType, actionType),
        sql`(${transactions.actionPayload}->>'referenceId' = ${referenceId} or ${transactions.actionPayload}->>'reference_id' = ${referenceId})`,
      ),
    )
    .limit(1);
  return existing ?? null;
}

function requireBroadcastActionIdempotency(
  c: Context<{ Variables: AppVariables }>,
  broadcast: boolean,
  actionLabel: string,
): Response | null {
  if (!broadcast || isNonEmptyString(c.req.header("Idempotency-Key"))) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${actionLabel} require an Idempotency-Key header` },
    400,
  );
}

function getSendCallsActionPayload(payload: unknown): {
  type: "send_calls";
  broadcast: boolean;
  totalValue?: string;
  referenceId?: string;
} | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  if (value.type !== "send_calls") return null;
  return {
    type: "send_calls",
    broadcast: value.broadcast !== false,
    totalValue: typeof value.totalValue === "string" ? value.totalValue : undefined,
    referenceId: actionReferenceId(value) ?? undefined,
  };
}

function getTransactionActionPayload(payload: unknown): {
  type: "transaction";
  broadcast: boolean;
  referenceId?: string;
} | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  if (value.type !== "transaction") return null;
  return {
    type: "transaction",
    broadcast: value.broadcast !== false,
    referenceId: actionReferenceId(value) ?? undefined,
  };
}

type TransactionLifecycleEventType =
  | "transaction.broadcasted"
  | "transaction.confirmed"
  | "transaction.execution_reverted"
  | "transaction.replaced"
  | "transaction.failed"
  | "transaction.provider_error"
  | "transaction.still_pending";

const TRANSACTION_LIFECYCLE_EVENTS = new Set<TransactionLifecycleEventType>([
  "transaction.broadcasted",
  "transaction.confirmed",
  "transaction.execution_reverted",
  "transaction.replaced",
  "transaction.failed",
  "transaction.provider_error",
  "transaction.still_pending",
]);

function isTransactionLifecycleEvent(value: unknown): value is TransactionLifecycleEventType {
  return (
    typeof value === "string" &&
    TRANSACTION_LIFECYCLE_EVENTS.has(value as TransactionLifecycleEventType)
  );
}

function dispatchTransactionLifecycleWebhook(
  tenantId: string,
  agentId: string,
  type: TransactionLifecycleEventType,
  payload: {
    txId: string;
    txHash?: string | null;
    previousTxHash?: string | null;
    replacementTxHash?: string | null;
    chainId?: number;
    status?: string;
    reason?: string;
    error?: string;
    provider?: string;
    blockNumber?: string | number;
    confirmations?: number;
    referenceId?: string | null;
    transactionRequest?: Record<string, unknown> | null;
  },
): void {
  const caip2 = payload.chainId
    ? (toCaip2(payload.chainId) ?? `eip155:${payload.chainId}`)
    : undefined;
  dispatchWebhook(tenantId, agentId, type, {
    txId: payload.txId,
    wallet_id: agentId,
    transaction_id: payload.txId,
    ...(payload.txHash ? { txHash: payload.txHash } : {}),
    ...(payload.txHash ? { transaction_hash: payload.txHash } : {}),
    ...(payload.previousTxHash ? { previousTxHash: payload.previousTxHash } : {}),
    ...(payload.replacementTxHash ? { replacementTxHash: payload.replacementTxHash } : {}),
    ...(payload.chainId ? { chainId: payload.chainId } : {}),
    ...(caip2 ? { caip2 } : {}),
    ...(payload.status ? { status: payload.status } : {}),
    ...(payload.reason ? { reason: payload.reason } : {}),
    ...(payload.error ? { error: payload.error } : {}),
    ...(payload.provider ? { provider: payload.provider } : {}),
    ...(payload.blockNumber !== undefined ? { blockNumber: payload.blockNumber } : {}),
    ...(payload.confirmations !== undefined ? { confirmations: payload.confirmations } : {}),
    ...(payload.referenceId ? { reference_id: payload.referenceId } : {}),
    ...(payload.transactionRequest ? { transaction_request: payload.transactionRequest } : {}),
  });
}

function actionReferenceId(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  const referenceId = value.referenceId ?? value.reference_id;
  return typeof referenceId === "string" && referenceId.trim() ? referenceId : null;
}

function intentActionType(actionType: string | null | undefined): string {
  if (actionType === "transfer") return "wallet_action.transfer";
  if (actionType === "send_calls") return "wallet_action.send_calls";
  if (actionType === "user_operation") return "user_operation";
  if (actionType === "authorization") return "eip7702_authorization";
  return "transaction";
}

function dispatchIntentWebhook(
  tenantId: string,
  agentId: string,
  type:
    | "intent.created"
    | "intent.authorized"
    | "intent.executed"
    | "intent.failed"
    | "intent.rejected",
  payload: {
    intentId: string;
    actionType?: string | null;
    status: "pending" | "authorized" | "executed" | "failed" | "rejected";
    txHash?: string;
    signedTx?: string;
    error?: string;
    reason?: string;
    referenceId?: string | null;
    policyResults?: unknown;
  },
): void {
  dispatchWebhook(tenantId, agentId, type, {
    intent_id: payload.intentId,
    txId: payload.intentId,
    transaction_id: payload.intentId,
    wallet_id: agentId,
    action_type: intentActionType(payload.actionType),
    status: payload.status,
    ...(payload.txHash ? { txHash: payload.txHash, transaction_hash: payload.txHash } : {}),
    ...(payload.signedTx ? { signed_tx: payload.signedTx } : {}),
    ...(payload.error ? { error: payload.error } : {}),
    ...(payload.reason ? { reason: payload.reason } : {}),
    ...(payload.referenceId ? { reference_id: payload.referenceId } : {}),
    ...(payload.policyResults ? { policy_results: payload.policyResults } : {}),
  });
}

function transactionRequestPayload(row: typeof transactions.$inferSelect): Record<string, unknown> {
  return {
    to: row.toAddress,
    value: row.value,
    data: row.data ?? "0x",
    chainId: row.chainId,
    ...(row.txHash ? { transaction_hash: row.txHash } : {}),
  };
}

function userOperationEventPayload(
  agentId: string,
  row: typeof transactions.$inferSelect,
  payload: {
    txHash?: string | null;
    status: "completed" | "failed";
    error?: string;
    blockNumber?: string | number;
    confirmations?: number;
  },
): Record<string, unknown> | null {
  if (row.actionType !== "user_operation" || !row.actionPayload) return null;
  const actionPayload = row.actionPayload as Record<string, unknown>;
  const userOperationHash = actionPayload.userOperationHash;
  if (typeof userOperationHash !== "string" || !userOperationHash) return null;
  const caip2 = toCaip2(row.chainId) ?? `eip155:${row.chainId}`;
  return {
    wallet_id: agentId,
    transaction_id: row.id,
    user_operation_hash: userOperationHash,
    caip2,
    status: payload.status,
    ...(typeof actionPayload.entryPoint === "string"
      ? { entry_point: actionPayload.entryPoint }
      : {}),
    ...(typeof actionPayload.sender === "string" ? { sender: actionPayload.sender } : {}),
    ...(payload.txHash ? { transaction_hash: payload.txHash } : {}),
    ...(payload.error ? { error: payload.error } : {}),
    ...(payload.blockNumber !== undefined ? { blockNumber: payload.blockNumber } : {}),
    ...(payload.confirmations !== undefined ? { confirmations: payload.confirmations } : {}),
  };
}

function toTransactionResponse(row: typeof transactions.$inferSelect) {
  return {
    ...toTxRecord(row),
    actionType: row.actionType ?? null,
    actionPayload: row.actionPayload ?? null,
  };
}

function hasCalldata(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "" && value.trim().toLowerCase() !== "0x";
}

function isHex(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]*$/.test(value);
}

function encodeErc20TransferCalldata(recipient: string, amount: string): string {
  const normalizedRecipient = recipient.toLowerCase().replace(/^0x/, "");
  const encodedRecipient = normalizedRecipient.padStart(64, "0");
  const encodedAmount = BigInt(amount).toString(16).padStart(64, "0");
  return `0xa9059cbb${encodedRecipient}${encodedAmount}`;
}

function erc20TransferPolicyPrecheck(
  policySet: Array<{ id: string; type: string; enabled: boolean; config: unknown }>,
  token: string,
): PolicyResult | null {
  const selector = "0xa9059cbb";
  const target = token.toLowerCase();
  for (const policy of policySet) {
    if (policy.type !== "contract-allowlist" || !policy.enabled) continue;
    const config = policy.config;
    if (!config || typeof config !== "object" || !("contracts" in config)) continue;
    const contracts = (config as { contracts?: unknown }).contracts;
    if (!Array.isArray(contracts)) continue;
    for (const entry of contracts) {
      if (!entry || typeof entry !== "object") continue;
      const contract = entry as {
        address?: unknown;
        selectors?: unknown;
        constraints?: unknown;
      };
      if (typeof contract.address !== "string" || contract.address.toLowerCase() !== target) {
        continue;
      }
      if (
        !Array.isArray(contract.selectors) ||
        !contract.selectors.some(
          (allowed) => typeof allowed === "string" && allowed.toLowerCase() === selector,
        )
      ) {
        continue;
      }
      const constraints =
        contract.constraints && typeof contract.constraints === "object"
          ? (contract.constraints as Record<string, unknown>)
          : {};
      const constraint = constraints[selector] ?? constraints[selector.toUpperCase()];
      if (!constraint || typeof constraint !== "object") {
        return {
          policyId: policy.id,
          type: policy.type,
          passed: false,
          reason: "ERC20 transfer selector requires recipient and maxAmount constraints",
        };
      }
      const typedConstraint = constraint as Record<string, unknown>;
      const hasRecipientConstraint =
        Array.isArray(typedConstraint.recipientAllowlist) ||
        Array.isArray(typedConstraint.recipientBlocklist);
      if (typeof typedConstraint.maxAmount !== "string" || !hasRecipientConstraint) {
        return {
          policyId: policy.id,
          type: policy.type,
          passed: false,
          reason: "ERC20 transfer selector requires recipient and maxAmount constraints",
        };
      }
      return null;
    }
  }
  return {
    policyId: "erc20-transfer-contract-allowlist-required",
    type: "contract-allowlist",
    passed: false,
    reason:
      "ERC20 transfer actions require an enabled contract-allowlist policy for the token transfer selector",
  };
}

function isBytes32Hex(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function parseBigIntString(value: unknown): bigint | null {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (!isUint256DecimalString(value)) return null;
  return BigInt(value);
}

function parseUserOperation(body: unknown): UnpackedUserOperationFields | string {
  if (!body || typeof body !== "object") return "userOperation is required";
  const value = body as Record<string, unknown>;
  if (!isValidAddress(value.sender)) return "userOperation.sender must be an Ethereum address";
  if (!isHex(value.callData)) return "userOperation.callData must be hex";
  if (value.initCode !== undefined && !isHex(value.initCode)) {
    return "userOperation.initCode must be hex";
  }
  if (value.paymasterAndData !== undefined && !isHex(value.paymasterAndData)) {
    return "userOperation.paymasterAndData must be hex";
  }

  const nonce = parseBigIntString(value.nonce);
  const verificationGasLimit = parseBigIntString(value.verificationGasLimit);
  const callGasLimit = parseBigIntString(value.callGasLimit);
  const preVerificationGas = parseBigIntString(value.preVerificationGas);
  const maxPriorityFeePerGas = parseBigIntString(value.maxPriorityFeePerGas);
  const maxFeePerGas = parseBigIntString(value.maxFeePerGas);
  if (
    nonce === null ||
    verificationGasLimit === null ||
    callGasLimit === null ||
    preVerificationGas === null ||
    maxPriorityFeePerGas === null ||
    maxFeePerGas === null
  ) {
    return "userOperation gas, fee, and nonce fields must be non-negative decimal strings";
  }

  return {
    sender: value.sender as `0x${string}`,
    nonce,
    initCode: (value.initCode as `0x${string}` | undefined) ?? "0x",
    callData: value.callData,
    verificationGasLimit,
    callGasLimit,
    preVerificationGas,
    maxPriorityFeePerGas,
    maxFeePerGas,
    paymasterAndData: (value.paymasterAndData as `0x${string}` | undefined) ?? "0x",
  };
}

function looksLikeAuthMessage(message: string): boolean {
  const normalized = message.toLowerCase();
  return (
    normalized.includes("wants you to sign in with your ethereum account") ||
    normalized.includes("sign-in with ethereum") ||
    normalized.includes("siwe") ||
    normalized.includes("permit(") ||
    normalized.includes("permit2")
  );
}

function hasRecentSessionMfa(c: Context<{ Variables: AppVariables }>, maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function hasTenantAdminSession(c: Context<{ Variables: AppVariables }>): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function signerHasPermission(permissions: readonly string[], required: string): boolean {
  const family = required.includes("_") ? `${required.split("_")[0]}:*` : `${required}:*`;
  const aliases =
    required === "wallet_action_transfer"
      ? ["transfer"]
      : required === "wallet_action_send_calls"
        ? ["send_calls"]
        : [];
  return (
    permissions.includes("*") ||
    (required.startsWith("sign_") && permissions.includes("sign:*")) ||
    permissions.includes(required) ||
    aliases.some((permission) => permissions.includes(permission)) ||
    permissions.includes(family)
  );
}

type SignerAuthorization =
  | { authMode: "admin"; signerId: string | null }
  | { authMode: "signer"; signerId: string }
  | { authMode: "quorum"; quorumId: string; memberSignerIds: string[] };

function signerAuthAuditMetadata(auth: SignerAuthorization): Record<string, unknown> {
  if (auth.authMode === "quorum") {
    return {
      authMode: "quorum",
      quorumId: auth.quorumId,
      memberSignerIds: auth.memberSignerIds,
    };
  }
  return {
    authMode: auth.authMode,
    signerId: auth.signerId,
  };
}

async function requireSignerPermission(
  c: Context<{ Variables: AppVariables }>,
  tenantId: string,
  agentId: string,
  requiredPermission: string,
): Promise<{ ok: true; auth: SignerAuthorization } | { ok: false; response: Response }> {
  if (hasTenantAdminSession(c)) {
    if (hasRecentSessionMfa(c)) {
      return { ok: true, auth: { authMode: "admin", signerId: c.get("userId") ?? null } };
    }
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: "Signing requires recent MFA verification" },
        403,
      ),
    };
  }

  const signerId = c.req.header("x-steward-signer-id")?.trim();
  const signerSecret = c.req.header("x-steward-signer-secret");
  const quorumId = c.req.header("x-steward-key-quorum-id")?.trim();
  if (quorumId) {
    const credentialsHeader = c.req.header("x-steward-key-quorum-credentials");
    if (!credentialsHeader) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Key quorum signing requires X-Steward-Key-Quorum-Credentials" },
          403,
        ),
      };
    }

    let credentials: Array<{ signerId: string; signerSecret: string }>;
    try {
      const parsed = JSON.parse(credentialsHeader) as unknown;
      if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > MAX_QUORUM_CREDENTIALS) {
        throw new Error("invalid quorum credential count");
      }
      credentials = parsed.map((credential) => {
        if (!credential || typeof credential !== "object") {
          throw new Error("invalid quorum credential");
        }
        const value = credential as Record<string, unknown>;
        if (typeof value.signerId !== "string" || !value.signerId.trim()) {
          throw new Error("invalid quorum signer id");
        }
        if (typeof value.signerSecret !== "string" || !value.signerSecret) {
          throw new Error("invalid quorum signer secret");
        }
        return {
          signerId: value.signerId.trim(),
          signerSecret: value.signerSecret,
        };
      });
    } catch {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Invalid X-Steward-Key-Quorum-Credentials header" },
          400,
        ),
      };
    }

    const uniqueSignerIds = [...new Set(credentials.map((credential) => credential.signerId))];
    if (uniqueSignerIds.length !== credentials.length) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Key quorum credentials must use unique signer ids" },
          400,
        ),
      };
    }

    const [quorum] = await db
      .select()
      .from(agentKeyQuorums)
      .where(
        and(
          eq(agentKeyQuorums.id, quorumId),
          eq(agentKeyQuorums.tenantId, tenantId),
          eq(agentKeyQuorums.agentId, agentId),
        ),
      );
    if (!quorum || quorum.status !== "active") {
      return {
        ok: false,
        response: c.json<ApiResponse>({ ok: false, error: "Invalid or inactive key quorum" }, 403),
      };
    }
    if (!signerHasPermission(quorum.permissions, requiredPermission)) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: `Key quorum lacks ${requiredPermission} permission` },
          403,
        ),
      };
    }

    const memberSet = new Set(quorum.memberSignerIds);
    if (uniqueSignerIds.some((id) => !memberSet.has(id))) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Key quorum credentials include non-member signer" },
          403,
        ),
      };
    }
    if (uniqueSignerIds.length < quorum.threshold) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Key quorum threshold was not met" },
          403,
        ),
      };
    }

    const rows = await db
      .select()
      .from(agentSigners)
      .where(and(eq(agentSigners.tenantId, tenantId), eq(agentSigners.agentId, agentId)));
    const signersById = new Map(rows.map((row) => [row.id, row]));
    const now = new Date();
    for (const credential of credentials) {
      const signer = signersById.get(credential.signerId);
      const credentialHash =
        signer?.metadata && typeof signer.metadata.credentialHash === "string"
          ? signer.metadata.credentialHash
          : null;
      if (
        !signer ||
        signer.status !== "active" ||
        !credentialHash ||
        !(await verifySignerCredential(credential.signerSecret, credentialHash))
      ) {
        return {
          ok: false,
          response: c.json<ApiResponse>(
            { ok: false, error: "Invalid or inactive key quorum signer credential" },
            403,
          ),
        };
      }
      if (!signerHasPermission(signer.permissions, requiredPermission)) {
        return {
          ok: false,
          response: c.json<ApiResponse>(
            { ok: false, error: `Key quorum member lacks ${requiredPermission} permission` },
            403,
          ),
        };
      }
      await db
        .update(agentSigners)
        .set({
          metadata: {
            ...signer.metadata,
            credentialLastUsedAt: now.toISOString(),
          },
          updatedAt: now,
        })
        .where(eq(agentSigners.id, signer.id));
    }

    return {
      ok: true,
      auth: { authMode: "quorum", quorumId: quorum.id, memberSignerIds: uniqueSignerIds },
    };
  }

  if (!signerId || !signerSecret) {
    return {
      ok: false,
      response: c.json<ApiResponse>(
        {
          ok: false,
          error:
            "Signing requires owner/admin MFA or signer-bound X-Steward-Signer-Id and X-Steward-Signer-Secret headers",
        },
        403,
      ),
    };
  }

  const [signer] = await db
    .select()
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    );
  const credentialHash =
    signer?.metadata && typeof signer.metadata.credentialHash === "string"
      ? signer.metadata.credentialHash
      : null;

  if (
    !signer ||
    signer.status !== "active" ||
    !credentialHash ||
    !(await verifySignerCredential(signerSecret, credentialHash))
  ) {
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: "Invalid or inactive delegated signer credential" },
        403,
      ),
    };
  }
  if (!signerHasPermission(signer.permissions, requiredPermission)) {
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: `Delegated signer lacks ${requiredPermission} permission` },
        403,
      ),
    };
  }

  await db
    .update(agentSigners)
    .set({
      metadata: {
        ...signer.metadata,
        credentialLastUsedAt: new Date().toISOString(),
      },
      updatedAt: new Date(),
    })
    .where(eq(agentSigners.id, signer.id));

  return { ok: true, auth: { authMode: "signer", signerId: signer.id } };
}

function typedDataSigningDisabled(): boolean {
  return true;
}

function solanaTransactionSigningDisabled(): boolean {
  return true;
}

async function withAgentSpendLock<T>(agentId: string, fn: () => Promise<T>): Promise<T> {
  if (process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true") {
    return fn();
  }
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${agentId}))`);
    return fn();
  });
}

async function nativeTransferGasAccountingGuard(
  c: Context<{ Variables: AppVariables }>,
  to: string,
  chainId: number,
  gasLimit: unknown,
): Promise<Response | null> {
  if (!isValidAddress(to)) return null;
  if (gasLimit !== undefined) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Native transfers cannot set gasLimit because gas spend is not policy-accounted",
      },
      403,
    );
  }

  let codeResponse: Awaited<ReturnType<typeof vault.rpcPassthrough>>;
  try {
    codeResponse = await vault.rpcPassthrough({
      method: "eth_getCode",
      params: [to, "latest"],
      chainId,
    });
  } catch {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Native transfers cannot be signed until recipient contract code is verified",
      },
      502,
    );
  }
  if (codeResponse.error) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Native transfers cannot be signed until recipient contract code is verified",
      },
      502,
    );
  }
  if (typeof codeResponse.result !== "string" || !/^0x[0-9a-fA-F]*$/.test(codeResponse.result)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Recipient contract code lookup returned an invalid response" },
      502,
    );
  }
  if (codeResponse.result !== "0x") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Native transfers to contract recipients are disabled because gas spend is not policy-accounted",
      },
      403,
    );
  }
  return null;
}

// ─── Sign transaction (EVM) ───────────────────────────────────────────────────

vaultRoutes.post("/:agentId/sign", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Unsafe message signing requires owner or admin session with recent MFA",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const request = await safeJsonParse<Omit<SignRequest, "agentId" | "tenantId">>(c);
  if (!request) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(request.to)) {
    return c.json<ApiResponse>({ ok: false, error: "'to' address is required" }, 400);
  }
  if (!isValidAnyAddress(request.to)) {
    const errMsg = request.to.startsWith("0x")
      ? "'to' must be a valid Ethereum address (0x + 40 hex chars)"
      : "'to' must be a valid Ethereum address (0x + 40 hex chars) or a valid Solana address (base58, 32–44 chars)";
    return c.json<ApiResponse>({ ok: false, error: errMsg }, 400);
  }
  if (request.value === undefined || request.value === null) {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required (wei amount as string)" },
      400,
    );
  }
  if (!isNonEmptyString(request.value) || !isUint256DecimalString(request.value)) {
    return c.json<ApiResponse>({ ok: false, error: "'value' must be a uint256 wei string" }, 400);
  }
  if (hasCalldata(request.data) && !ALLOW_UNSAFE_CONTRACT_CALL_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Contract calldata signing is disabled unless selector-specific policy extraction is configured",
      },
      403,
    );
  }

  const resolvedChainId = request.chainId || parseInt(process.env.CHAIN_ID || "8453", 10);
  if (!hasCalldata(request.data)) {
    const gasGuard = await nativeTransferGasAccountingGuard(
      c,
      request.to,
      resolvedChainId,
      request.gasLimit,
    );
    if (gasGuard) return gasGuard;
  }
  const signRequest: SignRequest = {
    ...request,
    tenantId,
    agentId,
    chainId: resolvedChainId,
  };
  const shouldBroadcast = signRequest.broadcast !== false;
  if (shouldBroadcast && !isNonEmptyString(c.req.header("Idempotency-Key"))) {
    return c.json<ApiResponse>(
      { ok: false, error: "Broadcast signing requires an Idempotency-Key header" },
      428,
    );
  }
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "sign_transaction",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;

  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);

  // ── Redis rate-limit check (before policy evaluation) ──────────────────────
  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  // Set rate limit headers on success too
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) {
      c.header(key, value);
    }
  }

  return withAgentSpendLock(agentId, async () => {
    const stats = await getTransactionStats(agentId);

    const evaluation = await policyEngine.evaluate(policySet, {
      request: signRequest,
      recentTxCount1h: stats.recentTxCount1h,
      recentTxCount24h: stats.recentTxCount24h,
      spentToday: stats.spentToday,
      spentThisWeek: stats.spentThisWeek,
      priceOracle,
      conditionSets,
    });

    if (!evaluation.approved) {
      const txId = crypto.randomUUID();

      if (evaluation.requiresManualApproval) {
        await db.transaction(async (tx) => {
          await tx.insert(transactions).values({
            id: txId,
            agentId,
            status: "pending",
            toAddress: signRequest.to,
            value: signRequest.value,
            data: signRequest.data,
            chainId: signRequest.chainId,
            policyResults: evaluation.results,
            actionPayload: transactionActionPayload({
              broadcast: signRequest.broadcast !== false,
            }),
          });
          await tx.insert(approvalQueue).values({
            id: crypto.randomUUID(),
            txId,
            agentId,
            status: "pending",
          });
        });

        await writeVaultAudit(c, {
          tenantId,
          actorType: "agent",
          actorId: agentId,
          action: "vault.sign.queued_for_approval",
          resourceType: "transaction",
          resourceId: txId,
          metadata: {
            chainId: signRequest.chainId,
            to: signRequest.to,
            value: signRequest.value,
            ...signerAuthAuditMetadata(signerAuthorization.auth),
            policyResults: evaluation.results,
          },
        });

        dispatchWebhook(tenantId, agentId, "approval_required", {
          txId,
          results: evaluation.results,
        });
        dispatchIntentWebhook(tenantId, agentId, "intent.created", {
          intentId: txId,
          status: "pending",
          policyResults: evaluation.results,
        });

        return c.json<ApiResponse>(
          {
            ok: false,
            error: "Transaction requires manual approval",
            data: {
              txId,
              results: evaluation.results,
              status: "pending_approval",
            },
          },
          202,
        );
      }

      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "rejected",
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.rejected_by_policy",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          to: signRequest.to,
          value: signRequest.value,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          policyResults: evaluation.results,
        },
      });

      dispatchWebhook(tenantId, agentId, "tx_rejected", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction rejected by policy",
          data: { txId, results: evaluation.results },
        },
        403,
      );
    }

    try {
      const txId = crypto.randomUUID();
      const txStatus: "broadcast" | "signed" = shouldBroadcast ? "broadcast" : "signed";
      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.authorized",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: resolvedChainId,
          to: signRequest.to,
          value: signRequest.value,
          broadcast: shouldBroadcast,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          policyResults: evaluation.results,
        },
      });
      const result = await vault.signTransaction(signRequest, {
        txId,
        policyResults: evaluation.results,
        status: txStatus,
      });

      await db
        .update(transactions)
        .set({
          status: txStatus,
          txHash: shouldBroadcast ? result : undefined,
          policyResults: evaluation.results,
          signedAt: new Date(),
        })
        .where(eq(transactions.id, txId));

      // ── Record spend in Redis (fire-and-forget) ──────────────────────────────
      recordVaultSpend(agentId, tenantId, signRequest.value, resolvedChainId).catch((err) =>
        console.error("[vault] Failed to record spend:", err),
      );

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: resolvedChainId,
          to: signRequest.to,
          value: signRequest.value,
          broadcast: shouldBroadcast,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          txHash: shouldBroadcast ? result : undefined,
        },
      });

      dispatchWebhook(tenantId, agentId, "tx_signed", {
        txId,
        txHash: shouldBroadcast ? result : undefined,
      });
      if (shouldBroadcast) {
        dispatchTransactionLifecycleWebhook(tenantId, agentId, "transaction.broadcasted", {
          txId,
          txHash: result,
          chainId: resolvedChainId,
          status: "broadcast",
        });
      }

      if (shouldBroadcast) {
        return c.json<ApiResponse<{ txId: string; txHash: string }>>({
          ok: true,
          data: { txId, txHash: result },
        });
      }

      return c.json<ApiResponse<{ txId: string; signedTx: string }>>({
        ok: true,
        data: { txId, signedTx: result },
      });
    } catch (e: unknown) {
      const requestId = c.get("requestId") || "unknown";
      const rawMessage = e instanceof Error ? e.message : "Unknown error";
      console.error(`[${requestId}] Sign transaction failed for agent ${agentId}:`, e);

      dispatchWebhook(tenantId, agentId, "tx_failed", {
        error: rawMessage,
        requestId,
      });

      if (isRpcError(e)) {
        return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
      }
      return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
    }
  });
});

// ─── Privy-style transfer actions ────────────────────────────────────────────

vaultRoutes.post("/:agentId/actions/transfer/quote", async (c) => {
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transfer actions require owner or admin session with recent MFA" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<TransferActionInput>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const transfer = parseTransferActionInput(body);
  if (!transfer) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "'to' must be an EVM address, optional 'token' must be 'native' or an EVM token address, and 'value'/'amountWei' must be a uint256 wei string",
      },
      400,
    );
  }

  const quoteId = crypto.randomUUID();
  return c.json<
    ApiResponse<{
      quoteId: string;
      type: "transfer";
      chainId: number;
      from: string;
      to: string;
      value: string;
      token: "native" | string;
      expiresAt: string;
      request: {
        to: string;
        token: "native" | string;
        value: string;
        chainId: number;
        broadcast: boolean;
        referenceId?: string;
        sponsor?: boolean;
      };
    }>
  >({
    ok: true,
    data: {
      quoteId,
      type: "transfer",
      chainId: transfer.chainId,
      from: agent.walletAddress,
      to: transfer.to,
      value: transfer.value,
      token: transfer.token,
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
      request: transfer,
    },
  });
});

vaultRoutes.post("/:agentId/actions/send-calls", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "wallet_action_send_calls",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;

  const body = await safeJsonParse<SendCallsActionInput>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const parsed = parseSendCallsActionInput(body);
  if (typeof parsed === "string") {
    return c.json<ApiResponse>({ ok: false, error: parsed }, 400);
  }
  const sponsorship = await resolveGasSponsorshipRequest({
    tenantId,
    agentId,
    chainId: parsed.chainId,
    caip2: toCaip2(parsed.chainId),
    sponsor: parsed.sponsor,
  });
  if (sponsorship.requested && !sponsorship.sponsored) {
    const status: 403 | 501 | 503 =
      sponsorship.status === 501 ? 501 : sponsorship.status === 503 ? 503 : 403;
    return c.json<ApiResponse>({ ok: false, error: sponsorship.error }, status);
  }
  const sponsorshipPayload =
    sponsorship.requested && sponsorship.sponsored
      ? {
          requested: true,
          sponsored: true,
          provider: sponsorship.provider,
          mode: sponsorship.mode,
          estimatedUsd: sponsorship.estimatedUsd,
        }
      : parsed.sponsor
        ? { requested: true, sponsored: false }
        : undefined;
  if (parsed.calls.some((call) => hasCalldata(call.data)) && !ALLOW_UNSAFE_CONTRACT_CALL_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Batch call calldata signing is disabled unless selector-specific policy extraction is configured",
      },
      403,
    );
  }
  const idempotencyResponse = requireBroadcastActionIdempotency(
    c,
    parsed.broadcast,
    "Broadcast send-calls actions",
  );
  if (idempotencyResponse) return idempotencyResponse;
  const existingAction = await findActionByReferenceId(agentId, "send_calls", parsed.referenceId);
  if (existingAction) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "referenceId has already been used for this action type",
        data: { actionId: existingAction.id, status: existingAction.status },
      },
      409,
    );
  }

  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);
  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) {
      c.header(key, value);
    }
  }

  return withAgentSpendLock(agentId, async () => {
    const lockedExistingAction = await findActionByReferenceId(
      agentId,
      "send_calls",
      parsed.referenceId,
    );
    if (lockedExistingAction) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "referenceId has already been used for this action type",
          data: { actionId: lockedExistingAction.id, status: lockedExistingAction.status },
        },
        409,
      );
    }

    const stats = await getTransactionStats(agentId);
    let runningSpentToday = stats.spentToday;
    let runningSpentThisWeek = stats.spentThisWeek;
    const evaluations = [];
    for (const call of parsed.calls) {
      const request: SignRequest = {
        tenantId,
        agentId,
        to: call.to,
        value: call.value,
        data: call.data,
        chainId: parsed.chainId,
        broadcast: parsed.broadcast,
      };
      evaluations.push(
        await policyEngine.evaluate(policySet, {
          request,
          recentTxCount1h: stats.recentTxCount1h,
          recentTxCount24h: stats.recentTxCount24h,
          spentToday: runningSpentToday,
          spentThisWeek: runningSpentThisWeek,
          priceOracle,
          conditionSets,
        }),
      );
      const callValue = BigInt(call.value);
      runningSpentToday += callValue;
      runningSpentThisWeek += callValue;
    }

    const requiresManualApproval = evaluations.some(
      (evaluation) => evaluation.requiresManualApproval,
    );
    const approved = evaluations.every((evaluation) => evaluation.approved);
    const policyResults = evaluations.flatMap((evaluation, index) =>
      evaluation.results.map((result) => ({ ...result, callIndex: index })),
    );
    const actionId = crypto.randomUUID();
    const payload = sendCallsActionPayload({
      calls: parsed.calls,
      broadcast: parsed.broadcast,
      totalValue: parsed.totalValue,
      referenceId: parsed.referenceId,
      sponsorship: sponsorshipPayload,
    });

    if (!approved) {
      const status = requiresManualApproval ? "pending" : "rejected";
      await db.insert(transactions).values({
        id: actionId,
        agentId,
        status,
        toAddress: parsed.calls[0].to,
        value: parsed.totalValue,
        data: JSON.stringify(parsed.calls),
        chainId: parsed.chainId,
        actionType: "send_calls",
        actionPayload: payload,
        policyResults,
      });
      if (requiresManualApproval) {
        await db.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId: actionId,
          agentId,
          status: "pending",
        });
      }
      await recordSponsoredActionIfNeeded({
        sponsorship: sponsorshipPayload,
        tenantId,
        agentId,
        txId: actionId,
        chainId: parsed.chainId,
        caip2: toCaip2(parsed.chainId),
        actionType: "send_calls",
        status: requiresManualApproval ? "pending" : "rejected",
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: requiresManualApproval
          ? "wallet_action.send_calls.queued_for_approval"
          : "wallet_action.send_calls.rejected",
        resourceType: "wallet_action",
        resourceId: actionId,
        metadata: {
          chainId: parsed.chainId,
          callCount: parsed.calls.length,
          totalValue: parsed.totalValue,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          policyResults,
        },
      });
      dispatchWebhook(
        tenantId,
        agentId,
        requiresManualApproval
          ? "wallet_action.send_calls.created"
          : "wallet_action.send_calls.rejected",
        { actionId, results: policyResults },
      );
      if (requiresManualApproval) {
        dispatchIntentWebhook(tenantId, agentId, "intent.created", {
          intentId: actionId,
          actionType: "send_calls",
          status: "pending",
          referenceId: parsed.referenceId,
          policyResults,
        });
      }

      return c.json<ApiResponse>(
        {
          ok: requiresManualApproval,
          error: requiresManualApproval ? undefined : "Batch calls rejected by policy",
          data: {
            id: actionId,
            type: "send_calls",
            status: requiresManualApproval ? "pending_approval" : "rejected",
            chainId: parsed.chainId,
            calls: parsed.calls,
            totalValue: parsed.totalValue,
            sponsorship: sponsorshipPayload,
            policyResults,
          },
        },
        requiresManualApproval ? 202 : 403,
      );
    }

    await db.insert(transactions).values({
      id: actionId,
      agentId,
      status: "pending",
      toAddress: parsed.calls[0].to,
      value: parsed.totalValue,
      data: JSON.stringify(parsed.calls),
      chainId: parsed.chainId,
      actionType: "send_calls",
      actionPayload: payload,
      policyResults,
    });
    await db.insert(approvalQueue).values({
      id: crypto.randomUUID(),
      txId: actionId,
      agentId,
      status: "pending",
    });
    await recordSponsoredActionIfNeeded({
      sponsorship: sponsorshipPayload,
      tenantId,
      agentId,
      txId: actionId,
      chainId: parsed.chainId,
      caip2: toCaip2(parsed.chainId),
      actionType: "send_calls",
      status: "pending",
    });
    await writeVaultAudit(c, {
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "wallet_action.send_calls.queued_for_approval",
      resourceType: "wallet_action",
      resourceId: actionId,
      metadata: {
        chainId: parsed.chainId,
        callCount: parsed.calls.length,
        totalValue: parsed.totalValue,
        ...signerAuthAuditMetadata(signerAuthorization.auth),
        policyResults,
      },
    });
    dispatchWebhook(tenantId, agentId, "wallet_action.send_calls.created", {
      actionId,
      results: policyResults,
    });
    dispatchIntentWebhook(tenantId, agentId, "intent.created", {
      intentId: actionId,
      actionType: "send_calls",
      status: "pending",
      referenceId: parsed.referenceId,
      policyResults,
    });

    return c.json<ApiResponse>(
      {
        ok: true,
        data: {
          id: actionId,
          type: "send_calls",
          status: "pending_approval",
          chainId: parsed.chainId,
          calls: parsed.calls,
          totalValue: parsed.totalValue,
          sponsorship: sponsorshipPayload,
          policyResults,
        },
      },
      202,
    );
  });
});

vaultRoutes.post("/:agentId/actions/transfer", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "wallet_action_transfer",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;

  const body = await safeJsonParse<TransferActionInput>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const transfer = parseTransferActionInput(body);
  if (!transfer) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "'to' must be an EVM address, optional 'token' must be 'native' or an EVM token address, and 'value'/'amountWei' must be a uint256 wei string",
      },
      400,
    );
  }
  if (transfer.sponsor === true && transfer.broadcast === false) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Gas sponsorship requires broadcast=true because signed-only actions do not spend sponsored gas",
      },
      400,
    );
  }
  const sponsorship = await resolveGasSponsorshipRequest({
    tenantId,
    agentId,
    chainId: transfer.chainId,
    caip2: toCaip2(transfer.chainId),
    sponsor: transfer.sponsor,
  });
  if (sponsorship.requested && !sponsorship.sponsored) {
    const status: 403 | 501 | 503 =
      sponsorship.status === 501 ? 501 : sponsorship.status === 503 ? 503 : 403;
    return c.json<ApiResponse>({ ok: false, error: sponsorship.error }, status);
  }
  const sponsorshipPayload =
    sponsorship.requested && sponsorship.sponsored
      ? {
          requested: true,
          sponsored: true,
          provider: sponsorship.provider,
          mode: sponsorship.mode,
          estimatedUsd: sponsorship.estimatedUsd,
        }
      : transfer.sponsor
        ? { requested: true, sponsored: false }
        : undefined;
  const idempotencyResponse = requireBroadcastActionIdempotency(
    c,
    transfer.broadcast,
    "Broadcast transfer actions",
  );
  if (idempotencyResponse) return idempotencyResponse;
  const existingAction = await findActionByReferenceId(agentId, "transfer", transfer.referenceId);
  if (existingAction) {
    return c.json<ApiResponse>({
      ok: existingAction.status !== "rejected" && existingAction.status !== "failed",
      error:
        existingAction.status === "rejected"
          ? "Transfer rejected by policy"
          : existingAction.status === "failed"
            ? "Transfer failed"
            : undefined,
      data: transferActionResponseFromTransaction(existingAction),
    });
  }

  const isTokenTransfer = transfer.token !== "native";
  if (isTokenTransfer) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "ERC20 transfer actions require token-aware spend accounting before signing",
      },
      403,
    );
  }
  const gasGuard = await nativeTransferGasAccountingGuard(
    c,
    transfer.to,
    transfer.chainId,
    undefined,
  );
  if (gasGuard) return gasGuard;
  const signRequest: SignRequest = {
    tenantId,
    agentId,
    to: isTokenTransfer ? transfer.token : transfer.to,
    value: isTokenTransfer ? "0" : transfer.value,
    data: isTokenTransfer ? encodeErc20TransferCalldata(transfer.to, transfer.value) : undefined,
    chainId: transfer.chainId,
    gasLimit: isTokenTransfer ? "65000" : undefined,
    broadcast: transfer.broadcast,
  };
  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);

  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) {
      c.header(key, value);
    }
  }

  return withAgentSpendLock(agentId, async () => {
    const lockedExistingAction = await findActionByReferenceId(
      agentId,
      "transfer",
      transfer.referenceId,
    );
    if (lockedExistingAction) {
      return c.json<ApiResponse>({
        ok: lockedExistingAction.status !== "rejected" && lockedExistingAction.status !== "failed",
        error:
          lockedExistingAction.status === "rejected"
            ? "Transfer rejected by policy"
            : lockedExistingAction.status === "failed"
              ? "Transfer failed"
              : undefined,
        data: transferActionResponseFromTransaction(lockedExistingAction),
      });
    }

    const stats = await getTransactionStats(agentId);
    const erc20PrecheckFailure = isTokenTransfer
      ? erc20TransferPolicyPrecheck(policySet, transfer.token)
      : null;
    const evaluation = erc20PrecheckFailure
      ? {
          approved: false,
          requiresManualApproval: false,
          results: [erc20PrecheckFailure],
        }
      : await policyEngine.evaluate(policySet, {
          request: signRequest,
          recentTxCount1h: stats.recentTxCount1h,
          recentTxCount24h: stats.recentTxCount24h,
          spentToday: stats.spentToday,
          spentThisWeek: stats.spentThisWeek,
          priceOracle,
          conditionSets,
        });

    const actionId = crypto.randomUUID();
    if (!evaluation.approved) {
      const status = evaluation.requiresManualApproval ? "pending" : "rejected";
      await db.insert(transactions).values({
        id: actionId,
        agentId,
        status,
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        actionType: "transfer",
        actionPayload: transferActionPayload({
          token: transfer.token,
          recipient: transfer.to,
          amount: transfer.value,
          broadcast: signRequest.broadcast !== false,
          referenceId: transfer.referenceId,
          sponsorship: sponsorshipPayload,
        }),
        policyResults: evaluation.results,
      });
      if (evaluation.requiresManualApproval) {
        await db.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId: actionId,
          agentId,
          status: "pending",
        });
      }
      if (evaluation.requiresManualApproval) {
        const reservationError = await recordSponsoredActionIfNeeded({
          sponsorship: sponsorshipPayload,
          tenantId,
          agentId,
          txId: actionId,
          chainId: signRequest.chainId,
          caip2: toCaip2(signRequest.chainId),
          actionType: "transfer",
          status: "reserved",
        });
        if (typeof reservationError === "string") {
          await db.delete(transactions).where(eq(transactions.id, actionId));
          return c.json<ApiResponse>({ ok: false, error: reservationError }, 403);
        }
      }

      try {
        await writeVaultAudit(c, {
          tenantId,
          actorType: "agent",
          actorId: agentId,
          action: evaluation.requiresManualApproval
            ? "wallet_action.transfer.queued_for_approval"
            : "wallet_action.transfer.rejected",
          resourceType: "wallet_action",
          resourceId: actionId,
          metadata: {
            chainId: signRequest.chainId,
            to: transfer.to,
            value: transfer.value,
            token: transfer.token,
            ...signerAuthAuditMetadata(signerAuthorization.auth),
            policyResults: evaluation.results,
          },
        });
      } catch (error) {
        if (evaluation.requiresManualApproval) {
          await recordSponsoredActionIfNeeded({
            sponsorship: sponsorshipPayload,
            tenantId,
            agentId,
            txId: actionId,
            chainId: signRequest.chainId,
            caip2: toCaip2(signRequest.chainId),
            actionType: "transfer",
            status: "failed",
          });
        }
        await db.delete(transactions).where(eq(transactions.id, actionId));
        throw error;
      }
      dispatchWebhook(
        tenantId,
        agentId,
        evaluation.requiresManualApproval
          ? "wallet_action.transfer.created"
          : "wallet_action.transfer.rejected",
        { actionId, results: evaluation.results },
      );
      if (evaluation.requiresManualApproval) {
        dispatchIntentWebhook(tenantId, agentId, "intent.created", {
          intentId: actionId,
          actionType: "transfer",
          status: "pending",
          referenceId: transfer.referenceId,
          policyResults: evaluation.results,
        });
      }

      const response = transferActionResponse({
        actionId,
        status: evaluation.requiresManualApproval ? "pending_approval" : "rejected",
        chainId: signRequest.chainId,
        to: transfer.to,
        value: transfer.value,
        token: transfer.token,
        policyResults: evaluation.results,
        sponsorship: sponsorshipPayload,
      });
      return c.json<ApiResponse>(
        {
          ok: evaluation.requiresManualApproval,
          error: evaluation.requiresManualApproval ? undefined : "Transfer rejected by policy",
          data: response,
        },
        evaluation.requiresManualApproval ? 202 : 403,
      );
    }

    let completedResult: string | null = null;
    let completedStatus: "broadcast" | "signed" | null = null;
    try {
      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "wallet_action.transfer.authorized",
        resourceType: "wallet_action",
        resourceId: actionId,
        metadata: {
          chainId: signRequest.chainId,
          to: transfer.to,
          value: transfer.value,
          token: transfer.token,
          broadcast: transfer.broadcast,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          policyResults: evaluation.results,
        },
      });
      const reservationError = await recordSponsoredActionIfNeeded({
        sponsorship: sponsorshipPayload,
        tenantId,
        agentId,
        txId: actionId,
        chainId: signRequest.chainId,
        caip2: toCaip2(signRequest.chainId),
        actionType: "transfer",
        status: "reserved",
      });
      if (typeof reservationError === "string") {
        return c.json<ApiResponse>({ ok: false, error: reservationError }, 403);
      }
      const result = await vault.signTransaction(signRequest, {
        txId: actionId,
        policyResults: evaluation.results,
        status: "signed",
      });
      const txStatus = transfer.broadcast ? "broadcast" : "signed";
      completedResult = result;
      completedStatus = txStatus;
      const signedTx = transfer.broadcast ? undefined : result;
      await db
        .update(transactions)
        .set({
          status: txStatus,
          txHash: transfer.broadcast ? result : undefined,
          actionType: "transfer",
          actionPayload: transferActionPayload({
            token: transfer.token,
            recipient: transfer.to,
            amount: transfer.value,
            broadcast: transfer.broadcast,
            referenceId: transfer.referenceId,
            sponsorship: sponsorshipPayload,
          }),
          policyResults: evaluation.results,
          signedAt: new Date(),
        })
        .where(eq(transactions.id, actionId));

      if (transfer.broadcast) {
        recordVaultSpend(agentId, tenantId, signRequest.value, signRequest.chainId).catch((err) =>
          console.error("[vault] Failed to record transfer action spend:", err),
        );
      }
      await recordSponsoredActionIfNeeded({
        sponsorship: sponsorshipPayload,
        tenantId,
        agentId,
        txId: actionId,
        chainId: signRequest.chainId,
        caip2: toCaip2(signRequest.chainId),
        txHash: transfer.broadcast ? result : undefined,
        actionType: "transfer",
        status: transfer.broadcast ? "submitted" : "signed",
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "wallet_action.transfer.succeeded",
        resourceType: "wallet_action",
        resourceId: actionId,
        metadata: {
          chainId: signRequest.chainId,
          to: transfer.to,
          value: transfer.value,
          token: transfer.token,
          broadcast: transfer.broadcast,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          txHash: transfer.broadcast ? result : undefined,
        },
      });
      dispatchWebhook(tenantId, agentId, "wallet_action.transfer.succeeded", {
        actionId,
        txHash: transfer.broadcast ? result : undefined,
      });
      if (transfer.broadcast) {
        dispatchTransactionLifecycleWebhook(tenantId, agentId, "transaction.broadcasted", {
          txId: actionId,
          txHash: result,
          chainId: signRequest.chainId,
          status: "broadcast",
        });
      }

      return c.json<ApiResponse>({
        ok: true,
        data: transferActionResponse({
          actionId,
          status: txStatus,
          chainId: signRequest.chainId,
          to: transfer.to,
          value: transfer.value,
          token: transfer.token,
          txHash: transfer.broadcast ? result : undefined,
          signedTx,
          sponsorship: sponsorshipPayload,
          policyResults: evaluation.results,
        }),
      });
    } catch (e: unknown) {
      if (completedResult && completedStatus) {
        await db
          .update(transactions)
          .set({
            status: completedStatus,
            txHash: transfer.broadcast ? completedResult : undefined,
            actionType: "transfer",
            actionPayload: transferActionPayload({
              token: transfer.token,
              recipient: transfer.to,
              amount: transfer.value,
              broadcast: transfer.broadcast,
              referenceId: transfer.referenceId,
              sponsorship: sponsorshipPayload,
            }),
            policyResults: evaluation.results,
            signedAt: new Date(),
          })
          .where(eq(transactions.id, actionId))
          .catch(() => null);

        return c.json<ApiResponse>({
          ok: true,
          data: transferActionResponse({
            actionId,
            status: completedStatus,
            chainId: signRequest.chainId,
            to: transfer.to,
            value: transfer.value,
            token: transfer.token,
            txHash: transfer.broadcast ? completedResult : undefined,
            signedTx: transfer.broadcast ? undefined : completedResult,
            sponsorship: sponsorshipPayload,
            policyResults: evaluation.results,
          }),
        });
      }
      await db.insert(transactions).values({
        id: actionId,
        agentId,
        status: "failed",
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        actionType: "transfer",
        actionPayload: transferActionPayload({
          token: transfer.token,
          recipient: transfer.to,
          amount: transfer.value,
          broadcast: signRequest.broadcast !== false,
          referenceId: transfer.referenceId,
          sponsorship: sponsorshipPayload,
        }),
        policyResults: evaluation.results,
      });
      await recordSponsoredActionIfNeeded({
        sponsorship: sponsorshipPayload,
        tenantId,
        agentId,
        txId: actionId,
        chainId: signRequest.chainId,
        caip2: toCaip2(signRequest.chainId),
        actionType: "transfer",
        status: "failed",
      });
      const error = isRpcError(e) ? extractRpcErrorMessage(e) : sanitizeErrorMessage(e);
      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "wallet_action.transfer.failed",
        resourceType: "wallet_action",
        resourceId: actionId,
        metadata: { error },
      });
      dispatchWebhook(tenantId, agentId, "wallet_action.transfer.failed", { actionId, error });
      return c.json<ApiResponse>(
        { ok: false, error, data: { actionId } },
        isRpcError(e) ? 502 : 500,
      );
    }
  });
});

vaultRoutes.get("/:agentId/actions/:actionId", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction lifecycle updates require owner or admin session with recent MFA",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const actionId = c.req.param("actionId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Wallet action not found" }, 404);

  const [row] = await db
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.id, actionId),
        eq(transactions.agentId, agentId),
        eq(transactions.actionType, "transfer"),
      ),
    );
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Wallet action not found" }, 404);
  const actionPayload = getTransferActionPayload(row.actionPayload);
  if (!actionPayload) {
    return c.json<ApiResponse>({ ok: false, error: "Wallet action not found" }, 404);
  }

  const status =
    row.status === "pending"
      ? "pending_approval"
      : row.status === "rejected"
        ? "rejected"
        : row.status === "broadcast"
          ? "broadcast"
          : row.status === "failed"
            ? "failed"
            : "signed";
  return c.json<ApiResponse>({
    ok: true,
    data: {
      id: row.id,
      type: "transfer",
      status,
      chainId: row.chainId,
      to: actionPayload.recipient ?? row.toAddress,
      value: actionPayload.amount ?? row.value,
      token: actionPayload.token,
      txHash: row.txHash ?? undefined,
      policyResults: row.policyResults,
      createdAt: row.createdAt.toISOString(),
      signedAt: row.signedAt?.toISOString(),
      confirmedAt: row.confirmedAt?.toISOString(),
    },
  });
});

// ─── Approve transaction ──────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/approve/:txId", async (c) => {
  if (!hasTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction approval requires owner or admin session",
      },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction approval requires recent MFA verification" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const actorId = c.get("userId") ?? tenantId;
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [transaction] = await db
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.id, txId),
        eq(transactions.agentId, agentId),
        eq(transactions.status, "pending"),
      ),
    );
  if (!transaction) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const isSolana = transaction.chainId === 101 || transaction.chainId === 102;
  const transferPayload =
    transaction.actionType === "transfer"
      ? getTransferActionPayload(transaction.actionPayload)
      : null;
  const sendCallsPayload =
    transaction.actionType === "send_calls"
      ? getSendCallsActionPayload(transaction.actionPayload)
      : null;
  const transactionPayload =
    !transaction.actionType || transaction.actionType === "transaction"
      ? getTransactionActionPayload(transaction.actionPayload)
      : null;
  const isSendCallsAction = sendCallsPayload !== null;
  if (
    transaction.actionType === "send_calls" ||
    transaction.actionType === "user_operation" ||
    transaction.actionType === "authorization"
  ) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          transaction.actionType === "send_calls"
            ? "Approval execution for batch call actions is disabled until typed batch replay is implemented"
            : "Approval execution for unsafe account-abstraction actions is disabled until typed replay is implemented",
      },
      403,
    );
  }
  await writeVaultAudit(c, {
    tenantId,
    actorType: "user",
    actorId,
    action: transferPayload
      ? "wallet_action.transfer.approve.authorized"
      : isSendCallsAction
        ? "wallet_action.send_calls.approve.authorized"
        : "vault.approve.authorized",
    resourceType: transferPayload || isSendCallsAction ? "wallet_action" : "transaction",
    resourceId: txId,
    metadata: {
      agentId,
      chainId: transaction.chainId,
      to: transaction.toAddress,
      value: transaction.value,
      broadcast:
        transferPayload?.broadcast ?? sendCallsPayload?.broadcast ?? transactionPayload?.broadcast,
    },
  });

  return withAgentSpendLock(agentId, async () => {
    const resolvedAt = new Date();
    let irreversibleResult = false;
    try {
      const requestedBroadcast = transferPayload
        ? transferPayload.broadcast
        : sendCallsPayload
          ? sendCallsPayload.broadcast
          : transactionPayload
            ? transactionPayload.broadcast
            : true;
      const shouldBroadcast = requestedBroadcast !== false;
      const approvalSignRequest: SignRequest = {
        ...toSignRequest(transaction),
        tenantId,
        gasLimit:
          transferPayload && transferPayload.token !== "native" && transaction.data
            ? "65000"
            : undefined,
        broadcast: requestedBroadcast,
      };
      const currentPolicySet = await getPolicySet(tenantId, agentId);
      const currentRateLimitResult = await enforceRateLimit(agentId, currentPolicySet);
      if (!currentRateLimitResult.allowed) {
        if (currentRateLimitResult.headers) {
          for (const [key, value] of Object.entries(currentRateLimitResult.headers)) {
            c.header(key, value);
          }
        }
        return c.json<ApiResponse>(
          { ok: false, error: currentRateLimitResult.reason || "Rate limit exceeded" },
          429,
        );
      }
      if (currentRateLimitResult.headers) {
        for (const [key, value] of Object.entries(currentRateLimitResult.headers)) {
          c.header(key, value);
        }
      }
      const currentConditionSets = await loadConditionSetsForPolicies(tenantId, currentPolicySet);
      const stats = await getTransactionStats(agentId);
      const currentEvaluation = await policyEngine.evaluate(currentPolicySet, {
        request: approvalSignRequest,
        recentTxCount1h: stats.recentTxCount1h,
        recentTxCount24h: stats.recentTxCount24h,
        spentToday: stats.spentToday,
        spentThisWeek: stats.spentThisWeek,
        priceOracle,
        conditionSets: currentConditionSets,
      });

      if (!currentEvaluation.approved && !currentEvaluation.requiresManualApproval) {
        await db
          .update(transactions)
          .set({ status: "rejected", policyResults: currentEvaluation.results })
          .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
        await db
          .update(approvalQueue)
          .set({ status: "rejected", resolvedAt, resolvedBy: actorId })
          .where(
            and(
              eq(approvalQueue.txId, txId),
              eq(approvalQueue.agentId, agentId),
              eq(approvalQueue.status, "pending"),
            ),
          );
        await writeVaultAudit(c, {
          tenantId,
          actorType: "user",
          actorId,
          action: "vault.approve.rejected_by_current_policy",
          resourceType: transferPayload || isSendCallsAction ? "wallet_action" : "transaction",
          resourceId: txId,
          metadata: {
            agentId,
            chainId: transaction.chainId,
            to: transaction.toAddress,
            value: transaction.value,
            policyResults: currentEvaluation.results,
          },
        });
        return c.json<ApiResponse>(
          {
            ok: false,
            error: "Pending transaction no longer satisfies current policy",
            data: { txId, results: currentEvaluation.results },
          },
          403,
        );
      }

      const claimResult = await db
        .update(approvalQueue)
        .set({ status: "approved", resolvedAt, resolvedBy: actorId })
        .where(
          and(
            eq(approvalQueue.txId, txId),
            eq(approvalQueue.agentId, agentId),
            eq(approvalQueue.status, "pending"),
          ),
        )
        .returning();

      if (claimResult.length === 0) {
        return c.json<ApiResponse>(
          { ok: false, error: "Transaction already processed or not found" },
          409,
        );
      }
      if (transferPayload?.sponsorship?.sponsored === true && !shouldBroadcast) {
        await db
          .update(approvalQueue)
          .set({ status: "pending", resolvedAt: null, resolvedBy: null })
          .where(and(eq(approvalQueue.txId, txId), eq(approvalQueue.agentId, agentId)));
        return c.json<ApiResponse>(
          {
            ok: false,
            error:
              "Gas sponsorship requires broadcast=true because signed-only actions do not spend sponsored gas",
          },
          400,
        );
      }
      if (transferPayload) {
        const reservationError = await recordSponsoredActionIfNeeded({
          sponsorship: transferPayload.sponsorship,
          tenantId,
          agentId,
          txId,
          chainId: transaction.chainId,
          caip2: toCaip2(transaction.chainId),
          actionType: "transfer",
          status: "reserved",
        });
        if (typeof reservationError === "string") {
          await db
            .update(approvalQueue)
            .set({ status: "pending", resolvedAt: null, resolvedBy: null })
            .where(and(eq(approvalQueue.txId, txId), eq(approvalQueue.agentId, agentId)));
          return c.json<ApiResponse>({ ok: false, error: reservationError }, 403);
        }
      }
      dispatchIntentWebhook(tenantId, agentId, "intent.authorized", {
        intentId: txId,
        actionType: transaction.actionType,
        status: "authorized",
        referenceId: actionReferenceId(transaction.actionPayload),
        policyResults: transaction.policyResults,
      });

      let txHash: string;

      if (isSolana) {
        if (!transaction.data) {
          throw new Error("Solana transaction blob not found; cannot replay approval");
        }
        const result = await vault.signSolanaTransaction({
          agentId,
          tenantId,
          transaction: transaction.data,
          chainId: transaction.chainId,
          broadcast: shouldBroadcast,
          expectedTo: transaction.toAddress,
          expectedValue: transaction.value,
        });
        txHash = result.signature;
        irreversibleResult = shouldBroadcast;
      } else {
        txHash = await vault.signTransaction(approvalSignRequest, {
          txId,
          policyResults: currentEvaluation.results,
          status: shouldBroadcast ? "broadcast" : "signed",
        });
        irreversibleResult = shouldBroadcast;
      }

      const nextStatus = transferPayload
        ? transferPayload.broadcast === false
          ? "signed"
          : "broadcast"
        : sendCallsPayload
          ? sendCallsPayload.broadcast === false
            ? "signed"
            : "broadcast"
          : transactionPayload?.broadcast === false
            ? "signed"
            : "broadcast";
      await db
        .update(transactions)
        .set({
          status: nextStatus,
          txHash: shouldBroadcast ? txHash : null,
          policyResults: currentEvaluation.results,
          actionPayload: transferPayload
            ? transferActionPayload({
                token: transferPayload.token,
                recipient: transferPayload.recipient ?? transaction.toAddress,
                amount: transferPayload.amount ?? transaction.value,
                broadcast: transferPayload.broadcast,
                referenceId: transferPayload.referenceId,
                sponsorship: transferPayload.sponsorship,
              })
            : transactionPayload
              ? transactionActionPayload({
                  broadcast: transactionPayload.broadcast,
                  referenceId: transactionPayload.referenceId,
                })
              : transaction.actionPayload,
          signedAt: resolvedAt,
        })
        .where(eq(transactions.id, txId));

      if (!isSolana && shouldBroadcast) {
        recordVaultSpend(agentId, tenantId, transaction.value, transaction.chainId).catch((err) =>
          console.error("[vault] Failed to record approved transaction spend:", err),
        );
      }
      if (transferPayload) {
        await recordSponsoredActionIfNeeded({
          sponsorship: transferPayload.sponsorship,
          tenantId,
          agentId,
          txId,
          chainId: transaction.chainId,
          caip2: toCaip2(transaction.chainId),
          txHash: shouldBroadcast ? txHash : undefined,
          actionType: "transfer",
          status: shouldBroadcast ? "submitted" : "signed",
        });
      }

      await writeVaultAudit(c, {
        tenantId,
        actorType: "user",
        actorId,
        action: transferPayload
          ? "wallet_action.transfer.succeeded"
          : isSendCallsAction
            ? "wallet_action.send_calls.succeeded"
            : "vault.approve",
        resourceType: transferPayload || isSendCallsAction ? "wallet_action" : "transaction",
        resourceId: txId,
        metadata: {
          agentId,
          chainId: transaction.chainId,
          txHash: shouldBroadcast ? txHash : undefined,
          broadcast:
            transferPayload?.broadcast ??
            sendCallsPayload?.broadcast ??
            transactionPayload?.broadcast,
        },
      });

      if (transferPayload) {
        dispatchWebhook(tenantId, agentId, "wallet_action.transfer.succeeded", {
          actionId: txId,
          txHash: transferPayload.broadcast ? txHash : undefined,
        });
      } else if (isSendCallsAction) {
        dispatchWebhook(tenantId, agentId, "wallet_action.send_calls.succeeded", {
          actionId: txId,
          txHash: sendCallsPayload.broadcast ? txHash : undefined,
        });
      } else {
        dispatchWebhook(tenantId, agentId, "tx_signed", {
          txId,
          txHash: shouldBroadcast ? txHash : undefined,
          signedTx: shouldBroadcast ? undefined : txHash,
        });
      }
      dispatchIntentWebhook(tenantId, agentId, "intent.executed", {
        intentId: txId,
        actionType: transaction.actionType,
        status: "executed",
        txHash: shouldBroadcast ? txHash : undefined,
        signedTx: shouldBroadcast ? undefined : txHash,
        referenceId: actionReferenceId(transaction.actionPayload),
        policyResults: transaction.policyResults,
      });
      if (shouldBroadcast) {
        dispatchTransactionLifecycleWebhook(tenantId, agentId, "transaction.broadcasted", {
          txId,
          txHash,
          chainId: transaction.chainId,
          status: "broadcast",
        });
      }

      return c.json<ApiResponse<{ txId: string; txHash?: string; signedTx?: string }>>({
        ok: true,
        data: !shouldBroadcast ? { txId, signedTx: txHash } : { txId, txHash },
      });
    } catch (e: unknown) {
      if (!irreversibleResult) {
        await db
          .update(approvalQueue)
          .set({ status: "pending", resolvedAt: null, resolvedBy: null })
          .where(and(eq(approvalQueue.txId, txId), eq(approvalQueue.agentId, agentId)));
        if (transferPayload) {
          await recordSponsoredActionIfNeeded({
            sponsorship: transferPayload.sponsorship,
            tenantId,
            agentId,
            txId,
            chainId: transaction.chainId,
            caip2: toCaip2(transaction.chainId),
            actionType: "transfer",
            status: "failed",
          });
        }
      } else {
        await db
          .update(transactions)
          .set({ status: "broadcast", signedAt: resolvedAt })
          .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
      }

      const requestId = c.get("requestId") || "unknown";
      const rawMessage = e instanceof Error ? e.message : "Unknown error";
      console.error(
        `[${requestId}] Approve transaction failed for agent ${agentId}, tx ${txId}:`,
        e,
      );

      if (transaction.actionType === "send_calls") {
        dispatchWebhook(tenantId, agentId, "wallet_action.send_calls.failed", {
          actionId: txId,
          error: rawMessage,
          requestId,
        });
      } else {
        dispatchWebhook(tenantId, agentId, "tx_failed", {
          txId,
          error: rawMessage,
          requestId,
        });
      }
      dispatchIntentWebhook(tenantId, agentId, "intent.failed", {
        intentId: txId,
        actionType: transaction.actionType,
        status: "failed",
        error: rawMessage,
        referenceId: actionReferenceId(transaction.actionPayload),
        policyResults: transaction.policyResults,
      });

      if (isRpcError(e)) {
        return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
      }
      return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
    }
  });
});

// ─── Reject transaction ───────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/reject/:txId", async (c) => {
  if (!hasTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejection requires owner or admin session",
      },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction rejection requires recent MFA verification" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const actorId = c.get("userId") ?? tenantId;
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  await writeVaultAudit(c, {
    tenantId,
    actorType: "user",
    actorId,
    action: "vault.reject.authorized",
    resourceType: "transaction",
    resourceId: txId,
    metadata: { agentId },
  });

  const [rejectedTransaction] = await db.transaction(async (tx) => {
    const rejectResult = await tx
      .update(approvalQueue)
      .set({ status: "rejected", resolvedAt: new Date(), resolvedBy: actorId })
      .where(
        and(
          eq(approvalQueue.txId, txId),
          eq(approvalQueue.agentId, agentId),
          eq(approvalQueue.status, "pending"),
        ),
      )
      .returning();

    if (rejectResult.length === 0) return [];

    return tx
      .update(transactions)
      .set({ status: "rejected" })
      .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)))
      .returning({
        actionType: transactions.actionType,
        actionPayload: transactions.actionPayload,
        policyResults: transactions.policyResults,
      });
  });

  if (!rejectedTransaction) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  await writeVaultAudit(c, {
    tenantId,
    actorType: "user",
    actorId,
    action:
      rejectedTransaction?.actionType === "transfer"
        ? "wallet_action.transfer.rejected"
        : rejectedTransaction?.actionType === "send_calls"
          ? "wallet_action.send_calls.rejected"
          : "vault.reject",
    resourceType:
      rejectedTransaction?.actionType === "transfer" ||
      rejectedTransaction?.actionType === "send_calls"
        ? "wallet_action"
        : "transaction",
    resourceId: txId,
    metadata: { agentId },
  });

  if (rejectedTransaction?.actionType === "transfer") {
    dispatchWebhook(tenantId, agentId, "wallet_action.transfer.rejected", { actionId: txId });
  } else if (rejectedTransaction?.actionType === "send_calls") {
    dispatchWebhook(tenantId, agentId, "wallet_action.send_calls.rejected", { actionId: txId });
  }
  dispatchIntentWebhook(tenantId, agentId, "intent.rejected", {
    intentId: txId,
    actionType: rejectedTransaction?.actionType,
    status: "rejected",
    referenceId: actionReferenceId(rejectedTransaction?.actionPayload),
    policyResults: rejectedTransaction?.policyResults,
  });

  return c.json<ApiResponse>({ ok: true });
});

// ─── Pending approvals ────────────────────────────────────────────────────────

vaultRoutes.get("/:agentId/pending", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Unsafe message signing requires owner or admin session with recent MFA",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const limit = parseListLimit(c.req.query("limit"));
  const offset = parseListOffset(c.req.query("offset"));
  const pendingTransactions = await db
    .select({
      queueId: approvalQueue.id,
      status: approvalQueue.status,
      requestedAt: approvalQueue.requestedAt,
      transaction: transactions,
    })
    .from(approvalQueue)
    .innerJoin(transactions, eq(transactions.id, approvalQueue.txId))
    .where(
      and(
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
        eq(transactions.agentId, agentId),
      ),
    )
    .orderBy(desc(approvalQueue.requestedAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({
    ok: true,
    data: {
      approvals: pendingTransactions.map((entry) => ({
        queueId: entry.queueId,
        status: entry.status,
        requestedAt: entry.requestedAt,
        transaction: toTxRecord(entry.transaction),
      })),
      limit,
      offset,
    },
  });
});

// ─── Transaction history ──────────────────────────────────────────────────────

vaultRoutes.get("/:agentId/history", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const limit = parseListLimit(c.req.query("limit"));
  const offset = parseListOffset(c.req.query("offset"));
  const history = await db
    .select()
    .from(transactions)
    .where(eq(transactions.agentId, agentId))
    .orderBy(desc(transactions.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({
    ok: true,
    data: { transactions: history.map(toTxRecord), limit, offset },
  });
});

vaultRoutes.get("/:agentId/transactions", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const limit = parseListLimit(c.req.query("limit"));
  const offset = parseListOffset(c.req.query("offset"));
  const status = c.req.query("status");
  const actionType = c.req.query("actionType");
  const txHash = c.req.query("txHash");
  const allowedStatuses = new Set([
    "pending",
    "approved",
    "rejected",
    "signed",
    "broadcast",
    "confirmed",
    "failed",
  ]);
  if (status && !allowedStatuses.has(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid transaction status filter" }, 400);
  }

  const conditions: SQL[] = [eq(transactions.agentId, agentId)];
  if (status)
    conditions.push(eq(transactions.status, status as typeof transactions.$inferSelect.status));
  if (actionType) conditions.push(eq(transactions.actionType, actionType));
  if (txHash) conditions.push(eq(transactions.txHash, txHash));

  const rows = await db
    .select()
    .from(transactions)
    .where(and(...conditions))
    .orderBy(desc(transactions.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({
    ok: true,
    data: { transactions: rows.map(toTransactionResponse), limit, offset },
  });
});

vaultRoutes.get("/:agentId/transactions/:txId", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const [row] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));

  if (!row) return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);

  return c.json<ApiResponse>({ ok: true, data: toTransactionResponse(row) });
});

vaultRoutes.post("/:agentId/transactions/:txId/lifecycle", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction lifecycle updates require owner or admin session with recent MFA",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const body = await safeJsonParse<{
    type?: unknown;
    txHash?: unknown;
    replacementTxHash?: unknown;
    reason?: unknown;
    error?: unknown;
    provider?: unknown;
    blockNumber?: unknown;
    confirmations?: unknown;
  }>(c);
  if (!isTransactionLifecycleEvent(body?.type)) {
    return c.json<ApiResponse>(
      { ok: false, error: "type must be a valid transaction lifecycle event" },
      400,
    );
  }

  const [row] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);

  const isBroadcastPromotion =
    body.type === "transaction.broadcasted" ||
    body.type === "transaction.confirmed" ||
    body.type === "transaction.replaced";
  if (
    (body.type === "transaction.broadcasted" || body.type === "transaction.replaced") &&
    !["signed", "broadcast"].includes(row.status)
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction must be signed or broadcast before this lifecycle event" },
      409,
    );
  }
  if (body.type === "transaction.confirmed" && row.status !== "broadcast") {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction must be broadcast before confirmation" },
      409,
    );
  }
  if (isBroadcastPromotion) {
    const [pendingApproval] = await db
      .select({ id: approvalQueue.id })
      .from(approvalQueue)
      .where(
        and(
          eq(approvalQueue.txId, txId),
          eq(approvalQueue.agentId, agentId),
          eq(approvalQueue.status, "pending"),
        ),
      );
    if (pendingApproval) {
      return c.json<ApiResponse>(
        { ok: false, error: "Pending approval must be resolved before lifecycle promotion" },
        409,
      );
    }
  }

  const txHash = typeof body.txHash === "string" && body.txHash.trim() ? body.txHash.trim() : null;
  const replacementTxHash =
    typeof body.replacementTxHash === "string" && body.replacementTxHash.trim()
      ? body.replacementTxHash.trim()
      : null;
  const reason =
    typeof body.reason === "string" && body.reason.trim() ? body.reason.trim() : undefined;
  const error = typeof body.error === "string" && body.error.trim() ? body.error.trim() : undefined;
  const provider =
    typeof body.provider === "string" && body.provider.trim() ? body.provider.trim() : undefined;
  const blockNumber =
    typeof body.blockNumber === "string" || typeof body.blockNumber === "number"
      ? body.blockNumber
      : undefined;
  const confirmations =
    typeof body.confirmations === "number" && Number.isSafeInteger(body.confirmations)
      ? body.confirmations
      : undefined;

  const update: Partial<typeof transactions.$inferInsert> = {};
  let eventTxHash = txHash ?? row.txHash;
  let nextStatus = row.status;
  const now = new Date();

  switch (body.type) {
    case "transaction.broadcasted":
      if (!eventTxHash) {
        return c.json<ApiResponse>({ ok: false, error: "txHash is required" }, 400);
      }
      update.status = "broadcast";
      update.txHash = eventTxHash;
      update.signedAt = row.signedAt ?? now;
      nextStatus = "broadcast";
      break;
    case "transaction.confirmed":
      if (txHash && row.txHash && txHash !== row.txHash) {
        return c.json<ApiResponse>({ ok: false, error: "txHash does not match transaction" }, 409);
      }
      if (!eventTxHash) {
        return c.json<ApiResponse>({ ok: false, error: "txHash is required" }, 400);
      }
      update.status = "confirmed";
      update.txHash = eventTxHash;
      update.confirmedAt = now;
      nextStatus = "confirmed";
      break;
    case "transaction.failed":
    case "transaction.provider_error":
    case "transaction.execution_reverted":
      update.status = "failed";
      if (txHash) update.txHash = txHash;
      nextStatus = "failed";
      break;
    case "transaction.replaced":
      if (!replacementTxHash) {
        return c.json<ApiResponse>({ ok: false, error: "replacementTxHash is required" }, 400);
      }
      update.status = "broadcast";
      update.txHash = replacementTxHash;
      update.signedAt = row.signedAt ?? now;
      eventTxHash = replacementTxHash;
      nextStatus = "broadcast";
      break;
    case "transaction.still_pending":
      break;
  }

  await writeVaultAudit(c, {
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? null,
    action: "transaction.lifecycle.authorized",
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      type: body.type,
      currentStatus: row.status,
      nextStatus,
      txHash: eventTxHash,
      previousTxHash: body.type === "transaction.replaced" ? row.txHash : undefined,
      replacementTxHash: body.type === "transaction.replaced" ? replacementTxHash : undefined,
      reason,
      error,
      provider,
      blockNumber,
      confirmations,
    },
  });

  const [updated] =
    Object.keys(update).length > 0
      ? await db
          .update(transactions)
          .set(update)
          .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)))
          .returning()
      : [row];

  await writeVaultAudit(c, {
    tenantId,
    actorType: "agent",
    actorId: agentId,
    action: body.type,
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      txHash: eventTxHash,
      previousTxHash: body.type === "transaction.replaced" ? row.txHash : undefined,
      replacementTxHash: body.type === "transaction.replaced" ? replacementTxHash : undefined,
      status: nextStatus,
      reason,
      error,
      provider,
      blockNumber,
      confirmations,
    },
  });

  dispatchTransactionLifecycleWebhook(tenantId, agentId, body.type, {
    txId,
    txHash: eventTxHash,
    previousTxHash: body.type === "transaction.replaced" ? row.txHash : undefined,
    replacementTxHash: body.type === "transaction.replaced" ? replacementTxHash : undefined,
    chainId: row.chainId,
    status: nextStatus,
    reason,
    error,
    provider,
    blockNumber,
    confirmations,
    referenceId: actionReferenceId(row.actionPayload),
    transactionRequest:
      body.type === "transaction.still_pending" ? transactionRequestPayload(row) : undefined,
  });

  if (body.type === "transaction.confirmed") {
    const eventPayload = userOperationEventPayload(agentId, updated, {
      txHash: eventTxHash,
      status: "completed",
      blockNumber,
      confirmations,
    });
    if (eventPayload) {
      dispatchWebhook(tenantId, agentId, "user_operation.completed", eventPayload);
    }
  } else if (
    body.type === "transaction.failed" ||
    body.type === "transaction.provider_error" ||
    body.type === "transaction.execution_reverted"
  ) {
    const eventPayload = userOperationEventPayload(agentId, updated, {
      txHash: eventTxHash,
      status: "failed",
      error,
      blockNumber,
      confirmations,
    });
    if (eventPayload) {
      dispatchWebhook(tenantId, agentId, "user_operation.failed", eventPayload);
    }
  }

  return c.json<ApiResponse>({
    ok: true,
    data: toTransactionResponse(updated),
  });
});

vaultRoutes.post("/:agentId/transactions/:txId/replace", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction replacement requires owner or admin session with recent MFA",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const body = await safeJsonParse<{
    replacementTxHash?: unknown;
    reason?: unknown;
    provider?: unknown;
    blockNumber?: unknown;
    confirmations?: unknown;
  }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  const replacementTxHash =
    typeof body.replacementTxHash === "string" && body.replacementTxHash.trim()
      ? body.replacementTxHash.trim()
      : null;
  if (!replacementTxHash) {
    return c.json<ApiResponse>({ ok: false, error: "replacementTxHash is required" }, 400);
  }

  const [row] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  if (!["signed", "broadcast"].includes(row.status)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction must be signed or broadcast before replacement" },
      409,
    );
  }

  const [pendingApproval] = await db
    .select({ id: approvalQueue.id })
    .from(approvalQueue)
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
      ),
    );
  if (pendingApproval) {
    return c.json<ApiResponse>(
      { ok: false, error: "Pending approval must be resolved before replacement" },
      409,
    );
  }

  const reason =
    typeof body?.reason === "string" && body.reason.trim() ? body.reason.trim() : undefined;
  const provider =
    typeof body?.provider === "string" && body.provider.trim() ? body.provider.trim() : undefined;
  const blockNumber =
    typeof body?.blockNumber === "string" || typeof body?.blockNumber === "number"
      ? body.blockNumber
      : undefined;
  const confirmations =
    typeof body?.confirmations === "number" && Number.isSafeInteger(body.confirmations)
      ? body.confirmations
      : undefined;
  const now = new Date();

  await writeVaultAudit(c, {
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? null,
    action: "transaction.replace.authorized",
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      currentStatus: row.status,
      nextStatus: "broadcast",
      previousTxHash: row.txHash,
      replacementTxHash,
      reason,
      provider,
      blockNumber,
      confirmations,
    },
  });

  const [updated] = await db
    .update(transactions)
    .set({
      status: "broadcast",
      txHash: replacementTxHash,
      signedAt: row.signedAt ?? now,
    })
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)))
    .returning();

  await writeVaultAudit(c, {
    tenantId,
    actorType: "agent",
    actorId: agentId,
    action: "transaction.replaced",
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      txHash: replacementTxHash,
      previousTxHash: row.txHash,
      replacementTxHash,
      status: "broadcast",
      reason,
      provider,
      blockNumber,
      confirmations,
    },
  });

  dispatchTransactionLifecycleWebhook(tenantId, agentId, "transaction.replaced", {
    txId,
    txHash: replacementTxHash,
    previousTxHash: row.txHash,
    replacementTxHash,
    chainId: row.chainId,
    status: "broadcast",
    reason,
    provider,
    blockNumber,
    confirmations,
    referenceId: actionReferenceId(row.actionPayload),
  });

  return c.json<ApiResponse>({
    ok: true,
    data: toTransactionResponse(updated),
  });
});

// ─── EIP-712 Typed Data Signing ───────────────────────────────────────────────

// ─── Sign arbitrary message (personal_sign / eth_sign) ───────────────────────────────
//
// Used by server-to-server flows that need an off-chain signature from an
// agent (e.g. four.meme SIWE login). EVM uses viem's personal_sign over the
// UTF-8 bytes of the message. Solana uses Ed25519 over the message bytes.
//
// POST /vault/:agentId/sign-message
// body: { "message": "<string>" }
// resp: { ok: true, data: { signature: "0x..." } }
vaultRoutes.post("/:agentId/sign-message", async (c) => {
  if (!ALLOW_UNSAFE_MESSAGE_SIGNING || !ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Message signing is disabled because arbitrary signatures bypass transaction policy controls. Set STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING=true and STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING=true only for audited compatibility flows.",
      },
      403,
    );
  }
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{ message: string }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isNonEmptyString(body.message)) {
    return c.json<ApiResponse>({ ok: false, error: "'message' is required" }, 400);
  }
  if (looksLikeAuthMessage(body.message)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Refusing to sign authentication or permit-style messages" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Message signing requires owner/admin session with recent MFA verification",
      },
      403,
    );
  }
  const signerAuthorization = await requireSignerPermission(c, tenantId, agentId, "sign_message");
  if (!signerAuthorization.ok) return signerAuthorization.response;

  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? null,
      action: "vault.message.sign.authorized",
      resourceType: "wallet",
      resourceId: agentId,
      metadata: {
        messageLength: body.message.length,
        ...signerAuthAuditMetadata(signerAuthorization.auth),
        unsafeCompatibilityMode: true,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    const signature = await vault.signMessage(tenantId, agentId, body.message);
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? null,
      action: "vault.message.signed",
      resourceType: "wallet",
      resourceId: agentId,
      metadata: {
        messageLength: body.message.length,
        ...signerAuthAuditMetadata(signerAuthorization.auth),
        unsafeCompatibilityMode: true,
      },
    });
    return c.json<ApiResponse>({ ok: true, data: { signature } });
  } catch (e) {
    console.error(`[Vault] sign-message failed for ${tenantId}/${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Sign raw EVM digest (secp256k1_sign) ────────────────────────────────────
//
// POST /vault/:agentId/sign-raw-hash
// body: { "hash": "0x<32-byte digest>", "referenceId"?: "caller-id" }
// resp: { ok: true, data: { signature, hash, walletAddress } }
vaultRoutes.post("/:agentId/sign-raw-hash", async (c) => {
  if (!ALLOW_UNSAFE_RAW_SIGNING || !ALLOW_VAULT_UNSAFE_RAW_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Raw secp256k1 signing is disabled because digest signatures bypass transaction and message policy controls. Set STEWARD_ALLOW_UNSAFE_RAW_SIGNING=true and STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING=true only for audited compatibility flows.",
      },
      403,
    );
  }
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Unsafe raw hash signing requires owner or admin session with recent MFA",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{ hash: string; referenceId?: string }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isBytes32Hex(body.hash)) {
    return c.json<ApiResponse>({ ok: false, error: "hash must be a 32-byte hex string" }, 400);
  }
  if (body.referenceId !== undefined && !isNonEmptyString(body.referenceId)) {
    return c.json<ApiResponse>({ ok: false, error: "referenceId must be a non-empty string" }, 400);
  }
  const signerAuthorization = await requireSignerPermission(c, tenantId, agentId, "sign_raw_hash");
  if (!signerAuthorization.ok) return signerAuthorization.response;

  try {
    await writeVaultAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "vault.raw_hash.sign.authorized",
      resourceType: "wallet",
      resourceId: agentId,
      metadata: {
        hash: body.hash,
        referenceId: body.referenceId ?? null,
        ...signerAuthAuditMetadata(signerAuthorization.auth),
        unsafeCompatibilityMode: true,
      },
    });

    const result = await vault.signRawHash(tenantId, agentId, body.hash);

    await writeVaultAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "vault.raw_hash.signed",
      resourceType: "wallet",
      resourceId: agentId,
      metadata: {
        hash: body.hash,
        referenceId: body.referenceId ?? null,
        ...signerAuthAuditMetadata(signerAuthorization.auth),
        walletAddress: result.walletAddress,
        unsafeCompatibilityMode: true,
      },
    });

    return c.json<ApiResponse>({ ok: true, data: result });
  } catch (e) {
    console.error(`[Vault] sign-raw-hash failed for ${tenantId}/${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

vaultRoutes.post("/:agentId/sign-typed-data", async (c) => {
  if (typedDataSigningDisabled()) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "EIP-712 typed data signing is disabled until typed-data-specific policy extraction is configured.",
      },
      403,
    );
  }

  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "sign_typed_data",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;

  const body = await safeJsonParse<{
    domain: SignTypedDataRequest["domain"];
    types: SignTypedDataRequest["types"];
    primaryType: string;
    value: Record<string, unknown>;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!body.domain || typeof body.domain !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'domain' is required and must be an object" },
      400,
    );
  }
  if (!body.types || typeof body.types !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'types' is required and must be an object" },
      400,
    );
  }
  if (!isNonEmptyString(body.primaryType)) {
    return c.json<ApiResponse>({ ok: false, error: "'primaryType' is required" }, 400);
  }
  if (!body.value || typeof body.value !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required and must be an object" },
      400,
    );
  }

  const resolvedChainId =
    (typeof body.domain.chainId === "number" ? body.domain.chainId : 0) ||
    parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: "0x0000000000000000000000000000000000000000",
    value: "0",
    chainId: resolvedChainId,
  };

  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);

  // ── Redis rate-limit check (typed data) ────────────────────────────────────
  const rlResult = await enforceRateLimit(agentId, policySet);
  if (!rlResult.allowed) {
    if (rlResult.headers) {
      for (const [key, value] of Object.entries(rlResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>({ ok: false, error: rlResult.reason || "Rate limit exceeded" }, 429);
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
    conditionSets,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress: signRequest.to,
          value: signRequest.value,
          chainId: signRequest.chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
        });
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.typed_data.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          primaryType: body.primaryType,
          policyResults: evaluation.results,
        },
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });
      dispatchIntentWebhook(tenantId, agentId, "intent.created", {
        intentId: txId,
        status: "pending",
        policyResults: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress: signRequest.to,
      value: signRequest.value,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
    });

    await writeVaultAudit(c, {
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.typed_data.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        primaryType: body.primaryType,
        policyResults: evaluation.results,
      },
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  const txId = crypto.randomUUID();

  try {
    const signature = await vault.signTypedData({
      agentId,
      tenantId,
      domain: body.domain,
      types: body.types,
      primaryType: body.primaryType,
      value: body.value,
    });

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "signed",
      toAddress: signRequest.to,
      value: signRequest.value,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
      signedAt: new Date(),
    });

    await writeVaultAudit(c, {
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.typed_data",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        primaryType: body.primaryType,
      },
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", { txId });

    return c.json<ApiResponse<{ signature: string; txId: string }>>({
      ok: true,
      data: { signature, txId },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Sign typed data failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      error: rawMessage,
      requestId,
    });

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── ERC-4337 User Operation Signing ─────────────────────────────────────────

vaultRoutes.post("/:agentId/sign-user-operation", async (c) => {
  if (!ALLOW_UNSAFE_USER_OPERATION_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "User operation signing is disabled because policy fields cannot be trusted until callData decoding and sender ownership checks are implemented. Set STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING=true only for audited compatibility flows.",
      },
      403,
    );
  }

  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Unsafe user operation signing requires owner or admin session with recent MFA",
      },
      403,
    );
  }
  if (!userOperationPolicyModelAvailable()) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "User operation signing is disabled because policy fields cannot be trusted until callData decoding and sender ownership checks are implemented.",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "sign_user_operation",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;

  const body = await safeJsonParse<{
    userOperation?: unknown;
    entryPoint?: string;
    chainId?: number;
    to?: string;
    value?: string;
    referenceId?: unknown;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const userOperation = parseUserOperation(body.userOperation);
  if (typeof userOperation === "string") {
    return c.json<ApiResponse>({ ok: false, error: userOperation }, 400);
  }
  if (body.entryPoint !== undefined && !isValidAddress(body.entryPoint)) {
    return c.json<ApiResponse>({ ok: false, error: "entryPoint must be an Ethereum address" }, 400);
  }
  if (!Number.isSafeInteger(body.chainId) || !body.chainId || body.chainId <= 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "chainId is required and must be a positive integer" },
      400,
    );
  }
  if (!isNonEmptyString(body.to) || !isValidAddress(body.to)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'to' is required for policy evaluation and must be an Ethereum address",
      },
      400,
    );
  }
  if (!isNonEmptyString(body.value) || !isUint256DecimalString(body.value)) {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required for policy evaluation as a uint256 wei string" },
      400,
    );
  }
  const referenceId = parseReferenceId(body.referenceId);
  if (referenceId === null) {
    return c.json<ApiResponse>(
      { ok: false, error: "referenceId must be a non-empty string up to 128 characters" },
      400,
    );
  }

  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: body.to,
    value: body.value,
    data: userOperation.callData,
    chainId: body.chainId,
    broadcast: false,
  };
  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);
  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) c.header(key, value);
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) c.header(key, value);
  }

  return withAgentSpendLock(agentId, async () => {
    const stats = await getTransactionStats(agentId);
    const evaluation = await policyEngine.evaluate(policySet, {
      request: signRequest,
      recentTxCount1h: stats.recentTxCount1h,
      recentTxCount24h: stats.recentTxCount24h,
      spentToday: stats.spentToday,
      spentThisWeek: stats.spentThisWeek,
      priceOracle,
      conditionSets,
    });
    const txId = crypto.randomUUID();

    if (!evaluation.approved) {
      const status: "pending" | "rejected" = evaluation.requiresManualApproval
        ? "pending"
        : "rejected";
      const transactionRow = {
        id: txId,
        agentId,
        status,
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
        actionType: "user_operation",
        actionPayload: {
          type: "user_operation",
          entryPoint: body.entryPoint ?? ENTRY_POINT_V07,
          sender: userOperation.sender,
          ...(referenceId ? { referenceId } : {}),
        },
      };

      if (evaluation.requiresManualApproval) {
        await db.transaction(async (tx) => {
          await tx.insert(transactions).values(transactionRow);
          await tx.insert(approvalQueue).values({
            id: crypto.randomUUID(),
            txId,
            agentId,
            status: "pending",
          });
        });
      } else {
        await db.insert(transactions).values(transactionRow);
      }

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: evaluation.requiresManualApproval
          ? "vault.sign.user_operation.queued_for_approval"
          : "vault.sign.user_operation.rejected_by_policy",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          to: signRequest.to,
          value: signRequest.value,
          sender: userOperation.sender,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          policyResults: evaluation.results,
        },
      });

      dispatchWebhook(
        tenantId,
        agentId,
        evaluation.requiresManualApproval ? "approval_required" : "tx_rejected",
        { txId, results: evaluation.results },
      );
      if (evaluation.requiresManualApproval) {
        dispatchIntentWebhook(tenantId, agentId, "intent.created", {
          intentId: txId,
          actionType: "user_operation",
          status: "pending",
          referenceId,
          policyResults: evaluation.results,
        });
      }

      return c.json<ApiResponse>(
        {
          ok: false,
          error: evaluation.requiresManualApproval
            ? "User operation requires manual approval"
            : "User operation rejected by policy",
          data: evaluation.requiresManualApproval
            ? { txId, results: evaluation.results, status: "pending_approval" }
            : { txId, results: evaluation.results },
        },
        evaluation.requiresManualApproval ? 202 : 403,
      );
    }

    try {
      await writeVaultAudit(c, {
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? null,
        action: "vault.sign.user_operation.authorized",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          sender: userOperation.sender,
          entryPoint: body.entryPoint ?? ENTRY_POINT_V07,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          unsafeCompatibilityMode: true,
          policyResults: evaluation.results,
        },
      });
      const result = await vault.signUserOperation({
        agentId,
        tenantId,
        userOperation,
        entryPoint: (body.entryPoint as `0x${string}` | undefined) ?? ENTRY_POINT_V07,
        chainId: signRequest.chainId,
      });
      const userOperationHash = getUserOperationHash(
        packUserOperation(userOperation),
        result.entryPoint as `0x${string}`,
        result.chainId,
      );

      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "signed",
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
        signedAt: new Date(),
        actionType: "user_operation",
        actionPayload: {
          type: "user_operation",
          entryPoint: result.entryPoint,
          sender: userOperation.sender,
          userOperationHash,
          ...(referenceId ? { referenceId } : {}),
        },
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? null,
        action: "vault.sign.user_operation",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          sender: userOperation.sender,
          entryPoint: result.entryPoint,
          userOperationHash,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
        },
      });

      dispatchWebhook(tenantId, agentId, "tx_signed", { txId });

      return c.json<
        ApiResponse<{
          signature: string;
          userOperationHash: string;
          entryPoint: string;
          chainId: number;
          txId: string;
        }>
      >({
        ok: true,
        data: { ...result, userOperationHash, txId },
      });
    } catch (e: unknown) {
      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.user_operation.failed",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          sender: userOperation.sender,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          error: e instanceof Error ? e.message : "Unknown error",
        },
      });

      dispatchWebhook(tenantId, agentId, "tx_failed", {
        txId,
        error: e instanceof Error ? e.message : "Unknown error",
      });

      return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
    }
  });
});

// ─── EIP-7702 Authorization Signing ──────────────────────────────────────────

vaultRoutes.post("/:agentId/sign-authorization", async (c) => {
  if (!ALLOW_UNSAFE_AUTHORIZATION_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "EIP-7702 authorization signing is disabled because delegation can bypass transaction policy controls. Set STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING=true only for audited break-glass flows.",
      },
      403,
    );
  }

  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Unsafe authorization signing requires owner or admin session with recent MFA",
      },
      403,
    );
  }
  if (!authorizationPolicyModelAvailable()) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "EIP-7702 authorization signing is disabled because delegation can bypass transaction policy controls.",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "sign_authorization",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;

  const body = await safeJsonParse<{
    contractAddress?: string;
    chainId?: number;
    nonce?: number;
    referenceId?: unknown;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isValidAddress(body.contractAddress)) {
    return c.json<ApiResponse>(
      { ok: false, error: "contractAddress must be an Ethereum address" },
      400,
    );
  }
  if (
    typeof body.chainId !== "number" ||
    !Number.isSafeInteger(body.chainId) ||
    body.chainId <= 0
  ) {
    return c.json<ApiResponse>({ ok: false, error: "chainId must be a positive integer" }, 400);
  }
  if (typeof body.nonce !== "number" || !Number.isSafeInteger(body.nonce) || body.nonce < 0) {
    return c.json<ApiResponse>({ ok: false, error: "nonce must be a non-negative integer" }, 400);
  }
  const referenceId = parseReferenceId(body.referenceId);
  if (referenceId === null) {
    return c.json<ApiResponse>(
      { ok: false, error: "referenceId must be a non-empty string up to 128 characters" },
      400,
    );
  }
  const contractAddress = body.contractAddress as `0x${string}`;
  const chainId = body.chainId as number;
  const nonce = body.nonce as number;

  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: contractAddress,
    value: "0",
    chainId,
    broadcast: false,
  };
  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);
  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) c.header(key, value);
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) c.header(key, value);
  }

  return withAgentSpendLock(agentId, async () => {
    const stats = await getTransactionStats(agentId);
    const evaluation = await policyEngine.evaluate(policySet, {
      request: signRequest,
      recentTxCount1h: stats.recentTxCount1h,
      recentTxCount24h: stats.recentTxCount24h,
      spentToday: stats.spentToday,
      spentThisWeek: stats.spentThisWeek,
      priceOracle,
      conditionSets,
    });
    const txId = crypto.randomUUID();

    if (!evaluation.approved) {
      const status: "pending" | "rejected" = evaluation.requiresManualApproval
        ? "pending"
        : "rejected";
      const transactionRow = {
        id: txId,
        agentId,
        status,
        toAddress: signRequest.to,
        value: signRequest.value,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
        actionType: "authorization",
        actionPayload: {
          type: "eip7702_authorization",
          contractAddress,
          nonce,
          ...(referenceId ? { referenceId } : {}),
        },
      };

      if (evaluation.requiresManualApproval) {
        await db.transaction(async (tx) => {
          await tx.insert(transactions).values(transactionRow);
          await tx.insert(approvalQueue).values({
            id: crypto.randomUUID(),
            txId,
            agentId,
            status: "pending",
          });
        });
      } else {
        await db.insert(transactions).values(transactionRow);
      }

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: evaluation.requiresManualApproval
          ? "vault.sign.authorization.queued_for_approval"
          : "vault.sign.authorization.rejected_by_policy",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          contractAddress,
          nonce,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          policyResults: evaluation.results,
        },
      });

      dispatchWebhook(
        tenantId,
        agentId,
        evaluation.requiresManualApproval ? "approval_required" : "tx_rejected",
        { txId, results: evaluation.results },
      );
      if (evaluation.requiresManualApproval) {
        dispatchIntentWebhook(tenantId, agentId, "intent.created", {
          intentId: txId,
          actionType: "authorization",
          status: "pending",
          referenceId,
          policyResults: evaluation.results,
        });
      }

      return c.json<ApiResponse>(
        {
          ok: false,
          error: evaluation.requiresManualApproval
            ? "Authorization requires manual approval"
            : "Authorization rejected by policy",
          data: evaluation.requiresManualApproval
            ? { txId, results: evaluation.results, status: "pending_approval" }
            : { txId, results: evaluation.results },
        },
        evaluation.requiresManualApproval ? 202 : 403,
      );
    }

    try {
      await writeVaultAudit(c, {
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? null,
        action: "vault.sign.authorization.authorized",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          contractAddress,
          nonce,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          unsafeCompatibilityMode: true,
          policyResults: evaluation.results,
        },
      });
      const authorization = await vault.signAuthorization(tenantId, agentId, {
        contractAddress,
        chainId,
        nonce,
      });

      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "signed",
        toAddress: signRequest.to,
        value: signRequest.value,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
        signedAt: new Date(),
        actionType: "authorization",
        actionPayload: {
          type: "eip7702_authorization",
          contractAddress,
          nonce,
          ...(referenceId ? { referenceId } : {}),
        },
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? null,
        action: "vault.sign.authorization",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          contractAddress,
          nonce,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
        },
      });

      dispatchWebhook(tenantId, agentId, "tx_signed", { txId });

      return c.json<ApiResponse<{ authorization: typeof authorization; txId: string }>>({
        ok: true,
        data: { authorization, txId },
      });
    } catch (e: unknown) {
      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.authorization.failed",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          contractAddress,
          nonce,
          ...signerAuthAuditMetadata(signerAuthorization.auth),
          error: e instanceof Error ? e.message : "Unknown error",
        },
      });

      dispatchWebhook(tenantId, agentId, "tx_failed", {
        txId,
        error: e instanceof Error ? e.message : "Unknown error",
      });

      return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
    }
  });
});

// ─── Solana Transaction Signing ───────────────────────────────────────────────

vaultRoutes.post("/:agentId/sign-solana", async (c) => {
  if (solanaTransactionSigningDisabled()) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Serialized Solana transaction signing is disabled until policy fields are derived from transaction instructions.",
      },
      403,
    );
  }

  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    transaction: string;
    chainId?: number;
    broadcast?: boolean;
    to?: string;
    value?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.transaction)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'transaction' is required (base64-encoded serialized Solana transaction)",
      },
      400,
    );
  }

  if (body.to !== undefined && body.to !== "") {
    if (!isValidSolanaAddress(body.to) && !isValidAddress(body.to)) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "'to' must be a valid Solana address (base58, 32–44 chars) or Ethereum address",
        },
        400,
      );
    }
  }

  if (!body.to || !body.value) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Solana signing requires 'to' (recipient address) and 'value' (lamports as string) for policy evaluation",
      },
      400,
    );
  }
  if (!isNonEmptyString(body.value) || !isUint256DecimalString(body.value)) {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' must be a uint256 lamports string" },
      400,
    );
  }

  const chainId = body.chainId ?? 101;
  const toAddress = body.to;
  const txValue = body.value;

  const signRequest = {
    agentId,
    tenantId,
    to: toAddress,
    value: txValue,
    chainId,
  };

  const policySet = await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);

  // ── Redis rate-limit check (Solana) ────────────────────────────────────────
  const solRlResult = await enforceRateLimit(agentId, policySet);
  if (!solRlResult.allowed) {
    if (solRlResult.headers) {
      for (const [key, value] of Object.entries(solRlResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: solRlResult.reason || "Rate limit exceeded" },
      429,
    );
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
    conditionSets,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress,
          value: txValue,
          data: body.transaction,
          chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
        });
      });

      await writeVaultAudit(c, {
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.solana.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId,
          to: toAddress,
          value: txValue,
          policyResults: evaluation.results,
        },
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });
      dispatchIntentWebhook(tenantId, agentId, "intent.created", {
        intentId: txId,
        status: "pending",
        policyResults: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress,
      value: txValue,
      chainId,
      policyResults: evaluation.results,
    });

    await writeVaultAudit(c, {
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.solana.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId,
        to: toAddress,
        value: txValue,
        policyResults: evaluation.results,
      },
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  try {
    const txId = crypto.randomUUID();

    const result = await vault.signSolanaTransaction({
      agentId,
      tenantId,
      transaction: body.transaction,
      chainId,
      broadcast: body.broadcast,
      expectedTo: toAddress,
      expectedValue: txValue,
    });

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "signed",
      toAddress,
      value: txValue,
      chainId,
      txHash: result.broadcast ? result.signature : undefined,
      policyResults: evaluation.results,
      signedAt: new Date(),
    });

    // ── Record spend in Redis (fire-and-forget) ──────────────────────────────
    recordVaultSpend(agentId, tenantId, txValue, chainId).catch((err) =>
      console.error("[vault] Failed to record Solana spend:", err),
    );

    await writeVaultAudit(c, {
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.solana",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId,
        to: toAddress,
        value: txValue,
        broadcast: result.broadcast,
        signature: result.broadcast ? result.signature : undefined,
      },
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", {
      txId,
      txHash: result.broadcast ? result.signature : undefined,
    });

    return c.json<
      ApiResponse<{
        txId: string;
        signature: string;
        broadcast: boolean;
        chainId: number;
        caip2?: string;
      }>
    >({
      ok: true,
      data: { txId, ...result },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Solana sign failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      error: e instanceof Error ? e.message : "Unknown error",
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Generic RPC Passthrough ──────────────────────────────────────────────────

vaultRoutes.post("/:agentId/rpc", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<RpcRequest>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.method)) {
    return c.json<ApiResponse>({ ok: false, error: "'method' is required" }, 400);
  }
  if (!VAULT_RPC_ALLOWLIST.has(body.method)) {
    return c.json<ApiResponse>({ ok: false, error: "RPC method is not allowlisted" }, 403);
  }

  if (!body.chainId || typeof body.chainId !== "number") {
    return c.json<ApiResponse>(
      { ok: false, error: "'chainId' is required and must be a number" },
      400,
    );
  }

  try {
    const result = await vault.rpcPassthrough(body);
    return c.json<ApiResponse<RpcResponse>>({
      ok: true,
      data: result,
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const message = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] RPC passthrough failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Multi-Wallet Address List ────────────────────────────────────────────────

vaultRoutes.get("/:agentId/addresses", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const addresses = await vault.getAddresses(tenantId, agentId);
    return c.json<
      ApiResponse<{
        agentId: string;
        addresses: Array<{ chainFamily: "evm" | "solana"; address: string }>;
      }>
    >({
      ok: true,
      data: { agentId, addresses },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] getAddresses failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Import ───────────────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/import", async (c) => {
  if (!ALLOW_PRIVATE_KEY_IMPORT || !ALLOW_VAULT_PRIVATE_KEY_IMPORT) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Private key import is disabled. Set STEWARD_ALLOW_PRIVATE_KEY_IMPORT=true and STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT=true only for audited break-glass operations.",
      },
      403,
    );
  }

  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key import requires tenant-level authentication" },
      403,
    );
  }
  if (!hasTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key import requires tenant admin session authentication" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key import requires a recent MFA step-up session" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!isValidAgentId(agentId)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)",
      },
      400,
    );
  }
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    privateKey: string;
    chain: "evm" | "solana";
  }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.privateKey)) {
    return c.json<ApiResponse>({ ok: false, error: "privateKey is required" }, 400);
  }

  if (body.chain !== "evm" && body.chain !== "solana") {
    return c.json<ApiResponse>({ ok: false, error: "chain must be 'evm' or 'solana'" }, 400);
  }

  try {
    await writeVaultAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "vault.key.import.authorized",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { chain: body.chain },
    });
    const result = await vault.importKey(tenantId, agentId, body.privateKey, body.chain);
    await writeVaultAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "vault.key.import",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { chain: body.chain, walletAddress: result.walletAddress },
    });
    return c.json<ApiResponse<{ agentId: string; walletAddress: string; chain: string }>>({
      ok: true,
      data: { agentId, walletAddress: result.walletAddress, chain: body.chain },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Key import failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Export ──────────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/export", async (c) => {
  if (!ALLOW_PRIVATE_KEY_EXPORT || !ALLOW_VAULT_PRIVATE_KEY_EXPORT) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Private key export is disabled. Set STEWARD_ALLOW_PRIVATE_KEY_EXPORT=true and STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT=true only for audited break-glass operations.",
      },
      403,
    );
  }

  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires tenant-level authentication" },
      403,
    );
  }
  if (!hasTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires tenant admin session authentication" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires a recent MFA step-up session" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "vault.private_key_export.authorized",
      resourceType: "wallet",
      resourceId: agentId,
      metadata: { breakGlass: true },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    const keys = await vault.exportPrivateKey(tenantId, agentId, {
      breakGlass: true,
      actorId: c.get("userId") ?? c.get("authType") ?? "unknown",
      reason: "tenant-admin break-glass export",
    });
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "vault.private_key_export.succeeded",
      resourceType: "wallet",
      resourceId: agentId,
      metadata: { breakGlass: true },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    dispatchWebhook(tenantId, agentId, "private_key.exported", {
      agentId,
      breakGlass: true,
    });

    return c.json<
      ApiResponse<{
        evm?: { privateKey: string; address: string };
        solana?: { privateKey: string; address: string };
        warning: string;
      }>
    >({
      ok: true,
      data: {
        ...keys,
        warning: "This key controls real funds. Store securely.",
      },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Key export failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});
