/**
 * Privy-style generic intent routes.
 *
 * Mount: app.route("/intents", intentRoutes)
 */

import { auditEvents, toPersistedPolicyRule } from "@stwd/db";
import type { PolicyRule } from "@stwd/shared";
import { and, desc, eq, inArray, type SQL, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { enforceRateLimit, recordVaultSpend } from "../middleware/redis-enforcement";
import { type ActorType, writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  agentKeyQuorums,
  agentSigners,
  agents,
  db,
  getConditionSetReferenceValidationError,
  getPolicySet,
  getTransactionStats,
  intents,
  loadConditionSetsForPolicies,
  policies,
  policyEngine,
  priceOracle,
  requireTenantLevel,
  safeJsonParse,
  setNoStoreHeaders,
  toPolicyRule,
  transactions,
  vault,
} from "../services/context";
import { getPolicyRulesValidationError } from "../services/policy-validation";
import { dispatchWebhook } from "../services/webhook-dispatch";

export const intentRoutes = new Hono<{ Variables: AppVariables }>();

intentRoutes.use("*", async (c, next) => {
  setNoStoreHeaders(c);
  await next();
});

const INTENT_STATUSES = new Set([
  "pending",
  "authorized",
  "executing",
  "executed",
  "failed",
  "rejected",
  "canceled",
  "expired",
]);
const FINAL_INTENT_STATUSES = new Set([
  "authorized",
  "executed",
  "failed",
  "rejected",
  "canceled",
  "expired",
]);
const INTENT_TYPES = new Set([
  "rpc",
  "transfer",
  "wallet_update",
  "policy_update",
  "policy_rule_update",
  "quorum_update",
  "wallet_action",
]);
const HUMAN_APPROVER_INTENT_TYPES = new Set([
  "wallet_update",
  "policy_update",
  "policy_rule_update",
  "quorum_update",
]);
const MAX_INTENT_LIST_LIMIT = 200;
const MAX_INTENT_PAYLOAD_BYTES = 32_768;
const MAX_AUTHORIZATION_DETAILS = 50;
const MAX_AGENT_KEY_QUORUM_MEMBERS = 32;
const MAX_AGENT_SIGNER_PERMISSIONS = 32;
const MAX_AGENT_SIGNER_METADATA_BYTES = 8_192;
const DEFAULT_INTENT_TTL_SECONDS = 24 * 60 * 60;
const MAX_INTENT_TTL_SECONDS = 7 * 24 * 60 * 60;
const AGENT_KEY_QUORUM_STATUSES = new Set(["active", "paused", "revoked"]);
const VAULT_RPC_ALLOWLIST = new Set(
  (process.env.STEWARD_VAULT_RPC_ALLOWLIST ?? "eth_chainId,eth_blockNumber,eth_getBalance")
    .split(",")
    .map((method) => method.trim())
    .filter(Boolean),
);
const MAX_UINT256_DECIMAL =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const MAX_UINT256_DECIMAL_DIGITS = 78;

type IntentHttpStatus = 400 | 403 | 404 | 409 | 429 | 500 | 502;
type IntentSignRequest = {
  tenantId: string;
  agentId: string;
  to: string;
  value: string;
  data?: string;
  chainId: number;
  nonce?: number;
  gasLimit?: string;
  broadcast?: boolean;
};

type IntentSendCall = {
  to: string;
  value: string;
  data?: string;
};

type IntentAuthorizationBaseline = {
  kind: "policy-set" | "quorum";
  hash: string;
};

const AUTHORIZATION_BASELINE_KEY = "__authorizationBaseline";

function requireHumanIntentApprover(c: Context<{ Variables: AppVariables }>): boolean {
  const role = c.get("tenantRole");
  return (
    (c.get("authType") === "session-jwt" || c.get("authType") === "dashboard-jwt") &&
    Boolean(c.get("userId")) &&
    (role === "owner" || role === "admin")
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

function parseListLimit(value: string | undefined): number | null {
  if (!value) return 50;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_INTENT_LIST_LIMIT) return null;
  return parsed;
}

function parseListOffset(value: string | undefined): number | null {
  if (!value) return 0;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 100_000) return null;
  return parsed;
}

function normalizeOptionalText(value: unknown, field: string, maxLength: number): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || !value.trim()) throw new Error(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized.length > maxLength) throw new Error(`${field} is too long`);
  return normalized;
}

function normalizeIntentType(value: unknown): string {
  const intentType = normalizeOptionalText(value, "intentType", 64)?.toLowerCase();
  if (!intentType) throw new Error("intentType is required");
  if (!INTENT_TYPES.has(intentType)) {
    throw new Error(`intentType must be one of: ${[...INTENT_TYPES].join(", ")}`);
  }
  return intentType;
}

function normalizeJsonObject(value: unknown, field: string, fallback: Record<string, unknown>) {
  if (value === undefined) return fallback;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  if (JSON.stringify(value).length > MAX_INTENT_PAYLOAD_BYTES) {
    throw new Error(`${field} is too large`);
  }
  return value as Record<string, unknown>;
}

function normalizeAuthorizationDetails(value: unknown): Array<Record<string, unknown>> {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("authorizationDetails must be an array");
  if (value.length > MAX_AUTHORIZATION_DETAILS) {
    throw new Error(`authorizationDetails cannot exceed ${MAX_AUTHORIZATION_DETAILS} entries`);
  }
  for (const detail of value) {
    if (!detail || typeof detail !== "object" || Array.isArray(detail)) {
      throw new Error("authorizationDetails entries must be objects");
    }
  }
  if (JSON.stringify(value).length > MAX_INTENT_PAYLOAD_BYTES) {
    throw new Error("authorizationDetails is too large");
  }
  return value as Array<Record<string, unknown>>;
}

function hasAuthorizationRequirements(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (!value || typeof value !== "object") return JSON.stringify(value);
  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  return `{${entries.map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`).join(",")}}`;
}

async function hashStableJson(value: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stableJson(value)));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function payloadWithoutAuthorizationBaseline(payload: Record<string, unknown>) {
  const { [AUTHORIZATION_BASELINE_KEY]: _baseline, ...rest } = payload;
  return rest;
}

function intentNotExpiredPredicate() {
  return sql`${intents.expiresAt} is null or ${intents.expiresAt} > now()`;
}

function normalizeIntentExpiry(value: unknown, ttlSeconds: unknown): Date | null {
  const now = Date.now();
  if (ttlSeconds !== undefined) {
    if (!Number.isSafeInteger(ttlSeconds) || Number(ttlSeconds) < 1) {
      throw new Error("ttlSeconds must be a positive integer");
    }
    if (Number(ttlSeconds) > MAX_INTENT_TTL_SECONDS) {
      throw new Error(`ttlSeconds cannot exceed ${MAX_INTENT_TTL_SECONDS}`);
    }
    return new Date(now + Number(ttlSeconds) * 1000);
  }
  if (value === undefined || value === null || value === "") {
    return new Date(now + DEFAULT_INTENT_TTL_SECONDS * 1000);
  }
  if (typeof value !== "string") throw new Error("expiresAt must be an ISO timestamp");
  const expiresAt = new Date(value);
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("expiresAt must be an ISO timestamp");
  if (expiresAt.getTime() <= now) throw new Error("expiresAt must be in the future");
  if (expiresAt.getTime() > now + MAX_INTENT_TTL_SECONDS * 1000) {
    throw new Error(
      `expiresAt cannot be more than ${MAX_INTENT_TTL_SECONDS} seconds in the future`,
    );
  }
  return expiresAt;
}

function isEvmAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[a-fA-F0-9]{40}$/.test(value);
}

function isHex(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/.test(value);
}

function hasContractCalldata(data: string | undefined): boolean {
  return Boolean(data && data !== "0x");
}

function hasEnabledContractAllowlistPolicy(policySet: PolicyRule[]): boolean {
  return policySet.some((policy) => policy.enabled && policy.type === "contract-allowlist");
}

function isUint256DecimalString(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
  const normalized = value.replace(/^0+/, "") || "0";
  if (normalized.length > MAX_UINT256_DECIMAL_DIGITS) return false;
  return normalized.length < MAX_UINT256_DECIMAL_DIGITS || normalized <= MAX_UINT256_DECIMAL;
}

function normalizeChainId(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error("chainId must be a positive integer");
  }
  return Number(value);
}

function normalizeRequiredText(value: unknown, field: string, maxLength: number): string {
  const normalized = normalizeOptionalText(value, field, maxLength);
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function isValidPolicyRuleId(value: string): boolean {
  return /^[A-Za-z0-9_.:-]{1,64}$/.test(value);
}

function normalizePolicyRuleInput(value: unknown): PolicyRule {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Policy rule must be an object");
  }
  const raw = value as Record<string, unknown>;
  const id = typeof raw.id === "string" && raw.id.trim() ? raw.id.trim() : crypto.randomUUID();
  if (!isValidPolicyRuleId(id)) {
    throw new Error("Policy rule id must be 1-64 characters using letters, numbers, _, -, ., or :");
  }
  return {
    id,
    type: raw.type as PolicyRule["type"],
    enabled: raw.enabled === undefined ? true : (raw.enabled as boolean),
    config: raw.config as Record<string, unknown>,
  };
}

function normalizePolicyRulePatch(existing: PolicyRule, value: unknown): PolicyRule {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Policy rule update must be an object");
  }
  const raw = value as Record<string, unknown>;
  if (raw.id !== undefined && raw.id !== existing.id) {
    throw new Error("Policy rule id cannot be changed");
  }
  return {
    ...existing,
    type: raw.type === undefined ? existing.type : (raw.type as PolicyRule["type"]),
    enabled: raw.enabled === undefined ? existing.enabled : (raw.enabled as boolean),
    config: raw.config === undefined ? existing.config : (raw.config as Record<string, unknown>),
  };
}

function normalizeSignerPermissions(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("permissions must be an array of strings");
  if (value.length > MAX_AGENT_SIGNER_PERMISSIONS) {
    throw new Error(`permissions cannot contain more than ${MAX_AGENT_SIGNER_PERMISSIONS} entries`);
  }
  return [
    ...new Set(
      value.map((permission) => {
        if (typeof permission !== "string" || !permission.trim()) {
          throw new Error("permissions must be non-empty strings");
        }
        const normalized = permission.trim();
        if (normalized.length > 128)
          throw new Error("permissions entries must be 128 chars or less");
        return normalized;
      }),
    ),
  ];
}

function normalizeSignerMetadata(value: unknown): Record<string, unknown> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("metadata must be an object");
  }
  if (JSON.stringify(value).length > MAX_AGENT_SIGNER_METADATA_BYTES) {
    throw new Error(`metadata cannot exceed ${MAX_AGENT_SIGNER_METADATA_BYTES} bytes`);
  }
  return value as Record<string, unknown>;
}

function normalizeQuorumMemberSignerIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("memberSignerIds must be a non-empty array");
  }
  if (value.length > MAX_AGENT_KEY_QUORUM_MEMBERS) {
    throw new Error(`memberSignerIds cannot contain more than ${MAX_AGENT_KEY_QUORUM_MEMBERS}`);
  }
  return [
    ...new Set(
      value.map((id) => {
        if (typeof id !== "string" || !id.trim()) {
          throw new Error("memberSignerIds must contain non-empty strings");
        }
        return id.trim();
      }),
    ),
  ];
}

function normalizeQuorumThreshold(value: unknown, memberCount: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new Error("threshold must be a positive integer");
  }
  const threshold = Number(value);
  if (threshold > memberCount) throw new Error("threshold cannot exceed member count");
  return threshold;
}

async function validateQuorumMembers(
  tenantId: string,
  agentId: string,
  memberSignerIds: string[],
): Promise<string | null> {
  const rows = await db
    .select({ id: agentSigners.id, status: agentSigners.status })
    .from(agentSigners)
    .where(and(eq(agentSigners.tenantId, tenantId), eq(agentSigners.agentId, agentId)));
  const byId = new Map(rows.map((row) => [row.id, row.status]));
  for (const id of memberSignerIds) {
    const status = byId.get(id);
    if (!status) return `memberSignerIds contains unknown signer ${id}`;
    if (status !== "active") return `memberSignerIds contains inactive signer ${id}`;
  }
  return null;
}

function toAgentKeyQuorumResponse(row: typeof agentKeyQuorums.$inferSelect) {
  return {
    id: row.id,
    tenantId: row.tenantId,
    agentId: row.agentId,
    name: row.name,
    threshold: row.threshold,
    memberSignerIds: row.memberSignerIds,
    permissions: row.permissions,
    metadata: row.metadata,
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function normalizeTransferIntentPayload(row: typeof intents.$inferSelect): IntentSignRequest & {
  referenceId?: string;
} {
  const payload =
    row.intentType === "wallet_action" &&
    row.payload.action === "transfer" &&
    row.payload.transfer &&
    typeof row.payload.transfer === "object" &&
    !Array.isArray(row.payload.transfer)
      ? (row.payload.transfer as Record<string, unknown>)
      : row.payload;
  const value = typeof payload.value === "string" ? payload.value : payload.amountWei;
  const referenceId = normalizeOptionalText(
    payload.referenceId ?? payload.reference_id,
    "referenceId",
    128,
  );
  if (!isEvmAddress(payload.to))
    throw new IntentExecutionError("transfer.to must be an EVM address");
  if (!isUint256DecimalString(value)) {
    throw new IntentExecutionError("transfer value must be a uint256 wei string");
  }
  if (payload.data !== undefined && !isHex(payload.data)) {
    throw new IntentExecutionError("transfer.data must be hex");
  }
  if (payload.data && payload.data !== "0x") {
    throw new IntentExecutionError(
      "Contract-call transfer intent execution is disabled until selector policies are enforced",
      403,
    );
  }
  return {
    tenantId: row.tenantId,
    agentId: intentAgentId(row),
    to: payload.to,
    value,
    data: payload.data === "0x" ? undefined : payload.data,
    chainId: normalizeChainId(payload.chainId),
    nonce:
      payload.nonce === undefined
        ? undefined
        : Number.isSafeInteger(payload.nonce) && Number(payload.nonce) >= 0
          ? Number(payload.nonce)
          : (() => {
              throw new IntentExecutionError("transfer.nonce must be a non-negative integer");
            })(),
    gasLimit:
      payload.gasLimit === undefined
        ? undefined
        : isUint256DecimalString(payload.gasLimit)
          ? payload.gasLimit
          : (() => {
              throw new IntentExecutionError("transfer.gasLimit must be a uint256 decimal string");
            })(),
    broadcast: payload.broadcast !== false,
    ...(referenceId ? { referenceId } : {}),
  };
}

function normalizeSendCallsIntentPayload(row: typeof intents.$inferSelect): {
  tenantId: string;
  agentId: string;
  calls: IntentSendCall[];
  chainId: number;
  broadcast: boolean;
  totalValue: string;
  referenceId?: string;
} {
  const payload =
    row.intentType === "wallet_action" &&
    row.payload.action === "send_calls" &&
    row.payload.sendCalls &&
    typeof row.payload.sendCalls === "object" &&
    !Array.isArray(row.payload.sendCalls)
      ? (row.payload.sendCalls as Record<string, unknown>)
      : row.payload;
  if (!Array.isArray(payload.calls) || payload.calls.length === 0) {
    throw new IntentExecutionError("send_calls.calls must be a non-empty array");
  }
  if (payload.calls.length > 25) {
    throw new IntentExecutionError("send_calls.calls must contain at most 25 entries");
  }
  const chainId = normalizeChainId(payload.chainId);
  const referenceId = normalizeOptionalText(
    payload.referenceId ?? payload.reference_id,
    "referenceId",
    128,
  );
  let totalValue = 0n;
  const calls = payload.calls.map((rawCall, index) => {
    if (!rawCall || typeof rawCall !== "object" || Array.isArray(rawCall)) {
      throw new IntentExecutionError(`send_calls.calls[${index}] must be an object`);
    }
    const call = rawCall as Record<string, unknown>;
    const value = call.value === undefined ? "0" : call.value;
    if (!isEvmAddress(call.to)) {
      throw new IntentExecutionError(`send_calls.calls[${index}].to must be an EVM address`);
    }
    if (!isUint256DecimalString(value)) {
      throw new IntentExecutionError(
        `send_calls.calls[${index}].value must be a uint256 wei string`,
      );
    }
    if (call.data !== undefined && !isHex(call.data)) {
      throw new IntentExecutionError(`send_calls.calls[${index}].data must be hex`);
    }
    totalValue += BigInt(value);
    return {
      to: call.to,
      value,
      data: call.data === "0x" || call.data === undefined ? undefined : call.data,
    };
  });
  return {
    tenantId: row.tenantId,
    agentId: intentAgentId(row),
    calls,
    chainId,
    broadcast: payload.broadcast !== false,
    totalValue: totalValue.toString(),
    ...(referenceId ? { referenceId } : {}),
  };
}

async function executeTransferIntent(row: typeof intents.$inferSelect) {
  const request = normalizeTransferIntentPayload(row);
  const policySet = await getPolicySet(row.tenantId, request.agentId);
  const conditionSets = await loadConditionSetsForPolicies(row.tenantId, policySet);
  const rateLimitResult = await enforceRateLimit(request.agentId, policySet);
  if (!rateLimitResult.allowed) {
    throw new IntentExecutionError(rateLimitResult.reason || "Rate limit exceeded", 429);
  }

  return withAgentSpendLock(request.agentId, async () => {
    const stats = await getTransactionStats(request.agentId);
    const evaluation = await policyEngine.evaluate(policySet, {
      request,
      recentTxCount1h: stats.recentTxCount1h,
      recentTxCount24h: stats.recentTxCount24h,
      spentToday: stats.spentToday,
      spentThisWeek: stats.spentThisWeek,
      priceOracle,
      conditionSets,
    });
    if (!evaluation.approved && !evaluation.requiresManualApproval) {
      throw new IntentExecutionError("Transfer rejected by policy", 403);
    }

    const txId = row.id;
    let completedResult: Record<string, unknown> | null = null;
    try {
      const signed = await vault.signTransaction(request, {
        txId,
        policyResults: evaluation.results,
        status: request.broadcast === false ? "signed" : "broadcast",
      });
      completedResult = {
        handler: row.intentType === "wallet_action" ? "wallet_action.transfer" : "transfer",
        actionId: txId,
        status: request.broadcast === false ? "signed" : "broadcast",
        chainId: request.chainId,
        to: request.to,
        value: request.value,
        policyResults: evaluation.results,
        ...(request.broadcast === false ? { signedTx: signed } : { txHash: signed }),
      };
      await db
        .update(transactions)
        .set({
          actionType: "transfer",
          actionPayload: {
            type: "transfer",
            token: "native",
            broadcast: request.broadcast !== false,
            ...(request.referenceId ? { referenceId: request.referenceId } : {}),
            sourceIntentId: row.id,
          },
        })
        .where(eq(transactions.id, txId));
      if (request.broadcast !== false) {
        recordVaultSpend(request.agentId, row.tenantId, request.value, request.chainId).catch(
          (error) => console.error("[intents] Failed to record transfer intent spend:", error),
        );
      }
      return completedResult;
    } catch (error) {
      if (completedResult) {
        console.error("[intents] Post-transfer intent bookkeeping failed after signing:", error);
        return completedResult;
      }
      const message = error instanceof Error ? error.message : "Transfer execution failed";
      dispatchWebhook(row.tenantId, request.agentId, "wallet_action.transfer.failed", {
        actionId: txId,
        intent_id: row.id,
        error: message,
      });
      throw new IntentExecutionError(message, 502);
    }
  });
}

async function executeSendCallsIntent(row: typeof intents.$inferSelect) {
  const request = normalizeSendCallsIntentPayload(row);
  if (request.broadcast) {
    throw new IntentExecutionError(
      "Broadcasted send_calls intent execution is disabled until idempotent batch nonce tracking is implemented",
      403,
    );
  }
  const policySet = await getPolicySet(row.tenantId, request.agentId);
  if (
    request.calls.some((call) => hasContractCalldata(call.data)) &&
    !hasEnabledContractAllowlistPolicy(policySet)
  ) {
    throw new IntentExecutionError(
      "Contract-call send_calls intent execution requires an enabled contract-allowlist policy",
      403,
    );
  }
  const conditionSets = await loadConditionSetsForPolicies(row.tenantId, policySet);
  const rateLimitResult = await enforceRateLimit(request.agentId, policySet);
  if (!rateLimitResult.allowed) {
    throw new IntentExecutionError(rateLimitResult.reason || "Rate limit exceeded", 429);
  }

  return withAgentSpendLock(request.agentId, async () => {
    const stats = await getTransactionStats(request.agentId);
    let runningSpentToday = BigInt(stats.spentToday);
    let runningSpentThisWeek = BigInt(stats.spentThisWeek);
    const evaluations = [];
    for (const call of request.calls) {
      const signRequest: IntentSignRequest = {
        tenantId: row.tenantId,
        agentId: request.agentId,
        to: call.to,
        value: call.value,
        data: call.data,
        chainId: request.chainId,
        broadcast: request.broadcast,
      };
      evaluations.push(
        await policyEngine.evaluate(policySet, {
          request: signRequest,
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

    const hardRejected = evaluations.some(
      (evaluation) => !evaluation.approved && !evaluation.requiresManualApproval,
    );
    const policyResults = evaluations.flatMap((evaluation, index) =>
      evaluation.results.map((result) => ({ ...result, callIndex: index })),
    );
    if (hardRejected) {
      throw new IntentExecutionError("Batch calls rejected by policy", 403);
    }

    const signedCalls = [];
    try {
      for (const [index, call] of request.calls.entries()) {
        const txId = `${row.id}:${index}`;
        const signed = await vault.signTransaction(
          {
            tenantId: row.tenantId,
            agentId: request.agentId,
            to: call.to,
            value: call.value,
            data: call.data,
            chainId: request.chainId,
            broadcast: request.broadcast,
          },
          {
            txId,
            policyResults: policyResults.filter((result) => result.callIndex === index),
            status: request.broadcast === false ? "signed" : "broadcast",
          },
        );
        await db
          .update(transactions)
          .set({
            actionType: "send_calls",
            actionPayload: {
              type: "send_calls",
              parentIntentId: row.id,
              callIndex: index,
              broadcast: request.broadcast,
              totalValue: request.totalValue,
              calls: request.calls,
              ...(request.referenceId ? { referenceId: request.referenceId } : {}),
            },
          })
          .where(eq(transactions.id, txId));
        signedCalls.push({
          txId,
          callIndex: index,
          to: call.to,
          value: call.value,
          ...(request.broadcast === false ? { signedTx: signed } : { txHash: signed }),
        });
      }
      if (request.broadcast) {
        recordVaultSpend(request.agentId, row.tenantId, request.totalValue, request.chainId).catch(
          (error) => console.error("[intents] Failed to record send-calls intent spend:", error),
        );
      }
      return {
        handler: "wallet_action.send_calls",
        actionId: row.id,
        status: request.broadcast ? "broadcast" : "signed",
        chainId: request.chainId,
        callCount: request.calls.length,
        totalValue: request.totalValue,
        policyResults,
        signedCalls,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Batch call execution failed";
      dispatchWebhook(row.tenantId, request.agentId, "wallet_action.send_calls.failed", {
        actionId: row.id,
        intent_id: row.id,
        error: message,
      });
      throw new IntentExecutionError(message, 502);
    }
  });
}

async function executeRpcIntent(row: typeof intents.$inferSelect) {
  const method = normalizeRequiredText(row.payload.method, "method", 128);
  if (!VAULT_RPC_ALLOWLIST.has(method)) {
    throw new IntentExecutionError("RPC method is not allowlisted", 403);
  }
  const request = {
    method,
    params: Array.isArray(row.payload.params) ? row.payload.params : undefined,
    chainId: normalizeChainId(row.payload.chainId),
  };
  try {
    const result = await vault.rpcPassthrough(request);
    return {
      handler: "rpc",
      method,
      chainId: request.chainId,
      result,
    };
  } catch (error) {
    throw new IntentExecutionError(
      error instanceof Error ? error.message : "RPC intent execution failed",
      502,
    );
  }
}

function actorId(c: Context<{ Variables: AppVariables }>): string {
  return c.get("userId") ?? `${c.get("authType") ?? "tenant"}:${c.get("tenantId")}`;
}

function actorType(c: Context<{ Variables: AppVariables }>): string {
  return c.get("userId") ? "user" : (c.get("authType") ?? "api");
}

function auditActorType(c: Context<{ Variables: AppVariables }>): ActorType {
  if (c.get("userId")) return "user";
  if (c.get("authType") === "agent-token") return "agent";
  if (c.get("authType") === "api-key") return "api-key";
  return "platform";
}

async function ensureIntentAgent(tenantId: string, agentId: string | null) {
  if (!agentId) return true;
  const [agent] = await db
    .select({ id: agents.id })
    .from(agents)
    .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
  return Boolean(agent);
}

async function policySetAuthorizationBaseline(
  tenantId: string,
  agentId: string,
): Promise<IntentAuthorizationBaseline> {
  const rows = await db.select().from(policies).where(eq(policies.agentId, agentId));
  const policySet =
    rows.length > 0 ? rows.map(toPolicyRule) : await getPolicySet(tenantId, agentId);
  const conditionSets = await loadConditionSetsForPolicies(tenantId, policySet);
  const normalizedConditionSets = Object.fromEntries(
    Object.entries(conditionSets)
      .map(([id, values]) => [id, [...values].sort()] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  const normalized = rows
    .map((row) => ({
      id: row.id,
      type: row.type,
      enabled: row.enabled,
      config: row.config,
      updatedAt: row.updatedAt?.getTime?.() ?? null,
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
  return {
    kind: "policy-set",
    hash: await hashStableJson({
      tenantId,
      agentId,
      policies:
        normalized.length > 0
          ? normalized
          : policySet
              .map((policy) => ({
                id: policy.id,
                type: policy.type,
                enabled: policy.enabled,
                config: policy.config,
              }))
              .sort((left, right) => left.id.localeCompare(right.id)),
      conditionSets: normalizedConditionSets,
    }),
  };
}

async function quorumAuthorizationBaseline(
  tenantId: string,
  agentId: string,
  quorumId: string | null,
  memberSignerIds?: string[],
): Promise<IntentAuthorizationBaseline> {
  const [row] = quorumId
    ? await db
        .select()
        .from(agentKeyQuorums)
        .where(
          and(
            eq(agentKeyQuorums.id, quorumId),
            eq(agentKeyQuorums.tenantId, tenantId),
            eq(agentKeyQuorums.agentId, agentId),
          ),
        )
    : [];
  const signerIds = [...new Set(memberSignerIds ?? row?.memberSignerIds ?? [])].sort();
  const signerRows =
    signerIds.length === 0
      ? []
      : await db
          .select()
          .from(agentSigners)
          .where(
            and(
              eq(agentSigners.tenantId, tenantId),
              eq(agentSigners.agentId, agentId),
              inArray(agentSigners.id, signerIds),
            ),
          );
  const signers = signerRows
    .map((signer) => ({
      id: signer.id,
      signerType: signer.signerType,
      subjectType: signer.subjectType,
      subjectId: signer.subjectId,
      address: signer.address,
      chainFamily: signer.chainFamily,
      permissions: signer.permissions,
      metadata: signer.metadata,
      status: signer.status,
      updatedAt: signer.updatedAt?.getTime?.() ?? null,
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
  return {
    kind: "quorum",
    hash: await hashStableJson({
      tenantId,
      agentId,
      quorumId,
      quorum: row
        ? {
            id: row.id,
            name: row.name,
            threshold: row.threshold,
            memberSignerIds: row.memberSignerIds,
            permissions: row.permissions,
            metadata: row.metadata,
            status: row.status,
            updatedAt: row.updatedAt?.getTime?.() ?? null,
          }
        : null,
      signerIds,
      signers,
    }),
  };
}

async function buildIntentAuthorizationBaseline(
  row: typeof intents.$inferSelect,
): Promise<IntentAuthorizationBaseline | null> {
  const agentId = row.agentId;
  if (!agentId) return null;
  if (
    row.intentType === "policy_update" ||
    row.intentType === "policy_rule_update" ||
    row.intentType === "transfer" ||
    (row.intentType === "wallet_action" &&
      (row.payload.action === "transfer" || row.payload.action === "send_calls"))
  ) {
    return policySetAuthorizationBaseline(row.tenantId, agentId);
  }
  if (row.intentType === "quorum_update") {
    const action = normalizeRequiredText(row.payload.action, "action", 32);
    if (action === "create") {
      return quorumAuthorizationBaseline(
        row.tenantId,
        agentId,
        null,
        normalizeQuorumMemberSignerIds(row.payload.memberSignerIds),
      );
    }
    const quorumId = normalizeRequiredText(
      row.payload.quorumId ?? row.payload.quorum_id,
      "quorumId",
      64,
    );
    const [quorum] = await db
      .select({ memberSignerIds: agentKeyQuorums.memberSignerIds })
      .from(agentKeyQuorums)
      .where(
        and(
          eq(agentKeyQuorums.id, quorumId),
          eq(agentKeyQuorums.tenantId, row.tenantId),
          eq(agentKeyQuorums.agentId, agentId),
        ),
      );
    const memberSignerIds =
      row.payload.memberSignerIds === undefined
        ? quorum?.memberSignerIds
        : normalizeQuorumMemberSignerIds(row.payload.memberSignerIds);
    return quorumAuthorizationBaseline(row.tenantId, agentId, quorumId, memberSignerIds);
  }
  return null;
}

function intentAuthorizationBaseline(
  row: typeof intents.$inferSelect,
): IntentAuthorizationBaseline | null {
  const baseline = row.payload[AUTHORIZATION_BASELINE_KEY];
  if (!baseline || typeof baseline !== "object" || Array.isArray(baseline)) return null;
  const value = baseline as Record<string, unknown>;
  if (
    (value.kind !== "policy-set" && value.kind !== "quorum") ||
    typeof value.hash !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.hash)
  ) {
    return null;
  }
  return { kind: value.kind, hash: value.hash };
}

async function payloadWithIntentAuthorizationBaseline(row: typeof intents.$inferSelect) {
  const payload = payloadWithoutAuthorizationBaseline(row.payload);
  const baseline = await buildIntentAuthorizationBaseline({ ...row, payload });
  return baseline ? { ...payload, [AUTHORIZATION_BASELINE_KEY]: baseline } : payload;
}

async function assertIntentAuthorizationBaselineCurrent(row: typeof intents.$inferSelect) {
  const authorizedBaseline = intentAuthorizationBaseline(row);
  if (!authorizedBaseline) return;
  const currentBaseline = await buildIntentAuthorizationBaseline({
    ...row,
    payload: payloadWithoutAuthorizationBaseline(row.payload),
  });
  if (
    !currentBaseline ||
    currentBaseline.kind !== authorizedBaseline.kind ||
    currentBaseline.hash !== authorizedBaseline.hash
  ) {
    throw new IntentExecutionError(
      "Intent authorized state is stale; recreate and reauthorize",
      409,
    );
  }
}

function toIntentResponse(row: typeof intents.$inferSelect) {
  return {
    id: row.id,
    intent_id: row.id,
    tenantId: row.tenantId,
    agentId: row.agentId,
    wallet_id: row.agentId,
    intentType: row.intentType,
    intent_type: row.intentType,
    status: row.status,
    resourceType: row.resourceType,
    resource_id: row.resourceId,
    resourceId: row.resourceId,
    createdByType: row.createdByType,
    created_by_id: row.createdById,
    createdById: row.createdById,
    created_by_display_name: row.createdByDisplayName,
    createdByDisplayName: row.createdByDisplayName,
    authorizationDetails: row.authorizationDetails,
    authorization_details: row.authorizationDetails,
    payload: row.payload,
    executionResult: redactSignedTransactions(row.executionResult),
    execution_result: redactSignedTransactions(row.executionResult),
    expiresAt: row.expiresAt,
    expires_at: row.expiresAt?.getTime() ?? null,
    authorizedBy: row.authorizedBy,
    authorized_by: row.authorizedBy,
    canceledAt: row.canceledAt,
    canceledBy: row.canceledBy,
    canceled_by: row.canceledBy,
    cancellationReason: row.cancellationReason,
    cancellation_reason: row.cancellationReason,
    expiredAt: row.expiredAt,
    expiredBy: row.expiredBy,
    expired_by: row.expiredBy,
    rejectedAt: row.rejectedAt,
    rejectedBy: row.rejectedBy,
    rejected_by: row.rejectedBy,
    rejectionReason: row.rejectionReason,
    rejection_reason: row.rejectionReason,
    executedBy: row.executedBy,
    executed_by: row.executedBy,
    failedAt: row.failedAt,
    failedBy: row.failedBy,
    failed_by: row.failedBy,
    failureReason: row.failureReason,
    failure_reason: row.failureReason,
    createdAt: row.createdAt,
    created_at: row.createdAt.getTime(),
    updatedAt: row.updatedAt,
    authorizedAt: row.authorizedAt,
    executedAt: row.executedAt,
  };
}

function redactSignedTransactions(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSignedTransactions);
  if (!value || typeof value !== "object") return value;
  const redacted: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (key === "signedTx" || key === "signed_tx") {
      redacted[key] = "[redacted]";
    } else {
      redacted[key] = redactSignedTransactions(nested);
    }
  }
  return redacted;
}

async function writeIntentAudit(
  c: Context<{ Variables: AppVariables }>,
  action: string,
  intentId: string,
  metadata: Record<string, unknown>,
) {
  await writeAuditEvent({
    tenantId: c.get("tenantId"),
    actorType: auditActorType(c),
    actorId: actorId(c),
    action,
    resourceType: "intent",
    resourceId: intentId,
    metadata,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

function finalIntentAuditAction(status: string): string | null {
  return FINAL_INTENT_STATUSES.has(status) ? `intent.${status}` : null;
}

async function hasIntentAudit(
  tenantId: string,
  intentId: string,
  action: string,
): Promise<boolean> {
  const [row] = await db
    .select({ id: auditEvents.id })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.tenantId, tenantId),
        eq(auditEvents.resourceType, "intent"),
        eq(auditEvents.resourceId, intentId),
        eq(auditEvents.action, action),
      ),
    )
    .limit(1);
  return Boolean(row);
}

function dispatchFinalIntentWebhooks(
  tenantId: string,
  row: typeof intents.$inferSelect,
  executionResult?: Record<string, unknown>,
) {
  if (row.status === "executed") {
    const result =
      executionResult ??
      (row.executionResult && typeof row.executionResult === "object"
        ? (row.executionResult as Record<string, unknown>)
        : {});
    dispatchWalletActionSuccessWebhook(tenantId, row.agentId, result);
    dispatchIntentWebhook(tenantId, row.agentId, "intent.executed", row);
    return;
  }
  if (row.status === "authorized")
    dispatchIntentWebhook(tenantId, row.agentId, "intent.authorized", row);
  if (row.status === "failed") dispatchIntentWebhook(tenantId, row.agentId, "intent.failed", row);
  if (row.status === "rejected")
    dispatchIntentWebhook(tenantId, row.agentId, "intent.rejected", row);
  if (row.status === "canceled")
    dispatchIntentWebhook(tenantId, row.agentId, "intent.canceled", row);
  if (row.status === "expired") dispatchIntentWebhook(tenantId, row.agentId, "intent.expired", row);
}

function dispatchIntentWebhook(
  tenantId: string,
  agentId: string | null,
  type:
    | "intent.created"
    | "intent.authorized"
    | "intent.executed"
    | "intent.failed"
    | "intent.rejected"
    | "intent.canceled"
    | "intent.expired",
  row: typeof intents.$inferSelect,
) {
  if (!agentId) return;
  dispatchWebhook(tenantId, agentId, type, {
    intent_id: row.id,
    wallet_id: agentId,
    action_type: row.intentType,
    status: row.status,
    resource_id: row.resourceId,
    authorization_details: row.authorizationDetails,
    execution_result: redactSignedTransactions(row.executionResult),
    rejection_reason: row.rejectionReason,
    cancellation_reason: row.cancellationReason,
    failure_reason: row.failureReason,
  });
}

function dispatchWalletActionSuccessWebhook(
  tenantId: string,
  agentId: string | null,
  executionResult: Record<string, unknown>,
) {
  if (!agentId) return;
  if (executionResult.handler === "wallet_action.transfer") {
    dispatchWebhook(tenantId, agentId, "wallet_action.transfer.succeeded", {
      actionId: executionResult.actionId,
      intent_id: executionResult.actionId,
      txHash: executionResult.txHash,
      signedTx: executionResult.signedTx ? "[redacted]" : undefined,
    });
  }
  if (executionResult.handler === "wallet_action.send_calls") {
    dispatchWebhook(tenantId, agentId, "wallet_action.send_calls.succeeded", {
      actionId: executionResult.actionId,
      intent_id: executionResult.actionId,
      signedCalls: redactSignedTransactions(executionResult.signedCalls),
    });
  }
}

class IntentExecutionError extends Error {
  constructor(
    message: string,
    readonly status: IntentHttpStatus = 400,
  ) {
    super(message);
  }
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

function intentAgentId(row: typeof intents.$inferSelect): string {
  if (!row.agentId) throw new IntentExecutionError("Intent execution requires agentId");
  return row.agentId;
}

async function executeWalletUpdateIntent(row: typeof intents.$inferSelect) {
  const payload = row.payload;
  const updates: Partial<typeof agents.$inferInsert> = {};
  if (payload.name !== undefined || payload.displayName !== undefined) {
    updates.name = normalizeRequiredText(payload.name ?? payload.displayName, "name", 255);
  }
  if (payload.platformId !== undefined) {
    updates.platformId = normalizeOptionalText(payload.platformId, "platformId", 255);
  }
  if (payload.erc8004TokenId !== undefined) {
    updates.erc8004TokenId = normalizeOptionalText(payload.erc8004TokenId, "erc8004TokenId", 255);
  }

  if (Object.keys(updates).length === 0) {
    throw new IntentExecutionError(
      "wallet_update payload must include at least one updatable field",
    );
  }

  const [updated] = await db
    .update(agents)
    .set({ ...updates, updatedAt: new Date() })
    .where(and(eq(agents.id, intentAgentId(row)), eq(agents.tenantId, row.tenantId)))
    .returning();
  if (!updated) throw new IntentExecutionError("Agent not found", 404);
  return {
    handler: "wallet_update",
    agentId: updated.id,
    updatedFields: Object.keys(updates),
  };
}

async function executePolicyUpdateIntent(row: typeof intents.$inferSelect) {
  const agentId = intentAgentId(row);
  const payload = row.payload;
  const nextPolicies = payload.policies;
  if (!Array.isArray(nextPolicies)) {
    throw new IntentExecutionError("policy_update payload.policies must be an array");
  }
  if (nextPolicies.length === 0 && payload.allowClearAllPolicies !== true) {
    throw new IntentExecutionError(
      "policy_update clearing all policies requires allowClearAllPolicies=true",
      403,
    );
  }

  const policyValidationError = getPolicyRulesValidationError(nextPolicies);
  if (policyValidationError) throw new IntentExecutionError(policyValidationError);
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    row.tenantId,
    nextPolicies,
  );
  if (conditionSetValidationError) throw new IntentExecutionError(conditionSetValidationError);

  const storedPolicies = await db.transaction(async (tx) => {
    await tx.delete(policies).where(eq(policies.agentId, agentId));
    if (nextPolicies.length > 0) {
      const persistedPolicies = (nextPolicies as PolicyRule[]).map(toPersistedPolicyRule);
      await tx.insert(policies).values(
        persistedPolicies.map((policy) => ({
          id: policy.id || crypto.randomUUID(),
          agentId,
          type: policy.type,
          enabled: policy.enabled,
          config: policy.config,
        })),
      );
    }
    return tx.select().from(policies).where(eq(policies.agentId, agentId));
  });

  return {
    handler: "policy_update",
    agentId,
    policies: storedPolicies.map(toPolicyRule),
  };
}

async function executePolicyRuleUpdateIntent(row: typeof intents.$inferSelect) {
  const agentId = intentAgentId(row);
  const payload = row.payload;
  const action = normalizeRequiredText(payload.action, "action", 32);
  if (!["create", "update", "delete"].includes(action)) {
    throw new IntentExecutionError(
      "policy_rule_update payload.action must be create, update, or delete",
    );
  }

  const currentRows = await db.select().from(policies).where(eq(policies.agentId, agentId));
  if (action === "delete") {
    const ruleId = normalizeRequiredText(payload.ruleId ?? payload.rule_id, "ruleId", 64);
    const existing = currentRows.find((rule) => rule.id === ruleId);
    if (!existing) throw new IntentExecutionError("Policy rule not found", 404);
    if (currentRows.length === 1 && payload.allowDeleteLastPolicy !== true) {
      throw new IntentExecutionError(
        "Deleting the final policy rule requires allowDeleteLastPolicy=true",
        403,
      );
    }
    const [deleted] = await db
      .delete(policies)
      .where(and(eq(policies.agentId, agentId), eq(policies.id, ruleId)))
      .returning();
    return { handler: "policy_rule_update", action, agentId, rule: toPolicyRule(deleted) };
  }

  let nextRule: PolicyRule;
  if (action === "create") {
    nextRule = normalizePolicyRuleInput(payload.rule);
    const [existingRuleId] = await db
      .select({ id: policies.id })
      .from(policies)
      .where(eq(policies.id, nextRule.id));
    if (existingRuleId) throw new IntentExecutionError("Policy rule id already exists", 409);
    const nextRules = [...currentRows.map(toPolicyRule), nextRule];
    const policyValidationError = getPolicyRulesValidationError(nextRules);
    if (policyValidationError) throw new IntentExecutionError(policyValidationError);
    const conditionSetValidationError = await getConditionSetReferenceValidationError(
      row.tenantId,
      nextRules,
    );
    if (conditionSetValidationError) throw new IntentExecutionError(conditionSetValidationError);
    const persistedRule = toPersistedPolicyRule(nextRule);
    await db.insert(policies).values({
      id: persistedRule.id,
      agentId,
      type: persistedRule.type,
      enabled: persistedRule.enabled,
      config: persistedRule.config,
    });
    return { handler: "policy_rule_update", action, agentId, rule: nextRule };
  }

  const ruleId = normalizeRequiredText(payload.ruleId ?? payload.rule_id, "ruleId", 64);
  const existing = currentRows.find((rule) => rule.id === ruleId);
  if (!existing) throw new IntentExecutionError("Policy rule not found", 404);
  nextRule = normalizePolicyRulePatch(toPolicyRule(existing), payload.patch ?? payload.rule);
  const nextRules = currentRows.map((rule) => (rule.id === ruleId ? nextRule : toPolicyRule(rule)));
  const policyValidationError = getPolicyRulesValidationError(nextRules);
  if (policyValidationError) throw new IntentExecutionError(policyValidationError);
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    row.tenantId,
    nextRules,
  );
  if (conditionSetValidationError) throw new IntentExecutionError(conditionSetValidationError);

  const persistedRule = toPersistedPolicyRule(nextRule);
  const [updated] = await db
    .update(policies)
    .set({
      type: persistedRule.type,
      enabled: persistedRule.enabled,
      config: persistedRule.config,
      updatedAt: new Date(),
    })
    .where(and(eq(policies.agentId, agentId), eq(policies.id, ruleId)))
    .returning();
  if (!updated) throw new IntentExecutionError("Policy rule not found", 404);
  return { handler: "policy_rule_update", action, agentId, rule: toPolicyRule(updated) };
}

async function executeQuorumUpdateIntent(row: typeof intents.$inferSelect) {
  const agentId = intentAgentId(row);
  const payload = row.payload;
  const action = normalizeRequiredText(payload.action, "action", 32);
  if (!["create", "update", "revoke"].includes(action)) {
    throw new IntentExecutionError(
      "quorum_update payload.action must be create, update, or revoke",
    );
  }

  if (action === "create") {
    const name = normalizeRequiredText(payload.name, "name", 255);
    const memberSignerIds = normalizeQuorumMemberSignerIds(payload.memberSignerIds);
    const threshold = normalizeQuorumThreshold(payload.threshold, memberSignerIds.length);
    const permissions = normalizeSignerPermissions(payload.permissions);
    const metadata = normalizeSignerMetadata(payload.metadata);
    const memberError = await validateQuorumMembers(row.tenantId, agentId, memberSignerIds);
    if (memberError) throw new IntentExecutionError(memberError);
    const [created] = await db
      .insert(agentKeyQuorums)
      .values({
        tenantId: row.tenantId,
        agentId,
        name,
        threshold,
        memberSignerIds,
        permissions,
        metadata,
        status: "active",
        createdBy: row.authorizedBy,
      })
      .returning();
    return { handler: "quorum_update", action, quorum: toAgentKeyQuorumResponse(created) };
  }

  const quorumId = normalizeRequiredText(payload.quorumId ?? payload.quorum_id, "quorumId", 64);
  const [existing] = await db
    .select()
    .from(agentKeyQuorums)
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, row.tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    );
  if (!existing) throw new IntentExecutionError("Key quorum not found", 404);

  if (action === "revoke") {
    const [revoked] = await db
      .update(agentKeyQuorums)
      .set({ status: "revoked", updatedAt: new Date() })
      .where(
        and(
          eq(agentKeyQuorums.id, quorumId),
          eq(agentKeyQuorums.tenantId, row.tenantId),
          eq(agentKeyQuorums.agentId, agentId),
        ),
      )
      .returning();
    return { handler: "quorum_update", action, quorum: toAgentKeyQuorumResponse(revoked) };
  }

  const updates: Partial<typeof agentKeyQuorums.$inferInsert> = {};
  if (payload.name !== undefined) updates.name = normalizeRequiredText(payload.name, "name", 255);
  const nextMemberSignerIds =
    payload.memberSignerIds === undefined
      ? existing.memberSignerIds
      : normalizeQuorumMemberSignerIds(payload.memberSignerIds);
  if (payload.memberSignerIds !== undefined) updates.memberSignerIds = nextMemberSignerIds;
  if (payload.threshold !== undefined) {
    updates.threshold = normalizeQuorumThreshold(payload.threshold, nextMemberSignerIds.length);
  } else if (
    payload.memberSignerIds !== undefined &&
    existing.threshold > nextMemberSignerIds.length
  ) {
    throw new IntentExecutionError("threshold cannot exceed member count");
  }
  if (payload.permissions !== undefined)
    updates.permissions = normalizeSignerPermissions(payload.permissions);
  if (payload.metadata !== undefined) updates.metadata = normalizeSignerMetadata(payload.metadata);
  if (payload.status !== undefined) {
    const status = normalizeRequiredText(payload.status, "status", 32);
    if (!AGENT_KEY_QUORUM_STATUSES.has(status)) {
      throw new IntentExecutionError("status must be one of: active, paused, revoked");
    }
    updates.status = status;
  }
  if (payload.memberSignerIds !== undefined) {
    const memberError = await validateQuorumMembers(row.tenantId, agentId, nextMemberSignerIds);
    if (memberError) throw new IntentExecutionError(memberError);
  }
  if (Object.keys(updates).length === 0) {
    throw new IntentExecutionError("No key quorum updates provided");
  }

  const [updated] = await db
    .update(agentKeyQuorums)
    .set({ ...updates, updatedAt: new Date() })
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, row.tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    )
    .returning();
  return { handler: "quorum_update", action, quorum: toAgentKeyQuorumResponse(updated) };
}

async function executeTypedIntent(
  row: typeof intents.$inferSelect,
): Promise<Record<string, unknown>> {
  if (row.intentType === "wallet_update") return executeWalletUpdateIntent(row);
  if (row.intentType === "policy_update") return executePolicyUpdateIntent(row);
  if (row.intentType === "policy_rule_update") return executePolicyRuleUpdateIntent(row);
  if (row.intentType === "quorum_update") return executeQuorumUpdateIntent(row);
  if (row.intentType === "transfer") return executeTransferIntent(row);
  if (row.intentType === "rpc") return executeRpcIntent(row);
  if (row.intentType === "wallet_action") {
    if (row.payload.action === "transfer") return executeTransferIntent(row);
    if (row.payload.action === "send_calls") return executeSendCallsIntent(row);
    throw new IntentExecutionError(
      "Only wallet_action transfer and send_calls intent execution is currently supported",
      403,
    );
  }
  throw new IntentExecutionError(`No typed executor is available for ${row.intentType}`);
}

intentRoutes.get("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const limit = parseListLimit(c.req.query("limit"));
  const offset = parseListOffset(c.req.query("offset"));
  if (limit === null || offset === null) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid limit or offset" }, 400);
  }
  const status = c.req.query("status");
  if (status && !INTENT_STATUSES.has(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid intent status" }, 400);
  }
  const intentType = c.req.query("intentType") ?? c.req.query("type");
  if (intentType && !INTENT_TYPES.has(intentType)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid intent type" }, 400);
  }
  const agentId = c.req.query("agentId");

  const conditions: SQL[] = [eq(intents.tenantId, tenantId)];
  if (status) conditions.push(eq(intents.status, status));
  if (intentType) conditions.push(eq(intents.intentType, intentType));
  if (agentId) conditions.push(eq(intents.agentId, agentId));

  const rows = await db
    .select()
    .from(intents)
    .where(and(...conditions))
    .orderBy(desc(intents.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({
    ok: true,
    data: { intents: rows.map(toIntentResponse), limit, offset },
  });
});

intentRoutes.post("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  let intentType: string;
  let agentId: string | null;
  let resourceType: string | null;
  let resourceId: string | null;
  let authorizationDetails: Array<Record<string, unknown>>;
  let payload: Record<string, unknown>;
  let expiresAt: Date | null;
  try {
    intentType = normalizeIntentType(body.intentType ?? body.intent_type);
    agentId = normalizeOptionalText(body.agentId ?? body.wallet_id, "agentId", 64);
    resourceType = normalizeOptionalText(
      body.resourceType ?? body.resource_type,
      "resourceType",
      64,
    );
    resourceId = normalizeOptionalText(body.resourceId ?? body.resource_id, "resourceId", 255);
    authorizationDetails = normalizeAuthorizationDetails(
      body.authorizationDetails ?? body.authorization_details,
    );
    payload = payloadWithoutAuthorizationBaseline(normalizeJsonObject(body.payload, "payload", {}));
    expiresAt = normalizeIntentExpiry(body.expiresAt ?? body.expires_at, body.ttlSeconds);
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid intent payload" },
      400,
    );
  }
  if (!(await ensureIntentAgent(tenantId, agentId))) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  if (c.get("authType") === "api-key" && HUMAN_APPROVER_INTENT_TYPES.has(intentType)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Control-plane intents require a human owner/admin session as creator",
      },
      403,
    );
  }
  if (hasAuthorizationRequirements(authorizationDetails)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "authorizationDetails are not supported until multi-approver enforcement is implemented",
      },
      400,
    );
  }

  const id = crypto.randomUUID();
  const [row] = await db
    .insert(intents)
    .values({
      id,
      tenantId,
      agentId,
      intentType,
      status: "pending",
      resourceType,
      resourceId,
      createdByType: actorType(c),
      createdById: actorId(c),
      createdByDisplayName: normalizeOptionalText(
        body.createdByDisplayName ?? body.created_by_display_name,
        "createdByDisplayName",
        255,
      ),
      authorizationDetails,
      payload,
      expiresAt,
    })
    .returning();

  await writeIntentAudit(c, "intent.create", row.id, {
    agentId,
    intentType,
    resourceType,
    resourceId,
  });
  dispatchIntentWebhook(tenantId, agentId, "intent.created", row);

  return c.json<ApiResponse>({ ok: true, data: toIntentResponse(row) }, 201);
});

intentRoutes.get("/:intentId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  const [row] = await db
    .select()
    .from(intents)
    .where(and(eq(intents.id, c.req.param("intentId")), eq(intents.tenantId, c.get("tenantId"))));
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Intent not found" }, 404);
  return c.json<ApiResponse>({ ok: true, data: toIntentResponse(row) });
});

async function updateIntentStatus(
  c: Context<{ Variables: AppVariables }>,
  status: "authorized" | "executed" | "failed" | "rejected" | "canceled" | "expired",
) {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const intentId = c.req.param("intentId");
  if (!intentId) return c.json<ApiResponse>({ ok: false, error: "Intent id is required" }, 400);
  const body = (await safeJsonParse<Record<string, unknown>>(c)) ?? {};
  const [existing] = await db
    .select()
    .from(intents)
    .where(and(eq(intents.id, intentId), eq(intents.tenantId, tenantId)));
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Intent not found" }, 404);

  if (
    status === "authorized" ||
    status === "rejected" ||
    status === "executed" ||
    status === "failed" ||
    status === "canceled" ||
    status === "expired"
  ) {
    if (!requireHumanIntentApprover(c)) {
      const action =
        status === "executed" ||
        status === "failed" ||
        status === "canceled" ||
        status === "expired"
          ? "finalization"
          : "authorization";
      return c.json<ApiResponse>(
        { ok: false, error: `Intent ${action} requires owner or admin user session` },
        403,
      );
    }
    if (!hasRecentSessionMfa(c)) {
      const action =
        status === "executed" ||
        status === "failed" ||
        status === "canceled" ||
        status === "expired"
          ? "finalization"
          : "authorization";
      return c.json<ApiResponse>(
        { ok: false, error: `Intent ${action} requires recent MFA verification` },
        403,
      );
    }
  }

  if (
    status !== "expired" &&
    existing.expiresAt &&
    existing.expiresAt.getTime() <= Date.now() &&
    ["pending", "authorized"].includes(existing.status)
  ) {
    const now = new Date();
    const [expired] = await db
      .update(intents)
      .set({
        status: "expired",
        updatedAt: now,
        expiredAt: now,
        expiredBy: "system:expires_at",
      })
      .where(
        and(
          eq(intents.id, intentId),
          eq(intents.tenantId, tenantId),
          inArray(intents.status, ["pending", "authorized"]),
        ),
      )
      .returning();
    if (!expired) return c.json<ApiResponse>({ ok: false, error: "Intent is terminal" }, 409);
    await writeIntentAudit(c, "intent.expired", expired.id, {
      agentId: expired.agentId,
      intentType: expired.intentType,
    });
    dispatchIntentWebhook(tenantId, expired.agentId, "intent.expired", expired);
    return c.json<ApiResponse>(
      { ok: false, error: "Intent has expired", data: toIntentResponse(expired) },
      409,
    );
  }

  if (existing.status === status) {
    const finalAuditAction = finalIntentAuditAction(status);
    if (finalAuditAction && !(await hasIntentAudit(tenantId, existing.id, finalAuditAction))) {
      await writeIntentAudit(c, finalAuditAction, existing.id, {
        agentId: existing.agentId,
        intentType: existing.intentType,
        repaired: true,
      });
      dispatchFinalIntentWebhooks(tenantId, existing);
      return c.json<ApiResponse>({ ok: true, data: toIntentResponse(existing) });
    }
  }

  if ((status === "authorized" || status === "rejected") && existing.status !== "pending") {
    return c.json<ApiResponse>({ ok: false, error: "Intent is no longer pending" }, 409);
  }
  if (
    status === "authorized" &&
    existing.createdByType === "user" &&
    existing.createdById === actorId(c)
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "Intent authorization requires a different approver" },
      403,
    );
  }
  if (
    (status === "authorized" || status === "executed") &&
    hasAuthorizationRequirements(existing.authorizationDetails)
  ) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Intent authorization requirements are not enforceable by this route; recreate without authorizationDetails or use a supported approval flow",
      },
      409,
    );
  }
  if (status === "executed" && existing.status !== "authorized") {
    return c.json<ApiResponse>(
      { ok: false, error: "Intent must be authorized before execution" },
      409,
    );
  }
  if (status === "executed") {
    try {
      await assertIntentAuthorizationBaselineCurrent(existing);
    } catch (error) {
      if (error instanceof IntentExecutionError) {
        return c.json<ApiResponse>({ ok: false, error: error.message }, error.status);
      }
      throw error;
    }
  }
  if (status === "failed" && !["pending", "authorized"].includes(existing.status)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Only pending or authorized intents can be failed" },
      409,
    );
  }
  if (status === "canceled" && !["pending", "authorized"].includes(existing.status)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Only pending or authorized intents can be canceled" },
      409,
    );
  }
  if (status === "expired" && !["pending", "authorized"].includes(existing.status)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Only pending or authorized intents can expire" },
      409,
    );
  }
  if (status === "executed") {
    await writeIntentAudit(c, "intent.execute.authorized", existing.id, {
      agentId: existing.agentId,
      intentType: existing.intentType,
    });
    const claimedAt = new Date();
    const [claimedUpdate] = await db
      .update(intents)
      .set({
        status: "executing",
        updatedAt: claimedAt,
        executedBy: actorId(c),
      })
      .where(
        and(
          eq(intents.id, intentId),
          eq(intents.tenantId, tenantId),
          eq(intents.status, "authorized"),
          intentNotExpiredPredicate(),
        ),
      )
      .returning();
    if (!claimedUpdate) {
      const [expired] = await db
        .update(intents)
        .set({
          status: "expired",
          updatedAt: new Date(),
          expiredAt: new Date(),
          expiredBy: "system:expires_at",
        })
        .where(
          and(
            eq(intents.id, intentId),
            eq(intents.tenantId, tenantId),
            eq(intents.status, "authorized"),
            sql`${intents.expiresAt} is not null and ${intents.expiresAt} <= now()`,
          ),
        )
        .returning();
      if (expired) {
        await writeIntentAudit(c, "intent.expired", expired.id, {
          agentId: expired.agentId,
          intentType: expired.intentType,
        });
        dispatchIntentWebhook(tenantId, expired.agentId, "intent.expired", expired);
        return c.json<ApiResponse>(
          { ok: false, error: "Intent has expired", data: toIntentResponse(expired) },
          409,
        );
      }
      return c.json<ApiResponse>({ ok: false, error: "Intent lifecycle conflict" }, 409);
    }
    const [claimed] = await db
      .select()
      .from(intents)
      .where(and(eq(intents.id, intentId), eq(intents.tenantId, tenantId)));
    if (!claimed || claimed.status !== "executing") {
      return c.json<ApiResponse>({ ok: false, error: "Intent lifecycle conflict" }, 409);
    }

    let executionResult: Record<string, unknown>;
    try {
      await assertIntentAuthorizationBaselineCurrent(claimed);
      executionResult = await executeTypedIntent(claimed);
    } catch (error) {
      const failureReason = error instanceof Error ? error.message : "Invalid intent execution";
      const failedAt = new Date();
      const [failed] = await db
        .update(intents)
        .set({
          status: "failed",
          updatedAt: failedAt,
          failedAt,
          failedBy: actorId(c),
          failureReason,
        })
        .where(
          and(
            eq(intents.id, intentId),
            eq(intents.tenantId, tenantId),
            eq(intents.status, "executing"),
          ),
        )
        .returning();
      if (failed) {
        await writeIntentAudit(c, "intent.failed", failed.id, {
          agentId: failed.agentId,
          intentType: failed.intentType,
          reason: failureReason,
        });
        dispatchIntentWebhook(tenantId, failed.agentId, "intent.failed", failed);
      }
      if (error instanceof IntentExecutionError) {
        if (error.status === 403) {
          return c.json<ApiResponse>({ ok: false, error: error.message }, 403);
        }
        if (error.status === 404) {
          return c.json<ApiResponse>({ ok: false, error: error.message }, 404);
        }
        if (error.status === 409) {
          return c.json<ApiResponse>({ ok: false, error: error.message }, 409);
        }
        if (error.status === 429) {
          return c.json<ApiResponse>({ ok: false, error: error.message }, 429);
        }
        if (error.status === 502) {
          return c.json<ApiResponse>({ ok: false, error: error.message }, 502);
        }
        return c.json<ApiResponse>({ ok: false, error: error.message }, 400);
      }
      return c.json<ApiResponse>({ ok: false, error: failureReason }, 400);
    }

    const storedExecutionResult = redactSignedTransactions(executionResult) as Record<
      string,
      unknown
    >;
    const now = new Date();
    const [row] = await db
      .update(intents)
      .set({
        status: "executed",
        executionResult: storedExecutionResult,
        updatedAt: now,
        executedAt: now,
        executedBy: actorId(c),
      })
      .where(
        and(
          eq(intents.id, intentId),
          eq(intents.tenantId, tenantId),
          eq(intents.status, "executing"),
        ),
      )
      .returning();
    if (!row) return c.json<ApiResponse>({ ok: false, error: "Intent lifecycle conflict" }, 409);

    await writeIntentAudit(c, "intent.executed", row.id, {
      agentId: row.agentId,
      intentType: row.intentType,
    });
    dispatchWalletActionSuccessWebhook(tenantId, row.agentId, executionResult);
    dispatchIntentWebhook(tenantId, row.agentId, "intent.executed", row);
    return c.json<ApiResponse>({
      ok: true,
      data: {
        ...toIntentResponse(row),
        executionResult,
        execution_result: executionResult,
      },
    });
  }

  const lifecycleStatus = status as "authorized" | "failed" | "rejected" | "canceled" | "expired";
  const allowedStatuses =
    lifecycleStatus === "failed" || lifecycleStatus === "canceled" || lifecycleStatus === "expired"
      ? ["pending", "authorized"]
      : ["pending"];

  const executionResult =
    lifecycleStatus === "failed"
      ? normalizeJsonObject(body.executionResult ?? body.execution_result, "executionResult", {})
      : existing.executionResult;
  const now = new Date();
  const reason = typeof body.reason === "string" && body.reason.trim() ? body.reason.trim() : null;
  const payload =
    lifecycleStatus === "authorized"
      ? await payloadWithIntentAuthorizationBaseline(existing)
      : existing.payload;
  await writeIntentAudit(c, `intent.${lifecycleStatus}.authorized`, existing.id, {
    agentId: existing.agentId,
    intentType: existing.intentType,
    previousStatus: existing.status,
    reason: reason ?? undefined,
  });
  const [row] = await db
    .update(intents)
    .set({
      status: lifecycleStatus,
      payload,
      executionResult,
      updatedAt: now,
      authorizedAt: lifecycleStatus === "authorized" ? now : existing.authorizedAt,
      authorizedBy: lifecycleStatus === "authorized" ? actorId(c) : existing.authorizedBy,
      executedAt: existing.executedAt,
      executedBy: existing.executedBy,
      canceledAt: lifecycleStatus === "canceled" ? now : existing.canceledAt,
      canceledBy: lifecycleStatus === "canceled" ? actorId(c) : existing.canceledBy,
      cancellationReason: lifecycleStatus === "canceled" ? reason : existing.cancellationReason,
      expiredAt: lifecycleStatus === "expired" ? now : existing.expiredAt,
      expiredBy: lifecycleStatus === "expired" ? "system:manual" : existing.expiredBy,
      rejectedAt: lifecycleStatus === "rejected" ? now : existing.rejectedAt,
      rejectedBy: lifecycleStatus === "rejected" ? actorId(c) : existing.rejectedBy,
      rejectionReason: lifecycleStatus === "rejected" ? reason : existing.rejectionReason,
      failedAt: lifecycleStatus === "failed" ? now : existing.failedAt,
      failedBy: lifecycleStatus === "failed" ? actorId(c) : existing.failedBy,
      failureReason: lifecycleStatus === "failed" ? reason : existing.failureReason,
    })
    .where(
      and(
        eq(intents.id, intentId),
        eq(intents.tenantId, tenantId),
        inArray(intents.status, allowedStatuses),
        lifecycleStatus !== "expired" ? intentNotExpiredPredicate() : undefined,
      ),
    )
    .returning();
  if (!row) {
    if (lifecycleStatus !== "expired") {
      const [expired] = await db
        .update(intents)
        .set({
          status: "expired",
          updatedAt: new Date(),
          expiredAt: new Date(),
          expiredBy: "system:expires_at",
        })
        .where(
          and(
            eq(intents.id, intentId),
            eq(intents.tenantId, tenantId),
            inArray(intents.status, allowedStatuses),
            sql`${intents.expiresAt} is not null and ${intents.expiresAt} <= now()`,
          ),
        )
        .returning();
      if (expired) {
        await writeIntentAudit(c, "intent.expired", expired.id, {
          agentId: expired.agentId,
          intentType: expired.intentType,
        });
        dispatchIntentWebhook(tenantId, expired.agentId, "intent.expired", expired);
        return c.json<ApiResponse>(
          { ok: false, error: "Intent has expired", data: toIntentResponse(expired) },
          409,
        );
      }
    }
    return c.json<ApiResponse>({ ok: false, error: "Intent lifecycle conflict" }, 409);
  }

  await writeIntentAudit(c, `intent.${lifecycleStatus}`, row.id, {
    agentId: row.agentId,
    intentType: row.intentType,
    reason: reason ?? undefined,
  });
  dispatchIntentWebhook(
    tenantId,
    row.agentId,
    lifecycleStatus === "authorized"
      ? "intent.authorized"
      : lifecycleStatus === "failed"
        ? "intent.failed"
        : lifecycleStatus === "canceled"
          ? "intent.canceled"
          : lifecycleStatus === "expired"
            ? "intent.expired"
            : "intent.rejected",
    row,
  );

  return c.json<ApiResponse>({ ok: true, data: toIntentResponse(row) });
}

intentRoutes.post("/:intentId/authorize", (c) => updateIntentStatus(c, "authorized"));
intentRoutes.post("/:intentId/reject", (c) => updateIntentStatus(c, "rejected"));
intentRoutes.post("/:intentId/execute", (c) => updateIntentStatus(c, "executed"));
intentRoutes.post("/:intentId/fail", (c) => updateIntentStatus(c, "failed"));
intentRoutes.post("/:intentId/cancel", (c) => updateIntentStatus(c, "canceled"));
intentRoutes.post("/:intentId/expire", (c) => updateIntentStatus(c, "expired"));
