/**
 * Agent CRUD, batch creation, token generation, and policy management routes.
 *
 * Mount: app.route("/agents", agentRoutes)
 */

import { hashSha256Hex, revocationStore } from "@stwd/auth";
import { agentPolicies, toPersistedPolicyRule } from "@stwd/db";
import { getSpend, getSpendByHost, invalidateCache, type SpendPeriod } from "@stwd/redis";
import { and, eq, gte, sql } from "drizzle-orm";
import { Hono } from "hono";
import { isRedisAvailable } from "../middleware/redis";
import { writeAuditEvent } from "../services/audit";
import {
  AGENT_TOKEN_EXPIRY,
  type AgentIdentity,
  type ApiResponse,
  type AppVariables,
  agentKeyQuorums,
  agentSigners,
  agents,
  agentWallets,
  approvalQueue,
  createAgentToken,
  db,
  encryptedChainKeys,
  encryptedKeys,
  ensureAgentForTenant,
  getConditionSetReferenceValidationError,
  getTransactionStats,
  isNonEmptyString,
  isValidAgentId,
  type PolicyRule,
  parseAgentTokenScopes,
  policies,
  priceOracle,
  requireAgentAccess,
  requireTenantLevel,
  safeJsonParse,
  sanitizeErrorMessage,
  setNoStoreHeaders,
  toPolicyRule,
  transactions,
  vault,
} from "../services/context";
import {
  publicGasSponsorshipState,
  readTenantGasSponsorshipConfig,
} from "../services/gas-sponsorship";
import { getPolicyRulesValidationError } from "../services/policy-validation";
import { createSignerCredentialHash } from "../services/signer-credentials";

export const agentRoutes = new Hono<{ Variables: AppVariables }>();

const MAX_BATCH_AGENTS = 25;
const MAX_POLICIES_PER_AGENT = 100;
const MAX_AGENT_LIST_LIMIT = 200;
const MAX_AGENT_TOKEN_SECONDS = 30 * 24 * 60 * 60;
const MAX_CUSTOM_TOKEN_BALANCES = 25;
const SPEND_PERIODS = ["day", "week", "month"] as const satisfies readonly SpendPeriod[];

const TRADE_POLICY_DEFAULTS = {
  dailyCap: 1000,
  perOrderCap: 500,
  leverageCap: 10,
  allowedAssets: ["BTC", "ETH", "BNB"],
  allowedVenues: ["hyperliquid"],
} as const;

const TRADE_POLICY_LAYER_1_MAX = {
  dailyCap: 50_000,
  perOrderCap: 10_000,
  leverageCap: 50,
} as const;

type AgentTradePolicyResponse = {
  agentId: string;
  dailyCap: number;
  perOrderCap: number;
  leverageCap: number;
  allowedAssets: string[];
  allowedVenues: string[];
  updatedAt: string;
  updatedBy: string;
  updatedReason: string | null;
};

type AgentTradePolicySnapshot = Omit<
  AgentTradePolicyResponse,
  "updatedAt" | "updatedBy" | "updatedReason"
>;

type AgentTradePolicyPatch = {
  dailyCap?: unknown;
  perOrderCap?: unknown;
  leverageCap?: unknown;
  allowedAssets?: unknown;
  allowedVenues?: unknown;
  reason?: unknown;
  multisigApproval?: unknown;
};

function parseNumericPolicyValue(value: string | number): number {
  return typeof value === "number" ? value : Number(value);
}

function policyRowToResponse(row: typeof agentPolicies.$inferSelect): AgentTradePolicyResponse {
  return {
    agentId: row.agentId,
    dailyCap: parseNumericPolicyValue(row.dailyCapUsd),
    perOrderCap: parseNumericPolicyValue(row.perOrderCapUsd),
    leverageCap: parseNumericPolicyValue(row.leverageCap),
    allowedAssets: row.allowedAssets,
    allowedVenues: row.allowedVenues,
    updatedAt: row.updatedAt.toISOString(),
    updatedBy: row.updatedBy,
    updatedReason: row.updatedReason ?? null,
  };
}

function defaultPolicySnapshot(agentId: string): AgentTradePolicySnapshot {
  return {
    agentId,
    dailyCap: TRADE_POLICY_DEFAULTS.dailyCap,
    perOrderCap: TRADE_POLICY_DEFAULTS.perOrderCap,
    leverageCap: TRADE_POLICY_DEFAULTS.leverageCap,
    allowedAssets: [...TRADE_POLICY_DEFAULTS.allowedAssets],
    allowedVenues: [...TRADE_POLICY_DEFAULTS.allowedVenues],
  };
}

function policyDiff(before: AgentTradePolicySnapshot, after: AgentTradePolicyResponse) {
  return {
    dailyCap: { before: before.dailyCap, after: after.dailyCap },
    perOrderCap: { before: before.perOrderCap, after: after.perOrderCap },
    leverageCap: { before: before.leverageCap, after: after.leverageCap },
    allowedAssets: { before: before.allowedAssets, after: after.allowedAssets },
    allowedVenues: { before: before.allowedVenues, after: after.allowedVenues },
  };
}

function validatePolicyNumber(
  name: "dailyCap" | "perOrderCap" | "leverageCap",
  value: unknown,
): number | string {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return `${name} must be a positive number`;
  }
  if (value > TRADE_POLICY_LAYER_1_MAX[name]) {
    return `${name} exceeds platform ceiling ${TRADE_POLICY_LAYER_1_MAX[name]}`;
  }
  return value;
}

function validatePolicyStringArray(name: string, value: unknown): string[] | string {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    return `${name} must be a non-empty string array`;
  }
  return [...new Set(value)];
}

const MAX_AGENT_SIGNER_PERMISSIONS = 32;
const MAX_AGENT_SIGNER_METADATA_BYTES = 8_192;
const MAX_AGENT_KEY_QUORUM_MEMBERS = 32;
const AGENT_SIGNER_TYPES = new Set(["owner", "delegated", "service", "quorum_member"]);
const AGENT_SIGNER_SUBJECT_TYPES = new Set(["user", "wallet", "api_key", "external"]);
const AGENT_SIGNER_STATUSES = new Set(["active", "paused", "revoked"]);
const AGENT_KEY_QUORUM_STATUSES = new Set(["active", "paused", "revoked"]);
const PREGENERATED_USER_WALLET_TYPE = "pregenerated_user";
const PREGENERATED_CLAIM_PREFIX = "pregenerated:";
const RESERVED_SIGNER_METADATA_KEYS = new Set([
  "credentialHash",
  "credentialCreatedAt",
  "credentialLastUsedAt",
]);
const ACCOUNT_CAPABILITIES = [
  "sign_transaction",
  "sign_message",
  "sign_typed_data",
  "sign_user_operation",
  "sign_authorization",
  "send_calls",
  "transfer",
  "solana_transaction",
] as const;

type PortfolioAsset = {
  token: string;
  symbol: string;
  balance: string;
  formatted: string;
  decimals: number;
  usdPrice: number | null;
  usdValue: number | null;
  usdPriceText: string | null;
  usdValueText: string | null;
};
type AgentSignerRow = typeof agentSigners.$inferSelect;
type AgentKeyQuorumRow = typeof agentKeyQuorums.$inferSelect;
type PolicyRow = typeof policies.$inferSelect;

const USD_SCALE_DECIMALS = 18;

function parseDecimalToScaled(value: string, scaleDecimals = USD_SCALE_DECIMALS): bigint | null {
  const normalized = value.trim();
  if (!/^\d+(?:\.\d+)?$/.test(normalized)) return null;
  const [whole = "0", fraction = ""] = normalized.split(".");
  const scaledFraction = fraction.slice(0, scaleDecimals).padEnd(scaleDecimals, "0");
  return BigInt(whole) * 10n ** BigInt(scaleDecimals) + BigInt(scaledFraction || "0");
}

function formatScaledDecimal(value: bigint, scaleDecimals = USD_SCALE_DECIMALS): string {
  const whole = value / 10n ** BigInt(scaleDecimals);
  const fraction = value % 10n ** BigInt(scaleDecimals);
  const trimmedFraction = fraction.toString().padStart(scaleDecimals, "0").replace(/0+$/, "");
  return trimmedFraction ? `${whole}.${trimmedFraction}` : whole.toString();
}

function priceToScaledText(price: number | null): string | null {
  if (price === null || !Number.isFinite(price) || price < 0) return null;
  const scaled = parseDecimalToScaled(price.toFixed(USD_SCALE_DECIMALS));
  return scaled === null ? null : formatScaledDecimal(scaled);
}

function tokenAmountUsdText(
  balance: string,
  decimals: number,
  price: number | null,
): string | null {
  if (price === null || !Number.isFinite(price) || price < 0) return null;
  if (!/^\d+$/.test(balance) || !Number.isSafeInteger(decimals) || decimals < 0) return null;
  const scaledPrice = parseDecimalToScaled(price.toFixed(USD_SCALE_DECIMALS));
  if (scaledPrice === null) return null;
  const usdScaled = (BigInt(balance) * scaledPrice) / 10n ** BigInt(decimals);
  return formatScaledDecimal(usdScaled);
}

function sumUsdText(values: Array<string | null>): string | null {
  let total = 0n;
  let hasValue = false;
  for (const value of values) {
    if (value === null) continue;
    const scaled = parseDecimalToScaled(value);
    if (scaled === null) continue;
    total += scaled;
    hasValue = true;
  }
  return hasValue ? formatScaledDecimal(total) : null;
}

function sumNullableUsd(values: Array<number | null>): number | null {
  let total = 0;
  let hasValue = false;
  for (const value of values) {
    if (value === null) continue;
    total += value;
    hasValue = true;
  }
  return hasValue ? total : null;
}

function agentWalletRowsToAccountWallets(
  agent: AgentIdentity,
  rows: Array<{
    id: string;
    chainFamily: "evm" | "solana";
    address: string;
    venue: string | null;
    purpose: string | null;
    createdAt: Date;
  }>,
) {
  if (rows.length > 0) {
    return rows.map((wallet) => ({
      id: wallet.id,
      chainFamily: wallet.chainFamily,
      address: wallet.address,
      venue: wallet.venue,
      purpose: wallet.purpose,
      createdAt: wallet.createdAt,
    }));
  }

  return [
    {
      id: `${agent.id}:evm`,
      chainFamily: "evm" as const,
      address: agent.walletAddress,
      venue: null,
      purpose: "primary",
      createdAt: agent.createdAt,
    },
  ];
}

async function writeAgentAudit(
  c: Parameters<typeof requireTenantLevel>[0],
  event: {
    tenantId: string;
    action: string;
    resourceType: string;
    resourceId: string;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await writeAuditEvent({
    tenantId: event.tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? event.tenantId,
    action: event.action,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    metadata: event.metadata,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

function parseDurationSeconds(value: string): number | null {
  const match = value.trim().match(/^(\d+)([smhd])$/i);
  if (!match) return null;
  const amount = Number(match[1]);
  if (!Number.isSafeInteger(amount) || amount <= 0) return null;
  const unit = match[2].toLowerCase();
  const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 60 * 60 : 24 * 60 * 60;
  return amount * multiplier;
}

function normalizeAgentTokenExpiry(value: unknown): string | null {
  const requested = typeof value === "string" && value.trim() ? value.trim() : AGENT_TOKEN_EXPIRY;
  const seconds = parseDurationSeconds(requested);
  if (!seconds || seconds > MAX_AGENT_TOKEN_SECONDS) return null;
  return requested;
}

function parseListLimit(value: string | undefined, fallback = 100): number {
  const parsed = value ? Number(value) : fallback;
  if (!Number.isSafeInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, MAX_AGENT_LIST_LIMIT);
}

function parseListOffset(value: string | undefined): number {
  const parsed = value ? Number(value) : 0;
  if (!Number.isSafeInteger(parsed) || parsed < 0) return 0;
  return Math.min(parsed, 100_000);
}

function requireTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function generateAgentId(): string {
  return `agt_${crypto.randomUUID()}`;
}

function generatePregeneratedWalletClaimToken(): string {
  return `stwd_claim_${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
}

async function deleteAgentRows(agentId: string, tenantId: string): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
    await tx.delete(transactions).where(eq(transactions.agentId, agentId));
    await tx.delete(policies).where(eq(policies.agentId, agentId));
    await tx.delete(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, agentId));
    await tx.delete(encryptedKeys).where(eq(encryptedKeys.agentId, agentId));
    await tx.delete(agentWallets).where(eq(agentWallets.agentId, agentId));
    await tx.delete(agents).where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
  });
}

async function deleteAgentWalletRows(
  agentId: string,
  chainFamily: "evm" | "solana",
  venue: string,
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .delete(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, chainFamily),
          eq(encryptedChainKeys.venue, venue),
        ),
      );
    await tx
      .delete(agentWallets)
      .where(
        and(
          eq(agentWallets.agentId, agentId),
          eq(agentWallets.chainFamily, chainFamily),
          eq(agentWallets.venue, venue),
        ),
      );
  });
}

async function deleteAgentSignerRow(signerId: string): Promise<void> {
  await db.delete(agentSigners).where(eq(agentSigners.id, signerId));
}

async function restoreAgentSigner(row: AgentSignerRow): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(agentSigners).where(eq(agentSigners.id, row.id));
    await tx.insert(agentSigners).values(row);
  });
}

async function deleteAgentKeyQuorumRow(quorumId: string): Promise<void> {
  await db.delete(agentKeyQuorums).where(eq(agentKeyQuorums.id, quorumId));
}

async function restoreAgentKeyQuorum(row: AgentKeyQuorumRow): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(agentKeyQuorums).where(eq(agentKeyQuorums.id, row.id));
    await tx.insert(agentKeyQuorums).values(row);
  });
}

async function snapshotAgentPolicies(agentId: string): Promise<PolicyRow[]> {
  return db.select().from(policies).where(eq(policies.agentId, agentId));
}

async function restoreAgentPolicies(agentId: string, snapshot: PolicyRow[]): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(policies).where(eq(policies.agentId, agentId));
    if (snapshot.length > 0) {
      await tx.insert(policies).values(snapshot);
    }
  });
}

/**
 * Drop the cached policy set after any per-agent policy mutation so a tightening
 * change (lowering a limit, disabling/deleting a rule) is never masked by a stale
 * permissive cache entry. Best-effort: a Redis failure must not block the write —
 * the next read falls back to the DB. No-op when Redis is unavailable (tests/pglite).
 */
async function invalidateAgentPolicyCache(agentId: string, tenantId: string): Promise<void> {
  if (!isRedisAvailable()) return;
  try {
    await invalidateCache(agentId, tenantId);
  } catch (err) {
    console.error("[policy] Failed to invalidate policy cache:", err);
  }
}

function parseCustomTokenList(value: string | undefined): string[] | string | undefined {
  if (!value) return undefined;
  if (value.length > 2_500) return "tokens query is too long";
  const tokens = [
    ...new Set(
      value
        .split(",")
        .map((token) => token.trim())
        .filter(Boolean),
    ),
  ];
  if (tokens.length > MAX_CUSTOM_TOKEN_BALANCES) {
    return `tokens cannot contain more than ${MAX_CUSTOM_TOKEN_BALANCES} addresses`;
  }
  for (const token of tokens) {
    if (!/^0x[a-fA-F0-9]{40}$/.test(token)) return "tokens must be comma-separated EVM addresses";
  }
  return tokens;
}

function parseOptionalChainId(value: string | undefined): number | string | undefined {
  if (value === undefined || value === "") return undefined;
  if (!/^\d+$/.test(value)) return "chainId must be a positive integer";
  const chainId = Number(value);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return "chainId must be a positive integer";
  return chainId;
}

function normalizeOptionalText(value: unknown, field: string, maxLength: number): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${field} must be a non-empty string`);
  }
  const normalized = value.trim();
  if (normalized.length > maxLength) throw new Error(`${field} is too long`);
  return normalized;
}

function normalizeRequiredText(value: unknown, field: string, maxLength: number): string {
  const normalized = normalizeOptionalText(value, field, maxLength);
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
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
        if (normalized.length > 128) {
          throw new Error("permissions entries must be 128 chars or less");
        }
        return normalized;
      }),
    ),
  ];
}

function hasRecentSessionMfa(c: Parameters<typeof requireTenantLevel>[0], maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function requireRecentAdminMfa(c: Parameters<typeof requireTenantLevel>[0], reason: string) {
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

function normalizeSignerMetadata(value: unknown): Record<string, unknown> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("metadata must be an object");
  }
  if (JSON.stringify(value).length > MAX_AGENT_SIGNER_METADATA_BYTES) {
    throw new Error(`metadata cannot exceed ${MAX_AGENT_SIGNER_METADATA_BYTES} bytes`);
  }
  for (const key of Object.keys(value)) {
    if (RESERVED_SIGNER_METADATA_KEYS.has(key)) {
      throw new Error(`metadata.${key} is reserved and cannot be set by clients`);
    }
  }
  return value as Record<string, unknown>;
}

function mergeSignerMetadataPreservingReserved(
  existing: unknown,
  next: Record<string, unknown>,
): Record<string, unknown> {
  const merged = { ...next };
  if (existing && typeof existing === "object" && !Array.isArray(existing)) {
    for (const key of RESERVED_SIGNER_METADATA_KEYS) {
      const value = (existing as Record<string, unknown>)[key];
      if (value !== undefined) merged[key] = value;
    }
  }
  return merged;
}

function normalizeQuorumMemberSignerIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("memberSignerIds must be a non-empty array");
  }
  if (value.length > MAX_AGENT_KEY_QUORUM_MEMBERS) {
    throw new Error(`memberSignerIds cannot contain more than ${MAX_AGENT_KEY_QUORUM_MEMBERS}`);
  }
  const ids = [
    ...new Set(
      value.map((id) => {
        if (typeof id !== "string" || !id.trim()) {
          throw new Error("memberSignerIds must contain non-empty strings");
        }
        return id.trim();
      }),
    ),
  ];
  return ids;
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

function createSignerSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `stwd_signer_${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function redactSignerMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
  const {
    credentialHash: _credentialHash,
    credentialCreatedAt: _credentialCreatedAt,
    credentialLastUsedAt: _credentialLastUsedAt,
    ...safeMetadata
  } = metadata;
  return safeMetadata;
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

function toAgentSignerResponse(row: typeof agentSigners.$inferSelect) {
  return {
    id: row.id,
    tenantId: row.tenantId,
    agentId: row.agentId,
    signerType: row.signerType,
    subjectType: row.subjectType,
    subjectId: row.subjectId,
    address: row.address,
    chainFamily: row.chainFamily,
    label: row.label,
    permissions: row.permissions,
    metadata: redactSignerMetadata(row.metadata),
    hasCredential: typeof row.metadata.credentialHash === "string",
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

// ─── Create agent ─────────────────────────────────────────────────────────────

agentRoutes.post("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent creation requires owner or admin session",
      },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Agent creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    id?: string;
    name: string;
    platformId?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (body.id !== undefined && !isValidAgentId(body.id)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)",
      },
      400,
    );
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>(
      { ok: false, error: "name is required and must be a non-empty string" },
      400,
    );
  }

  try {
    const agentId = generateAgentId();
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.create.authorized",
      resourceType: "agent",
      resourceId: agentId,
      metadata: {
        name: body.name,
        requestedId: body.id ?? null,
        platformId: body.platformId ?? null,
      },
    });
    const identity = await vault.createAgent(tenantId, agentId, body.name, body.platformId);
    try {
      await writeAgentAudit(c, {
        tenantId,
        action: "agent.create",
        resourceType: "agent",
        resourceId: agentId,
        metadata: {
          name: body.name,
          requestedId: body.id ?? null,
          platformId: body.platformId ?? null,
        },
      });
    } catch (error) {
      await deleteAgentRows(agentId, tenantId);
      throw error;
    }
    return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: identity });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Create user-claimable pregenerated wallets ──────────────────────────────

agentRoutes.post("/pregenerated", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Pregenerated wallet creation requires owner or admin session",
      },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Pregenerated wallet creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    count?: unknown;
    namePrefix?: unknown;
    applyPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const count = body.count === undefined ? 1 : Number(body.count);
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_BATCH_AGENTS) {
    return c.json<ApiResponse>(
      { ok: false, error: `count must be an integer between 1 and ${MAX_BATCH_AGENTS}` },
      400,
    );
  }

  const namePrefix =
    body.namePrefix === undefined || body.namePrefix === null
      ? "Pregenerated user wallet"
      : isNonEmptyString(body.namePrefix)
        ? body.namePrefix.trim()
        : null;
  if (!namePrefix) {
    return c.json<ApiResponse>(
      { ok: false, error: "namePrefix must be a non-empty string when provided" },
      400,
    );
  }

  if (body.applyPolicies !== undefined) {
    if (!Array.isArray(body.applyPolicies)) {
      return c.json<ApiResponse>({ ok: false, error: "applyPolicies must be an array" }, 400);
    }
    if (body.applyPolicies.length > MAX_POLICIES_PER_AGENT) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `applyPolicies cannot contain more than ${MAX_POLICIES_PER_AGENT}`,
        },
        400,
      );
    }
    const policyValidationError = getPolicyRulesValidationError(body.applyPolicies);
    if (policyValidationError) {
      return c.json<ApiResponse>({ ok: false, error: policyValidationError }, 400);
    }
    const conditionSetValidationError = await getConditionSetReferenceValidationError(
      tenantId,
      body.applyPolicies,
    );
    if (conditionSetValidationError) {
      return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
    }
  }

  const wallets: Array<{ agent: AgentIdentity; claimToken: string }> = [];
  const persistedPolicies = body.applyPolicies?.map(toPersistedPolicyRule);

  try {
    for (let index = 0; index < count; index += 1) {
      const agentId = generateAgentId();
      const claimToken = generatePregeneratedWalletClaimToken();
      const claimTokenHash = hashSha256Hex(claimToken);
      const platformId = `${PREGENERATED_CLAIM_PREFIX}${claimTokenHash}`;
      const name = count === 1 ? namePrefix : `${namePrefix} ${index + 1}`;

      await writeAgentAudit(c, {
        tenantId,
        action: "agent.pregenerated_user_wallet.create.authorized",
        resourceType: "agent",
        resourceId: agentId,
        metadata: { batch: count > 1, claimTokenHash },
      });

      const identity = await vault.createAgent(tenantId, agentId, name, platformId);

      try {
        await db.transaction(async (tx) => {
          await tx
            .update(agents)
            .set({ walletType: PREGENERATED_USER_WALLET_TYPE, updatedAt: new Date() })
            .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

          if (persistedPolicies && persistedPolicies.length > 0) {
            await tx.insert(policies).values(
              persistedPolicies.map((policy) => ({
                id: crypto.randomUUID(),
                agentId,
                type: policy.type,
                enabled: policy.enabled,
                config: policy.config,
              })),
            );
          }
        });

        await writeAgentAudit(c, {
          tenantId,
          action: "agent.pregenerated_user_wallet.create",
          resourceType: "agent",
          resourceId: agentId,
          metadata: {
            batch: count > 1,
            appliedPolicyCount: persistedPolicies?.length ?? 0,
            claimTokenHash,
          },
        });
      } catch (error) {
        await deleteAgentRows(agentId, tenantId);
        throw error;
      }

      wallets.push({ agent: identity, claimToken });
    }
  } catch (error) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          error instanceof Error
            ? `Failed to create pregenerated wallets: ${error.message}`
            : "Failed to create pregenerated wallets",
      },
      500,
    );
  }

  setNoStoreHeaders(c);
  return c.json<
    ApiResponse<{
      wallets: Array<{ agent: AgentIdentity; claimToken: string }>;
      warning: string;
    }>
  >(
    {
      ok: true,
      data: {
        wallets,
        warning:
          "Claim tokens are shown once. Steward stores only SHA-256 hashes and cannot recover lost claim tokens.",
      },
    },
    201,
  );
});

// ─── List agents ──────────────────────────────────────────────────────────────

agentRoutes.get("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent listing requires tenant-level authentication",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const limit = parseListLimit(c.req.query("limit"));
  const offset = parseListOffset(c.req.query("offset"));
  const tenantAgents = await vault.listAgentsByTenant(tenantId, {
    limit,
    offset,
  });
  return c.json<ApiResponse<{ agents: AgentIdentity[]; limit: number; offset: number }>>({
    ok: true,
    data: { agents: tenantAgents, limit, offset },
  });
});

// ─── Agent token generation ───────────────────────────────────────────────────

agentRoutes.post("/:agentId/token", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent token creation requires owner or admin session",
      },
      403,
    );
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    expiresIn?: string;
    scopes?: string[] | string;
  }>(c);
  const expiresIn = normalizeAgentTokenExpiry(body?.expiresIn);
  if (!expiresIn) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "expiresIn must be a duration up to 30d using s, m, h, or d",
      },
      400,
    );
  }
  const scopes = parseAgentTokenScopes(body?.scopes ?? c.req.query("scopes"));
  if (!scopes) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid scopes — supported values: agent, api:proxy",
      },
      400,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Agent token creation");
  if (mfaResponse) return mfaResponse;

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.token.create.authorized",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { scopes, expiresIn },
    });
    const token = await createAgentToken(agentId, tenantId, expiresIn, scopes);
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.token.create",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { scopes, expiresIn },
    });
    c.header("Cache-Control", "no-store, max-age=0");
    c.header("Pragma", "no-cache");
    c.header("Expires", "0");
    return c.json<
      ApiResponse<{
        token: string;
        agentId: string;
        tenantId: string;
        scope: string;
        scopes: string[];
        expiresIn: string;
      }>
    >({
      ok: true,
      data: { token, agentId, tenantId, scope: "agent", scopes, expiresIn },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Failed to generate agent token for ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: "Failed to generate token" }, 500);
  }
});

// Create venue-scoped wallet (Sprint 4)
//
// POST /agents/:agentId/wallets
// Body: { venue: string, chainType: "evm" | "solana", purpose?: string }
//
// Creates a venue-scoped wallet under (agentId, chainFamily, venue).
// Required before trading on a venue: /v1/trade/sessions and
// /v1/trade/orders/hyperliquid both call vault.getWallet({ agentId, venue })
// and reject if no row exists.
//
// Tenant-level auth required (provisions wallets, not Sol's own JWT).

agentRoutes.post("/:agentId/wallets", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Venue wallet creation requires owner or admin session",
      },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Venue wallet creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    venue?: string;
    chainType?: "evm" | "solana";
    purpose?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isNonEmptyString(body.venue)) {
    return c.json<ApiResponse>({ ok: false, error: "venue is required" }, 400);
  }
  if (body.chainType !== "evm" && body.chainType !== "solana") {
    return c.json<ApiResponse>({ ok: false, error: 'chainType must be "evm" or "solana"' }, 400);
  }

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.wallet.create.authorized",
      resourceType: "agent",
      resourceId: agentId,
      metadata: {
        venue: body.venue,
        chainType: body.chainType,
        purpose: body.purpose ?? null,
      },
    });
    const wallet = await vault.createWallet({
      agentId,
      venue: body.venue,
      chainType: body.chainType,
      purpose: body.purpose,
    });
    try {
      await writeAgentAudit(c, {
        tenantId,
        action: "agent.wallet.create",
        resourceType: "agent",
        resourceId: agentId,
        metadata: {
          venue: body.venue,
          chainType: body.chainType,
          purpose: body.purpose ?? null,
          address: wallet.address,
        },
      });
    } catch (error) {
      await deleteAgentWalletRows(agentId, wallet.chainFamily, wallet.venue);
      throw error;
    }
    return c.json<
      ApiResponse<{
        agentId: string;
        chainFamily: "evm" | "solana";
        venue: string;
        purpose: string | null;
        address: string;
      }>
    >({ ok: true, data: wallet });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Agent trade policy ──────────────────────────────────────────────────────

agentRoutes.get("/:agentId/policy", async (c) => {
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

  const [policy] = await db
    .select()
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentId, agentId), eq(agentPolicies.tenantId, tenantId)));

  if (!policy) {
    return c.json<ApiResponse<{ defaults: typeof TRADE_POLICY_DEFAULTS; message: string }>>(
      {
        ok: false,
        error: "Agent policy not found",
        data: {
          defaults: TRADE_POLICY_DEFAULTS,
          message: "No agent policy row exists. Defaults apply until PUT creates one.",
        },
      },
      404,
    );
  }

  return c.json<ApiResponse<AgentTradePolicyResponse>>({
    ok: true,
    data: policyRowToResponse(policy),
  });
});

agentRoutes.put("/:agentId/policy", async (c) => {
  // SECURITY: policy/cap changes are PATRON/OWNER-only, never the agent itself.
  // An agent must NOT be able to raise its own caps, leverage, or withdrawal
  // allowlist — that would defeat the entire policy system. Require tenant-level
  // auth (tenant API key / owner session); reject agent-token auth.
  if (c.get("authType") === "agent-token") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Forbidden: agents cannot modify their own policy; patron/owner auth required",
      },
      403,
    );
  }
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy updates require patron/owner (tenant-level) authentication" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<AgentTradePolicyPatch>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (typeof body.reason !== "string" || body.reason.trim().length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "reason is required" }, 400);
  }

  const [existing] = await db
    .select()
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentId, agentId), eq(agentPolicies.tenantId, tenantId)));
  const before = existing ? policyRowToResponse(existing) : defaultPolicySnapshot(agentId);

  const nextDailyCap =
    body.dailyCap === undefined ? before.dailyCap : validatePolicyNumber("dailyCap", body.dailyCap);
  const nextPerOrderCap =
    body.perOrderCap === undefined
      ? before.perOrderCap
      : validatePolicyNumber("perOrderCap", body.perOrderCap);
  const nextLeverageCap =
    body.leverageCap === undefined
      ? before.leverageCap
      : validatePolicyNumber("leverageCap", body.leverageCap);
  const nextAllowedAssets =
    body.allowedAssets === undefined
      ? before.allowedAssets
      : validatePolicyStringArray("allowedAssets", body.allowedAssets);
  const nextAllowedVenues =
    body.allowedVenues === undefined
      ? before.allowedVenues
      : validatePolicyStringArray("allowedVenues", body.allowedVenues);

  const validationError = [
    nextDailyCap,
    nextPerOrderCap,
    nextLeverageCap,
    nextAllowedAssets,
    nextAllowedVenues,
  ].find((value) => typeof value === "string");
  if (typeof validationError === "string") {
    return c.json<ApiResponse>({ ok: false, error: validationError }, 400);
  }

  const dailyCapValue = nextDailyCap as number;
  const perOrderCapValue = nextPerOrderCap as number;
  const leverageCapValue = nextLeverageCap as number;
  const allowedAssetsValue = nextAllowedAssets as string[];
  const allowedVenuesValue = nextAllowedVenues as string[];

  if (perOrderCapValue > dailyCapValue) {
    return c.json<ApiResponse>({ ok: false, error: "perOrderCap cannot exceed dailyCap" }, 400);
  }

  const updatedBy = c.get("agentSubject") ?? `agent:${agentId}`;
  const updatedReason = body.reason.trim();
  const [upserted] = await db
    .insert(agentPolicies)
    .values({
      agentId,
      tenantId,
      dailyCapUsd: String(dailyCapValue),
      perOrderCapUsd: String(perOrderCapValue),
      leverageCap: String(leverageCapValue),
      allowedAssets: allowedAssetsValue,
      allowedVenues: allowedVenuesValue,
      updatedAt: new Date(),
      updatedBy,
      updatedReason,
    })
    .onConflictDoUpdate({
      target: agentPolicies.agentId,
      set: {
        dailyCapUsd: String(dailyCapValue),
        perOrderCapUsd: String(perOrderCapValue),
        leverageCap: String(leverageCapValue),
        allowedAssets: allowedAssetsValue,
        allowedVenues: allowedVenuesValue,
        updatedAt: new Date(),
        updatedBy,
        updatedReason,
      },
    })
    .returning();

  const after = policyRowToResponse(upserted);
  const diff = policyDiff(before, after);
  await writeAuditEvent({
    tenantId,
    actorType: "agent",
    actorId: updatedBy,
    action: "agent.policy.updated",
    resourceType: "agent_policy",
    resourceId: agentId,
    metadata: {
      agentId,
      reason: updatedReason,
      diff,
      before,
      after,
      multisigApprovalProvided: body.multisigApproval !== undefined,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  return c.json<
    ApiResponse<{ policy: AgentTradePolicyResponse; diff: ReturnType<typeof policyDiff> }>
  >({
    ok: true,
    data: { policy: after, diff },
  });
});

// ─── Agent owners and delegated signers ──────────────────────────────────────

agentRoutes.get("/:agentId/signers", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer inventory requires owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const status = c.req.query("status");
  if (status && !AGENT_SIGNER_STATUSES.has(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid signer status filter" }, 400);
  }

  const conditions = [eq(agentSigners.tenantId, tenantId), eq(agentSigners.agentId, agentId)];
  if (status) conditions.push(eq(agentSigners.status, status));
  const rows = await db
    .select()
    .from(agentSigners)
    .where(and(...conditions))
    .orderBy(agentSigners.createdAt);

  return c.json<ApiResponse>({
    ok: true,
    data: { signers: rows.map(toAgentSignerResponse) },
  });
});

agentRoutes.post("/:agentId/signers", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer creation requires owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (
    body.credentialSecret !== undefined &&
    body.credentialSecret !== null &&
    body.credentialSecret !== ""
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "credentialSecret is server-generated; use issueCredential=true" },
      400,
    );
  }

  const credentialRequested = body.issueCredential === true;
  if (credentialRequested) {
    const mfaResponse = requireRecentAdminMfa(c, "Signer credential issuance");
    if (mfaResponse) return mfaResponse;
  }

  let signerType: string;
  let subjectType: string;
  let subjectId: string;
  let address: string | null;
  let chainFamily: "evm" | "solana" | null;
  let label: string | null;
  let permissions: string[];
  let metadata: Record<string, unknown>;
  let credentialSecret: string | null;
  try {
    signerType = normalizeRequiredText(body.signerType, "signerType", 32);
    subjectType = normalizeRequiredText(body.subjectType, "subjectType", 32);
    subjectId = normalizeRequiredText(body.subjectId, "subjectId", 255);
    if (!AGENT_SIGNER_TYPES.has(signerType)) {
      throw new Error("signerType must be one of: owner, delegated, service, quorum_member");
    }
    if (!AGENT_SIGNER_SUBJECT_TYPES.has(subjectType)) {
      throw new Error("subjectType must be one of: user, wallet, api_key, external");
    }
    address = normalizeOptionalText(body.address, "address", 128);
    if (
      address &&
      !/^0x[a-fA-F0-9]{40}$/.test(address) &&
      !/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(address)
    ) {
      throw new Error("address must be an EVM or Solana address");
    }
    chainFamily =
      body.chainFamily === undefined || body.chainFamily === null
        ? null
        : body.chainFamily === "evm" || body.chainFamily === "solana"
          ? body.chainFamily
          : (() => {
              throw new Error("chainFamily must be evm or solana");
            })();
    label = normalizeOptionalText(body.label, "label", 255);
    permissions = normalizeSignerPermissions(body.permissions);
    metadata = normalizeSignerMetadata(body.metadata);
    credentialSecret = body.issueCredential === true ? createSignerSecret() : null;
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid signer payload" },
      400,
    );
  }

  const [existingSigner] = await db
    .select({ id: agentSigners.id })
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
        eq(agentSigners.subjectType, subjectType),
        eq(agentSigners.subjectId, subjectId),
      ),
    );
  if (existingSigner) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer already exists for this agent and subject" },
      409,
    );
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.signer.create.authorized",
    resourceType: "agent",
    resourceId: agentId,
    metadata: { signerType, subjectType, subjectId, permissions },
  });

  try {
    const storedMetadata = {
      ...metadata,
      ...(credentialSecret
        ? {
            credentialHash: await createSignerCredentialHash(credentialSecret),
            credentialCreatedAt: new Date().toISOString(),
          }
        : {}),
    };
    const [row] = await db
      .insert(agentSigners)
      .values({
        tenantId,
        agentId,
        signerType,
        subjectType,
        subjectId,
        address,
        chainFamily,
        label,
        permissions,
        metadata: storedMetadata,
        status: "active",
        createdBy: c.get("userId") ?? c.get("authType") ?? null,
      })
      .returning();

    try {
      await writeAgentAudit(c, {
        tenantId,
        action: "agent.signer.create",
        resourceType: "agent_signer",
        resourceId: row.id,
        metadata: { agentId, signerType, subjectType, subjectId },
      });
    } catch (error) {
      await deleteAgentSignerRow(row.id);
      throw error;
    }

    if (credentialSecret) {
      c.header("Cache-Control", "no-store, max-age=0");
      c.header("Pragma", "no-cache");
      c.header("Expires", "0");
    }
    return c.json<ApiResponse>(
      {
        ok: true,
        data: {
          ...toAgentSignerResponse(row),
          ...(credentialSecret ? { credentialSecret } : {}),
        },
      },
      201,
    );
  } catch (error) {
    const message = sanitizeErrorMessage(error);
    const duplicateSigner =
      message.includes("agent_signers_agent_subject_idx") ||
      message.toLowerCase().includes("duplicate key") ||
      message.toLowerCase().includes("unique constraint");
    return c.json<ApiResponse>(
      {
        ok: false,
        error: duplicateSigner ? "Signer already exists for this agent and subject" : message,
      },
      duplicateSigner ? 409 : 500,
    );
  }
});

agentRoutes.patch("/:agentId/signers/:signerId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer updates require owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const signerId = c.req.param("signerId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [existingSigner] = await db
    .select()
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    );
  if (!existingSigner) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const updates: Partial<typeof agentSigners.$inferInsert> = {};
  let privilegedSignerUpdate = false;
  try {
    if (body.signerType !== undefined) {
      const signerType = normalizeRequiredText(body.signerType, "signerType", 32);
      if (!AGENT_SIGNER_TYPES.has(signerType)) {
        throw new Error("signerType must be one of: owner, delegated, service, quorum_member");
      }
      if (signerType !== existingSigner.signerType) privilegedSignerUpdate = true;
      updates.signerType = signerType;
    }
    if (body.address !== undefined) {
      const address = normalizeOptionalText(body.address, "address", 128);
      if (
        address &&
        !/^0x[a-fA-F0-9]{40}$/.test(address) &&
        !/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(address)
      ) {
        throw new Error("address must be an EVM or Solana address");
      }
      // Re-pointing the resolvable address of an active signer is functionally
      // credential takeover for any flow that resolves authority through
      // agentSigners.address, so this needs the same recent-MFA gate as a
      // permissions/status change. Matches the key-quorum PATCH model.
      if ((address ?? null) !== (existingSigner.address ?? null)) privilegedSignerUpdate = true;
      updates.address = address;
    }
    if (body.chainFamily !== undefined) {
      const chainFamily =
        body.chainFamily === null
          ? null
          : body.chainFamily === "evm" || body.chainFamily === "solana"
            ? body.chainFamily
            : (() => {
                throw new Error("chainFamily must be evm or solana");
              })();
      if ((chainFamily ?? null) !== (existingSigner.chainFamily ?? null)) {
        privilegedSignerUpdate = true;
      }
      updates.chainFamily = chainFamily;
    }
    if (body.label !== undefined) updates.label = normalizeOptionalText(body.label, "label", 255);
    if (body.permissions !== undefined) {
      privilegedSignerUpdate = true;
      updates.permissions = normalizeSignerPermissions(body.permissions);
    }
    if (body.metadata !== undefined) {
      privilegedSignerUpdate = true;
      updates.metadata = mergeSignerMetadataPreservingReserved(
        existingSigner.metadata,
        normalizeSignerMetadata(body.metadata),
      );
    }
    if (body.status !== undefined) {
      const status = normalizeRequiredText(body.status, "status", 32);
      if (!AGENT_SIGNER_STATUSES.has(status)) {
        throw new Error("status must be one of: active, paused, revoked");
      }
      if (status !== existingSigner.status) privilegedSignerUpdate = true;
      updates.status = status;
    }
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid signer update" },
      400,
    );
  }

  if (Object.keys(updates).length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "No signer updates provided" }, 400);
  }
  // Single MFA gate for any privileged field change, mirroring the key-quorum PATCH
  // handler. Cosmetic-only updates (label) are exempt; everything that affects
  // signer authority requires a recent step-up.
  if (privilegedSignerUpdate) {
    const mfaResponse = requireRecentAdminMfa(c, "Signer updates");
    if (mfaResponse) return mfaResponse;
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.signer.update.authorized",
    resourceType: "agent_signer",
    resourceId: signerId,
    metadata: { agentId, fields: Object.keys(updates) },
  });

  const [row] = await db
    .update(agentSigners)
    .set(updates)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    )
    .returning();

  if (!row) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.signer.update",
      resourceType: "agent_signer",
      resourceId: row.id,
      metadata: { agentId, status: row.status },
    });
  } catch (error) {
    await restoreAgentSigner(existingSigner);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentSignerResponse(row) });
});

agentRoutes.delete("/:agentId/signers/:signerId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer revocation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Signer revocation");
  if (mfaResponse) return mfaResponse;
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const signerId = c.req.param("signerId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  const [existingSigner] = await db
    .select()
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    );
  if (!existingSigner) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.signer.revoke.authorized",
    resourceType: "agent_signer",
    resourceId: signerId,
    metadata: { agentId },
  });

  const [row] = await db
    .update(agentSigners)
    .set({ status: "revoked" })
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    )
    .returning();

  if (!row) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.signer.revoke",
      resourceType: "agent_signer",
      resourceId: row.id,
      metadata: { agentId },
    });
  } catch (error) {
    await restoreAgentSigner(existingSigner);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentSignerResponse(row) });
});

// ─── Agent key quorums ───────────────────────────────────────────────────────

agentRoutes.get("/:agentId/key-quorums", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum inventory requires owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const status = c.req.query("status");
  if (status && !AGENT_KEY_QUORUM_STATUSES.has(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid key quorum status filter" }, 400);
  }
  const conditions = [eq(agentKeyQuorums.tenantId, tenantId), eq(agentKeyQuorums.agentId, agentId)];
  if (status) conditions.push(eq(agentKeyQuorums.status, status));
  const rows = await db
    .select()
    .from(agentKeyQuorums)
    .where(and(...conditions))
    .orderBy(agentKeyQuorums.createdAt);

  return c.json<ApiResponse>({
    ok: true,
    data: { quorums: rows.map(toAgentKeyQuorumResponse) },
  });
});

agentRoutes.post("/:agentId/key-quorums", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Key quorum creation");
  if (mfaResponse) return mfaResponse;
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  let name: string;
  let threshold: number;
  let memberSignerIds: string[];
  let permissions: string[];
  let metadata: Record<string, unknown>;
  try {
    name = normalizeRequiredText(body.name, "name", 255);
    memberSignerIds = normalizeQuorumMemberSignerIds(body.memberSignerIds);
    threshold = normalizeQuorumThreshold(body.threshold, memberSignerIds.length);
    permissions = normalizeSignerPermissions(body.permissions);
    metadata = normalizeSignerMetadata(body.metadata);
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid key quorum payload" },
      400,
    );
  }
  const memberError = await validateQuorumMembers(tenantId, agentId, memberSignerIds);
  if (memberError) return c.json<ApiResponse>({ ok: false, error: memberError }, 400);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.key_quorum.create.authorized",
    resourceType: "agent_key_quorum",
    resourceId: agentId,
    metadata: { agentId, name, threshold, memberSignerIds, permissions },
  });

  const [row] = await db
    .insert(agentKeyQuorums)
    .values({
      tenantId,
      agentId,
      name,
      threshold,
      memberSignerIds,
      permissions,
      metadata,
      status: "active",
      createdBy: c.get("userId") ?? c.get("authType") ?? null,
    })
    .returning();

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.key_quorum.create",
      resourceType: "agent_key_quorum",
      resourceId: row.id,
      metadata: { agentId, threshold, memberSignerIds },
    });
  } catch (error) {
    await deleteAgentKeyQuorumRow(row.id);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentKeyQuorumResponse(row) }, 201);
});

agentRoutes.patch("/:agentId/key-quorums/:quorumId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum updates require owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const quorumId = c.req.param("quorumId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const [existing] = await db
    .select()
    .from(agentKeyQuorums)
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    );
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Key quorum not found" }, 404);

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  const updates: Partial<typeof agentKeyQuorums.$inferInsert> = {};
  let privilegedUpdate = false;
  try {
    if (body.name !== undefined) updates.name = normalizeRequiredText(body.name, "name", 255);
    const nextMemberSignerIds =
      body.memberSignerIds === undefined
        ? existing.memberSignerIds
        : normalizeQuorumMemberSignerIds(body.memberSignerIds);
    if (body.memberSignerIds !== undefined) {
      updates.memberSignerIds = nextMemberSignerIds;
      privilegedUpdate = true;
    }
    if (body.threshold !== undefined) {
      updates.threshold = normalizeQuorumThreshold(body.threshold, nextMemberSignerIds.length);
      privilegedUpdate = true;
    } else if (
      body.memberSignerIds !== undefined &&
      existing.threshold > nextMemberSignerIds.length
    ) {
      throw new Error("threshold cannot exceed member count");
    }
    if (body.permissions !== undefined) {
      updates.permissions = normalizeSignerPermissions(body.permissions);
      privilegedUpdate = true;
    }
    if (body.metadata !== undefined) updates.metadata = normalizeSignerMetadata(body.metadata);
    if (body.status !== undefined) {
      const status = normalizeRequiredText(body.status, "status", 32);
      if (!AGENT_KEY_QUORUM_STATUSES.has(status)) {
        throw new Error("status must be one of: active, paused, revoked");
      }
      updates.status = status;
      if (status !== existing.status) privilegedUpdate = true;
    }
    if (body.memberSignerIds !== undefined) {
      const memberError = await validateQuorumMembers(tenantId, agentId, nextMemberSignerIds);
      if (memberError) throw new Error(memberError);
    }
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid key quorum update" },
      400,
    );
  }

  if (Object.keys(updates).length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "No key quorum updates provided" }, 400);
  }
  if (privilegedUpdate) {
    const mfaResponse = requireRecentAdminMfa(c, "Key quorum privilege updates");
    if (mfaResponse) return mfaResponse;
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.key_quorum.update.authorized",
    resourceType: "agent_key_quorum",
    resourceId: quorumId,
    metadata: { agentId, fields: Object.keys(updates) },
  });

  const [row] = await db
    .update(agentKeyQuorums)
    .set({ ...updates, updatedAt: new Date() })
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    )
    .returning();

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.key_quorum.update",
      resourceType: "agent_key_quorum",
      resourceId: row.id,
      metadata: { agentId, status: row.status },
    });
  } catch (error) {
    await restoreAgentKeyQuorum(existing);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentKeyQuorumResponse(row) });
});

agentRoutes.delete("/:agentId/key-quorums/:quorumId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum revocation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Key quorum revocation");
  if (mfaResponse) return mfaResponse;
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const quorumId = c.req.param("quorumId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  const [existing] = await db
    .select()
    .from(agentKeyQuorums)
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    );
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Key quorum not found" }, 404);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.key_quorum.revoke.authorized",
    resourceType: "agent_key_quorum",
    resourceId: quorumId,
    metadata: { agentId },
  });

  const [row] = await db
    .update(agentKeyQuorums)
    .set({ status: "revoked", updatedAt: new Date() })
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    )
    .returning();
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Key quorum not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.key_quorum.revoke",
      resourceType: "agent_key_quorum",
      resourceId: row.id,
      metadata: { agentId },
    });
  } catch (error) {
    await restoreAgentKeyQuorum(existing);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentKeyQuorumResponse(row) });
});

// ─── Get agent ────────────────────────────────────────────────────────────────

agentRoutes.get("/:agentId", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agent = await vault.getAgent(tenantId, c.req.param("agentId"));
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: agent });
});

// ─── Delete agent ─────────────────────────────────────────────────────────────

agentRoutes.delete("/:agentId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent deletion requires owner or admin session",
      },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Agent deletion");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const deleteSnapshot = await db.transaction(async (tx) => {
    const [agentRow] = await tx
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    return {
      agent: agentRow ?? null,
      approvalQueue: await tx
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.agentId, agentId)),
      transactions: await tx.select().from(transactions).where(eq(transactions.agentId, agentId)),
      policies: await tx.select().from(policies).where(eq(policies.agentId, agentId)),
      encryptedChainKeys: await tx
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, agentId)),
      encryptedKeys: await tx
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, agentId)),
      agentWallets: await tx.select().from(agentWallets).where(eq(agentWallets.agentId, agentId)),
    };
  });
  let agentRowsDeleted = false;
  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.delete.authorized",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { walletAddress: agent.walletAddress },
    });
    const issuedBefore = Math.floor(Date.now() / 1000);
    await revocationStore.revokeAgentTokens(agentId, issuedBefore);
    await db.transaction(async (tx) => {
      // Cascade delete in dependency order
      await tx.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
      await tx.delete(transactions).where(eq(transactions.agentId, agentId));
      await tx.delete(policies).where(eq(policies.agentId, agentId));
      await tx.delete(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, agentId));
      await tx.delete(encryptedKeys).where(eq(encryptedKeys.agentId, agentId));
      await tx.delete(agentWallets).where(eq(agentWallets.agentId, agentId));
      await tx.delete(agents).where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    });
    agentRowsDeleted = true;
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.delete",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { revokedAgentTokensIssuedBefore: issuedBefore },
    });

    return c.json<ApiResponse<{ deleted: string }>>({
      ok: true,
      data: { deleted: agentId },
    });
  } catch (e: unknown) {
    if (agentRowsDeleted && deleteSnapshot.agent) {
      await db.transaction(async (tx) => {
        await tx.insert(agents).values(deleteSnapshot.agent).onConflictDoNothing();
        if (deleteSnapshot.agentWallets.length > 0) {
          await tx.insert(agentWallets).values(deleteSnapshot.agentWallets).onConflictDoNothing();
        }
        if (deleteSnapshot.encryptedKeys.length > 0) {
          await tx.insert(encryptedKeys).values(deleteSnapshot.encryptedKeys).onConflictDoNothing();
        }
        if (deleteSnapshot.encryptedChainKeys.length > 0) {
          await tx
            .insert(encryptedChainKeys)
            .values(deleteSnapshot.encryptedChainKeys)
            .onConflictDoNothing();
        }
        if (deleteSnapshot.policies.length > 0) {
          await tx.insert(policies).values(deleteSnapshot.policies).onConflictDoNothing();
        }
        if (deleteSnapshot.transactions.length > 0) {
          await tx.insert(transactions).values(deleteSnapshot.transactions).onConflictDoNothing();
        }
        if (deleteSnapshot.approvalQueue.length > 0) {
          await tx.insert(approvalQueue).values(deleteSnapshot.approvalQueue).onConflictDoNothing();
        }
      });
    }
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Failed to delete agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Agent balance ────────────────────────────────────────────────────────────

agentRoutes.get("/:agentId/balance", async (c) => {
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

  const chainId = parseOptionalChainId(c.req.query("chainId"));
  if (typeof chainId === "string") {
    return c.json<ApiResponse>({ ok: false, error: chainId }, 400);
  }

  try {
    const balance = await vault.getBalance(tenantId, agentId, chainId);
    return c.json<ApiResponse>({
      ok: true,
      data: {
        agentId,
        walletAddress: balance.walletAddress,
        balances: {
          native: balance.native.toString(),
          nativeFormatted: balance.nativeFormatted,
          chainId: balance.chainId,
          symbol: balance.symbol,
        },
      },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Agent token balances (ERC-20) ────────────────────────────────────────────

agentRoutes.get("/:agentId/tokens", async (c) => {
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

  const chainId = parseOptionalChainId(c.req.query("chainId"));
  if (typeof chainId === "string") {
    return c.json<ApiResponse>({ ok: false, error: chainId }, 400);
  }
  const tokensParam = c.req.query("tokens");
  const customTokens = parseCustomTokenList(tokensParam);
  if (typeof customTokens === "string") {
    return c.json<ApiResponse>({ ok: false, error: customTokens }, 400);
  }

  try {
    // Fetch native balance
    const balance = await vault.getBalance(tenantId, agentId, chainId);

    // Fetch ERC-20 token balances
    const tokenBalances = await vault.getTokenBalances(tenantId, agentId, chainId, customTokens);

    return c.json<ApiResponse>({
      ok: true,
      data: {
        agentId,
        walletAddress: balance.walletAddress,
        chainId: balance.chainId,
        native: {
          symbol: balance.symbol,
          balance: balance.native.toString(),
          formatted: balance.nativeFormatted,
        },
        tokens: tokenBalances,
      },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Agent spend summary ─────────────────────────────────────────────────────

agentRoutes.get("/:agentId/spend", async (c) => {
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

  const txStats = await getTransactionStats(agentId);
  const sponsorship = publicGasSponsorshipState(await readTenantGasSponsorshipConfig(tenantId));
  const oneMonthAgo = new Date(Date.now() - 30 * 86400_000);
  const [monthlyStats] = await db
    .select({
      spentThisMonth: sql<string>`coalesce(sum((${transactions.value})::numeric), 0)::text`,
    })
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        gte(transactions.createdAt, oneMonthAgo),
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`,
      ),
    );

  const realtimeEnabled = isRedisAvailable();
  const realtimePeriods = realtimeEnabled
    ? await Promise.all(
        SPEND_PERIODS.map(async (period) => ({
          period,
          spentUsd: await getSpend(agentId, period),
          byHost: await getSpendByHost(agentId, period),
        })),
      )
    : SPEND_PERIODS.map((period) => ({ period, spentUsd: null, byHost: {} }));

  return c.json<ApiResponse>({
    ok: true,
    data: {
      agentId,
      walletAddress: agent.walletAddress,
      onchain: {
        todayWei: txStats.spentToday.toString(),
        weekWei: txStats.spentThisWeek.toString(),
        monthWei: monthlyStats?.spentThisMonth ?? "0",
      },
      realtime: {
        enabled: realtimeEnabled,
        periods: realtimePeriods,
      },
      sponsorship: {
        enabled: sponsorship.enabled,
        provider: sponsorship.provider,
        mode: sponsorship.mode,
        circuitBreakerEnabled: sponsorship.circuitBreakerEnabled,
      },
    },
  });
});

// ─── Agent account aggregation ───────────────────────────────────────────────

agentRoutes.get("/:agentId/account", async (c) => {
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

  const chainId = parseOptionalChainId(c.req.query("chainId"));
  if (typeof chainId === "string") {
    return c.json<ApiResponse>({ ok: false, error: chainId }, 400);
  }
  const tokensParam = c.req.query("tokens");
  const customTokens = parseCustomTokenList(tokensParam);
  if (typeof customTokens === "string") {
    return c.json<ApiResponse>({ ok: false, error: customTokens }, 400);
  }

  const [
    walletRows,
    txStats,
    monthlyStats,
    balanceResult,
    tokenBalancesResult,
    gasSponsorshipConfig,
  ] = await Promise.all([
    db
      .select({
        id: agentWallets.id,
        chainFamily: agentWallets.chainFamily,
        address: agentWallets.address,
        venue: agentWallets.venue,
        purpose: agentWallets.purpose,
        createdAt: agentWallets.createdAt,
      })
      .from(agentWallets)
      .where(eq(agentWallets.agentId, agentId)),
    getTransactionStats(agentId),
    db
      .select({
        spentThisMonth: sql<string>`coalesce(sum((${transactions.value})::numeric), 0)::text`,
      })
      .from(transactions)
      .where(
        and(
          eq(transactions.agentId, agentId),
          gte(transactions.createdAt, new Date(Date.now() - 30 * 86400_000)),
          sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`,
        ),
      ),
    vault.getBalance(tenantId, agentId, chainId).catch((error: unknown) => ({
      unavailable: true as const,
      reason: sanitizeErrorMessage(error),
    })),
    vault.getTokenBalances(tenantId, agentId, chainId, customTokens).catch((error: unknown) => ({
      unavailable: true as const,
      reason: sanitizeErrorMessage(error),
    })),
    readTenantGasSponsorshipConfig(tenantId),
  ]);
  const sponsorship = publicGasSponsorshipState(gasSponsorshipConfig);

  const wallets = agentWalletRowsToAccountWallets(agent, walletRows);
  const addresses = wallets.reduce<Record<string, string>>((acc, wallet) => {
    acc[wallet.chainFamily] = wallet.address;
    return acc;
  }, {});
  const portfolioChainId =
    "unavailable" in balanceResult ? (chainId ?? null) : balanceResult.chainId;
  const nativeAsset: PortfolioAsset | null =
    "unavailable" in balanceResult
      ? null
      : await (async () => {
          const balance = balanceResult.native.toString();
          const usdPrice = await priceOracle.getNativeUsdPrice(balanceResult.chainId);
          const usdValue = await priceOracle.weiToUsd(balance, balanceResult.chainId);
          return {
            token: "native",
            symbol: balanceResult.symbol,
            balance,
            formatted: balanceResult.nativeFormatted,
            decimals: 18,
            usdPrice,
            usdValue,
            usdPriceText: priceToScaledText(usdPrice),
            usdValueText: tokenAmountUsdText(balance, 18, usdPrice),
          };
        })();
  const tokenAssets: PortfolioAsset[] =
    "unavailable" in tokenBalancesResult
      ? []
      : await Promise.all(
          tokenBalancesResult.map(async (token) => {
            const usdPrice =
              portfolioChainId === null
                ? null
                : await priceOracle.getTokenUsdPrice(portfolioChainId, token.token);
            const usdValue =
              portfolioChainId === null
                ? null
                : await priceOracle.weiToUsd(token.balance, portfolioChainId, token.token);
            return {
              token: token.token,
              symbol: token.symbol,
              balance: token.balance,
              formatted: token.formatted,
              decimals: token.decimals,
              usdPrice,
              usdValue,
              usdPriceText: priceToScaledText(usdPrice),
              usdValueText: tokenAmountUsdText(token.balance, token.decimals, usdPrice),
            };
          }),
        );
  const portfolioUnavailableReasons = [
    "unavailable" in balanceResult ? balanceResult.reason : null,
    "unavailable" in tokenBalancesResult ? tokenBalancesResult.reason : null,
  ].filter((reason): reason is string => Boolean(reason));
  const totalUsd = sumNullableUsd([
    nativeAsset?.usdValue ?? null,
    ...tokenAssets.map((token) => token.usdValue),
  ]);
  const totalUsdText = sumUsdText([
    nativeAsset?.usdValueText ?? null,
    ...tokenAssets.map((token) => token.usdValueText),
  ]);

  return c.json<ApiResponse>({
    ok: true,
    data: {
      id: agentId,
      type: "agent",
      agentId,
      tenantId,
      name: agent.name,
      walletAddress: agent.walletAddress,
      walletAddresses: addresses,
      wallets,
      balances:
        "unavailable" in balanceResult
          ? {
              evm: null,
              unavailableReason: balanceResult.reason,
            }
          : {
              evm: {
                native: balanceResult.native.toString(),
                nativeFormatted: balanceResult.nativeFormatted,
                chainId: balanceResult.chainId,
                symbol: balanceResult.symbol,
                walletAddress: balanceResult.walletAddress,
              },
            },
      portfolio: {
        chainId: portfolioChainId,
        walletAddress:
          "unavailable" in balanceResult ? agent.walletAddress : balanceResult.walletAddress,
        native: nativeAsset,
        tokens: tokenAssets,
        totalUsd,
        totalUsdText,
        ...(portfolioUnavailableReasons.length > 0
          ? { unavailableReason: portfolioUnavailableReasons.join("; ") }
          : {}),
      },
      spend: {
        todayWei: txStats.spentToday.toString(),
        weekWei: txStats.spentThisWeek.toString(),
        monthWei: monthlyStats[0]?.spentThisMonth ?? "0",
      },
      capabilities: ACCOUNT_CAPABILITIES,
      sponsorship: {
        enabled: sponsorship.enabled,
        provider: sponsorship.provider,
        mode: sponsorship.mode,
        circuitBreakerEnabled: sponsorship.circuitBreakerEnabled,
      },
      createdAt: agent.createdAt,
    },
  });
});

agentRoutes.get("/:agentId/aggregation", (c) => {
  const query = new URL(c.req.url).search;
  return agentRoutes.request(`/${encodeURIComponent(c.req.param("agentId"))}/account${query}`, {
    method: "GET",
    headers: c.req.raw.headers,
  });
});

// ─── Batch create agents ──────────────────────────────────────────────────────

agentRoutes.post("/batch", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Batch agent creation requires owner or admin session",
      },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Batch agent creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    agents: Array<{ id?: string; name: string; platformId?: string }>;
    applyPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!Array.isArray(body.agents) || body.agents.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "agents array is required and must not be empty" },
      400,
    );
  }
  if (body.agents.length > MAX_BATCH_AGENTS) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `agents array cannot contain more than ${MAX_BATCH_AGENTS} agents`,
      },
      400,
    );
  }

  for (const agentSpec of body.agents) {
    if (agentSpec.id !== undefined && !isValidAgentId(agentSpec.id)) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `Invalid agent id "${String(agentSpec.id)}" — must be 1-128 alphanumeric characters (plus _ - . :)`,
        },
        400,
      );
    }
    if (!isNonEmptyString(agentSpec.name)) {
      return c.json<ApiResponse>(
        { ok: false, error: `Agent "${agentSpec.id}" is missing a name` },
        400,
      );
    }
  }
  if (body.applyPolicies !== undefined) {
    if (!Array.isArray(body.applyPolicies)) {
      return c.json<ApiResponse>({ ok: false, error: "applyPolicies must be an array" }, 400);
    }
    if (body.applyPolicies.length > MAX_POLICIES_PER_AGENT) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `applyPolicies cannot contain more than ${MAX_POLICIES_PER_AGENT}`,
        },
        400,
      );
    }
    const policyValidationError = getPolicyRulesValidationError(body.applyPolicies);
    if (policyValidationError) {
      return c.json<ApiResponse>({ ok: false, error: policyValidationError }, 400);
    }
    const conditionSetValidationError = await getConditionSetReferenceValidationError(
      tenantId,
      body.applyPolicies,
    );
    if (conditionSetValidationError) {
      return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
    }
  }

  const created: AgentIdentity[] = [];
  const errors: Array<{ id: string; error: string }> = [];
  const batchIds = new Set<string>();

  for (const agentSpec of body.agents) {
    const clientReferenceId = agentSpec.id ?? crypto.randomUUID();
    try {
      if (batchIds.has(clientReferenceId)) {
        errors.push({ id: clientReferenceId, error: "Duplicate agent reference id in batch" });
        continue;
      }
      batchIds.add(clientReferenceId);
      const agentId = generateAgentId();
      await writeAgentAudit(c, {
        tenantId,
        action: "agent.create.authorized",
        resourceType: "agent",
        resourceId: agentId,
        metadata: {
          name: agentSpec.name,
          requestedId: agentSpec.id ?? null,
          platformId: agentSpec.platformId ?? null,
          batch: true,
          appliedPolicyCount: body.applyPolicies?.length ?? 0,
        },
      });
      let identity: AgentIdentity | null = null;
      identity = await vault.createAgent(tenantId, agentId, agentSpec.name, agentSpec.platformId);

      try {
        if (body.applyPolicies && body.applyPolicies.length > 0) {
          const persistedPolicies = body.applyPolicies.map(toPersistedPolicyRule);
          await db.transaction(async (tx) => {
            await tx.delete(policies).where(eq(policies.agentId, agentId));
            await tx.insert(policies).values(
              persistedPolicies.map((policy) => ({
                id: crypto.randomUUID(),
                agentId,
                type: policy.type,
                enabled: policy.enabled,
                config: policy.config,
              })),
            );
          });
        }

        created.push(identity);
        await writeAgentAudit(c, {
          tenantId,
          action: "agent.create",
          resourceType: "agent",
          resourceId: agentId,
          metadata: {
            name: agentSpec.name,
            requestedId: agentSpec.id ?? null,
            platformId: agentSpec.platformId ?? null,
            batch: true,
            appliedPolicyCount: body.applyPolicies?.length ?? 0,
          },
        });
      } catch (postCreateError) {
        await deleteAgentRows(agentId, tenantId);
        throw postCreateError;
      }
    } catch (e: unknown) {
      errors.push({
        id: clientReferenceId,
        error:
          e instanceof Error && e.message.includes("already exists")
            ? "Agent id already exists"
            : "Failed to create agent",
      });
    }
  }

  return c.json<
    ApiResponse<{
      created: AgentIdentity[];
      errors: Array<{ id: string; error: string }>;
    }>
  >({
    ok: true,
    data: { created, errors },
  });
});

// ─── Get agent policies ───────────────────────────────────────────────────────

agentRoutes.get("/:agentId/policies", async (c) => {
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

  const agentPolicies = await db.select().from(policies).where(eq(policies.agentId, agentId));

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: agentPolicies.map(toPolicyRule),
  });
});

// ─── Update agent policies ────────────────────────────────────────────────────

agentRoutes.put("/:agentId/policies", async (c) => {
  // SECURITY: policy/cap changes are PATRON/OWNER-only, never the agent itself.
  // See PUT /:agentId/policy above — an agent raising its own policy rules
  // (caps, leverage, withdrawal allowlist) would defeat the policy system.
  if (c.get("authType") === "agent-token") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Forbidden: agents cannot modify their own policies; patron/owner auth required",
      },
      403,
    );
  }
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy updates");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const nextPolicies = await safeJsonParse<PolicyRule[]>(c);

  if (!nextPolicies || !Array.isArray(nextPolicies)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Request body must be a JSON array of policies" },
      400,
    );
  }

  const policyValidationError = getPolicyRulesValidationError(nextPolicies);
  if (policyValidationError) {
    return c.json<ApiResponse>({ ok: false, error: policyValidationError }, 400);
  }
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    tenantId,
    nextPolicies,
  );
  if (conditionSetValidationError) {
    return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
  }
  if (nextPolicies.length > MAX_POLICIES_PER_AGENT) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `Policy list cannot contain more than ${MAX_POLICIES_PER_AGENT}`,
      },
      400,
    );
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.policies.update.authorized",
    resourceType: "agent",
    resourceId: agentId,
    metadata: {
      count: nextPolicies.length,
      types: nextPolicies.map((policy) => policy.type),
    },
  });

  const previousPolicies = await snapshotAgentPolicies(agentId);
  const storedPolicies = await db.transaction(async (tx) => {
    await tx.delete(policies).where(eq(policies.agentId, agentId));

    if (nextPolicies.length > 0) {
      const persistedPolicies = nextPolicies.map(toPersistedPolicyRule);
      await tx.insert(policies).values(
        persistedPolicies.map((policy) => ({
          id: crypto.randomUUID(),
          agentId,
          type: policy.type,
          enabled: policy.enabled,
          config: policy.config,
        })),
      );
    }

    return tx.select().from(policies).where(eq(policies.agentId, agentId));
  });

  await invalidateAgentPolicyCache(agentId, tenantId);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.policies.update",
      resourceType: "agent",
      resourceId: agentId,
      metadata: {
        count: storedPolicies.length,
        types: storedPolicies.map((p) => p.type),
      },
    });
  } catch (error) {
    await restoreAgentPolicies(agentId, previousPolicies);
    throw error;
  }

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: storedPolicies.map(toPolicyRule),
  });
});

// ─── Privy-style nested policy rule CRUD ─────────────────────────────────────

agentRoutes.get("/:agentId/policies/rules", async (c) => {
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

  const rows = await db.select().from(policies).where(eq(policies.agentId, agentId));
  return c.json<ApiResponse<{ rules: PolicyRule[] }>>({
    ok: true,
    data: { rules: rows.map(toPolicyRule) },
  });
});

agentRoutes.post("/:agentId/policies/rules", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy rule creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy rule creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<unknown>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  let nextRule: PolicyRule;
  try {
    nextRule = { ...normalizePolicyRuleInput(body), id: crypto.randomUUID() };
  } catch (e) {
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 400);
  }

  const currentRules = (await db.select().from(policies).where(eq(policies.agentId, agentId))).map(
    toPolicyRule,
  );
  const nextRules = [...currentRules, nextRule];
  const policyValidationError = getPolicyRulesValidationError(nextRules);
  if (policyValidationError) {
    return c.json<ApiResponse>({ ok: false, error: policyValidationError }, 400);
  }
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    tenantId,
    nextRules,
  );
  if (conditionSetValidationError) {
    return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.policy_rule.create.authorized",
    resourceType: "policy_rule",
    resourceId: nextRule.id,
    metadata: { agentId, type: nextRule.type },
  });

  const persistedRule = toPersistedPolicyRule(nextRule);
  await db.insert(policies).values({
    id: persistedRule.id,
    agentId,
    type: persistedRule.type,
    enabled: persistedRule.enabled,
    config: persistedRule.config,
  });

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.policy_rule.create",
      resourceType: "policy_rule",
      resourceId: nextRule.id,
      metadata: { agentId, type: nextRule.type },
    });
  } catch (error) {
    await db
      .delete(policies)
      .where(and(eq(policies.agentId, agentId), eq(policies.id, nextRule.id)));
    throw error;
  }

  await invalidateAgentPolicyCache(agentId, tenantId);
  return c.json<ApiResponse<PolicyRule>>({ ok: true, data: nextRule }, 201);
});

agentRoutes.get("/:agentId/policies/rules/:ruleId", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const ruleId = c.req.param("ruleId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const [rule] = await db
    .select()
    .from(policies)
    .where(and(eq(policies.agentId, agentId), eq(policies.id, ruleId)));
  if (!rule) return c.json<ApiResponse>({ ok: false, error: "Policy rule not found" }, 404);

  return c.json<ApiResponse<PolicyRule>>({ ok: true, data: toPolicyRule(rule) });
});

agentRoutes.patch("/:agentId/policies/rules/:ruleId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy rule updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy rule updates");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const ruleId = c.req.param("ruleId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<unknown>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  const currentRows = await db.select().from(policies).where(eq(policies.agentId, agentId));
  const existing = currentRows.find((rule) => rule.id === ruleId);
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Policy rule not found" }, 404);

  let nextRule: PolicyRule;
  try {
    nextRule = normalizePolicyRulePatch(toPolicyRule(existing), body);
  } catch (e) {
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 400);
  }

  const nextRules = currentRows.map((rule) => (rule.id === ruleId ? nextRule : toPolicyRule(rule)));
  const policyValidationError = getPolicyRulesValidationError(nextRules);
  if (policyValidationError) {
    return c.json<ApiResponse>({ ok: false, error: policyValidationError }, 400);
  }
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    tenantId,
    nextRules,
  );
  if (conditionSetValidationError) {
    return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.policy_rule.update.authorized",
    resourceType: "policy_rule",
    resourceId: ruleId,
    metadata: { agentId, type: nextRule.type },
  });

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
  if (!updated) return c.json<ApiResponse>({ ok: false, error: "Policy rule not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.policy_rule.update",
      resourceType: "policy_rule",
      resourceId: ruleId,
      metadata: { agentId, type: nextRule.type },
    });
  } catch (error) {
    await db
      .update(policies)
      .set({
        type: existing.type,
        enabled: existing.enabled,
        config: existing.config,
        updatedAt: existing.updatedAt,
      })
      .where(and(eq(policies.agentId, agentId), eq(policies.id, ruleId)));
    throw error;
  }

  await invalidateAgentPolicyCache(agentId, tenantId);
  return c.json<ApiResponse<PolicyRule>>({ ok: true, data: toPolicyRule(updated) });
});

agentRoutes.delete("/:agentId/policies/rules/:ruleId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy rule deletion requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy rule deletion");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const ruleId = c.req.param("ruleId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.policy_rule.delete.authorized",
    resourceType: "policy_rule",
    resourceId: ruleId,
    metadata: { agentId },
  });

  const [deleted] = await db
    .delete(policies)
    .where(and(eq(policies.agentId, agentId), eq(policies.id, ruleId)))
    .returning();
  if (!deleted) return c.json<ApiResponse>({ ok: false, error: "Policy rule not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.policy_rule.delete",
      resourceType: "policy_rule",
      resourceId: ruleId,
      metadata: { agentId, type: deleted.type },
    });
  } catch (error) {
    await db.insert(policies).values(deleted);
    throw error;
  }

  await invalidateAgentPolicyCache(agentId, tenantId);
  return c.json<ApiResponse<PolicyRule>>({ ok: true, data: toPolicyRule(deleted) });
});
