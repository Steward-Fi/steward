/**
 * user.ts — User-facing wallet routes
 *
 * Route group mounted under `/user` (or wherever the main app mounts it).
 * All routes require a valid JWT session token in the `Authorization: Bearer <token>` header.
 *
 * Routes:
 *   GET  /me                  — current user info
 *   GET  /me/wallet           — wallet address + on-chain balance
 *   POST /me/wallet           — provision wallet if absent
 *   POST /me/wallet/sign      — sign a transaction (policy-enforced)
 *   GET  /me/wallet/history   — transaction history
 *   GET  /me/wallet/policies  — view active policies on the user's wallet
 *   POST /me/wallet/sign-message — sign arbitrary message data
 *
 * NOTE: Do NOT import or modify packages/api/src/index.ts.
 *       This file exports a Hono route group ready for mounting.
 */

import { createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import {
  ChallengeStore,
  generateApiKey,
  getProviderConfig,
  hashSha256Hex,
  isBuiltInProvider,
  isValidE164,
  OAuthClient,
  revocationStore,
  type TelegramLoginPayload,
  uint8ArrayToBase64url,
  verifyFarcasterLogin,
  verifyTelegramLogin,
} from "@stwd/auth";
import {
  accounts,
  agents,
  agentWallets,
  auditEvents,
  authenticators,
  getDb,
  policies,
  refreshTokens,
  tenantAppClients,
  tenantConfigs,
  tenantInvitations,
  tenants,
  toPolicyRule,
  toTxRecord,
  transactions,
  userPushSubscriptions,
  users,
  userTenants,
  userWalletAppConsents,
} from "@stwd/db";
import { PolicyEngine } from "@stwd/policy-engine";
import type {
  AgentBalance,
  AgentIdentity,
  ApiResponse,
  ChainFamily,
  PolicyRule,
  SignRequest,
} from "@stwd/shared";
import {
  applyUserWalletDefaults,
  generateMnemonic,
  getUserWallet,
  isValidMnemonic,
  provisionRecoverableUserWallet,
  provisionUserWallet,
  restoreRecoverableUserWallet,
  USER_WALLET_DEFAULT_POLICIES,
  Vault,
} from "@stwd/vault";
import bs58 from "bs58";
import { and, desc, eq, gte, ilike, isNull, ne, or, sql } from "drizzle-orm";
import { type Context, Hono, type Next } from "hono";
import { getAddress, verifyMessage as viemVerifyMessage } from "viem";
import { writeAuditEvent } from "../services/audit";
import { priceOracle, setNoStoreHeaders, verifySessionToken } from "../services/context";
import {
  publicGasSponsorshipState,
  readTenantGasSponsorshipConfig,
} from "../services/gas-sponsorship";
import { lockUserSession } from "../services/session-lock";
import { dispatchWebhook } from "../services/webhook-dispatch";
import {
  assertAllowedOAuthRedirectUri,
  createSessionToken,
  encryptOAuthProviderTokens,
  getEmailAuthForTenant,
  getPhoneAuth,
} from "./auth";

// ─── Session payload types ────────────────────────────────────────────────────

interface UserSessionPayload {
  userId: string;
  address?: string;
  email?: string;
  tenantId?: string;
  iat?: number;
  exp?: number;
  mfaVerifiedAt?: number;
  mfaMethod?: string;
  factorEnrollmentVerifiedAt?: number;
  [key: string]: unknown;
}

type UserVariables = {
  userId: string;
  userSession: UserSessionPayload;
  authType?: "session-jwt";
  sessionMfaVerifiedAt?: number;
  sessionMfaMethod?: string;
  requestId?: string;
};

type UserAccountRow = typeof accounts.$inferSelect;
type UserAuthenticatorRow = typeof authenticators.$inferSelect;
type UserRefreshTokenRow = typeof refreshTokens.$inferSelect;

type UserAccountUnlinkMutation = {
  accountId: string;
  deletedAccount?: UserAccountRow;
  deletedPasskey?: UserAuthenticatorRow;
  deletedRefreshTokens: UserRefreshTokenRow[];
};

type UserWalletSignResult =
  | { approved: false; results: unknown }
  | { approved: true; txId: string; txHash: string };

type UserPortfolioAsset = {
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

const MAX_CUSTOM_TOKEN_BALANCES = 25;
const USER_ACCOUNT_CAPABILITIES = [
  "sign_transaction",
  "sign_message",
  "transfer",
  "solana_transaction",
  "export_private_key",
] as const;
const USD_SCALE_DECIMALS = 18;
const WALLET_LINK_CHALLENGE_TTL_MS = 5 * 60_000;
const WALLET_LINK_REDEEM_LOCK_TTL_MS = 10_000;
const walletLinkChallenges = new ChallengeStore({ ttlMs: WALLET_LINK_CHALLENGE_TTL_MS });
const SOCIAL_LINK_CHALLENGE_TTL_MS = 5 * 60_000;
const socialLinkChallenges = new ChallengeStore({ ttlMs: SOCIAL_LINK_CHALLENGE_TTL_MS });
const OAUTH_LINK_CHALLENGE_TTL_MS = 5 * 60_000;
const oauthLinkChallenges = new ChallengeStore({ ttlMs: OAUTH_LINK_CHALLENGE_TTL_MS });
const TELEGRAM_LINK_MAX_AGE_SEC = 24 * 60 * 60;
const TENANT_ROLES = ["owner", "admin", "developer", "billing", "viewer", "member"] as const;
type TenantRole = (typeof TENANT_ROLES)[number];
const TENANT_INVITATION_ROLES = ["admin", "developer", "billing", "viewer", "member"] as const;
type TenantInvitationRole = (typeof TENANT_INVITATION_ROLES)[number];
const MAX_TENANT_METADATA_BYTES = 16_384;
const MAX_TENANT_METADATA_DEPTH = 8;
const MAX_TENANT_METADATA_KEYS = 100;
const MAX_TENANT_METADATA_STRING_BYTES = 4_096;
const PUSH_PROVIDERS = ["expo", "apns", "fcm"] as const;
const PUSH_PLATFORMS = ["ios", "android"] as const;
const MAX_PUSH_METADATA_BYTES = 8_192;
const PREGENERATED_USER_WALLET_TYPE = "pregenerated_user";
const PREGENERATED_CLAIM_PREFIX = "pregenerated:";

type PushProvider = (typeof PUSH_PROVIDERS)[number];
type PushPlatform = (typeof PUSH_PLATFORMS)[number];

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function safeJsonParse<T>(c: Context): Promise<T | null> {
  try {
    return await c.req.json<T>();
  } catch {
    return null;
  }
}

function isValidAddress(value: unknown): boolean {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidTenantId(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_\-.:]{1,64}$/.test(value);
}

function isPushProvider(value: unknown): value is PushProvider {
  return typeof value === "string" && PUSH_PROVIDERS.includes(value as PushProvider);
}

function isPushPlatform(value: unknown): value is PushPlatform {
  return typeof value === "string" && PUSH_PLATFORMS.includes(value as PushPlatform);
}

function normalizedOptionalString(value: unknown, maxLength: number): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) return null;
  return trimmed;
}

function normalizePushToken(token: unknown, provider: PushProvider): string | null {
  if (typeof token !== "string") return null;
  const normalized = token.trim();
  if (normalized.length < 16 || normalized.length > 4096 || /\s/.test(normalized)) return null;
  if (provider === "apns" && !/^[0-9a-f]{64}$/i.test(normalized)) return null;
  if (provider === "expo" && !/^(ExponentPushToken|ExpoPushToken)\[[^\]]+\]$/.test(normalized)) {
    return null;
  }
  return normalized;
}

function normalizePushMetadata(value: unknown): Record<string, unknown> | null {
  if (value === undefined || value === null) return {};
  if (!isPlainObject(value)) return null;
  try {
    if (new TextEncoder().encode(JSON.stringify(value)).byteLength > MAX_PUSH_METADATA_BYTES) {
      return null;
    }
  } catch {
    return null;
  }
  return value;
}

function isValidUserId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function isReservedTenantId(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized === "platform" ||
    normalized === "system" ||
    normalized === "default" ||
    normalized === "personal" ||
    normalized.startsWith("personal-") ||
    normalized.startsWith("eth:") ||
    normalized.startsWith("t-") ||
    normalized.startsWith("solana:")
  );
}

function normalizeTenantRole(value: unknown): TenantRole | null {
  if (typeof value !== "string") return null;
  const role = value.trim().toLowerCase();
  return (TENANT_ROLES as readonly string[]).includes(role) ? (role as TenantRole) : null;
}

function normalizeTenantInvitationRole(value: unknown): TenantInvitationRole | null {
  if (value === undefined || value === null || value === "") return "member";
  if (typeof value !== "string") return null;
  const role = value.trim().toLowerCase();
  return (TENANT_INVITATION_ROLES as readonly string[]).includes(role)
    ? (role as TenantInvitationRole)
    : null;
}

function normalizeInvitationExpiry(value: unknown): Date {
  const maxSeconds = 30 * 24 * 60 * 60;
  const defaultSeconds = 7 * 24 * 60 * 60;
  const seconds =
    typeof value === "number" && Number.isSafeInteger(value) && value > 0
      ? Math.min(value, maxSeconds)
      : defaultSeconds;
  return new Date(Date.now() + seconds * 1000);
}

function getTenantMetadataValidationError(value: unknown): string | null {
  if (!isPlainObject(value)) return "tenantCustomMetadata must be an object";

  let keyCount = 0;
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop() as { value: unknown; depth: number };
    if (current.depth > MAX_TENANT_METADATA_DEPTH) {
      return `tenantCustomMetadata must not exceed ${MAX_TENANT_METADATA_DEPTH} levels`;
    }
    if (typeof current.value === "string") {
      if (new TextEncoder().encode(current.value).length > MAX_TENANT_METADATA_STRING_BYTES) {
        return `tenantCustomMetadata string values must not exceed ${MAX_TENANT_METADATA_STRING_BYTES} bytes`;
      }
      continue;
    }
    if (
      current.value === null ||
      typeof current.value === "number" ||
      typeof current.value === "boolean"
    ) {
      continue;
    }
    if (Array.isArray(current.value)) {
      keyCount += current.value.length;
      if (keyCount > MAX_TENANT_METADATA_KEYS) {
        return `tenantCustomMetadata must not contain more than ${MAX_TENANT_METADATA_KEYS} keys or items`;
      }
      for (const child of current.value) {
        stack.push({ value: child, depth: current.depth + 1 });
      }
      continue;
    }
    if (isPlainObject(current.value)) {
      const entries = Object.entries(current.value);
      keyCount += entries.length;
      if (keyCount > MAX_TENANT_METADATA_KEYS) {
        return `tenantCustomMetadata must not contain more than ${MAX_TENANT_METADATA_KEYS} keys or items`;
      }
      for (const [, child] of entries) {
        stack.push({ value: child, depth: current.depth + 1 });
      }
      continue;
    }
    return "tenantCustomMetadata must contain only JSON values";
  }

  if (new TextEncoder().encode(JSON.stringify(value)).length > MAX_TENANT_METADATA_BYTES) {
    return `tenantCustomMetadata must not exceed ${MAX_TENANT_METADATA_BYTES} bytes`;
  }
  return null;
}

function tenantUserCsvRow(
  fields: Array<string | number | boolean | Date | null | undefined>,
): string {
  return fields
    .map((field) => {
      const raw = field instanceof Date ? field.toISOString() : String(field ?? "");
      const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
      if (safe.includes(",") || safe.includes('"') || safe.includes("\n")) {
        return `"${safe.replace(/"/g, '""')}"`;
      }
      return safe;
    })
    .join(",");
}

function slugifyTenantId(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function userTenantCreationAllowed(): boolean {
  return process.env.ALLOW_USER_TENANT_CREATION === "true";
}

async function writeUserAudit(
  c: Context<{ Variables: UserVariables }>,
  event: {
    tenantId: string;
    actorType: "user";
    actorId?: string | null;
    action: string;
    resourceType?: string | null;
    resourceId?: string | null;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await writeAuditEvent({
    ...event,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

async function restoreUserAccountUnlinkMutation(
  mutation: UserAccountUnlinkMutation,
): Promise<void> {
  const db = getDb();
  await db.transaction(async (tx) => {
    if (mutation.deletedAccount) {
      await tx.insert(accounts).values(mutation.deletedAccount).onConflictDoNothing();
    }
    if (mutation.deletedPasskey) {
      await tx.insert(authenticators).values(mutation.deletedPasskey).onConflictDoNothing();
    }
    if (mutation.deletedRefreshTokens.length > 0) {
      await tx.insert(refreshTokens).values(mutation.deletedRefreshTokens).onConflictDoNothing();
    }
  });
}

function hasRecentMfaStepUp(session: UserSessionPayload, maxAgeMs = 5 * 60_000): boolean {
  return (
    typeof session.mfaVerifiedAt === "number" &&
    Number.isFinite(session.mfaVerifiedAt) &&
    Date.now() - session.mfaVerifiedAt <= maxAgeMs
  );
}

function sessionTenantMatches(session: UserSessionPayload, tenantId: string): boolean {
  return typeof session.tenantId === "string" && session.tenantId === tenantId;
}

function isTenantAdminRole(role: string | null | undefined): boolean {
  return role === "owner" || role === "admin";
}

const TENANT_USER_DIRECTORY_READ_ROLES = ["owner", "admin", "developer", "viewer"] as const;

function isTenantUserDirectoryReaderRole(role: string | null | undefined): boolean {
  return (TENANT_USER_DIRECTORY_READ_ROLES as readonly string[]).includes(role ?? "");
}

async function activeTenantOwnerCount(
  tx: Pick<ReturnType<typeof getDb>, "select">,
  tenantId: string,
  excludeUserId?: string,
): Promise<number> {
  const conditions = [
    eq(userTenants.tenantId, tenantId),
    eq(userTenants.role, "owner"),
    isNull(users.deactivatedAt),
  ];
  if (excludeUserId) conditions.push(ne(userTenants.userId, excludeUserId));
  const [ownerCount] = await tx
    .select({ count: sql<number>`count(*)` })
    .from(userTenants)
    .innerJoin(users, eq(users.id, userTenants.userId))
    .where(and(...conditions));
  return Number(ownerCount?.count ?? 0);
}

function tenantOwnerLifecycleLockKey(tenantId: string): string {
  return `tenant_owner_lifecycle_${tenantId}`;
}

async function lockTenantOwnerLifecycle(
  tx: Pick<ReturnType<typeof getDb>, "execute">,
  tenantId: string,
): Promise<void> {
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtextextended(${tenantOwnerLifecycleLockKey(tenantId)}, 0))`,
  );
}

function clampLimit(value: string | null, fallback = 50): number {
  const parsed = value ? Number(value) : fallback;
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), 100);
}

function parseBoundedOffset(value: string | null): number {
  const parsed = value ? Number(value) : 0;
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return Math.min(Math.floor(parsed), 100_000);
}

async function requireTenantAdmin(userId: string, tenantId: string): Promise<string | null> {
  const db = getDb();
  const [membership] = await db
    .select({ role: userTenants.role })
    .from(userTenants)
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));
  return isTenantAdminRole(membership?.role) ? membership.role : null;
}

async function requireTenantUserDirectoryReader(
  userId: string,
  tenantId: string,
): Promise<string | null> {
  const db = getDb();
  const [membership] = await db
    .select({ role: userTenants.role })
    .from(userTenants)
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));
  return isTenantUserDirectoryReaderRole(membership?.role) ? membership.role : null;
}

async function ensurePersonalTenant(userId: string, displayName: string): Promise<string> {
  const tenantId = `personal-${userId}`;
  const { hash } = generateApiKey();
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: displayName, apiKeyHash: hash })
    .onConflictDoNothing();
  return tenantId;
}

/** Build a Vault instance from environment. Same defaults as index.ts. */
function getVault(): Vault {
  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  if (!masterPassword) {
    throw new Error("STEWARD_MASTER_PASSWORD is required");
  }
  return new Vault({
    masterPassword,
    rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
    chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
  });
}

async function getTransactionStats(agentId: string) {
  const db = getDb();
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 3_600_000);
  const oneDayAgo = new Date(now.getTime() - 86_400_000);
  const oneWeekAgo = new Date(now.getTime() - 604_800_000);

  const oneHourAgoStr = oneHourAgo.toISOString();
  const oneDayAgoStr = oneDayAgo.toISOString();

  const [stats] = await db
    .select({
      recentTxCount1h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneHourAgoStr}::timestamptz)`,
      recentTxCount24h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneDayAgoStr}::timestamptz)`,
      spentToday: sql<string>`
        coalesce(
          sum(
            case
              when ${transactions.createdAt} >= ${oneDayAgoStr}::timestamptz then (${transactions.value})::numeric
              else 0
            end
          ),
          0
        )::text
      `,
      spentThisWeek: sql<string>`coalesce(sum((${transactions.value})::numeric), 0)::text`,
    })
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        sql`${transactions.createdAt} >= ${oneWeekAgo.toISOString()}::timestamptz`,
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`,
      ),
    );

  return {
    recentTxCount1h: Number(stats?.recentTxCount1h ?? 0),
    recentTxCount24h: Number(stats?.recentTxCount24h ?? 0),
    spentToday: BigInt(stats?.spentToday ?? "0"),
    spentThisWeek: BigInt(stats?.spentThisWeek ?? "0"),
  };
}

async function getMonthlySpend(agentId: string): Promise<string> {
  const [stats] = await getDb()
    .select({
      spentThisMonth: sql<string>`coalesce(sum((${transactions.value})::numeric), 0)::text`,
    })
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        sql`${transactions.createdAt} >= ${new Date(Date.now() - 30 * 86400_000).toISOString()}::timestamptz`,
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`,
      ),
    );
  return stats?.spentThisMonth ?? "0";
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

function userWalletRowsToAccountWallets(
  wallet: AgentIdentity,
  rows: Array<{
    id: string;
    chainFamily: ChainFamily;
    address: string;
    venue: string | null;
    purpose: string | null;
    createdAt: Date;
  }>,
) {
  if (rows.length > 0) {
    return rows.map((row) => ({
      id: row.id,
      chainFamily: row.chainFamily,
      address: row.address,
      venue: row.venue,
      purpose: row.purpose,
      createdAt: row.createdAt,
    }));
  }

  return [
    {
      id: `${wallet.id}:evm`,
      chainFamily: "evm" as const,
      address: wallet.walletAddress,
      venue: null,
      purpose: "primary",
      createdAt: wallet.createdAt,
    },
  ];
}

async function withAgentSpendLock<T>(agentId: string, fn: () => Promise<T>): Promise<T> {
  const db = getDb();
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${agentId}))`);
    return fn();
  });
}

// ─── Session auth middleware ──────────────────────────────────────────────────

/**
 * Reads `Authorization: Bearer <jwt>`, verifies it with jose, and populates
 * `c.get("userId")` + `c.get("userSession")` for downstream handlers.
 *
 * The JWT is expected to contain `userId` from the auth identity layer. Legacy
 * address-only SIWE sessions are intentionally rejected here because user routes
 * operate on database users and tenant memberships, not raw wallet addresses.
 */
export async function userSessionAuth(
  c: Context<{ Variables: UserVariables }>,
  next: Next,
): Promise<Response | undefined> {
  if (c.get("userId") && c.get("userSession")) {
    await next();
    return undefined;
  }

  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json<ApiResponse>(
      { ok: false, error: "Authorization: Bearer <token> header is required" },
      401,
    );
  }

  const token = authHeader.slice(7);

  let payload: UserSessionPayload;
  try {
    const verified = await verifySessionToken(token);
    if (!verified) throw new Error("invalid session token");
    payload = verified as unknown as UserSessionPayload;
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired session token" }, 401);
  }

  const userId = payload.userId as string | undefined;
  if (!userId) {
    return c.json<ApiResponse>({ ok: false, error: "Session token missing userId claim" }, 401);
  }

  c.set("userId", userId);
  c.set("userSession", { ...payload, userId });
  c.set("authType", "session-jwt");
  if (typeof payload.mfaVerifiedAt === "number") {
    c.set("sessionMfaVerifiedAt", payload.mfaVerifiedAt);
  }
  if (typeof payload.mfaMethod === "string") {
    c.set("sessionMfaMethod", payload.mfaMethod);
  }

  await next();
}

// ─── Route group ──────────────────────────────────────────────────────────────

const user = new Hono<{ Variables: UserVariables }>();
const ALLOW_PRIVATE_KEY_EXPORT = process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT === "true";
const ALLOW_UNSAFE_MESSAGE_SIGNING = process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING === "true";
const ALLOW_USER_PRIVATE_KEY_EXPORT = process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT === "true";
const ALLOW_USER_UNSAFE_MESSAGE_SIGNING =
  process.env.STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING === "true";

// Apply session auth to all routes in this group
user.use("*", userSessionAuth);

function personalTenantId(userId: string): string {
  return `personal-${userId}`;
}

function requirePersonalUserSession(c: Context<{ Variables: UserVariables }>): Response | null {
  const userId = c.get("userId");
  const session = c.get("userSession");
  if (session.tenantId === personalTenantId(userId)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: "Personal user route requires a personal user session" },
    403,
  );
}

function hasCalldata(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "" && value.trim().toLowerCase() !== "0x";
}

// Canonical non-negative uint256 decimal string (same semantics as intents.ts/vault.ts).
// Guards against negative/garbage wei flowing into BigInt(value) + spend SQL `(value)::numeric`,
// which could otherwise reduce spentToday and loosen the daily cap.
const MAX_UINT256_DECIMAL =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const MAX_UINT256_DECIMAL_DIGITS = 78;
function isUint256DecimalString(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
  const normalized = value.replace(/^0+/, "") || "0";
  if (normalized.length > MAX_UINT256_DECIMAL_DIGITS) return false;
  return normalized.length < MAX_UINT256_DECIMAL_DIGITS || normalized <= MAX_UINT256_DECIMAL;
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

function isValidAccountProvider(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(value.trim());
}

function isValidProviderAccountId(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.trim().length <= 255;
}

function normalizeEvmAddress(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const candidate = value;
  if (!isValidAddress(candidate)) return null;
  try {
    return getAddress(candidate);
  } catch {
    return null;
  }
}

function normalizeSolanaAddress(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const candidate = value.trim();
  try {
    return bs58.decode(candidate).length === 32 ? candidate : null;
  } catch {
    return null;
  }
}

type WalletLinkChain = "ethereum" | "solana";

function walletLinkChallengeKey(chain: WalletLinkChain, userId: string, nonce: string): string {
  return `wallet-link:${chain}:${userId}:${nonce}`;
}

function walletLinkRedeemLockKey(chain: WalletLinkChain, userId: string, nonce: string): string {
  return `wallet-link-lock:${chain}:${userId}:${nonce}`;
}

function walletLinkLabel(chain: WalletLinkChain): string {
  return chain === "ethereum" ? "Ethereum" : "Solana";
}

function buildWalletLinkMessage(input: {
  chain: WalletLinkChain;
  userId: string;
  nonce: string;
  issuedAt: string;
  account?: string;
}): string {
  const accountLabel = input.chain === "ethereum" ? "Address" : "Public Key";
  return [
    `Link this ${walletLinkLabel(input.chain)} wallet to your Steward account.`,
    "",
    `User ID: ${input.userId}`,
    ...(input.account ? [`${accountLabel}: ${input.account}`] : []),
    `Nonce: ${input.nonce}`,
    `Issued At: ${input.issuedAt}`,
  ].join("\n");
}

function parseWalletLinkMessage(
  chain: WalletLinkChain,
  message: string,
): {
  userId: string;
  nonce: string;
  issuedAt: string;
  account?: string;
} | null {
  const lines = message.split(/\r?\n/).map((line) => line.trim());
  if (lines[0] !== `Link this ${walletLinkLabel(chain)} wallet to your Steward account.`)
    return null;
  const fields = new Map<string, string>();
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const match = line.match(/^([A-Za-z ]+):\s*(.+)$/);
    if (match) fields.set(match[1].toLowerCase().replace(/\s+/g, ""), match[2]);
  }
  const userId = fields.get("userid");
  const nonce = fields.get("nonce");
  const issuedAt = fields.get("issuedat");
  if (!userId || !nonce || !issuedAt) return null;
  const account = fields.get(chain === "ethereum" ? "address" : "publickey");
  return { userId, nonce, issuedAt, ...(account ? { account } : {}) };
}

async function evmWalletAlreadyBelongsToAnotherUser(
  address: string,
  userId: string,
): Promise<boolean> {
  const normalized = address.toLowerCase();
  const [primaryOwner] = await getDb()
    .select({ id: users.id })
    .from(users)
    .where(
      and(
        ne(users.id, userId),
        eq(users.walletChain, "ethereum"),
        sql`lower(${users.walletAddress}) = ${normalized}`,
      ),
    );
  if (primaryOwner) return true;

  const [linkedOwner] = await getDb()
    .select({ userId: accounts.userId })
    .from(accounts)
    .where(
      and(eq(accounts.provider, "wallet:ethereum"), eq(accounts.providerAccountId, normalized)),
    );
  return Boolean(linkedOwner && linkedOwner.userId !== userId);
}

async function solanaWalletAlreadyBelongsToAnotherUser(
  publicKey: string,
  userId: string,
): Promise<boolean> {
  const [primaryOwner] = await getDb()
    .select({ id: users.id })
    .from(users)
    .where(
      and(
        ne(users.id, userId),
        eq(users.walletChain, "solana"),
        eq(users.walletAddress, publicKey),
      ),
    );
  if (primaryOwner) return true;

  const [linkedOwner] = await getDb()
    .select({ userId: accounts.userId })
    .from(accounts)
    .where(and(eq(accounts.provider, "wallet:solana"), eq(accounts.providerAccountId, publicKey)));
  return Boolean(linkedOwner && linkedOwner.userId !== userId);
}

function verifySolanaWalletLinkSignature(
  message: string,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const publicKeyBytes = bs58.decode(publicKey);
    const signatureBytes = bs58.decode(signature);
    if (publicKeyBytes.length !== 32) return false;
    const keyObject = createPublicKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: uint8ArrayToBase64url(publicKeyBytes),
      },
      format: "jwk",
    });
    return verifySignature(null, Buffer.from(message, "utf8"), keyObject, signatureBytes);
  } catch {
    return false;
  }
}

async function linkedAccountAlreadyBelongsToAnotherUser(
  provider: string,
  providerAccountId: string,
  userId: string,
): Promise<boolean> {
  const [linkedOwner] = await getDb()
    .select({ userId: accounts.userId })
    .from(accounts)
    .where(and(eq(accounts.provider, provider), eq(accounts.providerAccountId, providerAccountId)));
  return Boolean(linkedOwner && linkedOwner.userId !== userId);
}

function phoneLinkPurpose(channel: "sms" | "whatsapp", userId: string): string {
  return `user-link:${channel}:${userId}`;
}

function phoneProviderAccountId(phone: string): string {
  return `phone:${hashSha256Hex(phone)}`;
}

function maskedPhone(phone: string): string {
  return `***${phone.slice(-4)}`;
}

async function phoneAlreadyBelongsToAnotherUser(
  provider: "phone" | "whatsapp",
  phone: string,
  userId: string,
): Promise<boolean> {
  const providerAccountId = phoneProviderAccountId(phone);
  const [primaryOwner] = await getDb()
    .select({ id: users.id })
    .from(users)
    .where(and(ne(users.id, userId), eq(users.walletAddress, providerAccountId)));
  if (primaryOwner) return true;
  return linkedAccountAlreadyBelongsToAnotherUser(provider, providerAccountId, userId);
}

function farcasterProviderAccountId(address: string): string {
  return `address:${address.toLowerCase()}`;
}

function userFarcasterAllowedDomains(): string[] | undefined {
  const raw = process.env.SIWE_ALLOWED_DOMAINS?.trim();
  if (!raw) return undefined;
  const domains = raw
    .split(",")
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);
  return domains.length > 0 ? domains : undefined;
}

function socialLinkChallengeKey(provider: "telegram" | "farcaster", userId: string, nonce: string) {
  return `social-link:${provider}:${userId}:${nonce}`;
}

function oauthLinkChallengeKey(userId: string, state: string) {
  return `oauth-link:${userId}:${hashSha256Hex(state)}`;
}

function randomOAuthLinkState(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function telegramLinkHashKey(hash: string): string {
  return `social-link:telegram-hash:${hashSha256Hex(hash.toLowerCase())}`;
}

async function consumeTelegramLinkHashOnce(hash: string, authDate: number): Promise<boolean> {
  const expiresAtMs = (authDate + TELEGRAM_LINK_MAX_AGE_SEC) * 1000;
  const ttlMs = Math.max(1_000, expiresAtMs - Date.now());
  return socialLinkChallenges.setIfNotExists(telegramLinkHashKey(hash), "1", ttlMs);
}

type UserLinkedAccount = {
  id: string;
  provider: string;
  providerAccountId: string;
  expiresAt: number | null;
  type?: string;
  embeddedWallets?: Array<{ address: string }>;
  smartWallets?: Array<{ address: string }>;
  providerApp?: {
    id: string;
    name: string | null;
    logoUrl: string | null;
  };
  firstVerifiedAt?: string | Date;
  latestVerifiedAt?: string | Date;
};

async function listUserLinkedAccounts(userId: string): Promise<UserLinkedAccount[]> {
  const db = getDb();
  const linkedAccounts = await db
    .select({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    })
    .from(accounts)
    .where(eq(accounts.userId, userId));
  const passkeys = await db
    .select({
      id: authenticators.id,
      credentialId: authenticators.credentialId,
    })
    .from(authenticators)
    .where(eq(authenticators.userId, userId));
  const crossAppAccounts = await db
    .select({
      id: userWalletAppConsents.id,
      tenantId: userWalletAppConsents.tenantId,
      clientId: userWalletAppConsents.clientId,
      walletAddress: userWalletAppConsents.walletAddress,
      grantedAt: userWalletAppConsents.grantedAt,
      lastUsedAt: userWalletAppConsents.lastUsedAt,
      expiresAt: userWalletAppConsents.expiresAt,
      appName: tenantAppClients.name,
    })
    .from(userWalletAppConsents)
    .leftJoin(
      tenantAppClients,
      and(
        eq(tenantAppClients.tenantId, userWalletAppConsents.tenantId),
        eq(tenantAppClients.id, userWalletAppConsents.clientId),
      ),
    )
    .where(
      and(
        eq(userWalletAppConsents.userId, userId),
        eq(userWalletAppConsents.status, "active"),
        sql`(${userWalletAppConsents.expiresAt} is null or ${userWalletAppConsents.expiresAt} > now())`,
      ),
    );
  return [
    ...linkedAccounts,
    ...passkeys.map((passkey) => ({
      id: passkey.id,
      provider: "passkey",
      providerAccountId: passkey.credentialId,
      expiresAt: null,
    })),
    ...crossAppAccounts.map((account) => {
      const appId = `${account.tenantId}/${account.clientId}`;
      return {
        id: account.id,
        provider: "cross_app",
        providerAccountId: appId,
        expiresAt: account.expiresAt ? Math.floor(account.expiresAt.getTime() / 1000) : null,
        type: "cross_app",
        embeddedWallets: account.walletAddress ? [{ address: account.walletAddress }] : [],
        smartWallets: [],
        providerApp: {
          id: appId,
          name: account.appName,
          logoUrl: null,
        },
        firstVerifiedAt: account.grantedAt,
        latestVerifiedAt: account.lastUsedAt ?? account.grantedAt,
      } satisfies UserLinkedAccount;
    }),
  ];
}

function primaryLoginMethods(row: {
  email: string | null;
  walletAddress: string | null;
}): Array<{ provider: "email" | "wallet"; providerAccountId: string }> {
  const methods: Array<{ provider: "email" | "wallet"; providerAccountId: string }> = [];
  if (row.email) methods.push({ provider: "email", providerAccountId: row.email });
  if (row.walletAddress) {
    methods.push({ provider: "wallet", providerAccountId: row.walletAddress.toLowerCase() });
  }
  return methods;
}

// ─── GET /me ─────────────────────────────────────────────────────────────────

user.get("/me", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  const userId = c.get("userId");

  // Check if the user already has a wallet provisioned
  let walletInfo: { address: string; agentId: string } | null = null;
  try {
    const vault = getVault();
    const wallet = await getUserWallet(vault, userId);
    if (wallet) {
      walletInfo = { address: wallet.walletAddress, agentId: wallet.id };
    }
  } catch {
    // Non-fatal — wallet may not be provisioned yet
  }

  return c.json<
    ApiResponse<{
      userId: string;
      address?: string;
      email?: string;
      wallet: { address: string; agentId: string } | null;
    }>
  >({
    ok: true,
    data: {
      userId,
      address: session.address as string | undefined,
      email: session.email as string | undefined,
      wallet: walletInfo,
    },
  });
});

// ─── Push Subscriptions ──────────────────────────────────────────────────────

function publicPushSubscription(row: typeof userPushSubscriptions.$inferSelect) {
  return {
    id: row.id,
    tenantId: row.tenantId,
    provider: row.provider,
    token: row.token,
    platform: row.platform,
    deviceId: row.deviceId,
    appId: row.appId,
    locale: row.locale,
    timezone: row.timezone,
    metadata: row.metadata,
    status: row.status,
    lastSeenAt: row.lastSeenAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

user.get("/me/push-subscriptions", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const db = getDb();

  const rows = await db
    .select()
    .from(userPushSubscriptions)
    .where(
      and(eq(userPushSubscriptions.userId, userId), eq(userPushSubscriptions.status, "active")),
    )
    .orderBy(desc(userPushSubscriptions.lastSeenAt));

  return c.json<ApiResponse<{ subscriptions: ReturnType<typeof publicPushSubscription>[] }>>({
    ok: true,
    data: { subscriptions: rows.map(publicPushSubscription) },
  });
});

user.post("/me/push-subscriptions", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const body = await safeJsonParse<{
    provider?: unknown;
    token?: unknown;
    platform?: unknown;
    tenantId?: unknown;
    deviceId?: unknown;
    appId?: unknown;
    locale?: unknown;
    timezone?: unknown;
    metadata?: unknown;
  }>(c);
  if (!body || !isPushProvider(body.provider)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Push provider must be expo, apns, or fcm" },
      400,
    );
  }
  const token = normalizePushToken(body.token, body.provider);
  if (!token) return c.json<ApiResponse>({ ok: false, error: "Invalid push token" }, 400);
  const metadata = normalizePushMetadata(body.metadata);
  if (!metadata) {
    return c.json<ApiResponse>({ ok: false, error: "Push metadata must be a small object" }, 400);
  }
  const platform =
    body.platform === undefined ? null : isPushPlatform(body.platform) ? body.platform : null;
  if (body.platform !== undefined && !platform) {
    return c.json<ApiResponse>({ ok: false, error: "Push platform must be ios or android" }, 400);
  }
  const tenantId =
    body.tenantId === undefined || body.tenantId === null
      ? null
      : isValidTenantId(body.tenantId)
        ? body.tenantId
        : null;
  if (body.tenantId !== undefined && body.tenantId !== null && !tenantId) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenantId" }, 400);
  }

  const db = getDb();
  const [row] = await db
    .insert(userPushSubscriptions)
    .values({
      userId,
      tenantId,
      provider: body.provider,
      token,
      platform,
      deviceId: normalizedOptionalString(body.deviceId, 255),
      appId: normalizedOptionalString(body.appId, 255),
      locale: normalizedOptionalString(body.locale, 64),
      timezone: normalizedOptionalString(body.timezone, 128),
      metadata,
      status: "active",
      lastSeenAt: new Date(),
      revokedAt: null,
    })
    .onConflictDoUpdate({
      target: [
        userPushSubscriptions.userId,
        userPushSubscriptions.provider,
        userPushSubscriptions.token,
      ],
      targetWhere: sql`${userPushSubscriptions.status} = 'active'`,
      set: {
        tenantId,
        platform,
        deviceId: normalizedOptionalString(body.deviceId, 255),
        appId: normalizedOptionalString(body.appId, 255),
        locale: normalizedOptionalString(body.locale, 64),
        timezone: normalizedOptionalString(body.timezone, 128),
        metadata,
        lastSeenAt: new Date(),
        updatedAt: new Date(),
      },
    })
    .returning();

  await writeAuditEvent({
    tenantId: tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.push_subscription.registered",
    resourceType: "user_push_subscription",
    resourceId: row.id,
    metadata: { provider: row.provider, platform: row.platform, appId: row.appId },
  });

  return c.json<ApiResponse<{ subscription: ReturnType<typeof publicPushSubscription> }>>({
    ok: true,
    data: { subscription: publicPushSubscription(row) },
  });
});

user.delete("/me/push-subscriptions/:subscriptionId", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const subscriptionId = c.req.param("subscriptionId");
  const db = getDb();
  const revokedAt = new Date();

  const [row] = await db
    .update(userPushSubscriptions)
    .set({ status: "revoked", revokedAt, updatedAt: revokedAt })
    .where(
      and(
        eq(userPushSubscriptions.id, subscriptionId),
        eq(userPushSubscriptions.userId, userId),
        eq(userPushSubscriptions.status, "active"),
      ),
    )
    .returning();
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Push subscription not found" }, 404);

  await writeAuditEvent({
    tenantId: row.tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.push_subscription.revoked",
    resourceType: "user_push_subscription",
    resourceId: row.id,
    metadata: { provider: row.provider, platform: row.platform, appId: row.appId },
  });

  return c.json<ApiResponse<{ subscription: ReturnType<typeof publicPushSubscription> }>>({
    ok: true,
    data: { subscription: publicPushSubscription(row) },
  });
});

// ─── Linked Accounts ─────────────────────────────────────────────────────────

user.get("/me/accounts", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const db = getDb();
  const [userRow] = await db
    .select({
      id: users.id,
      email: users.email,
      walletAddress: users.walletAddress,
    })
    .from(users)
    .where(eq(users.id, userId));
  if (!userRow) return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);

  const linkedAccounts = await listUserLinkedAccounts(userId);

  return c.json<
    ApiResponse<{
      accounts: UserLinkedAccount[];
      primaryLoginMethods: Array<{ provider: "email" | "wallet"; providerAccountId: string }>;
    }>
  >({
    ok: true,
    data: {
      accounts: linkedAccounts,
      primaryLoginMethods: primaryLoginMethods(userRow),
    },
  });
});

user.post("/me/accounts/wallet/ethereum/nonce", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const body = await safeJsonParse<{ address?: unknown }>(c);
  const requestedAddress =
    body?.address === undefined || body.address === null || body.address === ""
      ? null
      : normalizeEvmAddress(body.address);
  if (body?.address !== undefined && !requestedAddress) {
    return c.json<ApiResponse>({ ok: false, error: "address must be an EVM address" }, 400);
  }

  const userId = c.get("userId");
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const message = buildWalletLinkMessage({
    chain: "ethereum",
    userId,
    nonce,
    issuedAt,
    ...(requestedAddress ? { account: requestedAddress } : {}),
  });
  await walletLinkChallenges.setIfNotExists(
    walletLinkChallengeKey("ethereum", userId, nonce),
    JSON.stringify({ userId, address: requestedAddress, issuedAt }),
  );

  return c.json<
    ApiResponse<{ nonce: string; message: string; expiresIn: number; address?: string }>
  >({
    ok: true,
    data: {
      nonce,
      message,
      expiresIn: Math.floor(WALLET_LINK_CHALLENGE_TTL_MS / 1000),
      ...(requestedAddress ? { address: requestedAddress } : {}),
    },
  });
});

user.post("/me/accounts/wallet/ethereum", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet linking requires a recent MFA step-up session" },
      403,
    );
  }

  const body = await safeJsonParse<{ address?: unknown; message?: unknown; signature?: unknown }>(
    c,
  );
  const address = normalizeEvmAddress(body?.address);
  if (!address)
    return c.json<ApiResponse>({ ok: false, error: "address must be an EVM address" }, 400);
  if (!isNonEmptyString(body?.message) || !isNonEmptyString(body?.signature)) {
    return c.json<ApiResponse>({ ok: false, error: "message and signature are required" }, 400);
  }

  const parsed = parseWalletLinkMessage("ethereum", body.message);
  const userId = c.get("userId");
  if (!parsed || parsed.userId !== userId) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid wallet link message" }, 400);
  }
  const parsedAddress = parsed.account ? normalizeEvmAddress(parsed.account) : null;
  if (parsedAddress && parsedAddress.toLowerCase() !== address.toLowerCase()) {
    return c.json<ApiResponse>({ ok: false, error: "Wallet link message address mismatch" }, 400);
  }

  const challengeKey = walletLinkChallengeKey("ethereum", userId, parsed.nonce);
  const rawChallenge = await walletLinkChallenges.get(challengeKey);
  if (!rawChallenge) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired wallet link nonce" }, 401);
  }
  const challenge = JSON.parse(rawChallenge) as { address?: string | null };
  if (challenge.address && challenge.address.toLowerCase() !== address.toLowerCase()) {
    return c.json<ApiResponse>({ ok: false, error: "Wallet link nonce address mismatch" }, 401);
  }

  const verified = await viemVerifyMessage({
    address: address as `0x${string}`,
    message: body.message,
    signature: body.signature as `0x${string}`,
  }).catch(() => false);
  if (!verified) return c.json<ApiResponse>({ ok: false, error: "Invalid wallet signature" }, 401);

  const lockKey = walletLinkRedeemLockKey("ethereum", userId, parsed.nonce);
  if (!(await walletLinkChallenges.setIfNotExists(lockKey, "1", WALLET_LINK_REDEEM_LOCK_TTL_MS))) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet link nonce is already being redeemed" },
      409,
    );
  }
  try {
    const consumed = await walletLinkChallenges.consume(challengeKey);
    if (!consumed || consumed !== rawChallenge) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid or expired wallet link nonce" }, 401);
    }
  } finally {
    walletLinkChallenges.delete(lockKey);
  }

  const normalized = address.toLowerCase();
  const [userRow] = await getDb()
    .select({ id: users.id, walletAddress: users.walletAddress, walletChain: users.walletChain })
    .from(users)
    .where(eq(users.id, userId));
  if (!userRow) return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);
  if (userRow.walletChain === "ethereum" && userRow.walletAddress?.toLowerCase() === normalized) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet is already a primary login method" },
      409,
    );
  }
  if (await evmWalletAlreadyBelongsToAnotherUser(address, userId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet is already linked to another user" },
      409,
    );
  }

  const [existing] = await getDb()
    .select({
      id: accounts.id,
      userId: accounts.userId,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    })
    .from(accounts)
    .where(
      and(eq(accounts.provider, "wallet:ethereum"), eq(accounts.providerAccountId, normalized)),
    );
  if (existing) {
    if (existing.userId !== userId) {
      return c.json<ApiResponse>(
        { ok: false, error: "Wallet is already linked to another user" },
        409,
      );
    }
    const { userId: _ownerUserId, ...account } = existing;
    return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
      ok: true,
      data: { account, isNew: false },
    });
  }

  const [account] = await getDb()
    .insert(accounts)
    .values({ userId, provider: "wallet:ethereum", providerAccountId: normalized })
    .returning({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    });
  await writeUserAudit(c, {
    tenantId: session.tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.account.link",
    resourceType: "user",
    resourceId: userId,
    metadata: { provider: "wallet:ethereum", providerAccountId: normalized },
  });
  dispatchWebhook(session.tenantId ?? personalTenantId(userId), userId, "user.linked_account", {
    userId,
    provider: "wallet:ethereum",
    providerAccountId: normalized,
    accountId: account.id,
  });

  return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
    ok: true,
    data: { account, isNew: true },
  });
});

user.post("/me/accounts/wallet/solana/nonce", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const body = await safeJsonParse<{ publicKey?: unknown }>(c);
  const requestedPublicKey =
    body?.publicKey === undefined || body.publicKey === null || body.publicKey === ""
      ? null
      : normalizeSolanaAddress(body.publicKey);
  if (body?.publicKey !== undefined && !requestedPublicKey) {
    return c.json<ApiResponse>({ ok: false, error: "publicKey must be a Solana address" }, 400);
  }

  const userId = c.get("userId");
  const nonce = crypto.randomUUID();
  const issuedAt = new Date().toISOString();
  const message = buildWalletLinkMessage({
    chain: "solana",
    userId,
    nonce,
    issuedAt,
    ...(requestedPublicKey ? { account: requestedPublicKey } : {}),
  });
  await walletLinkChallenges.setIfNotExists(
    walletLinkChallengeKey("solana", userId, nonce),
    JSON.stringify({ userId, publicKey: requestedPublicKey, issuedAt }),
  );

  return c.json<
    ApiResponse<{ nonce: string; message: string; expiresIn: number; publicKey?: string }>
  >({
    ok: true,
    data: {
      nonce,
      message,
      expiresIn: Math.floor(WALLET_LINK_CHALLENGE_TTL_MS / 1000),
      ...(requestedPublicKey ? { publicKey: requestedPublicKey } : {}),
    },
  });
});

user.post("/me/accounts/wallet/solana", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet linking requires a recent MFA step-up session" },
      403,
    );
  }

  const body = await safeJsonParse<{
    publicKey?: unknown;
    message?: unknown;
    signature?: unknown;
  }>(c);
  const publicKey = normalizeSolanaAddress(body?.publicKey);
  if (!publicKey) {
    return c.json<ApiResponse>({ ok: false, error: "publicKey must be a Solana address" }, 400);
  }
  if (!isNonEmptyString(body?.message) || !isNonEmptyString(body?.signature)) {
    return c.json<ApiResponse>({ ok: false, error: "message and signature are required" }, 400);
  }

  const parsed = parseWalletLinkMessage("solana", body.message);
  const userId = c.get("userId");
  if (!parsed || parsed.userId !== userId) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid wallet link message" }, 400);
  }
  const parsedPublicKey = parsed.account ? normalizeSolanaAddress(parsed.account) : null;
  if (parsedPublicKey && parsedPublicKey !== publicKey) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet link message public key mismatch" },
      400,
    );
  }

  const challengeKey = walletLinkChallengeKey("solana", userId, parsed.nonce);
  const rawChallenge = await walletLinkChallenges.get(challengeKey);
  if (!rawChallenge) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired wallet link nonce" }, 401);
  }
  const challenge = JSON.parse(rawChallenge) as { publicKey?: string | null };
  if (challenge.publicKey && challenge.publicKey !== publicKey) {
    return c.json<ApiResponse>({ ok: false, error: "Wallet link nonce public key mismatch" }, 401);
  }

  if (!verifySolanaWalletLinkSignature(body.message, body.signature, publicKey)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid wallet signature" }, 401);
  }

  const lockKey = walletLinkRedeemLockKey("solana", userId, parsed.nonce);
  if (!(await walletLinkChallenges.setIfNotExists(lockKey, "1", WALLET_LINK_REDEEM_LOCK_TTL_MS))) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet link nonce is already being redeemed" },
      409,
    );
  }
  try {
    const consumed = await walletLinkChallenges.consume(challengeKey);
    if (!consumed || consumed !== rawChallenge) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid or expired wallet link nonce" }, 401);
    }
  } finally {
    walletLinkChallenges.delete(lockKey);
  }

  const [userRow] = await getDb()
    .select({ id: users.id, walletAddress: users.walletAddress, walletChain: users.walletChain })
    .from(users)
    .where(eq(users.id, userId));
  if (!userRow) return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);
  if (userRow.walletChain === "solana" && userRow.walletAddress === publicKey) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet is already a primary login method" },
      409,
    );
  }
  if (await solanaWalletAlreadyBelongsToAnotherUser(publicKey, userId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet is already linked to another user" },
      409,
    );
  }

  const [existing] = await getDb()
    .select({
      id: accounts.id,
      userId: accounts.userId,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    })
    .from(accounts)
    .where(and(eq(accounts.provider, "wallet:solana"), eq(accounts.providerAccountId, publicKey)));
  if (existing) {
    if (existing.userId !== userId) {
      return c.json<ApiResponse>(
        { ok: false, error: "Wallet is already linked to another user" },
        409,
      );
    }
    const { userId: _ownerUserId, ...account } = existing;
    return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
      ok: true,
      data: { account, isNew: false },
    });
  }

  const [account] = await getDb()
    .insert(accounts)
    .values({ userId, provider: "wallet:solana", providerAccountId: publicKey })
    .returning({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    });
  await writeUserAudit(c, {
    tenantId: session.tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.account.link",
    resourceType: "user",
    resourceId: userId,
    metadata: { provider: "wallet:solana", providerAccountId: publicKey },
  });
  dispatchWebhook(session.tenantId ?? personalTenantId(userId), userId, "user.linked_account", {
    userId,
    provider: "wallet:solana",
    providerAccountId: publicKey,
    accountId: account.id,
  });

  return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
    ok: true,
    data: { account, isNew: true },
  });
});

user.post("/me/accounts/oauth/:provider/challenge", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "OAuth account linking requires a recent MFA step-up session" },
      403,
    );
  }

  const providerName = c.req.param("provider");
  if (!isBuiltInProvider(providerName)) {
    return c.json<ApiResponse>({ ok: false, error: `Unknown provider: ${providerName}` }, 400);
  }

  const body = await safeJsonParse<{
    redirectUri?: unknown;
    codeChallenge?: unknown;
    codeChallengeMethod?: unknown;
  }>(c);
  const redirectUri = typeof body?.redirectUri === "string" ? body.redirectUri.trim() : "";
  const codeChallenge =
    typeof body?.codeChallenge === "string" ? body.codeChallenge.trim() : undefined;
  const codeChallengeMethod =
    typeof body?.codeChallengeMethod === "string" ? body.codeChallengeMethod.trim() : undefined;
  if (!redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "redirectUri is required" }, 400);
  }

  try {
    await assertAllowedOAuthRedirectUri(redirectUri, session.tenantId);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirectUri" },
      400,
    );
  }

  const userId = c.get("userId");
  const state = randomOAuthLinkState();
  await oauthLinkChallenges.setIfNotExists(
    oauthLinkChallengeKey(userId, state),
    JSON.stringify({
      userId,
      providerName,
      redirectUri,
      tenantId: session.tenantId ?? null,
      codeChallenge,
      codeChallengeMethod,
      issuedAt: new Date().toISOString(),
    }),
  );

  return c.json<
    ApiResponse<{
      state: string;
      redirectUri: string;
      expiresIn: number;
    }>
  >({
    ok: true,
    data: {
      state,
      redirectUri,
      expiresIn: Math.floor(OAUTH_LINK_CHALLENGE_TTL_MS / 1000),
    },
  });
});

user.post("/me/accounts/oauth/:provider/token", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "OAuth account linking requires a recent MFA step-up session" },
      403,
    );
  }

  const providerName = c.req.param("provider");
  if (!isBuiltInProvider(providerName)) {
    return c.json<ApiResponse>({ ok: false, error: `Unknown provider: ${providerName}` }, 400);
  }

  const body = await safeJsonParse<{
    code?: unknown;
    redirectUri?: unknown;
    state?: unknown;
    codeVerifier?: unknown;
  }>(c);
  const code = typeof body?.code === "string" ? body.code.trim() : "";
  const redirectUri = typeof body?.redirectUri === "string" ? body.redirectUri.trim() : "";
  const state = typeof body?.state === "string" ? body.state.trim() : "";
  const codeVerifier = typeof body?.codeVerifier === "string" ? body.codeVerifier.trim() : "";
  if (!code || !redirectUri || !state) {
    return c.json<ApiResponse>(
      { ok: false, error: "code, redirectUri, and state are required" },
      400,
    );
  }

  const userId = c.get("userId");
  const challenge = await oauthLinkChallenges.consume(oauthLinkChallengeKey(userId, state));
  if (!challenge) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired OAuth link state" }, 401);
  }
  let challengePayload: {
    userId?: string;
    providerName?: string;
    redirectUri?: string;
    tenantId?: string | null;
    codeChallenge?: string;
    codeChallengeMethod?: string;
  };
  try {
    challengePayload = JSON.parse(challenge);
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Malformed OAuth link state" }, 401);
  }
  if (challengePayload.userId !== userId) {
    return c.json<ApiResponse>({ ok: false, error: "OAuth link state user mismatch" }, 401);
  }
  if (challengePayload.providerName !== providerName) {
    return c.json<ApiResponse>({ ok: false, error: "OAuth link state provider mismatch" }, 401);
  }
  if (challengePayload.redirectUri !== redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "OAuth link state redirectUri mismatch" }, 401);
  }
  if ((challengePayload.tenantId ?? null) !== (session.tenantId ?? null)) {
    return c.json<ApiResponse>({ ok: false, error: "OAuth link state tenant mismatch" }, 401);
  }
  try {
    await assertAllowedOAuthRedirectUri(redirectUri, session.tenantId);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirectUri" },
      400,
    );
  }

  let oauthClient: OAuthClient;
  try {
    oauthClient = new OAuthClient(getProviderConfig(providerName));
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Provider not configured" },
      503,
    );
  }

  let tokenResponse: Awaited<ReturnType<OAuthClient["exchangeCode"]>>;
  try {
    tokenResponse = await oauthClient.exchangeCode(code, redirectUri, codeVerifier || undefined);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Token exchange failed" },
      502,
    );
  }

  let providerUser: Awaited<ReturnType<OAuthClient["getUserInfo"]>>;
  try {
    providerUser = await oauthClient.getUserInfo(tokenResponse.access_token);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Failed to fetch user info" },
      502,
    );
  }

  if (!providerUser.id) {
    return c.json<ApiResponse>({ ok: false, error: "Provider returned no account ID" }, 400);
  }

  if (await linkedAccountAlreadyBelongsToAnotherUser(providerName, providerUser.id, userId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "OAuth account is already linked to another user" },
      409,
    );
  }
  const encryptedProviderTokens = encryptOAuthProviderTokens(
    tokenResponse.access_token,
    tokenResponse.refresh_token ?? null,
  );
  const expiresAt = tokenResponse.expires_in
    ? Math.floor(Date.now() / 1000) + tokenResponse.expires_in
    : null;
  const db = getDb();
  const [inserted] = await db
    .insert(accounts)
    .values({
      userId,
      provider: providerName,
      providerAccountId: providerUser.id,
      ...encryptedProviderTokens,
      expiresAt,
    })
    .onConflictDoNothing({
      target: [accounts.provider, accounts.providerAccountId],
    })
    .returning({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    });
  let account = inserted;
  const isNew = Boolean(inserted);
  if (!account) {
    const [current] = await db
      .select({
        id: accounts.id,
        userId: accounts.userId,
        provider: accounts.provider,
        providerAccountId: accounts.providerAccountId,
        expiresAt: accounts.expiresAt,
      })
      .from(accounts)
      .where(
        and(eq(accounts.provider, providerName), eq(accounts.providerAccountId, providerUser.id)),
      );
    if (!current || current.userId !== userId) {
      return c.json<ApiResponse>(
        { ok: false, error: "OAuth account is already linked to another user" },
        409,
      );
    }
    const [updated] = await db
      .update(accounts)
      .set({ ...encryptedProviderTokens, expiresAt })
      .where(and(eq(accounts.id, current.id), eq(accounts.userId, userId)))
      .returning({
        id: accounts.id,
        provider: accounts.provider,
        providerAccountId: accounts.providerAccountId,
        expiresAt: accounts.expiresAt,
      });
    if (!updated) {
      return c.json<ApiResponse>(
        { ok: false, error: "OAuth account ownership changed during link" },
        409,
      );
    }
    account = updated;
  }

  await writeUserAudit(c, {
    tenantId: session.tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.account.link",
    resourceType: "user",
    resourceId: userId,
    metadata: { provider: providerName, providerAccountId: providerUser.id },
  });
  dispatchWebhook(session.tenantId ?? personalTenantId(userId), userId, "user.linked_account", {
    userId,
    provider: providerName,
    providerAccountId: providerUser.id,
    accountId: account.id,
  });

  return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
    ok: true,
    data: { account, isNew },
  });
});

for (const channel of ["sms", "whatsapp"] as const) {
  user.post(`/me/accounts/phone/${channel}/send`, async (c) => {
    const personalSessionResponse = requirePersonalUserSession(c);
    if (personalSessionResponse) return personalSessionResponse;
    if (channel === "whatsapp" && process.env.WHATSAPP_OTP_ENABLED !== "true") {
      return c.json<ApiResponse>({ ok: false, error: "WhatsApp OTP is not configured" }, 503);
    }
    const session = c.get("userSession");
    if (!hasRecentMfaStepUp(session)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Phone account linking requires a recent MFA step-up session" },
        403,
      );
    }

    const body = await safeJsonParse<{ phone?: unknown }>(c);
    if (!isValidE164(body?.phone)) {
      return c.json<ApiResponse>({ ok: false, error: "phone must be E.164" }, 400);
    }

    const userId = c.get("userId");
    let expiresAt: Date;
    try {
      ({ expiresAt } = await getPhoneAuth().sendOtp(body.phone, phoneLinkPurpose(channel, userId)));
    } catch (err) {
      if (err instanceof Error && err.message === "SMS provider not configured") {
        return c.json<ApiResponse>(
          {
            ok: false,
            error:
              channel === "whatsapp"
                ? "WhatsApp OTP provider not configured"
                : "SMS provider not configured",
          },
          503,
        );
      }
      throw err;
    }

    return c.json<ApiResponse<{ phone: string; expiresAt: string }>>({
      ok: true,
      data: { phone: maskedPhone(body.phone), expiresAt: expiresAt.toISOString() },
    });
  });

  user.post(`/me/accounts/phone/${channel}/verify`, async (c) => {
    const personalSessionResponse = requirePersonalUserSession(c);
    if (personalSessionResponse) return personalSessionResponse;
    if (channel === "whatsapp" && process.env.WHATSAPP_OTP_ENABLED !== "true") {
      return c.json<ApiResponse>({ ok: false, error: "WhatsApp OTP is not configured" }, 503);
    }
    const session = c.get("userSession");
    if (!hasRecentMfaStepUp(session)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Phone account linking requires a recent MFA step-up session" },
        403,
      );
    }

    const body = await safeJsonParse<{ phone?: unknown; code?: unknown }>(c);
    if (!isValidE164(body?.phone) || typeof body?.code !== "string") {
      return c.json<ApiResponse>({ ok: false, error: "phone and code are required" }, 400);
    }
    if (!/^\d{6}$/.test(body.code)) {
      return c.json<ApiResponse>({ ok: false, error: "code must be 6 digits" }, 400);
    }

    const userId = c.get("userId");
    const verified = await getPhoneAuth().verifyOtp(
      body.phone,
      body.code,
      phoneLinkPurpose(channel, userId),
    );
    if (!verified.valid) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid or expired code" }, 401);
    }

    const provider = channel === "whatsapp" ? "whatsapp" : "phone";
    const providerAccountId = phoneProviderAccountId(body.phone);
    const [userRow] = await getDb()
      .select({ id: users.id, walletAddress: users.walletAddress })
      .from(users)
      .where(eq(users.id, userId));
    if (!userRow) return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);
    if (userRow.walletAddress === providerAccountId) {
      return c.json<ApiResponse>(
        { ok: false, error: "Phone is already a primary login method" },
        409,
      );
    }
    if (await phoneAlreadyBelongsToAnotherUser(provider, body.phone, userId)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Phone is already linked to another user" },
        409,
      );
    }

    const [existing] = await getDb()
      .select({
        id: accounts.id,
        userId: accounts.userId,
        provider: accounts.provider,
        providerAccountId: accounts.providerAccountId,
        expiresAt: accounts.expiresAt,
      })
      .from(accounts)
      .where(
        and(eq(accounts.provider, provider), eq(accounts.providerAccountId, providerAccountId)),
      );
    if (existing) {
      if (existing.userId !== userId) {
        return c.json<ApiResponse>(
          { ok: false, error: "Phone is already linked to another user" },
          409,
        );
      }
      const { userId: _ownerUserId, ...account } = existing;
      return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
        ok: true,
        data: { account, isNew: false },
      });
    }

    const [account] = await getDb()
      .insert(accounts)
      .values({ userId, provider, providerAccountId })
      .returning({
        id: accounts.id,
        provider: accounts.provider,
        providerAccountId: accounts.providerAccountId,
        expiresAt: accounts.expiresAt,
      });
    await writeUserAudit(c, {
      tenantId: session.tenantId ?? personalTenantId(userId),
      actorType: "user",
      actorId: userId,
      action: "user.account.link",
      resourceType: "user",
      resourceId: userId,
      metadata: { provider, providerAccountId },
    });
    dispatchWebhook(session.tenantId ?? personalTenantId(userId), userId, "user.linked_account", {
      userId,
      provider,
      providerAccountId,
      accountId: account.id,
    });

    return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
      ok: true,
      data: { account, isNew: true },
    });
  });
}

user.post("/me/accounts/telegram/challenge", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Telegram account linking requires a recent MFA step-up session" },
      403,
    );
  }

  const botToken = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!botToken) {
    return c.json<ApiResponse>({ ok: false, error: "Telegram login is not configured" }, 503);
  }
  const userId = c.get("userId");
  const challengeId = crypto.randomUUID();
  await socialLinkChallenges.setIfNotExists(
    socialLinkChallengeKey("telegram", userId, challengeId),
    JSON.stringify({ userId, issuedAt: new Date().toISOString() }),
  );
  return c.json<ApiResponse<{ challengeId: string; expiresIn: number }>>({
    ok: true,
    data: { challengeId, expiresIn: Math.floor(SOCIAL_LINK_CHALLENGE_TTL_MS / 1000) },
  });
});

user.post("/me/accounts/telegram", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Telegram account linking requires a recent MFA step-up session" },
      403,
    );
  }

  const botToken = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!botToken) {
    return c.json<ApiResponse>({ ok: false, error: "Telegram login is not configured" }, 503);
  }
  const body = await safeJsonParse<TelegramLoginPayload & { challengeId?: unknown }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const challengeId = typeof body.challengeId === "string" ? body.challengeId.trim() : "";
  if (!challengeId) {
    return c.json<ApiResponse>({ ok: false, error: "challengeId is required" }, 400);
  }
  const userId = c.get("userId");
  const challengeKey = socialLinkChallengeKey("telegram", userId, challengeId);
  const challenge = await socialLinkChallenges.consume(challengeKey);
  if (!challenge) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired Telegram challenge" }, 401);
  }

  const { challengeId: _challengeId, ...telegramPayload } = body;
  let telegramUser: ReturnType<typeof verifyTelegramLogin>;
  try {
    telegramUser = verifyTelegramLogin(telegramPayload, botToken);
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid Telegram login" },
      401,
    );
  }

  const telegramHash = typeof body.hash === "string" ? body.hash : String(body.hash);
  if (!(await consumeTelegramLinkHashOnce(telegramHash, telegramUser.authDate))) {
    return c.json<ApiResponse>(
      { ok: false, error: "Telegram login payload was already used" },
      401,
    );
  }
  if (await linkedAccountAlreadyBelongsToAnotherUser("telegram", telegramUser.id, userId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Telegram account is already linked to another user" },
      409,
    );
  }
  const [existing] = await getDb()
    .select({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    })
    .from(accounts)
    .where(and(eq(accounts.provider, "telegram"), eq(accounts.providerAccountId, telegramUser.id)));
  if (existing) {
    return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
      ok: true,
      data: { account: existing, isNew: false },
    });
  }

  const [account] = await getDb()
    .insert(accounts)
    .values({ userId, provider: "telegram", providerAccountId: telegramUser.id })
    .returning({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    });
  await writeUserAudit(c, {
    tenantId: session.tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.account.link",
    resourceType: "user",
    resourceId: userId,
    metadata: { provider: "telegram", providerAccountId: telegramUser.id },
  });
  dispatchWebhook(session.tenantId ?? personalTenantId(userId), userId, "user.linked_account", {
    userId,
    provider: "telegram",
    providerAccountId: telegramUser.id,
    accountId: account.id,
  });

  return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
    ok: true,
    data: { account, isNew: true },
  });
});

user.post("/me/accounts/farcaster/nonce", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Farcaster account linking requires a recent MFA step-up session" },
      403,
    );
  }
  if (process.env.FARCASTER_LOGIN_ENABLED !== "true") {
    return c.json<ApiResponse>({ ok: false, error: "Farcaster login is not configured" }, 503);
  }

  const userId = c.get("userId");
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  await socialLinkChallenges.setIfNotExists(
    socialLinkChallengeKey("farcaster", userId, nonce),
    JSON.stringify({ userId, issuedAt: new Date().toISOString() }),
  );
  return c.json<ApiResponse<{ nonce: string; expiresIn: number }>>({
    ok: true,
    data: { nonce, expiresIn: Math.floor(SOCIAL_LINK_CHALLENGE_TTL_MS / 1000) },
  });
});

user.post("/me/accounts/farcaster", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Farcaster account linking requires a recent MFA step-up session" },
      403,
    );
  }

  if (process.env.FARCASTER_LOGIN_ENABLED !== "true") {
    return c.json<ApiResponse>({ ok: false, error: "Farcaster login is not configured" }, 503);
  }
  const body = await safeJsonParse<Parameters<typeof verifyFarcasterLogin>[0]>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  let farcasterUser: Awaited<ReturnType<typeof verifyFarcasterLogin>>;
  try {
    farcasterUser = await verifyFarcasterLogin(body, {
      expectedDomain: userFarcasterAllowedDomains(),
      maxMessageAgeMs: 10 * 60 * 1000,
    });
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid Farcaster login" },
      401,
    );
  }

  const userId = c.get("userId");
  const nonceKey = socialLinkChallengeKey("farcaster", userId, farcasterUser.message.nonce);
  const nonceRecord = await socialLinkChallenges.consume(nonceKey);
  if (!nonceRecord) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired Farcaster nonce" }, 401);
  }

  const providerAccountId = farcasterProviderAccountId(farcasterUser.custodyAddress);
  if (await linkedAccountAlreadyBelongsToAnotherUser("farcaster", providerAccountId, userId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Farcaster account is already linked to another user" },
      409,
    );
  }
  const [existing] = await getDb()
    .select({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    })
    .from(accounts)
    .where(
      and(eq(accounts.provider, "farcaster"), eq(accounts.providerAccountId, providerAccountId)),
    );
  if (existing) {
    return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
      ok: true,
      data: { account: existing, isNew: false },
    });
  }

  const [account] = await getDb()
    .insert(accounts)
    .values({ userId, provider: "farcaster", providerAccountId })
    .returning({
      id: accounts.id,
      provider: accounts.provider,
      providerAccountId: accounts.providerAccountId,
      expiresAt: accounts.expiresAt,
    });
  await writeUserAudit(c, {
    tenantId: session.tenantId ?? personalTenantId(userId),
    actorType: "user",
    actorId: userId,
    action: "user.account.link",
    resourceType: "user",
    resourceId: userId,
    metadata: { provider: "farcaster", providerAccountId },
  });
  dispatchWebhook(session.tenantId ?? personalTenantId(userId), userId, "user.linked_account", {
    userId,
    provider: "farcaster",
    providerAccountId,
    accountId: account.id,
  });

  return c.json<ApiResponse<{ account: UserLinkedAccount; isNew: boolean }>>({
    ok: true,
    data: { account, isNew: true },
  });
});

user.delete("/me/accounts/:provider/:providerAccountId", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const session = c.get("userSession");
  const tenantId = session.tenantId ?? `personal-${userId}`;
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Account unlinking requires a recent MFA step-up session" },
      403,
    );
  }
  const provider = c.req.param("provider");
  const providerAccountId = c.req.param("providerAccountId");
  if (!isValidAccountProvider(provider) || !isValidProviderAccountId(providerAccountId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid account identifier" }, 400);
  }

  const db = getDb();
  const [initialUserRow] = await db
    .select({
      id: users.id,
      email: users.email,
      walletAddress: users.walletAddress,
    })
    .from(users)
    .where(eq(users.id, userId));
  if (!initialUserRow) return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);

  const initialUserAccounts = await db.select().from(accounts).where(eq(accounts.userId, userId));
  const initialPasskeys = await db
    .select({ id: authenticators.id, credentialId: authenticators.credentialId })
    .from(authenticators)
    .where(eq(authenticators.userId, userId));
  const initialAccount = initialUserAccounts.find(
    (row) => row.provider === provider && row.providerAccountId === providerAccountId,
  );
  const initialPasskey =
    provider === "passkey"
      ? initialPasskeys.find((row) => row.credentialId === providerAccountId)
      : undefined;
  const initialLinkedAccountId = initialAccount?.id ?? initialPasskey?.id;
  if (!initialLinkedAccountId) {
    return c.json<ApiResponse>({ ok: false, error: "Linked account not found" }, 404);
  }

  const initialLoginMethodCount =
    primaryLoginMethods(initialUserRow).length +
    initialUserAccounts.length +
    initialPasskeys.length;
  if (initialLoginMethodCount <= 1) {
    return c.json<ApiResponse>(
      { ok: false, error: "Cannot unlink the user's last login method" },
      409,
    );
  }

  const issuedBefore = Math.floor(Date.now() / 1000) + 1;
  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: userId,
    action: "user.account.unlink.authorized",
    resourceType: "user",
    resourceId: userId,
    metadata: {
      provider,
      providerAccountId,
      accountId: initialLinkedAccountId,
      issuedBefore,
    },
  });

  let mutation: UserAccountUnlinkMutation;
  try {
    mutation = await db.transaction(async (tx) => {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtextextended(${`user_session_${userId}`}, 0))`,
      );
      const [userRow] = await tx
        .select({
          id: users.id,
          email: users.email,
          walletAddress: users.walletAddress,
        })
        .from(users)
        .where(eq(users.id, userId));
      if (!userRow) throw new Error("User not found");

      const userAccounts = await tx.select().from(accounts).where(eq(accounts.userId, userId));
      const passkeys = await tx
        .select({ id: authenticators.id, credentialId: authenticators.credentialId })
        .from(authenticators)
        .where(eq(authenticators.userId, userId));
      const account = userAccounts.find(
        (row) => row.provider === provider && row.providerAccountId === providerAccountId,
      );
      const passkey =
        provider === "passkey"
          ? passkeys.find((row) => row.credentialId === providerAccountId)
          : undefined;
      if (!account && !passkey) throw new Error("Linked account not found");

      const loginMethodCount =
        primaryLoginMethods(userRow).length + userAccounts.length + passkeys.length;
      if (loginMethodCount <= 1) {
        throw new Error("Cannot unlink the user's last login method");
      }

      const refreshTokenSnapshot = await tx
        .select()
        .from(refreshTokens)
        .where(eq(refreshTokens.userId, userId));
      await revocationStore.revokeUserTokens(userId, issuedBefore);
      const [deleted] = account
        ? await tx
            .delete(accounts)
            .where(
              and(
                eq(accounts.id, account.id),
                eq(accounts.userId, userId),
                eq(accounts.provider, provider),
                eq(accounts.providerAccountId, providerAccountId),
              ),
            )
            .returning()
        : await tx
            .delete(authenticators)
            .where(
              and(
                eq(authenticators.id, passkey!.id),
                eq(authenticators.userId, userId),
                eq(authenticators.credentialId, providerAccountId),
              ),
            )
            .returning();
      if (!deleted) throw new Error("Linked account changed during unlink");
      await tx.delete(refreshTokens).where(eq(refreshTokens.userId, userId));
      return {
        accountId: deleted.id,
        deletedAccount: account ? (deleted as UserAccountRow) : undefined,
        deletedPasskey: passkey ? (deleted as UserAuthenticatorRow) : undefined,
        deletedRefreshTokens: refreshTokenSnapshot,
      };
    });
  } catch (error) {
    if (error instanceof Error) {
      const status =
        error.message === "User not found"
          ? 404
          : error.message === "Linked account not found"
            ? 404
            : error.message === "Cannot unlink the user's last login method"
              ? 409
              : error.message === "Linked account changed during unlink"
                ? 409
                : 500;
      return c.json<ApiResponse>({ ok: false, error: error.message }, status);
    }
    throw error;
  }

  try {
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "user.account.unlink",
      resourceType: "user",
      resourceId: userId,
      metadata: { provider, providerAccountId, accountId: mutation.accountId, issuedBefore },
    });
  } catch (error) {
    await restoreUserAccountUnlinkMutation(mutation);
    throw error;
  }
  dispatchWebhook(tenantId, userId, "user.unlinked_account", {
    userId,
    provider,
    providerAccountId,
    accountId: mutation.accountId,
  });

  return c.json<ApiResponse<{ deleted: boolean; issuedBefore: number }>>({
    ok: true,
    data: { deleted: true, issuedBefore },
  });
});

// ─── GET /me/account ─────────────────────────────────────────────────────────

user.get("/me/account", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const db = getDb();
  const [userRow] = await db
    .select({
      id: users.id,
      email: users.email,
      emailVerified: users.emailVerified,
      name: users.name,
      image: users.image,
      walletAddress: users.walletAddress,
      walletChain: users.walletChain,
      customMetadata: users.customMetadata,
      createdAt: users.createdAt,
      updatedAt: users.updatedAt,
    })
    .from(users)
    .where(eq(users.id, userId));
  if (!userRow) return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);

  const chainId = parseOptionalChainId(c.req.query("chainId"));
  if (typeof chainId === "string") return c.json<ApiResponse>({ ok: false, error: chainId }, 400);
  const customTokens = parseCustomTokenList(c.req.query("tokens"));
  if (typeof customTokens === "string") {
    return c.json<ApiResponse>({ ok: false, error: customTokens }, 400);
  }

  const linkedAccounts = await listUserLinkedAccounts(userId);

  let vault: Vault | null = null;
  let vaultUnavailableReason: string | null = null;
  try {
    vault = getVault();
  } catch (error) {
    vaultUnavailableReason = error instanceof Error ? error.message : "Vault not configured";
  }

  const wallet = vault ? await getUserWallet(vault, userId) : null;
  const personalTenant = personalTenantId(userId);
  const noWalletSponsorship = publicGasSponsorshipState(
    await readTenantGasSponsorshipConfig(personalTenant),
  );

  if (!wallet || !vault) {
    return c.json<ApiResponse>({
      ok: true,
      data: {
        id: userId,
        type: "user",
        userId,
        tenantId: personalTenant,
        email: userRow.email,
        emailVerified: userRow.emailVerified,
        name: userRow.name,
        image: userRow.image,
        walletAddress: userRow.walletAddress,
        walletChain: userRow.walletChain,
        customMetadata: userRow.customMetadata,
        linkedAccounts,
        primaryLoginMethods: primaryLoginMethods(userRow),
        wallet: null,
        wallets: [],
        walletAddresses: {},
        balances: { evm: null, unavailableReason: vaultUnavailableReason ?? "No wallet found" },
        portfolio: {
          chainId: chainId ?? null,
          walletAddress: null,
          native: null,
          tokens: [],
          totalUsd: null,
          totalUsdText: null,
          unavailableReason: vaultUnavailableReason ?? "No wallet found",
        },
        spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
        capabilities: [],
        sponsorship: {
          enabled: noWalletSponsorship.enabled,
          provider: noWalletSponsorship.provider,
          mode: noWalletSponsorship.mode,
          circuitBreakerEnabled: noWalletSponsorship.circuitBreakerEnabled,
        },
        createdAt: userRow.createdAt,
        updatedAt: userRow.updatedAt,
      },
    });
  }
  const activeVault = vault as Vault;

  const [walletRows, txStats, monthWei, balanceResult, tokenBalancesResult, gasSponsorshipConfig] =
    await Promise.all([
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
        .where(eq(agentWallets.agentId, wallet.id)),
      getTransactionStats(wallet.id),
      getMonthlySpend(wallet.id),
      activeVault.getBalance(personalTenant, wallet.id, chainId).catch((error: unknown) => ({
        unavailable: true as const,
        reason: error instanceof Error ? error.message : "Balance unavailable",
      })),
      activeVault
        .getTokenBalances(personalTenant, wallet.id, chainId, customTokens)
        .catch((error) => ({
          unavailable: true as const,
          reason: error instanceof Error ? error.message : "Token balances unavailable",
        })),
      readTenantGasSponsorshipConfig(personalTenant),
    ]);
  const sponsorship = publicGasSponsorshipState(gasSponsorshipConfig);

  const wallets = userWalletRowsToAccountWallets(wallet, walletRows);
  const walletAddresses = wallets.reduce<Partial<Record<ChainFamily, string>>>((acc, row) => {
    acc[row.chainFamily] = row.address;
    return acc;
  }, {});
  const portfolioChainId =
    "unavailable" in balanceResult ? (chainId ?? null) : balanceResult.chainId;
  const nativeAsset: UserPortfolioAsset | null =
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
  const tokenAssets: UserPortfolioAsset[] =
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

  return c.json<ApiResponse>({
    ok: true,
    data: {
      id: userId,
      type: "user",
      userId,
      tenantId: personalTenant,
      email: userRow.email,
      emailVerified: userRow.emailVerified,
      name: userRow.name,
      image: userRow.image,
      walletAddress: wallet.walletAddress,
      walletChain: userRow.walletChain,
      customMetadata: userRow.customMetadata,
      linkedAccounts,
      primaryLoginMethods: primaryLoginMethods(userRow),
      wallet: {
        id: wallet.id,
        agentId: wallet.id,
        walletAddress: wallet.walletAddress,
        walletAddresses,
        createdAt: wallet.createdAt,
      },
      wallets,
      walletAddresses,
      balances:
        "unavailable" in balanceResult
          ? { evm: null, unavailableReason: balanceResult.reason }
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
          "unavailable" in balanceResult ? wallet.walletAddress : balanceResult.walletAddress,
        native: nativeAsset,
        tokens: tokenAssets,
        totalUsd: sumNullableUsd([
          nativeAsset?.usdValue ?? null,
          ...tokenAssets.map((token) => token.usdValue),
        ]),
        totalUsdText: sumUsdText([
          nativeAsset?.usdValueText ?? null,
          ...tokenAssets.map((token) => token.usdValueText),
        ]),
        ...(portfolioUnavailableReasons.length > 0
          ? { unavailableReason: portfolioUnavailableReasons.join("; ") }
          : {}),
      },
      spend: {
        todayWei: txStats.spentToday.toString(),
        weekWei: txStats.spentThisWeek.toString(),
        monthWei,
      },
      capabilities: USER_ACCOUNT_CAPABILITIES,
      sponsorship: {
        enabled: sponsorship.enabled,
        provider: sponsorship.provider,
        mode: sponsorship.mode,
        circuitBreakerEnabled: sponsorship.circuitBreakerEnabled,
      },
      createdAt: userRow.createdAt,
      updatedAt: userRow.updatedAt,
    },
  });
});

user.get("/me/aggregation", (c) => {
  const query = new URL(c.req.url).search;
  return user.request(`/me/account${query}`, {
    method: "GET",
    headers: c.req.raw.headers,
  });
});

user.get("/me/accounts/aggregation", (c) => {
  const query = new URL(c.req.url).search;
  return user.request(`/me/account${query}`, {
    method: "GET",
    headers: c.req.raw.headers,
  });
});

// ─── GET /me/wallet ───────────────────────────────────────────────────────────

user.get("/me/wallet", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");

  let vault: Vault;
  try {
    vault = getVault();
  } catch (_e) {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const wallet: AgentIdentity | null = await getUserWallet(vault, userId);
  if (!wallet) {
    return c.json<ApiResponse>(
      { ok: false, error: "No wallet found — call POST /me/wallet to provision" },
      404,
    );
  }

  const chainIdParam = c.req.query("chainId");
  const chainId = chainIdParam ? parseInt(chainIdParam, 10) : undefined;

  try {
    const balance = await vault.getBalance(`personal-${userId}`, wallet.id, chainId);

    return c.json<ApiResponse<AgentBalance>>({
      ok: true,
      data: {
        agentId: wallet.id,
        walletAddress: wallet.walletAddress,
        balances: {
          native: balance.native.toString(),
          nativeFormatted: balance.nativeFormatted,
          chainId: balance.chainId,
          symbol: balance.symbol,
        },
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: msg }, 500);
  }
});

// ─── POST /me/wallet ──────────────────────────────────────────────────────────

user.post("/me/wallet", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");

  let vault: Vault;
  try {
    vault = getVault();
  } catch (_e) {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  let wallet: AgentIdentity | null = await getUserWallet(vault, userId);
  if (!wallet) {
    try {
      const session = c.get("userSession");
      const displayName = (session.address as string | undefined) ?? userId;
      const tenantId = await ensurePersonalTenant(userId, displayName);
      await provisionUserWallet(vault, userId, displayName);
      wallet = await getUserWallet(vault, userId);
      if (!wallet) throw new Error("Provision succeeded but agent not found");
      dispatchWebhook(tenantId, wallet.id, "user.wallet_created", {
        userId,
        walletId: wallet.id,
        walletAddress: wallet.walletAddress,
        walletAddresses: wallet.walletAddresses,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      return c.json<ApiResponse>({ ok: false, error: `Failed to provision wallet: ${msg}` }, 500);
    }
  }

  return c.json<ApiResponse<{ agentId: string; walletAddress: string }>>(
    {
      ok: true,
      data: {
        agentId: wallet.id,
        walletAddress: wallet.walletAddress,
      },
    },
    201,
  );
});

// ─── POST /me/wallet/claim-pregenerated ──────────────────────────────────────

user.post("/me/wallet/claim-pregenerated", async (c) => {
  setNoStoreHeaders(c);
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Pregenerated wallet claim requires a recent MFA step-up session" },
      403,
    );
  }

  const body = await safeJsonParse<{ tenantId?: unknown; claimToken?: unknown }>(c);
  const sourceTenantId = isValidTenantId(body?.tenantId) ? body.tenantId : null;
  const claimToken = typeof body?.claimToken === "string" ? body.claimToken.trim() : "";
  if (!sourceTenantId) {
    return c.json<ApiResponse>({ ok: false, error: "tenantId is required" }, 400);
  }
  if (!claimToken || claimToken.length > 160) {
    return c.json<ApiResponse>({ ok: false, error: "claimToken is required" }, 400);
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const existing = await getUserWallet(vault, userId);
  if (existing) {
    return c.json<ApiResponse>({ ok: false, error: "User already has an embedded wallet" }, 409);
  }

  const claimTokenHash = hashSha256Hex(claimToken);
  const platformId = `${PREGENERATED_CLAIM_PREFIX}${claimTokenHash}`;
  const db = getDb();
  const [claimable] = await db
    .select()
    .from(agents)
    .where(
      and(
        eq(agents.tenantId, sourceTenantId),
        eq(agents.walletType, PREGENERATED_USER_WALLET_TYPE),
        eq(agents.platformId, platformId),
      ),
    );
  if (!claimable) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid or already claimed wallet token" },
      404,
    );
  }

  const displayName = (session.address as string | undefined) ?? session.email ?? userId;
  const personalTenant = await ensurePersonalTenant(userId, displayName);
  const targetAgentId = `user-wallet-${userId}`;

  try {
    const keys = await vault.exportPrivateKey(sourceTenantId, claimable.id, {
      breakGlass: true,
      actorId: userId,
      reason: "claim pregenerated user wallet",
    });
    if (!keys.evm?.privateKey) {
      throw new Error("Pregenerated wallet is missing an EVM key");
    }

    const [claimed] = await db
      .update(agents)
      .set({ platformId: `claimed:${claimTokenHash}`, updatedAt: new Date() })
      .where(
        and(
          eq(agents.id, claimable.id),
          eq(agents.tenantId, sourceTenantId),
          eq(agents.walletType, PREGENERATED_USER_WALLET_TYPE),
          eq(agents.platformId, platformId),
        ),
      )
      .returning({ id: agents.id });
    if (!claimed) {
      return c.json<ApiResponse>(
        { ok: false, error: "Invalid or already claimed wallet token" },
        409,
      );
    }

    try {
      await writeUserAudit(c, {
        tenantId: personalTenant,
        actorType: "user",
        actorId: userId,
        action: "user.wallet.pregenerated_claim.authorized",
        resourceType: "wallet",
        resourceId: targetAgentId,
        metadata: { sourceTenantId, sourceAgentId: claimable.id, claimTokenHash },
      });

      if (keys.solana?.privateKey) {
        await vault.importKey(personalTenant, targetAgentId, keys.solana.privateKey, "solana");
      }
      await vault.importKey(personalTenant, targetAgentId, keys.evm.privateKey, "evm");
      await db
        .update(agents)
        .set({
          name: `${displayName}'s Wallet`,
          platformId: `user:${userId}`,
          walletType: "claimed_user",
          updatedAt: new Date(),
        })
        .where(and(eq(agents.id, targetAgentId), eq(agents.tenantId, personalTenant)));
      await applyUserWalletDefaults(userId, personalTenant);
      await db
        .delete(agents)
        .where(and(eq(agents.id, claimable.id), eq(agents.tenantId, sourceTenantId)));
    } catch (claimError) {
      await db
        .update(agents)
        .set({ platformId, updatedAt: new Date() })
        .where(
          and(
            eq(agents.id, claimable.id),
            eq(agents.tenantId, sourceTenantId),
            eq(agents.platformId, `claimed:${claimTokenHash}`),
          ),
        );
      throw claimError;
    }

    const wallet = await getUserWallet(vault, userId);
    if (!wallet) throw new Error("Claim succeeded but wallet could not be fetched");

    await writeUserAudit(c, {
      tenantId: personalTenant,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.pregenerated_claim",
      resourceType: "wallet",
      resourceId: wallet.id,
      metadata: { sourceTenantId, sourceAgentId: claimable.id },
    });
    dispatchWebhook(personalTenant, wallet.id, "user.wallet_created", {
      userId,
      walletId: wallet.id,
      walletAddress: wallet.walletAddress,
      pregenerated: true,
    });

    return c.json<ApiResponse<{ agentId: string; walletAddress: string; claimed: true }>>(
      {
        ok: true,
        data: { agentId: wallet.id, walletAddress: wallet.walletAddress, claimed: true },
      },
      201,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: `Failed to claim wallet: ${msg}` }, 500);
  }
});

// ─── POST /me/wallet/recovery/setup ──────────────────────────────────────────

user.post("/me/wallet/recovery/setup", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet recovery setup requires a recent MFA step-up session" },
      403,
    );
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const existing = await getUserWallet(vault, userId);
  if (existing) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "This wallet already exists and cannot be assigned a new recovery phrase. Use audited key export for break-glass backup or create recovery during initial wallet provisioning.",
      },
      409,
    );
  }

  const displayName = (session.address as string | undefined) ?? session.email ?? userId;
  const mnemonic = generateMnemonic(256);

  try {
    const tenantId = await ensurePersonalTenant(userId, displayName);
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.recovery_setup.authorized",
      resourceType: "wallet",
      resourceId: `user-wallet-${userId}`,
      metadata: { method: "bip39", strength: 256 },
    });

    const wallet = await provisionRecoverableUserWallet(
      vault,
      userId,
      displayName,
      mnemonic,
      tenantId,
    );

    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.recovery_setup",
      resourceType: "wallet",
      resourceId: wallet.agentId,
      metadata: { method: "bip39", strength: 256 },
    });
    dispatchWebhook(tenantId, wallet.agentId, "user.wallet_created", {
      userId,
      walletId: wallet.agentId,
      walletAddress: wallet.walletAddress,
      recoverable: true,
    });
    dispatchWebhook(tenantId, wallet.agentId, "wallet.recovery_setup", {
      userId,
      walletId: wallet.agentId,
      method: "bip39",
    });

    setNoStoreHeaders(c);
    return c.json<
      ApiResponse<{
        wallet: { agentId: string; walletAddress: string; recoverable: true };
        recovery: { type: "bip39"; mnemonic: string; warning: string };
      }>
    >(
      {
        ok: true,
        data: {
          wallet: {
            agentId: wallet.agentId,
            walletAddress: wallet.walletAddress,
            recoverable: true,
          },
          recovery: {
            type: "bip39",
            mnemonic,
            warning:
              "This recovery phrase is shown once. Steward does not store it; losing it means the wallet cannot be recovered from this phrase.",
          },
        },
      },
      201,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error(`[UserWallet] recovery setup failed for user "${userId}":`, e);
    return c.json<ApiResponse>({ ok: false, error: `Failed to set up recovery: ${msg}` }, 500);
  }
});

// ─── POST /me/wallet/recovery/restore ────────────────────────────────────────

user.post("/me/wallet/recovery/restore", async (c) => {
  setNoStoreHeaders(c);
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet recovery restore requires a recent MFA step-up session" },
      403,
    );
  }

  const body = await safeJsonParse<{ mnemonic?: unknown }>(c);
  const mnemonic =
    typeof body?.mnemonic === "string" ? body.mnemonic.trim().replace(/\s+/g, " ") : "";
  if (!mnemonic || !isValidMnemonic(mnemonic)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid BIP-39 recovery phrase" }, 400);
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const displayName = (session.address as string | undefined) ?? session.email ?? userId;
  const tenantId = await ensurePersonalTenant(userId, displayName);

  try {
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.recovery_restore.authorized",
      resourceType: "wallet",
      resourceId: `user-wallet-${userId}`,
      metadata: { method: "bip39" },
    });

    const wallet = await restoreRecoverableUserWallet(
      vault,
      userId,
      displayName,
      mnemonic,
      tenantId,
    );

    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.recovered",
      resourceType: "wallet",
      resourceId: wallet.agentId,
      metadata: { method: "bip39", restoredExisting: wallet.restoredExisting },
    });
    dispatchWebhook(tenantId, wallet.agentId, "wallet.recovered", {
      userId,
      walletId: wallet.agentId,
      walletAddress: wallet.walletAddress,
      method: "bip39",
      restoredExisting: wallet.restoredExisting,
    });
    if (!wallet.restoredExisting) {
      dispatchWebhook(tenantId, wallet.agentId, "user.wallet_created", {
        userId,
        walletId: wallet.agentId,
        walletAddress: wallet.walletAddress,
        recoverable: true,
      });
    }

    return c.json<
      ApiResponse<{
        wallet: {
          agentId: string;
          walletAddress: string;
          recoverable: true;
          restoredExisting: boolean;
        };
        recovery: { type: "bip39"; restored: true };
      }>
    >(
      {
        ok: true,
        data: {
          wallet: {
            agentId: wallet.agentId,
            walletAddress: wallet.walletAddress,
            recoverable: true,
            restoredExisting: wallet.restoredExisting,
          },
          recovery: { type: "bip39", restored: true },
        },
      },
      wallet.restoredExisting ? 200 : 201,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: `Failed to restore wallet: ${msg}` }, 409);
  }
});

// ─── POST /me/wallet/sign ─────────────────────────────────────────────────────

user.post("/me/wallet/sign", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Wallet transaction signing requires a recent MFA step-up session" },
      403,
    );
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const wallet = await getUserWallet(vault, userId);
  if (!wallet) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "No wallet found — call POST /me/wallet first to provision",
      },
      404,
    );
  }

  const body = await safeJsonParse<Omit<SignRequest, "agentId" | "tenantId">>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  const shouldBroadcast = body.broadcast !== false;
  if (shouldBroadcast && !isNonEmptyString(c.req.header("Idempotency-Key"))) {
    return c.json<ApiResponse>(
      { ok: false, error: "Broadcast signing requires an Idempotency-Key header" },
      400,
    );
  }

  if (!isNonEmptyString(body.to)) {
    return c.json<ApiResponse>({ ok: false, error: "'to' address is required" }, 400);
  }
  if (!isValidAddress(body.to)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'to' must be a valid Ethereum address (0x + 40 hex chars)",
      },
      400,
    );
  }
  if (body.value === undefined || body.value === null) {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required (wei amount as string)" },
      400,
    );
  }
  if (!isUint256DecimalString(body.value)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'value' must be a non-negative uint256 wei amount encoded as a decimal string",
      },
      400,
    );
  }
  if (body.chainId !== undefined) {
    if (
      typeof body.chainId !== "number" ||
      !Number.isSafeInteger(body.chainId) ||
      body.chainId <= 0
    ) {
      return c.json<ApiResponse>(
        { ok: false, error: "'chainId' must be a positive integer when provided" },
        400,
      );
    }
  }
  if (hasCalldata((body as { data?: unknown }).data)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "User wallet contract calldata is disabled unless a selector-specific policy is configured",
      },
      403,
    );
  }
  if ((body as { gasLimit?: unknown }).gasLimit !== undefined) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "User wallet native transfers cannot set gasLimit because gas spend is not policy-accounted",
      },
      403,
    );
  }

  const tenantId = `personal-${userId}`;
  const agentId = wallet.id;
  const chainId = body.chainId ?? parseInt(process.env.CHAIN_ID || "84532", 10);
  let codeResponse: Awaited<ReturnType<Vault["rpcPassthrough"]>>;
  try {
    codeResponse = await vault.rpcPassthrough({
      method: "eth_getCode",
      params: [getAddress(body.to), "latest"],
      chainId,
    });
  } catch {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "User wallet native transfers cannot be signed until recipient contract code is verified",
      },
      502,
    );
  }
  if (codeResponse.error) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "User wallet native transfers cannot be signed until recipient contract code is verified",
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
          "User wallet native transfers to contract recipients are disabled because gas spend is not policy-accounted",
      },
      403,
    );
  }
  const signRequest: SignRequest = { ...body, tenantId, agentId, chainId };

  // Fetch active policies
  const db = getDb();
  const storedPolicies = await db.select().from(policies).where(eq(policies.agentId, agentId));

  const policySet: PolicyRule[] =
    storedPolicies.length > 0 ? storedPolicies.map(toPolicyRule) : USER_WALLET_DEFAULT_POLICIES;

  let completedResult: { txId: string; txHash: string } | undefined;

  try {
    const result: UserWalletSignResult = await withAgentSpendLock(agentId, async () => {
      const stats = await getTransactionStats(agentId);
      const engine = new PolicyEngine();
      const evaluation = await engine.evaluate(policySet, {
        request: signRequest,
        recentTxCount1h: stats.recentTxCount1h,
        recentTxCount24h: stats.recentTxCount24h,
        spentToday: stats.spentToday,
        spentThisWeek: stats.spentThisWeek,
      });

      if (!evaluation.approved) {
        const txId = crypto.randomUUID();
        await writeUserAudit(c, {
          tenantId,
          actorType: "user",
          actorId: userId,
          action: "user.wallet.sign.rejected_by_policy",
          resourceType: "wallet_transaction",
          resourceId: txId,
          metadata: {
            agentId,
            to: signRequest.to,
            value: signRequest.value,
            chainId: signRequest.chainId,
            policyResults: evaluation.results,
          },
        });
        return { approved: false, results: evaluation.results };
      }

      const txId = crypto.randomUUID();
      await writeUserAudit(c, {
        tenantId,
        actorType: "user",
        actorId: userId,
        action: "user.wallet.sign.authorized",
        resourceType: "wallet_transaction",
        resourceId: txId,
        metadata: {
          agentId,
          to: signRequest.to,
          value: signRequest.value,
          chainId: signRequest.chainId,
        },
      });
      const txHash = await vault.signTransaction(signRequest, {
        txId,
        policyResults: evaluation.results,
        status: shouldBroadcast ? "broadcast" : "signed",
      });
      completedResult = { txId, txHash };
      await writeUserAudit(c, {
        tenantId,
        actorType: "user",
        actorId: userId,
        action: "user.wallet.sign",
        resourceType: "wallet_transaction",
        resourceId: txId,
        metadata: {
          agentId,
          to: signRequest.to,
          value: signRequest.value,
          chainId: signRequest.chainId,
          txHash,
        },
      });
      return { approved: true, txId, txHash };
    });

    if (!result.approved) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction rejected by policy",
          data: { results: result.results },
        },
        403,
      );
    }

    return c.json<ApiResponse<{ txId: string; txHash: string }>>({
      ok: true,
      data: { txId: result.txId, txHash: result.txHash },
    });
  } catch (e) {
    if (completedResult) {
      console.error(
        `[UserWallet] Post-sign bookkeeping failed for user "${userId}" after transaction "${completedResult.txId}" completed:`,
        e,
      );
      return c.json<ApiResponse<{ txId: string; txHash: string }>>({
        ok: true,
        data: completedResult,
      });
    }
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error(`[UserWallet] Sign failed for user "${userId}":`, e);
    try {
      await writeUserAudit(c, {
        tenantId: `personal-${userId}`,
        actorType: "user",
        actorId: userId,
        action: "user.wallet.sign.failed",
        resourceType: "wallet",
        resourceId: wallet.id,
        metadata: { error: msg },
      });
    } catch (auditErr) {
      console.error(`[UserWallet] Failed to audit signing failure for user "${userId}":`, auditErr);
    }
    return c.json<ApiResponse>({ ok: false, error: msg }, 500);
  }
});

// ─── GET /me/wallet/history ───────────────────────────────────────────────────

user.get("/me/wallet/history", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const wallet = await getUserWallet(vault, userId);
  if (!wallet) {
    return c.json<ApiResponse<[]>>({ ok: true, data: [] });
  }

  const db = getDb();
  const limit = clampLimit(c.req.query("limit") ?? null);
  const offset = parseBoundedOffset(c.req.query("offset") ?? null);
  const history = await db
    .select()
    .from(transactions)
    .where(eq(transactions.agentId, wallet.id))
    .orderBy(desc(transactions.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({
    ok: true,
    data: { transactions: history.map(toTxRecord), limit, offset },
  });
});

// ─── GET /me/wallet/policies ──────────────────────────────────────────────────

user.get("/me/wallet/policies", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Message signing requires a recent MFA step-up session" },
      403,
    );
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const wallet = await getUserWallet(vault, userId);
  if (!wallet) {
    // No wallet yet — return the defaults so the user can preview them
    return c.json<ApiResponse<PolicyRule[]>>({
      ok: true,
      data: USER_WALLET_DEFAULT_POLICIES,
    });
  }

  const db = getDb();
  const storedPolicies = await db.select().from(policies).where(eq(policies.agentId, wallet.id));

  const activePolicies: PolicyRule[] =
    storedPolicies.length > 0 ? storedPolicies.map(toPolicyRule) : USER_WALLET_DEFAULT_POLICIES;

  return c.json<ApiResponse<PolicyRule[]>>({ ok: true, data: activePolicies });
});

// ─── POST /me/wallet/sign-message ─────────────────────────────────────────────

user.post("/me/wallet/sign-message", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  if (!ALLOW_UNSAFE_MESSAGE_SIGNING || !ALLOW_USER_UNSAFE_MESSAGE_SIGNING) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Message signing is disabled because arbitrary signatures bypass transaction policy controls. Set STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING=true and STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING=true only for audited compatibility flows.",
      },
      403,
    );
  }

  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Message signing requires a recent MFA step-up session",
      },
      403,
    );
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const wallet = await getUserWallet(vault, userId);
  if (!wallet) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "No wallet found — call POST /me/wallet first to provision",
      },
      404,
    );
  }

  const body = await safeJsonParse<{ message: string }>(c);
  if (!body || !isNonEmptyString(body.message)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'message' is required and must be a non-empty string",
      },
      400,
    );
  }
  if (looksLikeAuthMessage(body.message)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Refusing to sign authentication or permit-style messages" },
      403,
    );
  }

  try {
    await writeAuditEvent({
      tenantId: `personal-${userId}`,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.sign_message.authorized",
      resourceType: "wallet",
      resourceId: wallet.id,
      metadata: { messageLength: body.message.length, unsafeCompatibilityMode: true },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    const signature = await vault.signMessage(`personal-${userId}`, wallet.id, body.message);
    await writeAuditEvent({
      tenantId: `personal-${userId}`,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.sign_message",
      resourceType: "wallet",
      resourceId: wallet.id,
      metadata: { messageLength: body.message.length, unsafeCompatibilityMode: true },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    setNoStoreHeaders(c);
    return c.json<ApiResponse<{ signature: string; address: string }>>({
      ok: true,
      data: { signature, address: wallet.walletAddress },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error(`[UserWallet] sign-message failed for user "${userId}":`, e);
    return c.json<ApiResponse>({ ok: false, error: msg }, 500);
  }
});

// ─── POST /me/wallet/export ────────────────────────────────────────────────────

user.post("/me/wallet/export", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  if (!ALLOW_PRIVATE_KEY_EXPORT || !ALLOW_USER_PRIVATE_KEY_EXPORT) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Private key export is disabled. Set STEWARD_ALLOW_PRIVATE_KEY_EXPORT=true and STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT=true only for audited break-glass operations.",
      },
      403,
    );
  }

  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Private key export requires a recent MFA step-up session",
      },
      403,
    );
  }

  const allowExport =
    process.env.STEWARD_ALLOW_KEY_EXPORT !== undefined
      ? process.env.STEWARD_ALLOW_KEY_EXPORT === "true"
      : process.env.NODE_ENV !== "production";
  if (!allowExport) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export is disabled by STEWARD_ALLOW_KEY_EXPORT" },
      403,
    );
  }

  const verifiedAt = session.sessionMfaVerifiedAt ?? session.mfaVerifiedAt;
  const verifiedAtMs =
    typeof verifiedAt === "number"
      ? verifiedAt < 10_000_000_000
        ? verifiedAt * 1000
        : verifiedAt
      : typeof verifiedAt === "string"
        ? Date.parse(verifiedAt)
        : Number.NaN;
  const hasRecentMfa = Number.isFinite(verifiedAtMs) && Date.now() - verifiedAtMs <= 5 * 60 * 1000;
  if (!hasRecentMfa) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires recent MFA or passkey step-up" },
      403,
    );
  }

  const body = await safeJsonParse<{ reason: string }>(c);
  if (!body || !isNonEmptyString(body.reason)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires a non-empty audited reason" },
      400,
    );
  }

  let vault: Vault;
  try {
    vault = getVault();
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Vault not configured" }, 503);
  }

  const wallet = await getUserWallet(vault, userId);
  if (!wallet) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "No wallet found — call POST /me/wallet first to provision",
      },
      404,
    );
  }

  const personalTenantId = `personal-${userId}`;

  try {
    await writeUserAudit(c, {
      tenantId: personalTenantId,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.private_key_export.authorized",
      resourceType: "wallet",
      resourceId: wallet.id,
      metadata: { breakGlass: true },
    });
    const keys = await vault.exportPrivateKey(personalTenantId, wallet.id, {
      breakGlass: true,
      actorId: userId,
      reason: "personal-wallet break-glass export",
    });
    await writeUserAudit(c, {
      tenantId: personalTenantId,
      actorType: "user",
      actorId: userId,
      action: "user.wallet.private_key_export.succeeded",
      resourceType: "wallet",
      resourceId: wallet.id,
      metadata: { breakGlass: true },
    });
    dispatchWebhook(personalTenantId, wallet.id, "private_key.exported", {
      userId,
      walletId: wallet.id,
      breakGlass: true,
    });

    c.header("Cache-Control", "no-store, max-age=0");
    c.header("Pragma", "no-cache");
    c.header("Expires", "0");
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
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    console.error(`[UserWallet] export failed for user "${userId}":`, e);
    return c.json<ApiResponse>({ ok: false, error: msg }, 500);
  }
});

// ─── Tenant membership routes ─────────────────────────────────────────────────

/**
 * GET /me/tenants
 * List all tenants the authenticated user belongs to.
 */
user.get("/me/tenants", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const db = getDb();

  const memberships = await db
    .select({
      tenantId: userTenants.tenantId,
      tenantName: tenants.name,
      role: userTenants.role,
      joinedAt: userTenants.createdAt,
    })
    .from(userTenants)
    .innerJoin(tenants, eq(userTenants.tenantId, tenants.id))
    .where(eq(userTenants.userId, userId));

  return c.json<ApiResponse<typeof memberships>>({
    ok: true,
    data: memberships,
  });
});

/**
 * POST /me/tenants
 * Create a new self-serve tenant owned by the authenticated user.
 */
user.post("/me/tenants", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  if (!userTenantCreationAllowed()) {
    return c.json<ApiResponse>({ ok: false, error: "User tenant creation is disabled" }, 403);
  }
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Tenant creation requires a recent MFA step-up session" },
      403,
    );
  }

  const body = await safeJsonParse<{ name?: string; slug?: string; settings?: unknown }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>(
      { ok: false, error: "name is required and must be a non-empty string" },
      400,
    );
  }

  const tenantId = body.slug ? body.slug.trim() : slugifyTenantId(body.name);
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid tenant slug — must be 1-64 alphanumeric chars (plus _ - . :)",
      },
      400,
    );
  }
  if (isReservedTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant slug is reserved" }, 400);
  }

  const userId = c.get("userId");
  const db = getDb();

  const [existing] = await db
    .select({ id: tenants.id })
    .from(tenants)
    .where(eq(tenants.id, tenantId));
  if (existing) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant already exists" }, 409);
  }

  const apiKeyPair = generateApiKey();

  try {
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "tenant.create.authorized",
      resourceType: "tenant",
      resourceId: tenantId,
      metadata: { name: body.name.trim(), selfServe: true },
    });
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "tenant.api_key.create.authorized",
      resourceType: "tenant",
      resourceId: tenantId,
      metadata: { selfServe: true },
    });

    const [tenant] = await db
      .insert(tenants)
      .values({
        id: tenantId,
        name: body.name.trim(),
        apiKeyHash: apiKeyPair.hash,
        ownerAddress: typeof session.address === "string" ? session.address : undefined,
      })
      .returning();

    if (!tenant) {
      return c.json<ApiResponse>({ ok: false, error: "Failed to create tenant" }, 500);
    }

    await db
      .insert(userTenants)
      .values({ userId, tenantId: tenant.id, role: "owner" })
      .onConflictDoNothing();

    try {
      await writeUserAudit(c, {
        tenantId: tenant.id,
        actorType: "user",
        actorId: userId,
        action: "tenant.create",
        resourceType: "tenant",
        resourceId: tenant.id,
        metadata: { name: tenant.name, selfServe: true },
      });
      await writeUserAudit(c, {
        tenantId: tenant.id,
        actorType: "user",
        actorId: userId,
        action: "tenant.api_key.create",
        resourceType: "tenant",
        resourceId: tenant.id,
        metadata: { selfServe: true },
      });
    } catch (auditErr) {
      await db.delete(tenants).where(eq(tenants.id, tenant.id));
      throw auditErr;
    }

    return c.json<
      ApiResponse<{
        tenantId: string;
        id: string;
        name: string;
        role: string;
        apiKey: string;
        createdAt: Date;
        updatedAt: Date;
      }>
    >(
      {
        ok: true,
        data: {
          tenantId: tenant.id,
          id: tenant.id,
          name: tenant.name,
          role: "owner",
          apiKey: apiKeyPair.key,
          createdAt: tenant.createdAt,
          updatedAt: tenant.updatedAt,
        },
      },
      201,
    );
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to create tenant";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

/**
 * POST /me/tenants/switch
 * Mint a new session token scoped to an existing tenant membership.
 */
user.post("/me/tenants/switch", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const body = await safeJsonParse<{ tenantId?: string }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isValidTenantId(body.tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "tenantId is required" }, 400);
  }

  const userId = c.get("userId");
  const session = c.get("userSession");
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Tenant switching requires a recent MFA step-up session" },
      403,
    );
  }
  const db = getDb();

  const [membership] = await db
    .select({ tenantId: userTenants.tenantId, role: userTenants.role })
    .from(userTenants)
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, body.tenantId)));

  if (!membership) {
    return c.json<ApiResponse>({ ok: false, error: "Not a member of this tenant" }, 403);
  }

  if (typeof session.exp !== "number" || !Number.isFinite(session.exp)) {
    return c.json<ApiResponse>({ ok: false, error: "Session expiry is required" }, 401);
  }
  const remainingSeconds = Math.floor(session.exp - Date.now() / 1000);
  if (remainingSeconds <= 0) {
    return c.json<ApiResponse>({ ok: false, error: "Session expired" }, 401);
  }
  const {
    exp: _exp,
    iat: _iat,
    nbf: _nbf,
    jti: _jti,
    iss: _iss,
    aud: _aud,
    tenantId: _tenantId,
    activeTenantId: _activeTenantId,
    mfaVerifiedAt: _mfaVerifiedAt,
    mfaMethod: _mfaMethod,
    factorEnrollmentVerifiedAt: _factorEnrollmentVerifiedAt,
    ...sessionClaims
  } = session;
  // MFA freshness is scoped to the tenant where it was performed. A switched
  // tenant token must perform its own step-up before sensitive tenant actions.
  const token = await createSessionToken(
    typeof session.address === "string" ? session.address : "",
    membership.tenantId,
    {
      ...sessionClaims,
      userId,
      tenantId: membership.tenantId,
      activeTenantId: membership.tenantId,
    },
    `${remainingSeconds}s`,
  );

  await writeUserAudit(c, {
    tenantId: membership.tenantId,
    actorType: "user",
    actorId: userId,
    action: "tenant.switch",
    resourceType: "tenant",
    resourceId: membership.tenantId,
  });
  dispatchWebhook(membership.tenantId, userId, "user.authenticated", {
    userId,
    authMethod: "tenant_switch",
  });

  return c.json<
    ApiResponse<{ token: string; tenantId: string; activeTenantId: string; role: string }>
  >({
    ok: true,
    data: {
      token,
      tenantId: membership.tenantId,
      activeTenantId: membership.tenantId,
      role: membership.role,
    },
  });
});

/**
 * GET /me/tenants/:tenantId
 * Get single tenant membership info for the authenticated user.
 */
user.get("/me/tenants/:tenantId", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const tenantId = c.req.param("tenantId");
  const db = getDb();

  const [membership] = await db
    .select({
      tenantId: userTenants.tenantId,
      tenantName: tenants.name,
      role: userTenants.role,
      joinedAt: userTenants.createdAt,
    })
    .from(userTenants)
    .innerJoin(tenants, eq(userTenants.tenantId, tenants.id))
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));

  if (!membership) {
    return c.json<ApiResponse>({ ok: false, error: "Not a member of this tenant" }, 404);
  }

  return c.json<ApiResponse<typeof membership>>({ ok: true, data: membership });
});

type TenantAdminUserRow = {
  userId: string;
  tenantId: string;
  role: string;
  joinedAt: Date;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  tenantCustomMetadata: Record<string, unknown>;
  deactivatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

type TenantAdminInvitationRow = {
  id: string;
  tenantId: string;
  email: string;
  role: string;
  status: string;
  invitedByUserId: string | null;
  acceptedByUserId: string | null;
  acceptedAt: Date | null;
  revokedAt: Date | null;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
};

type TenantAdminUserEventRow = {
  id: number;
  seq: number;
  action: string;
  actorType: string;
  actorId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
};

function tenantAdminUserSelection() {
  return {
    userId: users.id,
    tenantId: userTenants.tenantId,
    role: userTenants.role,
    joinedAt: userTenants.createdAt,
    email: users.email,
    emailVerified: users.emailVerified,
    name: users.name,
    tenantCustomMetadata: userTenants.customMetadata,
    deactivatedAt: users.deactivatedAt,
    createdAt: users.createdAt,
    updatedAt: users.updatedAt,
  };
}

function tenantAdminInvitationSelection() {
  return {
    id: tenantInvitations.id,
    tenantId: tenantInvitations.tenantId,
    email: tenantInvitations.email,
    role: tenantInvitations.role,
    status: tenantInvitations.status,
    invitedByUserId: tenantInvitations.invitedByUserId,
    acceptedByUserId: tenantInvitations.acceptedByUserId,
    acceptedAt: tenantInvitations.acceptedAt,
    revokedAt: tenantInvitations.revokedAt,
    expiresAt: tenantInvitations.expiresAt,
    createdAt: tenantInvitations.createdAt,
    updatedAt: tenantInvitations.updatedAt,
  };
}

async function requireTenantAdminMfa(
  c: Context<{ Variables: UserVariables }>,
  tenantId: string,
  message: string,
): Promise<{ ok: true; userId: string; role: string } | { ok: false; response: Response }> {
  const requesterId = c.get("userId");
  const session = c.get("userSession");
  if (!sessionTenantMatches(session, tenantId)) {
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: "Session tenant does not match requested tenant" },
        403,
      ),
    };
  }
  const requesterRole = await requireTenantAdmin(requesterId, tenantId);
  if (!requesterRole) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "Tenant admin access required" }, 403),
    };
  }
  if (!hasRecentMfaStepUp(session)) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: message }, 403),
    };
  }
  return { ok: true, userId: requesterId, role: requesterRole };
}

async function requireTenantUserDirectoryReaderMfa(
  c: Context<{ Variables: UserVariables }>,
  tenantId: string,
  message: string,
): Promise<{ ok: true; userId: string; role: string } | { ok: false; response: Response }> {
  const requesterId = c.get("userId");
  const session = c.get("userSession");
  if (!sessionTenantMatches(session, tenantId)) {
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: "Session tenant does not match requested tenant" },
        403,
      ),
    };
  }
  const requesterRole = await requireTenantUserDirectoryReader(requesterId, tenantId);
  if (!requesterRole) {
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: "Tenant user directory access required" },
        403,
      ),
    };
  }
  if (!hasRecentMfaStepUp(session)) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: message }, 403),
    };
  }
  return { ok: true, userId: requesterId, role: requesterRole };
}

/**
 * GET /me/tenants/:tenantId/invitations
 * Tenant-admin invitation list for dashboard views.
 */
user.get("/me/tenants/:tenantId/invitations", async (c) => {
  const tenantId = c.req.param("tenantId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant invitations require recent MFA verification",
  );
  if (!admin.ok) return admin.response;

  const status = c.req.query("status")?.trim().toLowerCase() || "pending";
  if (!["pending", "accepted", "revoked", "expired", "all"].includes(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid invitation status" }, 400);
  }
  const whereConditions = [eq(tenantInvitations.tenantId, tenantId)];
  if (status !== "all") whereConditions.push(eq(tenantInvitations.status, status));
  const rows = await getDb()
    .select(tenantAdminInvitationSelection())
    .from(tenantInvitations)
    .where(and(...whereConditions))
    .limit(clampLimit(c.req.query("limit") ?? null))
    .offset(parseBoundedOffset(c.req.query("offset") ?? null));

  return c.json<
    ApiResponse<{ invitations: TenantAdminInvitationRow[]; limit: number; offset: number }>
  >({
    ok: true,
    data: {
      invitations: rows,
      limit: clampLimit(c.req.query("limit") ?? null),
      offset: parseBoundedOffset(c.req.query("offset") ?? null),
    },
  });
});

/**
 * POST /me/tenants/:tenantId/invitations
 * Tenant-admin invitation creation. Returns a one-time token for delivery.
 */
user.post("/me/tenants/:tenantId/invitations", async (c) => {
  const tenantId = c.req.param("tenantId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant invitation creation requires recent MFA verification",
  );
  if (!admin.ok) return admin.response;

  const body = await safeJsonParse<{
    email?: unknown;
    role?: unknown;
    expiresInSeconds?: unknown;
    sendEmail?: unknown;
  }>(c);
  const email = typeof body?.email === "string" ? body.email.toLowerCase().trim() : "";
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return c.json<ApiResponse>({ ok: false, error: "valid email is required" }, 400);
  }
  const role = normalizeTenantInvitationRole(body?.role);
  if (!role) {
    return c.json<ApiResponse>(
      { ok: false, error: `role must be one of: ${TENANT_INVITATION_ROLES.join(", ")}` },
      400,
    );
  }

  const token = randomBytes(32).toString("hex");
  const tokenHash = hashSha256Hex(token);
  const expiresAt = normalizeInvitationExpiry(body?.expiresInSeconds);
  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.invitation.create.authorized",
    resourceType: "tenant_invitation",
    resourceId: email,
    metadata: { email, role, expiresAt: expiresAt.toISOString() },
  });

  const db = getDb();
  const invitation = await db.transaction(async (tx) => {
    const now = new Date();
    await tx
      .update(tenantInvitations)
      .set({ status: "revoked", revokedAt: now, updatedAt: now })
      .where(
        and(
          eq(tenantInvitations.tenantId, tenantId),
          eq(tenantInvitations.email, email),
          eq(tenantInvitations.status, "pending"),
        ),
      );
    const [created] = await tx
      .insert(tenantInvitations)
      .values({ tenantId, email, role, tokenHash, invitedByUserId: admin.userId, expiresAt })
      .returning(tenantAdminInvitationSelection());
    return created;
  });

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.invitation.create",
    resourceType: "tenant_invitation",
    resourceId: invitation.id,
    metadata: { email, role, expiresAt: expiresAt.toISOString() },
  });

  let emailSent = false;
  if (body?.sendEmail === true) {
    try {
      const emailAuth = await getEmailAuthForTenant(tenantId);
      await emailAuth.sendTenantInvitation(email, { tenantId, token, expiresAt });
      emailSent = true;
    } catch (error) {
      console.error("[TenantInvitation] Email delivery failed:", error);
    }
  }

  setNoStoreHeaders(c);
  return c.json<
    ApiResponse<{ invitation: TenantAdminInvitationRow; token: string; emailSent: boolean }>
  >({ ok: true, data: { invitation, token, emailSent } }, 201);
});

/**
 * DELETE /me/tenants/:tenantId/invitations/:invitationId
 * Tenant-admin pending invitation revocation.
 */
user.delete("/me/tenants/:tenantId/invitations/:invitationId", async (c) => {
  const tenantId = c.req.param("tenantId");
  const invitationId = c.req.param("invitationId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(invitationId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid invitation id format" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant invitation revocation requires recent MFA verification",
  );
  if (!admin.ok) return admin.response;

  const db = getDb();
  const [candidate] = await db
    .select({
      id: tenantInvitations.id,
      email: tenantInvitations.email,
      role: tenantInvitations.role,
    })
    .from(tenantInvitations)
    .where(
      and(
        eq(tenantInvitations.tenantId, tenantId),
        eq(tenantInvitations.id, invitationId),
        eq(tenantInvitations.status, "pending"),
      ),
    )
    .limit(1);
  if (!candidate) {
    return c.json<ApiResponse>({ ok: false, error: "Pending invitation not found" }, 404);
  }

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.invitation.revoke.authorized",
    resourceType: "tenant_invitation",
    resourceId: candidate.id,
    metadata: { email: candidate.email, role: candidate.role },
  });

  const [invitation] = await db
    .update(tenantInvitations)
    .set({ status: "revoked", revokedAt: new Date(), updatedAt: new Date() })
    .where(
      and(
        eq(tenantInvitations.tenantId, tenantId),
        eq(tenantInvitations.id, invitationId),
        eq(tenantInvitations.status, "pending"),
      ),
    )
    .returning(tenantAdminInvitationSelection());
  if (!invitation) {
    return c.json<ApiResponse>({ ok: false, error: "Pending invitation not found" }, 404);
  }

  return c.json<ApiResponse>({ ok: true });
});

/**
 * GET /me/tenants/:tenantId/users
 * Tenant-admin user search for dashboard views. This intentionally returns
 * tenant-scoped fields only and never exposes global linked accounts.
 */
user.get("/me/tenants/:tenantId/users", async (c) => {
  const tenantId = c.req.param("tenantId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  const reader = await requireTenantUserDirectoryReaderMfa(
    c,
    tenantId,
    "Tenant user directory requires recent MFA verification",
  );
  if (!reader.ok) return reader.response;

  const db = getDb();
  const limit = clampLimit(c.req.query("limit") ?? null);
  const offset = parseBoundedOffset(c.req.query("offset") ?? null);
  const email = c.req.query("email")?.trim().toLowerCase();
  const q = c.req.query("q")?.trim().toLowerCase();
  const whereConditions = [eq(userTenants.tenantId, tenantId)];
  if (email) whereConditions.push(eq(users.email, email));
  if (q) {
    const like = `%${q.replace(/[%_]/g, "\\$&")}%`;
    whereConditions.push(
      or(ilike(users.email, like), ilike(users.name, like), sql`${users.id}::text ilike ${like}`)!,
    );
  }

  const rows = await db
    .select(tenantAdminUserSelection())
    .from(userTenants)
    .innerJoin(users, eq(userTenants.userId, users.id))
    .where(and(...whereConditions))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse<{ users: TenantAdminUserRow[]; limit: number; offset: number }>>({
    ok: true,
    data: { users: rows, limit, offset },
  });
});

/**
 * GET /me/tenants/:tenantId/users/export
 * Export the tenant-scoped user directory as CSV. The export intentionally
 * excludes global metadata, linked accounts, wallets, and identity graph data.
 */
user.get("/me/tenants/:tenantId/users/export", async (c) => {
  const tenantId = c.req.param("tenantId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant user export requires recent MFA verification",
  );
  if (!admin.ok) return admin.response;

  const db = getDb();
  const limit = Math.min(clampLimit(c.req.query("limit") ?? null, 1000), 10_000);
  const email = c.req.query("email")?.trim().toLowerCase();
  const q = c.req.query("q")?.trim().toLowerCase();
  const whereConditions = [eq(userTenants.tenantId, tenantId)];
  if (email) whereConditions.push(eq(users.email, email));
  if (q) {
    const like = `%${q.replace(/[%_]/g, "\\$&")}%`;
    whereConditions.push(
      or(ilike(users.email, like), ilike(users.name, like), sql`${users.id}::text ilike ${like}`)!,
    );
  }

  const rows = await db
    .select(tenantAdminUserSelection())
    .from(userTenants)
    .innerJoin(users, eq(userTenants.userId, users.id))
    .where(and(...whereConditions))
    .limit(limit);

  const csvRows = [
    tenantUserCsvRow([
      "user_id",
      "tenant_id",
      "role",
      "status",
      "email",
      "email_verified",
      "name",
      "tenant_custom_metadata",
      "joined_at",
      "created_at",
      "updated_at",
      "deactivated_at",
    ]),
    ...rows.map((row) =>
      tenantUserCsvRow([
        row.userId,
        row.tenantId,
        row.role,
        row.deactivatedAt ? "deactivated" : "active",
        row.email,
        row.emailVerified,
        row.name,
        JSON.stringify(row.tenantCustomMetadata ?? {}),
        row.joinedAt,
        row.createdAt,
        row.updatedAt,
        row.deactivatedAt,
      ]),
    ),
  ];

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.member.export",
    resourceType: "tenant",
    resourceId: tenantId,
    metadata: { count: rows.length, limitedTo: limit, filtered: Boolean(email || q) },
  });

  c.header("Content-Type", "text/csv; charset=utf-8");
  c.header("Content-Disposition", `attachment; filename="${tenantId}-users.csv"`);
  return c.body(`${csvRows.join("\n")}\n`);
});

/**
 * GET /me/tenants/:tenantId/users/:userId
 * Tenant-admin user read. Keeps global identity graph and linked accounts out
 * of the tenant dashboard surface.
 */
user.get("/me/tenants/:tenantId/users/:targetUserId", async (c) => {
  const tenantId = c.req.param("tenantId");
  const targetUserId = c.req.param("targetUserId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(targetUserId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid user id" }, 400);
  }
  const reader = await requireTenantUserDirectoryReaderMfa(
    c,
    tenantId,
    "Tenant user directory requires recent MFA verification",
  );
  if (!reader.ok) return reader.response;

  const db = getDb();
  const [row] = await db
    .select(tenantAdminUserSelection())
    .from(userTenants)
    .innerJoin(users, eq(userTenants.userId, users.id))
    .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));

  if (!row) return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);
  return c.json<ApiResponse<TenantAdminUserRow>>({ ok: true, data: row });
});

/**
 * GET /me/tenants/:tenantId/users/:userId/events
 * Tenant-scoped lifecycle/activity history for a user. Returns only audit rows
 * for this tenant and user resource, avoiding global identity internals.
 */
user.get("/me/tenants/:tenantId/users/:targetUserId/events", async (c) => {
  const tenantId = c.req.param("tenantId");
  const targetUserId = c.req.param("targetUserId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(targetUserId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid user id" }, 400);
  }
  const reader = await requireTenantUserDirectoryReaderMfa(
    c,
    tenantId,
    "Tenant user activity requires recent MFA verification",
  );
  if (!reader.ok) return reader.response;

  const db = getDb();
  const [membership] = await db
    .select({ id: userTenants.id })
    .from(userTenants)
    .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)))
    .limit(1);
  if (!membership) {
    return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);
  }

  const limit = clampLimit(c.req.query("limit") ?? null, 25);
  const offset = parseBoundedOffset(c.req.query("offset") ?? null);
  const auditWhere = and(
    eq(auditEvents.tenantId, tenantId),
    eq(auditEvents.resourceType, "user"),
    eq(auditEvents.resourceId, targetUserId),
  );
  const rows = await db
    .select({
      id: auditEvents.id,
      seq: auditEvents.seq,
      action: auditEvents.action,
      actorType: auditEvents.actorType,
      actorId: auditEvents.actorId,
      resourceType: auditEvents.resourceType,
      resourceId: auditEvents.resourceId,
      metadata: auditEvents.metadata,
      createdAt: auditEvents.createdAt,
    })
    .from(auditEvents)
    .where(auditWhere)
    .orderBy(desc(auditEvents.seq))
    .limit(limit)
    .offset(offset);
  const [{ total } = { total: 0 }] = await db
    .select({ total: sql<number>`count(*)` })
    .from(auditEvents)
    .where(auditWhere);

  return c.json<
    ApiResponse<{
      events: TenantAdminUserEventRow[];
      limit: number;
      offset: number;
      total: number;
    }>
  >({
    ok: true,
    data: {
      events: rows.map((row) => ({
        id: row.id,
        seq: Number(row.seq),
        action: row.action,
        actorType: row.actorType,
        actorId: row.actorId,
        resourceType: row.resourceType,
        resourceId: row.resourceId,
        metadata: row.metadata,
        createdAt:
          row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
      })),
      limit,
      offset,
      total: Number(total),
    },
  });
});

/**
 * PATCH /me/tenants/:tenantId/users/:userId/role
 * Owner/admin role management for tenant teams. Privileged API access remains
 * restricted to owner/admin; developer/billing/viewer/member are non-admin roles.
 */
user.patch("/me/tenants/:tenantId/users/:targetUserId/role", async (c) => {
  const requesterId = c.get("userId");
  const session = c.get("userSession");
  const tenantId = c.req.param("tenantId");
  const targetUserId = c.req.param("targetUserId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(targetUserId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid user id" }, 400);
  }
  if (!sessionTenantMatches(session, tenantId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Session tenant does not match requested tenant" },
      403,
    );
  }
  const requesterRole = await requireTenantAdmin(requesterId, tenantId);
  if (!requesterRole) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant admin access required" }, 403);
  }
  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Tenant role updates require recent MFA verification" },
      403,
    );
  }

  const body = await safeJsonParse<{ role?: unknown }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const nextRole = normalizeTenantRole(body.role);
  if (!nextRole) {
    return c.json<ApiResponse>(
      { ok: false, error: `role must be one of: ${TENANT_ROLES.join(", ")}` },
      400,
    );
  }
  if (requesterRole !== "owner" && nextRole === "owner") {
    return c.json<ApiResponse>({ ok: false, error: "Only owners can grant owner role" }, 403);
  }

  const db = getDb();
  let updated: { row: TenantAdminUserRow; previousRole: string } | null = null;
  try {
    updated = await db.transaction(async (tx) => {
      await lockTenantOwnerLifecycle(tx, tenantId);
      const [membership] = await tx
        .select({ role: userTenants.role })
        .from(userTenants)
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
      if (!membership) return null;
      if (membership.role === "owner" && requesterRole !== "owner" && nextRole !== "owner") {
        throw new Error("Only owners can modify owner role");
      }
      if (membership.role === "owner" && nextRole !== "owner") {
        if ((await activeTenantOwnerCount(tx, tenantId, targetUserId)) < 1) {
          throw new Error("Cannot demote the sole owner");
        }
      }

      await writeUserAudit(c, {
        tenantId,
        actorType: "user",
        actorId: requesterId,
        action: "tenant.member.role.update.authorized",
        resourceType: "user",
        resourceId: targetUserId,
        metadata: { previousRole: membership.role, nextRole },
      });

      await tx
        .update(userTenants)
        .set({ role: nextRole })
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));

      const [row] = await tx
        .select(tenantAdminUserSelection())
        .from(userTenants)
        .innerJoin(users, eq(userTenants.userId, users.id))
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
      return row ? { row, previousRole: membership.role } : null;
    });
  } catch (err) {
    if (err instanceof Error && err.message === "Only owners can modify owner role") {
      return c.json<ApiResponse>({ ok: false, error: err.message }, 403);
    }
    if (err instanceof Error && err.message === "Cannot demote the sole owner") {
      return c.json<ApiResponse>({ ok: false, error: err.message }, 409);
    }
    throw err;
  }

  if (!updated) return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);

  try {
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: requesterId,
      action: "tenant.member.role.update",
      resourceType: "user",
      resourceId: targetUserId,
      metadata: { previousRole: updated.previousRole, role: updated.row.role },
    });
  } catch (error) {
    await db
      .update(userTenants)
      .set({ role: updated.previousRole })
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
    throw error;
  }

  return c.json<ApiResponse<TenantAdminUserRow>>({ ok: true, data: updated.row });
});

/**
 * PATCH /me/tenants/:tenantId/users/:userId/metadata
 * Tenant-admin metadata replacement for dashboard user management. This is
 * limited to the tenant membership metadata and never mutates global user data.
 */
user.patch("/me/tenants/:tenantId/users/:targetUserId/metadata", async (c) => {
  const tenantId = c.req.param("tenantId");
  const targetUserId = c.req.param("targetUserId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(targetUserId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid user id" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant user metadata updates require recent MFA verification",
  );
  if (!admin.ok) return admin.response;

  const body = await safeJsonParse<{ tenantCustomMetadata?: Record<string, unknown> }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (body.tenantCustomMetadata === undefined) {
    return c.json<ApiResponse>({ ok: false, error: "tenantCustomMetadata is required" }, 400);
  }
  const metadataError = getTenantMetadataValidationError(body.tenantCustomMetadata);
  if (metadataError) return c.json<ApiResponse>({ ok: false, error: metadataError }, 400);

  const db = getDb();
  const [existing] = await db
    .select({ customMetadata: userTenants.customMetadata })
    .from(userTenants)
    .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)))
    .limit(1);
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.member.metadata.update.authorized",
    resourceType: "user",
    resourceId: targetUserId,
    metadata: { updatedTenant: true },
  });

  await db
    .update(userTenants)
    .set({ customMetadata: body.tenantCustomMetadata })
    .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));

  const [row] = await db
    .select(tenantAdminUserSelection())
    .from(userTenants)
    .innerJoin(users, eq(userTenants.userId, users.id))
    .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));

  try {
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: admin.userId,
      action: "tenant.member.metadata.update",
      resourceType: "user",
      resourceId: targetUserId,
      metadata: { updatedTenant: true },
    });
  } catch (error) {
    await db
      .update(userTenants)
      .set({ customMetadata: existing.customMetadata })
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
    throw error;
  }

  dispatchWebhook(tenantId, targetUserId, "user.updated_account", {
    userId: targetUserId,
    scope: "tenant",
    field: "tenantCustomMetadata",
  });
  return c.json<ApiResponse<TenantAdminUserRow>>({ ok: true, data: row as TenantAdminUserRow });
});

/**
 * PATCH /me/tenants/:tenantId/users/:userId/deactivate
 * Dashboard lifecycle control for app-scoped users. Because deactivatedAt is a
 * global user field, this refuses targets that also belong to another
 * non-personal tenant; cross-tenant lifecycle remains platform-key only.
 */
user.patch("/me/tenants/:tenantId/users/:targetUserId/deactivate", async (c) => {
  const tenantId = c.req.param("tenantId");
  const targetUserId = c.req.param("targetUserId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(targetUserId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid user id" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant user lifecycle changes require recent MFA verification",
  );
  if (!admin.ok) return admin.response;

  const body = await safeJsonParse<{ deactivated?: boolean }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const deactivated = body.deactivated !== false;

  const db = getDb();
  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: deactivated
      ? "tenant.member.deactivate.authorized"
      : "tenant.member.reactivate.authorized",
    resourceType: "user",
    resourceId: targetUserId,
  });

  const result = await db
    .transaction(async (tx) => {
      await lockTenantOwnerLifecycle(tx, tenantId);
      const [membership] = await tx
        .select({ role: userTenants.role })
        .from(userTenants)
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)))
        .limit(1);
      if (!membership) return null;
      if (deactivated && membership.role === "owner") {
        if ((await activeTenantOwnerCount(tx, tenantId, targetUserId)) < 1) {
          throw new Error("Cannot deactivate the sole owner");
        }
      }

      const [otherTenantCount] = await tx
        .select({ count: sql<number>`count(*)` })
        .from(userTenants)
        .where(
          and(
            eq(userTenants.userId, targetUserId),
            ne(userTenants.tenantId, tenantId),
            sql`${userTenants.tenantId} <> ${`personal-${targetUserId}`}`,
          ),
        );
      if (Number(otherTenantCount?.count ?? 0) > 0) {
        throw new Error(
          "Tenant dashboard lifecycle changes are limited to users without other tenant memberships",
        );
      }

      const [previous] = await tx
        .select({ deactivatedAt: users.deactivatedAt, updatedAt: users.updatedAt })
        .from(users)
        .where(eq(users.id, targetUserId))
        .limit(1);
      if (!previous) return null;

      const issuedBefore = await revocationStore.revokeUserTokens(targetUserId);
      await tx
        .update(users)
        .set({ deactivatedAt: deactivated ? new Date() : null, updatedAt: new Date() })
        .where(eq(users.id, targetUserId));
      await tx
        .delete(refreshTokens)
        .where(and(eq(refreshTokens.tenantId, tenantId), eq(refreshTokens.userId, targetUserId)));

      const [row] = await tx
        .select(tenantAdminUserSelection())
        .from(userTenants)
        .innerJoin(users, eq(userTenants.userId, users.id))
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
      return { row, previous, issuedBefore };
    })
    .catch((err: unknown) => {
      if (err instanceof Error) {
        if (err.message === "Cannot deactivate the sole owner") return err.message;
        if (err.message.startsWith("Tenant dashboard lifecycle changes")) return err.message;
      }
      throw err;
    });

  if (typeof result === "string") {
    return c.json<ApiResponse>({ ok: false, error: result }, 409);
  }
  if (result === null || !result.row) {
    return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);
  }

  try {
    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: admin.userId,
      action: deactivated ? "tenant.member.deactivate" : "tenant.member.reactivate",
      resourceType: "user",
      resourceId: targetUserId,
      metadata: { issuedBefore: result.issuedBefore },
    });
  } catch (error) {
    await db
      .update(users)
      .set({
        deactivatedAt: result.previous.deactivatedAt,
        updatedAt: result.previous.updatedAt,
      })
      .where(eq(users.id, targetUserId));
    throw error;
  }

  dispatchWebhook(tenantId, targetUserId, "user.updated_account", {
    userId: targetUserId,
    scope: "tenant",
    field: "deactivatedAt",
  });
  return c.json<ApiResponse<TenantAdminUserRow>>({ ok: true, data: result.row });
});

/**
 * DELETE /me/tenants/:tenantId/users/:userId
 * Remove a user from the current tenant. This is the dashboard-safe app-level
 * delete equivalent; global hard-delete remains platform-key only.
 */
user.delete("/me/tenants/:tenantId/users/:targetUserId", async (c) => {
  const tenantId = c.req.param("tenantId");
  const targetUserId = c.req.param("targetUserId");
  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!isValidUserId(targetUserId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid user id" }, 400);
  }
  const admin = await requireTenantAdminMfa(
    c,
    tenantId,
    "Tenant user removal requires recent MFA verification",
  );
  if (!admin.ok) return admin.response;
  if (admin.userId === targetUserId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Use the tenant leave flow to remove your own membership" },
      400,
    );
  }

  const db = getDb();
  let member: { role: string } | null = null;
  try {
    member = await db.transaction(async (tx) => {
      await lockTenantOwnerLifecycle(tx, tenantId);
      const [current] = await tx
        .select({ role: userTenants.role })
        .from(userTenants)
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
      if (!current) return null;
      if (current.role === "owner") {
        if ((await activeTenantOwnerCount(tx, tenantId, targetUserId)) < 1) {
          throw new Error("Cannot remove the sole owner");
        }
      }
      return current;
    });
  } catch (err) {
    if (err instanceof Error && err.message === "Cannot remove the sole owner") {
      return c.json<ApiResponse>({ ok: false, error: err.message }, 409);
    }
    throw err;
  }
  if (!member) return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.member.remove.authorized",
    resourceType: "user",
    resourceId: targetUserId,
    metadata: { role: member.role },
  });

  let deleted: { role: string } | null = null;
  try {
    deleted = await db.transaction(async (tx) => {
      await lockTenantOwnerLifecycle(tx, tenantId);
      const [current] = await tx
        .select({ role: userTenants.role })
        .from(userTenants)
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)));
      if (!current) return null;
      if (current.role === "owner") {
        if ((await activeTenantOwnerCount(tx, tenantId, targetUserId)) < 1) {
          throw new Error("Cannot remove the sole owner");
        }
      }
      const [row] = await tx
        .delete(userTenants)
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, targetUserId)))
        .returning({ role: userTenants.role });
      await tx
        .delete(refreshTokens)
        .where(and(eq(refreshTokens.tenantId, tenantId), eq(refreshTokens.userId, targetUserId)));
      return row ?? null;
    });
  } catch (err) {
    if (err instanceof Error && err.message === "Cannot remove the sole owner") {
      return c.json<ApiResponse>({ ok: false, error: err.message }, 409);
    }
    throw err;
  }
  if (!deleted) return c.json<ApiResponse>({ ok: false, error: "User not found in tenant" }, 404);

  const revokedBefore = await revocationStore.revokeUserTokens(targetUserId);
  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: admin.userId,
    action: "tenant.member.remove",
    resourceType: "user",
    resourceId: targetUserId,
    metadata: { role: deleted.role, revokedUserTokensIssuedBefore: revokedBefore },
  });

  dispatchWebhook(tenantId, targetUserId, "user.updated_account", {
    userId: targetUserId,
    scope: "tenant",
    field: "tenantMembership",
  });
  return c.json<ApiResponse>({ ok: true });
});

/**
 * POST /me/tenants/:tenantId/invitations/accept
 * Accept a pending tenant invitation using a one-time token. The token is
 * scoped to the authenticated user's verified email and cannot grant owner.
 */
user.post("/me/tenants/:tenantId/invitations/accept", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const tenantId = c.req.param("tenantId");
  const body = await safeJsonParse<{ token?: string }>(c);

  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (isReservedTenantId(tenantId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Personal tenants cannot be joined by invitation" },
      403,
    );
  }
  if (!body?.token || typeof body.token !== "string" || !/^[a-f0-9]{64}$/i.test(body.token)) {
    return c.json<ApiResponse>({ ok: false, error: "token is required" }, 400);
  }

  const db = getDb();
  const [userRecord] = await db
    .select({ email: users.email, emailVerified: users.emailVerified })
    .from(users)
    .where(eq(users.id, userId));
  const email = userRecord?.email?.toLowerCase().trim();
  if (!email || !userRecord?.emailVerified) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invitation acceptance requires a verified email session" },
      403,
    );
  }

  const tokenHash = hashSha256Hex(body.token);
  const [candidate] = await db
    .select({ id: tenantInvitations.id, role: tenantInvitations.role })
    .from(tenantInvitations)
    .where(
      and(
        eq(tenantInvitations.tenantId, tenantId),
        eq(tenantInvitations.email, email),
        eq(tenantInvitations.tokenHash, tokenHash),
        eq(tenantInvitations.status, "pending"),
        gte(tenantInvitations.expiresAt, new Date()),
      ),
    );
  if (!candidate) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired invitation" }, 404);
  }

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: userId,
    action: "tenant.invitation.accept.authorized",
    resourceType: "tenant_invitation",
    resourceId: candidate.id,
    metadata: { email, role: candidate.role },
  });

  const accepted = await db.transaction(async (tx) => {
    const [existingMembership] = await tx
      .select({ role: userTenants.role })
      .from(userTenants)
      .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)))
      .limit(1);
    if (existingMembership) {
      return {
        id: candidate.id,
        role: existingMembership.role,
        alreadyMember: true,
      };
    }
    const [invitation] = await tx
      .update(tenantInvitations)
      .set({
        status: "accepted",
        acceptedByUserId: userId,
        acceptedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(tenantInvitations.id, candidate.id),
          eq(tenantInvitations.tenantId, tenantId),
          eq(tenantInvitations.email, email),
          eq(tenantInvitations.tokenHash, tokenHash),
          eq(tenantInvitations.status, "pending"),
          gte(tenantInvitations.expiresAt, new Date()),
        ),
      )
      .returning({ id: tenantInvitations.id, role: tenantInvitations.role });
    if (!invitation) return null;
    await tx
      .insert(userTenants)
      .values({ userId, tenantId, role: invitation.role })
      .onConflictDoNothing();
    return { ...invitation, alreadyMember: false };
  });
  if (!accepted) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired invitation" }, 404);
  }

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: userId,
    action: "tenant.invitation.accept",
    resourceType: "tenant_invitation",
    resourceId: accepted.id,
    metadata: { email, role: accepted.role },
  });
  return c.json({
    ok: true,
    tenantId,
    role: accepted.role,
    invitationId: accepted.id,
    ...(accepted.alreadyMember ? { alreadyMember: true } : {}),
  });
});

/**
 * POST /me/tenants/:tenantId/join
 * Join a tenant that has join_mode = 'open'.
 */
user.post("/me/tenants/:tenantId/join", async (c) => {
  const personalSessionResponse = requirePersonalUserSession(c);
  if (personalSessionResponse) return personalSessionResponse;
  const userId = c.get("userId");
  const tenantId = c.req.param("tenantId");
  const db = getDb();

  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (isReservedTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Personal tenants cannot be self-joined" }, 403);
  }

  // 1. Verify tenant exists
  const [tenant] = await db
    .select({ id: tenants.id })
    .from(tenants)
    .where(eq(tenants.id, tenantId));

  if (!tenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  }

  // 2. Check if already a member
  const [existing] = await db
    .select({ id: userTenants.id })
    .from(userTenants)
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));

  if (existing) {
    return c.json({ ok: true, tenantId, role: "member", alreadyMember: true });
  }

  // 3. Check join_mode
  const [config] = await db
    .select({ joinMode: tenantConfigs.joinMode })
    .from(tenantConfigs)
    .where(eq(tenantConfigs.tenantId, tenantId));

  const joinMode = config?.joinMode;

  if (joinMode === "invite") {
    const body = await safeJsonParse<{ token?: string }>(c);
    if (!body?.token || typeof body.token !== "string" || !/^[a-f0-9]{64}$/i.test(body.token)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Tenant invitation token is required to join" },
        403,
      );
    }

    const [userRecord] = await db
      .select({ email: users.email, emailVerified: users.emailVerified })
      .from(users)
      .where(eq(users.id, userId));
    const email = userRecord?.email?.toLowerCase().trim();
    if (!email || !userRecord?.emailVerified) {
      return c.json<ApiResponse>(
        { ok: false, error: "Tenant invitation acceptance requires a verified email session" },
        403,
      );
    }

    const tokenHash = hashSha256Hex(body.token);
    const [candidate] = await db
      .select({ id: tenantInvitations.id, role: tenantInvitations.role })
      .from(tenantInvitations)
      .where(
        and(
          eq(tenantInvitations.tenantId, tenantId),
          eq(tenantInvitations.email, email),
          eq(tenantInvitations.tokenHash, tokenHash),
          eq(tenantInvitations.status, "pending"),
          gte(tenantInvitations.expiresAt, new Date()),
        ),
      );
    if (!candidate) {
      return c.json<ApiResponse>(
        { ok: false, error: `Tenant '${tenantId}' requires an invitation to join` },
        403,
      );
    }

    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "tenant.member.accept_invite.authorized",
      resourceType: "tenant_invitation",
      resourceId: candidate.id,
      metadata: { email, role: candidate.role },
    });

    const accepted = await db.transaction(async (tx) => {
      const [invitation] = await tx
        .update(tenantInvitations)
        .set({
          status: "accepted",
          acceptedByUserId: userId,
          acceptedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(tenantInvitations.id, candidate.id),
            eq(tenantInvitations.tenantId, tenantId),
            eq(tenantInvitations.email, email),
            eq(tenantInvitations.tokenHash, tokenHash),
            eq(tenantInvitations.status, "pending"),
            gte(tenantInvitations.expiresAt, new Date()),
          ),
        )
        .returning({ id: tenantInvitations.id, role: tenantInvitations.role });
      if (!invitation) return null;
      await tx
        .insert(userTenants)
        .values({ userId, tenantId, role: invitation.role })
        .onConflictDoNothing();
      return invitation;
    });
    if (!accepted) {
      return c.json<ApiResponse>(
        { ok: false, error: `Tenant '${tenantId}' requires an invitation to join` },
        403,
      );
    }

    await writeUserAudit(c, {
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "tenant.member.accept_invite",
      resourceType: "tenant_invitation",
      resourceId: accepted.id,
      metadata: { email, role: accepted.role },
    });

    return c.json({ ok: true, tenantId, role: accepted.role });
  }

  if (joinMode !== "open") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: joinMode
          ? `Tenant is not open for joining (mode: ${joinMode})`
          : "Tenant is not configured for self-join",
      },
      403,
    );
  }

  await writeUserAudit(c, {
    tenantId,
    actorType: "user",
    actorId: userId,
    action: "tenant.member.join",
    resourceType: "tenant",
    resourceId: tenantId,
    metadata: { role: "member" },
  });
  // 4. Create membership
  await db.insert(userTenants).values({ userId, tenantId, role: "member" }).onConflictDoNothing();

  return c.json({ ok: true, tenantId, role: "member" });
});

/**
 * DELETE /me/tenants/:tenantId/leave
 * Leave a tenant. Cannot leave personal tenant.
 */
user.delete("/me/tenants/:tenantId/leave", async (c) => {
  const userId = c.get("userId");
  const session = c.get("userSession");
  const tenantId = c.req.param("tenantId");

  if (!hasRecentMfaStepUp(session)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Leaving a tenant requires a recent MFA step-up session" },
      403,
    );
  }

  if (!isValidTenantId(tenantId)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid tenant id format" }, 400);
  }
  if (!sessionTenantMatches(session, tenantId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Tenant leave requires a session scoped to the target tenant" },
      403,
    );
  }

  // Cannot leave personal tenant
  if (tenantId === `personal-${userId}`) {
    return c.json<ApiResponse>({ ok: false, error: "Cannot leave your personal tenant" }, 400);
  }

  const db = getDb();
  let deletedMembership: { role: string } | null | undefined;
  try {
    deletedMembership = await db.transaction(async (tx) => {
      await lockTenantOwnerLifecycle(tx, tenantId);
      await lockUserSession(tx, userId);
      const [membership] = await tx
        .select({ role: userTenants.role })
        .from(userTenants)
        .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));

      if (!membership) return null;
      if (membership.role === "owner") {
        if ((await activeTenantOwnerCount(tx, tenantId, userId)) < 1) {
          throw new Error("Cannot leave tenant as the sole owner");
        }
      }

      await writeUserAudit(c, {
        tenantId,
        actorType: "user",
        actorId: userId,
        action: "tenant.member.leave",
        resourceType: "tenant",
        resourceId: tenantId,
      });

      const [deleted] = await tx
        .delete(userTenants)
        .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)))
        .returning({ role: userTenants.role });
      await tx
        .delete(refreshTokens)
        .where(and(eq(refreshTokens.tenantId, tenantId), eq(refreshTokens.userId, userId)));
      return deleted ?? null;
    });
  } catch (err) {
    if (err instanceof Error && err.message === "Cannot leave tenant as the sole owner") {
      return c.json<ApiResponse>({ ok: false, error: err.message }, 409);
    }
    throw err;
  }

  if (!deletedMembership) {
    return c.json<ApiResponse>({ ok: false, error: "Not a member of this tenant" }, 404);
  }

  return c.json<ApiResponse>({ ok: true });
});

export { user as userRoutes };
