/**
 * Privy-style digital asset account resources.
 *
 * Mount: app.route("/accounts", accountRoutes)
 */

import {
  agentKeyQuorums,
  agentSigners,
  agents,
  agentWallets,
  digitalAssetAccountAggregations,
  digitalAssetAccounts,
  digitalAssetAccountWallets,
  policies,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  isNonEmptyString,
  requireTenantLevel,
  safeJsonParse,
  setNoStoreHeaders,
  vault,
} from "../services/context";
import { redactWalletMetadataSecrets } from "../services/wallet-metadata";

export const accountRoutes = new Hono<{ Variables: AppVariables }>();

const MAX_ACCOUNT_WALLETS = 5;
const MAX_CUSTOM_TOKEN_BALANCES = 25;
const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9_.:_-]{1,64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type ChainFamily = "evm" | "solana" | "bitcoin";
type WalletConfiguration = {
  chain_type?: unknown;
  chainType?: unknown;
  name?: unknown;
  wallet_id?: unknown;
  walletId?: unknown;
};

type AccountMutationBody = {
  id?: unknown;
  display_name?: unknown;
  displayName?: unknown;
  metadata?: unknown;
  owner_user_ids?: unknown;
  ownerUserIds?: unknown;
  additional_signer_ids?: unknown;
  additionalSignerIds?: unknown;
  signer_policy_ids?: unknown;
  signerPolicyIds?: unknown;
  wallet_ids?: unknown;
  walletIds?: unknown;
  user_wallet_ids?: unknown;
  userWalletIds?: unknown;
  wallets_configuration?: unknown;
  walletsConfiguration?: unknown;
};

type AccountAggregationMutationBody = {
  id?: unknown;
  display_name?: unknown;
  displayName?: unknown;
  metadata?: unknown;
};

type AccountBalanceRow = {
  walletId: string;
  chainFamily: ChainFamily;
  chainId: number | null;
  symbol: string | null;
  native: string | null;
  nativeFormatted: string | null;
  walletAddress: string | null;
  unavailableReason?: string;
};

type AccountTokenBalanceRow = {
  walletId: string;
  chainId: number;
  token: string;
  symbol: string;
  balance: string;
  formatted: string;
  decimals: number;
  unavailableReason?: string;
};

type AccountMembershipInput = {
  walletAgentId: string;
  chainFamily: ChainFamily | null;
};

type DigitalAssetAccountCapability =
  | "sign_transaction"
  | "sign_message"
  | "sign_typed_data"
  | "sign_user_operation"
  | "sign_authorization"
  | "send_calls"
  | "transfer"
  | "solana_transaction"
  | "export_private_key";

type WalletSigningSummary = {
  signerCount: number;
  activeSignerCount: number;
  quorumCount: number;
  activeQuorumCount: number;
};

type AccountAuthorizationMetadata = {
  ownerUserIds: string[];
  additionalSignerIds: string[];
  signerPolicyIds: string[];
};

const ACCOUNT_AUTH_METADATA_KEY = "authorization";
const MAX_ACCOUNT_AUTH_ENTRIES = 32;

accountRoutes.use("*", async (c, next) => {
  setNoStoreHeaders(c);
  await next();
});

function newAccountId(): string {
  return `acct_${crypto.randomUUID()}`;
}

function newAccountWalletAgentId(): string {
  return `acct_wlt_${crypto.randomUUID()}`;
}

function newAggregationId(): string {
  return `acct_agg_${crypto.randomUUID()}`;
}

function normalizeAccountId(value: unknown): string | null {
  if (value === undefined) return newAccountId();
  if (typeof value !== "string" || !ACCOUNT_ID_PATTERN.test(value)) return null;
  return value;
}

function normalizeAggregationId(value: unknown): string | null {
  if (value === undefined) return newAggregationId();
  if (typeof value !== "string" || !ACCOUNT_ID_PATTERN.test(value)) return null;
  return value;
}

function normalizeOptionalDisplayName(value: unknown): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null || value === "") return null;
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 255) {
    throw new Error("display_name must be a string up to 255 characters");
  }
  return value.trim();
}

function normalizeMetadata(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("metadata must be an object");
  }
  if (JSON.stringify(value).length > 16_384) {
    throw new Error("metadata cannot exceed 16384 bytes");
  }
  return value as Record<string, unknown>;
}

function accountAuthorizationInputError(
  metadata: Record<string, unknown> | undefined,
): string | null {
  if (metadata && ACCOUNT_AUTH_METADATA_KEY in metadata) {
    return "metadata.authorization is reserved; use owner_user_ids, additional_signer_ids, and signer_policy_ids";
  }
  return null;
}

function normalizeOptionalIdList(value: unknown, field: string): string[] | undefined | string {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) return `${field} must be an array`;
  if (value.length > MAX_ACCOUNT_AUTH_ENTRIES) {
    return `${field} can include at most ${MAX_ACCOUNT_AUTH_ENTRIES} entries`;
  }
  const ids = value.map((item) => (typeof item === "string" ? item.trim() : "")).filter(Boolean);
  if (ids.length !== value.length) return `${field} must contain non-empty strings`;
  if (ids.some((id) => !ACCOUNT_ID_PATTERN.test(id))) {
    return `${field} contains an invalid id`;
  }
  return [...new Set(ids)];
}

function accountAuthorizationFromMetadata(
  metadata: Record<string, unknown> | undefined,
): AccountAuthorizationMetadata {
  const raw = metadata?.[ACCOUNT_AUTH_METADATA_KEY];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ownerUserIds: [], additionalSignerIds: [], signerPolicyIds: [] };
  }
  const record = raw as Record<string, unknown>;
  const list = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  return {
    ownerUserIds: list(record.ownerUserIds ?? record.owner_user_ids),
    additionalSignerIds: list(record.additionalSignerIds ?? record.additional_signer_ids),
    signerPolicyIds: list(record.signerPolicyIds ?? record.signer_policy_ids),
  };
}

function mergeAccountAuthorizationMetadata(
  metadata: Record<string, unknown>,
  authorization: AccountAuthorizationMetadata,
): Record<string, unknown> {
  return {
    ...metadata,
    [ACCOUNT_AUTH_METADATA_KEY]: {
      ownerUserIds: authorization.ownerUserIds,
      owner_user_ids: authorization.ownerUserIds,
      additionalSignerIds: authorization.additionalSignerIds,
      additional_signer_ids: authorization.additionalSignerIds,
      signerPolicyIds: authorization.signerPolicyIds,
      signer_policy_ids: authorization.signerPolicyIds,
    },
  };
}

function normalizeChainFamily(value: unknown): ChainFamily | string {
  if (value === "evm" || value === "ethereum") return "evm";
  if (value === "solana") return "solana";
  if (value === "bitcoin") return "bitcoin";
  return 'chain_type must be "ethereum", "evm", "solana", or "bitcoin"';
}

function parseOptionalChainId(value: string | undefined): number | string | undefined {
  if (value === undefined || value === "") return undefined;
  if (!/^\d+$/.test(value)) return "chainId must be a positive integer";
  const chainId = Number(value);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return "chainId must be a positive integer";
  return chainId;
}

function isSolanaChainId(chainId: number): boolean {
  return chainId === 101 || chainId === 102;
}

function accountBalanceChainId(wallet: { chainFamily: ChainFamily }, chainId?: number): number {
  if (wallet.chainFamily === "solana") {
    return chainId && isSolanaChainId(chainId) ? chainId : 101;
  }
  if (wallet.chainFamily === "bitcoin") {
    return chainId === 202 ? 202 : 201;
  }
  return chainId && !isSolanaChainId(chainId) ? chainId : Number(process.env.CHAIN_ID || "84532");
}

function balanceRowsForChainFilter<T extends { chainFamily: ChainFamily }>(
  wallets: T[],
  chainId?: number,
): T[] {
  if (!chainId) return wallets;
  return wallets.filter((wallet) =>
    isSolanaChainId(chainId)
      ? wallet.chainFamily === "solana"
      : chainId === 201 || chainId === 202
        ? wallet.chainFamily === "bitcoin"
        : wallet.chainFamily === "evm",
  );
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

function buildNativeRollups(balances: AccountBalanceRow[]) {
  const rollups = new Map<string, { chainId: number; symbol: string; native: bigint }>();
  for (const balance of balances) {
    if (balance.native === null || balance.chainId === null || !balance.symbol) continue;
    const key = `${balance.chainId}:${balance.symbol}`;
    const current = rollups.get(key) ?? {
      chainId: balance.chainId,
      symbol: balance.symbol,
      native: 0n,
    };
    current.native += BigInt(balance.native);
    rollups.set(key, current);
  }
  return [...rollups.values()].map((rollup) => ({
    chainId: rollup.chainId,
    symbol: rollup.symbol,
    native: rollup.native.toString(),
  }));
}

function buildTokenRollups(tokenBalances: AccountTokenBalanceRow[]) {
  const rollups = new Map<
    string,
    { chainId: number; token: string; symbol: string; decimals: number; balance: bigint }
  >();
  for (const row of tokenBalances) {
    if (row.unavailableReason) continue;
    const key = `${row.chainId}:${row.token.toLowerCase()}`;
    const current = rollups.get(key) ?? {
      chainId: row.chainId,
      token: row.token,
      symbol: row.symbol,
      decimals: row.decimals,
      balance: 0n,
    };
    current.balance += BigInt(row.balance);
    rollups.set(key, current);
  }
  return [...rollups.values()].map((rollup) => ({
    chainId: rollup.chainId,
    token: rollup.token,
    symbol: rollup.symbol,
    balance: rollup.balance.toString(),
    decimals: rollup.decimals,
  }));
}

function uniqueCapabilities(
  capabilities: Iterable<DigitalAssetAccountCapability>,
): DigitalAssetAccountCapability[] {
  return [...new Set(capabilities)].sort();
}

function deriveWalletCapabilities(input: {
  chainFamily: ChainFamily;
  address: string | null;
  custodyType: "server" | "user_embedded";
}): DigitalAssetAccountCapability[] {
  if (!input.address) return [];
  if (input.chainFamily === "bitcoin") return [];
  const capabilities: DigitalAssetAccountCapability[] = [
    "sign_transaction",
    "sign_message",
    "transfer",
  ];
  if (input.chainFamily === "evm" && input.custodyType === "server") {
    capabilities.push("sign_typed_data", "sign_user_operation", "sign_authorization", "send_calls");
  }
  if (input.chainFamily === "solana") {
    capabilities.push("solana_transaction");
  }
  if (input.custodyType === "user_embedded") {
    capabilities.push("export_private_key");
  }
  return uniqueCapabilities(capabilities);
}

function deriveWalletCapabilityMetadata(input: {
  chainFamily: ChainFamily;
  address: string | null;
  custodyType: "server" | "user_embedded";
  ownerUserId: string | null;
  signing: WalletSigningSummary;
}) {
  const hasSupportedActions = input.address !== null && input.chainFamily !== "bitcoin";
  const canSign = hasSupportedActions;
  return {
    custody: {
      type: input.custodyType,
      ownerUserId: input.ownerUserId,
      owner_user_id: input.ownerUserId,
      serverManaged: input.custodyType === "server",
      server_managed: input.custodyType === "server",
      userOwned: input.custodyType === "user_embedded",
      user_owned: input.custodyType === "user_embedded",
    },
    signing: {
      mode:
        input.signing.activeQuorumCount > 0
          ? "quorum"
          : input.signing.activeSignerCount > 0
            ? "delegated"
            : input.custodyType === "server"
              ? "server"
              : "user",
      signerCount: input.signing.signerCount,
      signer_count: input.signing.signerCount,
      activeSignerCount: input.signing.activeSignerCount,
      active_signer_count: input.signing.activeSignerCount,
      quorumCount: input.signing.quorumCount,
      quorum_count: input.signing.quorumCount,
      activeQuorumCount: input.signing.activeQuorumCount,
      active_quorum_count: input.signing.activeQuorumCount,
      hasDelegatedSigners: input.signing.signerCount > 0,
      has_delegated_signers: input.signing.signerCount > 0,
      hasActiveDelegatedSigners: input.signing.activeSignerCount > 0,
      has_active_delegated_signers: input.signing.activeSignerCount > 0,
      hasKeyQuorums: input.signing.quorumCount > 0,
      has_key_quorums: input.signing.quorumCount > 0,
      hasActiveKeyQuorums: input.signing.activeQuorumCount > 0,
      has_active_key_quorums: input.signing.activeQuorumCount > 0,
    },
    operations: {
      readBalance: hasSupportedActions,
      read_balance: hasSupportedActions,
      transfer: hasSupportedActions,
      signTransaction: canSign,
      sign_transaction: canSign,
      signMessage: canSign,
      sign_message: canSign,
      signTypedData: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      sign_typed_data: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      signUserOperation: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      sign_user_operation: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      signAuthorization: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      sign_authorization: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      sendCalls: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      send_calls: canSign && input.chainFamily === "evm" && input.custodyType === "server",
      solanaTransaction: canSign && input.chainFamily === "solana",
      solana_transaction: canSign && input.chainFamily === "solana",
      exportPrivateKey: canSign && input.custodyType === "user_embedded",
      export_private_key: canSign && input.custodyType === "user_embedded",
    },
  };
}

function deriveAccountCapabilityMetadata(
  wallets: Array<{
    walletId: string;
    chainFamily: ChainFamily;
    walletType: string;
    custody: { type: "server" | "user_embedded" };
    signing: WalletSigningSummary;
  }>,
) {
  return {
    walletCount: wallets.length,
    wallet_count: wallets.length,
    walletIds: [...new Set(wallets.map((wallet) => wallet.walletId))],
    wallet_ids: [...new Set(wallets.map((wallet) => wallet.walletId))],
    chainFamilies: [...new Set(wallets.map((wallet) => wallet.chainFamily))].sort(),
    chain_families: [...new Set(wallets.map((wallet) => wallet.chainFamily))].sort(),
    custodyTypes: [...new Set(wallets.map((wallet) => wallet.custody.type))].sort(),
    custody_types: [...new Set(wallets.map((wallet) => wallet.custody.type))].sort(),
    walletTypes: [...new Set(wallets.map((wallet) => wallet.walletType))].sort(),
    wallet_types: [...new Set(wallets.map((wallet) => wallet.walletType))].sort(),
    hasServerWallets: wallets.some((wallet) => wallet.custody.type === "server"),
    has_server_wallets: wallets.some((wallet) => wallet.custody.type === "server"),
    hasUserEmbeddedWallets: wallets.some((wallet) => wallet.custody.type === "user_embedded"),
    has_user_embedded_wallets: wallets.some((wallet) => wallet.custody.type === "user_embedded"),
    hasDelegatedSigners: wallets.some((wallet) => wallet.signing.signerCount > 0),
    has_delegated_signers: wallets.some((wallet) => wallet.signing.signerCount > 0),
    hasActiveDelegatedSigners: wallets.some((wallet) => wallet.signing.activeSignerCount > 0),
    has_active_delegated_signers: wallets.some((wallet) => wallet.signing.activeSignerCount > 0),
    hasKeyQuorums: wallets.some((wallet) => wallet.signing.quorumCount > 0),
    has_key_quorums: wallets.some((wallet) => wallet.signing.quorumCount > 0),
    hasActiveKeyQuorums: wallets.some((wallet) => wallet.signing.activeQuorumCount > 0),
    has_active_key_quorums: wallets.some((wallet) => wallet.signing.activeQuorumCount > 0),
  };
}

function normalizeWalletIds(body: AccountMutationBody): string[] | undefined {
  const value = body.wallet_ids ?? body.walletIds;
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
    throw new Error("wallet_ids must be an array of non-empty strings");
  }
  return [...new Set(value.map((item) => item.trim()))];
}

function normalizeUserWalletIds(body: AccountMutationBody): string[] | undefined {
  const value = body.user_wallet_ids ?? body.userWalletIds;
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
    throw new Error("user_wallet_ids must be an array of non-empty strings");
  }
  return [...new Set(value.map((item) => item.trim()))];
}

function normalizeWalletConfigurations(
  body: AccountMutationBody,
): WalletConfiguration[] | undefined {
  const value = body.wallets_configuration ?? body.walletsConfiguration;
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => !item || typeof item !== "object")) {
    throw new Error("wallets_configuration must be an array of wallet configuration objects");
  }
  return value as WalletConfiguration[];
}

function dedupeMemberships(items: AccountMembershipInput[]): AccountMembershipInput[] {
  const seen = new Set<string>();
  const result: AccountMembershipInput[] = [];
  for (const item of items) {
    const key = `${item.walletAgentId}:${item.chainFamily ?? "*"}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

async function writeAccountAudit(input: Parameters<typeof writeAuditEvent>[0]) {
  try {
    await writeAuditEvent(input);
  } catch (error) {
    console.error("[accounts] Failed to write account audit event:", error);
  }
}

async function existingWalletMemberships(
  tenantId: string,
  walletIds: string[],
): Promise<AccountMembershipInput[] | string> {
  if (walletIds.length === 0) return [];
  const rows = await db
    .select({ id: agents.id })
    .from(agents)
    .where(and(eq(agents.tenantId, tenantId), inArray(agents.id, walletIds)));
  const found = new Set(rows.map((row) => row.id));
  const missing = walletIds.filter((walletId) => !found.has(walletId));
  if (missing.length > 0) return `Unknown wallet_ids: ${missing.join(", ")}`;
  return walletIds.map((walletAgentId) => ({ walletAgentId, chainFamily: null }));
}

async function existingUserWalletMemberships(
  tenantId: string,
  walletIds: string[],
): Promise<AccountMembershipInput[] | string> {
  if (walletIds.length === 0) return [];
  const rows = await db
    .select({ id: agents.id, ownerUserId: agents.ownerUserId })
    .from(agents)
    .where(and(eq(agents.tenantId, tenantId), inArray(agents.id, walletIds)));
  const byId = new Map(rows.map((row) => [row.id, row]));
  const missing = walletIds.filter((walletId) => !byId.has(walletId));
  if (missing.length > 0) return `Unknown user_wallet_ids: ${missing.join(", ")}`;
  const nonUserWalletIds = walletIds.filter((walletId) => !byId.get(walletId)?.ownerUserId);
  if (nonUserWalletIds.length > 0) {
    return `user_wallet_ids must reference user-owned wallets: ${nonUserWalletIds.join(", ")}`;
  }
  return walletIds.map((walletAgentId) => ({ walletAgentId, chainFamily: null }));
}

async function configuredWalletMemberships(
  tenantId: string,
  accountId: string,
  configs: WalletConfiguration[],
  createdWalletAgentIds: string[],
): Promise<AccountMembershipInput[] | string> {
  const memberships: AccountMembershipInput[] = [];
  for (const [index, config] of configs.entries()) {
    const chainFamily = normalizeChainFamily(config.chain_type ?? config.chainType);
    if (
      typeof chainFamily === "string" &&
      chainFamily !== "evm" &&
      chainFamily !== "solana" &&
      chainFamily !== "bitcoin"
    ) {
      await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
      return `wallets_configuration[${index}].${chainFamily}`;
    }
    if (chainFamily === "bitcoin") {
      await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
      return "wallets_configuration bitcoin wallets must be created through the agent wallet API";
    }
    const requestedId = config.wallet_id ?? config.walletId;
    const walletAgentId =
      typeof requestedId === "string" && requestedId.trim()
        ? requestedId.trim()
        : newAccountWalletAgentId();
    if (!ACCOUNT_ID_PATTERN.test(walletAgentId)) {
      await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
      return "wallet_id must be 1-64 alphanumeric characters (plus _ - . :)";
    }
    const name =
      typeof config.name === "string" && config.name.trim()
        ? config.name.trim()
        : `${accountId} ${chainFamily} wallet`;
    try {
      await vault.createAgent(tenantId, walletAgentId, name, accountId, chainFamily);
      createdWalletAgentIds.push(walletAgentId);
    } catch (error) {
      await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
      const message = error instanceof Error ? error.message : "Failed to create configured wallet";
      return message;
    }
    memberships.push({ walletAgentId, chainFamily });
  }
  return memberships;
}

async function buildMemberships(
  tenantId: string,
  accountId: string,
  body: AccountMutationBody,
  createdWalletAgentIds: string[] = [],
): Promise<AccountMembershipInput[] | undefined | string> {
  const walletIds = normalizeWalletIds(body);
  const userWalletIds = normalizeUserWalletIds(body);
  const walletConfigs = normalizeWalletConfigurations(body);
  if (walletIds === undefined && userWalletIds === undefined && walletConfigs === undefined) {
    return undefined;
  }
  const requestedCount =
    (walletIds?.length ?? 0) + (userWalletIds?.length ?? 0) + (walletConfigs?.length ?? 0);
  if (requestedCount > MAX_ACCOUNT_WALLETS) {
    return `accounts can contain at most ${MAX_ACCOUNT_WALLETS} wallets`;
  }

  const memberships: AccountMembershipInput[] = [];
  if (walletIds) {
    const existing = await existingWalletMemberships(tenantId, walletIds);
    if (typeof existing === "string") return existing;
    memberships.push(...existing);
  }
  if (userWalletIds) {
    const existing = await existingUserWalletMemberships(tenantId, userWalletIds);
    if (typeof existing === "string") return existing;
    memberships.push(...existing);
  }
  if (walletConfigs) {
    const configured = await configuredWalletMemberships(
      tenantId,
      accountId,
      walletConfigs,
      createdWalletAgentIds,
    );
    if (typeof configured === "string") return configured;
    memberships.push(...configured);
  }

  const deduped = dedupeMemberships(memberships);
  if (deduped.length > MAX_ACCOUNT_WALLETS) {
    return `accounts can contain at most ${MAX_ACCOUNT_WALLETS} wallets`;
  }
  return deduped;
}

async function cleanupCreatedAccountWallets(tenantId: string, walletAgentIds: string[]) {
  if (walletAgentIds.length === 0) return;
  await db
    .delete(agents)
    .where(and(eq(agents.tenantId, tenantId), inArray(agents.id, walletAgentIds)));
}

async function walletAgentIdsForAccount(tenantId: string, accountId: string): Promise<string[]> {
  const rows = await db
    .select({ walletAgentId: digitalAssetAccountWallets.walletAgentId })
    .from(digitalAssetAccountWallets)
    .where(
      and(
        eq(digitalAssetAccountWallets.tenantId, tenantId),
        eq(digitalAssetAccountWallets.accountId, accountId),
      ),
    );
  return [...new Set(rows.map((row) => row.walletAgentId))];
}

async function validateAccountAuthorizationMetadata(
  tenantId: string,
  authorization: AccountAuthorizationMetadata,
  walletAgentIds: string[],
): Promise<string | null> {
  if (authorization.ownerUserIds.length > 0) {
    if (authorization.ownerUserIds.some((userId) => !UUID_PATTERN.test(userId))) {
      return "owner_user_ids must contain UUID user ids";
    }
    const ownerRows = await db
      .select({ userId: userTenants.userId })
      .from(userTenants)
      .innerJoin(users, eq(userTenants.userId, users.id))
      .where(
        and(
          eq(userTenants.tenantId, tenantId),
          inArray(userTenants.userId, authorization.ownerUserIds),
          isNull(users.deactivatedAt),
        ),
      );
    const knownOwners = new Set(ownerRows.map((row) => row.userId));
    const missingOwner = authorization.ownerUserIds.find((userId) => !knownOwners.has(userId));
    if (missingOwner) {
      return `owner_user_ids contains a user that is not an active tenant member: ${missingOwner}`;
    }
  }

  if (authorization.additionalSignerIds.length > 0) {
    if (walletAgentIds.length === 0) return "additional_signer_ids requires account wallets";
    const signerRows = await db
      .select({ id: agentSigners.id })
      .from(agentSigners)
      .where(
        and(
          eq(agentSigners.tenantId, tenantId),
          inArray(agentSigners.agentId, walletAgentIds),
          inArray(agentSigners.id, authorization.additionalSignerIds),
          eq(agentSigners.status, "active"),
        ),
      );
    const knownSigners = new Set(signerRows.map((row) => row.id));
    const missingSigner = authorization.additionalSignerIds.find((id) => !knownSigners.has(id));
    if (missingSigner) {
      return `additional_signer_ids contains a signer outside this account: ${missingSigner}`;
    }
  }

  if (authorization.signerPolicyIds.length > 0) {
    if (walletAgentIds.length === 0) return "signer_policy_ids requires account wallets";
    const policyRows = await db
      .select({ id: policies.id })
      .from(policies)
      .where(
        and(
          inArray(policies.agentId, walletAgentIds),
          inArray(policies.id, authorization.signerPolicyIds),
        ),
      );
    const knownPolicies = new Set(policyRows.map((row) => row.id));
    const missingPolicy = authorization.signerPolicyIds.find((id) => !knownPolicies.has(id));
    if (missingPolicy) {
      return `signer_policy_ids contains a policy outside this account: ${missingPolicy}`;
    }
  }

  return null;
}

async function normalizeAccountAuthorization(
  tenantId: string,
  body: AccountMutationBody,
  baseMetadata: Record<string, unknown>,
  walletAgentIds: string[],
  options: { validateExisting?: boolean } = {},
): Promise<AccountAuthorizationMetadata | undefined | string> {
  const ownerUserIds = normalizeOptionalIdList(
    body.owner_user_ids ?? body.ownerUserIds,
    "owner_user_ids",
  );
  if (typeof ownerUserIds === "string") return ownerUserIds;
  const additionalSignerIds = normalizeOptionalIdList(
    body.additional_signer_ids ?? body.additionalSignerIds,
    "additional_signer_ids",
  );
  if (typeof additionalSignerIds === "string") return additionalSignerIds;
  const signerPolicyIds = normalizeOptionalIdList(
    body.signer_policy_ids ?? body.signerPolicyIds,
    "signer_policy_ids",
  );
  if (typeof signerPolicyIds === "string") return signerPolicyIds;

  if (
    ownerUserIds === undefined &&
    additionalSignerIds === undefined &&
    signerPolicyIds === undefined
  ) {
    if (!options.validateExisting) return undefined;
    const current = accountAuthorizationFromMetadata(baseMetadata);
    const error = await validateAccountAuthorizationMetadata(tenantId, current, walletAgentIds);
    return error ?? current;
  }

  const current = accountAuthorizationFromMetadata(baseMetadata);
  const authorization = {
    ownerUserIds: ownerUserIds ?? current.ownerUserIds,
    additionalSignerIds: additionalSignerIds ?? current.additionalSignerIds,
    signerPolicyIds: signerPolicyIds ?? current.signerPolicyIds,
  };
  const error = await validateAccountAuthorizationMetadata(tenantId, authorization, walletAgentIds);
  return error ?? authorization;
}

async function serializeAccount(tenantId: string, accountId: string) {
  const [account] = await db
    .select()
    .from(digitalAssetAccounts)
    .where(
      and(eq(digitalAssetAccounts.tenantId, tenantId), eq(digitalAssetAccounts.id, accountId)),
    );
  if (!account) return null;

  const memberships = await db
    .select({
      membershipId: digitalAssetAccountWallets.id,
      walletAgentId: digitalAssetAccountWallets.walletAgentId,
      membershipChainFamily: digitalAssetAccountWallets.chainFamily,
      agentName: agents.name,
      ownerUserId: agents.ownerUserId,
      walletType: agents.walletType,
      agentWalletAddress: agents.walletAddress,
      chainFamily: agentWallets.chainFamily,
      address: agentWallets.address,
      purpose: agentWallets.purpose,
      venue: agentWallets.venue,
      metadata: agentWallets.metadata,
      createdAt: agentWallets.createdAt,
    })
    .from(digitalAssetAccountWallets)
    .innerJoin(
      agents,
      and(
        eq(agents.tenantId, digitalAssetAccountWallets.tenantId),
        eq(agents.id, digitalAssetAccountWallets.walletAgentId),
      ),
    )
    .leftJoin(agentWallets, eq(agentWallets.agentId, agents.id))
    .where(
      and(
        eq(digitalAssetAccountWallets.tenantId, tenantId),
        eq(digitalAssetAccountWallets.accountId, accountId),
        sql`(${digitalAssetAccountWallets.chainFamily} is null or ${agentWallets.chainFamily} = ${digitalAssetAccountWallets.chainFamily})`,
      ),
    );

  const walletAgentIds = [...new Set(memberships.map((row) => row.walletAgentId))];
  const [signerRows, quorumRows] =
    walletAgentIds.length === 0
      ? [[], []]
      : await Promise.all([
          db
            .select({
              agentId: agentSigners.agentId,
              status: agentSigners.status,
            })
            .from(agentSigners)
            .where(
              and(
                eq(agentSigners.tenantId, tenantId),
                inArray(agentSigners.agentId, walletAgentIds),
              ),
            ),
          db
            .select({
              agentId: agentKeyQuorums.agentId,
              status: agentKeyQuorums.status,
            })
            .from(agentKeyQuorums)
            .where(
              and(
                eq(agentKeyQuorums.tenantId, tenantId),
                inArray(agentKeyQuorums.agentId, walletAgentIds),
              ),
            ),
        ]);
  const signingByWallet = new Map<
    string,
    {
      signerCount: number;
      activeSignerCount: number;
      quorumCount: number;
      activeQuorumCount: number;
    }
  >();
  for (const walletAgentId of walletAgentIds) {
    const signers = signerRows.filter((row) => row.agentId === walletAgentId);
    const quorums = quorumRows.filter((row) => row.agentId === walletAgentId);
    signingByWallet.set(walletAgentId, {
      signerCount: signers.length,
      activeSignerCount: signers.filter((row) => row.status === "active").length,
      quorumCount: quorums.length,
      activeQuorumCount: quorums.filter((row) => row.status === "active").length,
    });
  }

  const wallets = memberships.map((row) => {
    const chainFamily = row.chainFamily ?? row.membershipChainFamily ?? "evm";
    const custodyType: "server" | "user_embedded" =
      row.ownerUserId || row.walletType?.includes("user") ? "user_embedded" : "server";
    const signing = signingByWallet.get(row.walletAgentId) ?? {
      signerCount: 0,
      activeSignerCount: 0,
      quorumCount: 0,
      activeQuorumCount: 0,
    };
    const address = row.address ?? row.agentWalletAddress;
    const capabilityMetadata = deriveWalletCapabilityMetadata({
      chainFamily,
      address,
      custodyType,
      ownerUserId: row.ownerUserId,
      signing,
    });
    return {
      id: row.walletAgentId,
      walletId: row.walletAgentId,
      membershipId: row.membershipId,
      name: row.agentName,
      ownerUserId: row.ownerUserId,
      owner_user_id: row.ownerUserId,
      walletType: row.walletType ?? "agent",
      wallet_type: row.walletType ?? "agent",
      custody: {
        type: custodyType,
        ownerUserId: row.ownerUserId,
        owner_user_id: row.ownerUserId,
      },
      signing,
      capabilities: deriveWalletCapabilities({ chainFamily, address, custodyType }),
      capabilityMetadata,
      capability_metadata: capabilityMetadata,
      chainType:
        chainFamily === "solana" ? "solana" : chainFamily === "bitcoin" ? "bitcoin" : "ethereum",
      chainFamily,
      address,
      purpose: row.purpose,
      venue: row.venue,
      metadata: redactWalletMetadataSecrets(row.metadata),
      createdAt: row.createdAt,
    };
  });
  const accountCapabilities = uniqueCapabilities(wallets.flatMap((wallet) => wallet.capabilities));
  const accountCapabilityMetadata = deriveAccountCapabilityMetadata(wallets);
  const authorization = accountAuthorizationFromMetadata(account.metadata);

  return {
    id: account.id,
    tenantId: account.tenantId,
    displayName: account.displayName,
    display_name: account.displayName,
    metadata: account.metadata,
    ownerUserIds: authorization.ownerUserIds,
    owner_user_ids: authorization.ownerUserIds,
    additionalSignerIds: authorization.additionalSignerIds,
    additional_signer_ids: authorization.additionalSignerIds,
    signerPolicyIds: authorization.signerPolicyIds,
    signer_policy_ids: authorization.signerPolicyIds,
    walletIds: [...new Set(wallets.map((wallet) => wallet.walletId))],
    wallet_ids: [...new Set(wallets.map((wallet) => wallet.walletId))],
    wallets,
    capabilities: accountCapabilities,
    capabilityMetadata: accountCapabilityMetadata,
    capability_metadata: accountCapabilityMetadata,
    createdAt: account.createdAt,
    created_at: account.createdAt,
    updatedAt: account.updatedAt,
    updated_at: account.updatedAt,
  };
}

async function serializeAggregation(tenantId: string, accountId: string, aggregationId: string) {
  const [aggregation] = await db
    .select()
    .from(digitalAssetAccountAggregations)
    .where(
      and(
        eq(digitalAssetAccountAggregations.tenantId, tenantId),
        eq(digitalAssetAccountAggregations.accountId, accountId),
        eq(digitalAssetAccountAggregations.id, aggregationId),
      ),
    );
  if (!aggregation) return null;
  return {
    id: aggregation.id,
    accountId: aggregation.accountId,
    account_id: aggregation.accountId,
    tenantId: aggregation.tenantId,
    displayName: aggregation.displayName,
    display_name: aggregation.displayName,
    walletIds: aggregation.walletAgentIds,
    wallet_ids: aggregation.walletAgentIds,
    chainFamilies: aggregation.chainFamilies,
    chain_families: aggregation.chainFamilies,
    metadata: aggregation.metadata,
    createdAt: aggregation.createdAt,
    created_at: aggregation.createdAt,
    updatedAt: aggregation.updatedAt,
    updated_at: aggregation.updatedAt,
  };
}

async function applyAccountUpdates(
  tenantId: string,
  accountId: string,
  updates: Partial<typeof digitalAssetAccounts.$inferInsert>,
  memberships: AccountMembershipInput[] | undefined,
) {
  await db.transaction(async (tx) => {
    if (Object.keys(updates).length > 0) {
      await tx
        .update(digitalAssetAccounts)
        .set(updates)
        .where(
          and(eq(digitalAssetAccounts.tenantId, tenantId), eq(digitalAssetAccounts.id, accountId)),
        );
    }

    if (memberships !== undefined) {
      await tx
        .delete(digitalAssetAccountWallets)
        .where(
          and(
            eq(digitalAssetAccountWallets.tenantId, tenantId),
            eq(digitalAssetAccountWallets.accountId, accountId),
          ),
        );
      if (memberships.length > 0) {
        await tx.insert(digitalAssetAccountWallets).values(
          memberships.map((membership) => ({
            tenantId,
            accountId,
            walletAgentId: membership.walletAgentId,
            chainFamily: membership.chainFamily,
          })),
        );
      }
    }
  });
}

accountRoutes.get("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const rows = await db
    .select({ id: digitalAssetAccounts.id })
    .from(digitalAssetAccounts)
    .where(eq(digitalAssetAccounts.tenantId, tenantId))
    .orderBy(digitalAssetAccounts.createdAt);
  const accounts = await Promise.all(rows.map((row) => serializeAccount(tenantId, row.id)));
  return c.json<ApiResponse>({
    ok: true,
    data: {
      accounts: accounts.filter((account): account is NonNullable<typeof account> => !!account),
    },
  });
});

accountRoutes.post("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<AccountMutationBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  const accountId = normalizeAccountId(body.id);
  if (!accountId) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid account id" }, 400);
  }

  let displayName: string | null | undefined;
  let metadata: Record<string, unknown> | undefined;
  try {
    displayName = normalizeOptionalDisplayName(body.display_name ?? body.displayName);
    metadata = normalizeMetadata(body.metadata);
  } catch (error) {
    return c.json<ApiResponse>({ ok: false, error: (error as Error).message }, 400);
  }
  const metadataAuthorizationError = accountAuthorizationInputError(metadata);
  if (metadataAuthorizationError) {
    return c.json<ApiResponse>({ ok: false, error: metadataAuthorizationError }, 400);
  }
  if (!isNonEmptyString(displayName ?? "Account")) {
    displayName = null;
  }

  let memberships: AccountMembershipInput[] | undefined | string;
  const createdWalletAgentIds: string[] = [];
  try {
    memberships = await buildMemberships(tenantId, accountId, body, createdWalletAgentIds);
  } catch (error) {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>({ ok: false, error: (error as Error).message }, 400);
  }
  if (memberships === undefined) {
    return c.json<ApiResponse>(
      { ok: false, error: "wallet_ids, user_wallet_ids, or wallets_configuration is required" },
      400,
    );
  }
  if (typeof memberships === "string") {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>({ ok: false, error: memberships }, 400);
  }
  const authorization = await normalizeAccountAuthorization(
    tenantId,
    body,
    metadata ?? {},
    memberships.map((membership) => membership.walletAgentId),
  );
  if (typeof authorization === "string") {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>({ ok: false, error: authorization }, 400);
  }
  const storedMetadata =
    authorization === undefined
      ? (metadata ?? {})
      : mergeAccountAuthorizationMetadata(metadata ?? {}, authorization);

  try {
    await db.transaction(async (tx) => {
      await tx.insert(digitalAssetAccounts).values({
        id: accountId,
        tenantId,
        displayName,
        metadata: storedMetadata,
      });
      if (memberships.length > 0) {
        await tx.insert(digitalAssetAccountWallets).values(
          memberships.map((membership) => ({
            tenantId,
            accountId,
            walletAgentId: membership.walletAgentId,
            chainFamily: membership.chainFamily,
          })),
        );
      }
    });
    await writeAccountAudit({
      tenantId,
      actorType: "api-key",
      action: "account.create",
      resourceType: "account",
      resourceId: accountId,
      metadata: { walletCount: memberships.length },
    });
  } catch (error) {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Failed to create account" },
      400,
    );
  }

  const account = await serializeAccount(tenantId, accountId);
  return c.json<ApiResponse>({ ok: true, data: account }, 201);
});

accountRoutes.get("/:accountId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const account = await serializeAccount(tenantId, c.req.param("accountId"));
  if (!account) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
  return c.json<ApiResponse>({ ok: true, data: account });
});

accountRoutes.get("/:accountId/balance", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const chainId = parseOptionalChainId(c.req.query("chainId"));
  if (typeof chainId === "string") {
    return c.json<ApiResponse>({ ok: false, error: chainId }, 400);
  }
  const customTokens = parseCustomTokenList(c.req.query("tokens"));
  if (typeof customTokens === "string") {
    return c.json<ApiResponse>({ ok: false, error: customTokens }, 400);
  }
  const account = await serializeAccount(tenantId, c.req.param("accountId"));
  if (!account) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
  const balanceWallets = balanceRowsForChainFilter(account.wallets, chainId);
  const rpcBalanceWallets = balanceWallets.filter((wallet) => wallet.chainFamily !== "bitcoin");
  const balances = await Promise.all(
    rpcBalanceWallets.map(async (wallet) => {
      const resolvedChainId = accountBalanceChainId(wallet, chainId);
      try {
        const balance = await vault.getBalance(tenantId, wallet.walletId, resolvedChainId);
        return {
          walletId: wallet.walletId,
          chainFamily: wallet.chainFamily,
          chainId: balance.chainId,
          symbol: balance.symbol,
          native: balance.native.toString(),
          nativeFormatted: balance.nativeFormatted,
          walletAddress: balance.walletAddress,
        } satisfies AccountBalanceRow;
      } catch (error) {
        return {
          walletId: wallet.walletId,
          chainFamily: wallet.chainFamily,
          chainId: resolvedChainId,
          symbol: null,
          native: null,
          nativeFormatted: null,
          walletAddress: wallet.address ?? null,
          unavailableReason: error instanceof Error ? error.message : "Balance unavailable",
        } satisfies AccountBalanceRow;
      }
    }),
  );
  const tokenBalanceWallets = rpcBalanceWallets;
  const tokenBalances = (
    await Promise.all(
      tokenBalanceWallets.map(async (wallet) => {
        const resolvedChainId = accountBalanceChainId(wallet, chainId);
        try {
          const tokens =
            wallet.chainFamily === "solana"
              ? await vault.getSplTokenBalances(tenantId, wallet.walletId, resolvedChainId)
              : await vault.getTokenBalances(
                  tenantId,
                  wallet.walletId,
                  resolvedChainId,
                  customTokens,
                );
          return tokens.map(
            (token): AccountTokenBalanceRow => ({
              walletId: wallet.walletId,
              chainId: resolvedChainId,
              token: token.token,
              symbol: token.symbol,
              balance: token.balance,
              formatted: token.formatted,
              decimals: token.decimals,
            }),
          );
        } catch (error) {
          return [
            {
              walletId: wallet.walletId,
              chainId: resolvedChainId,
              token: "",
              symbol: "",
              balance: "0",
              formatted: "0",
              decimals: 0,
              unavailableReason:
                error instanceof Error ? error.message : "Token balances unavailable",
            },
          ];
        }
      }),
    )
  ).flat();
  return c.json<ApiResponse>({
    ok: true,
    data: {
      id: account.id,
      accountId: account.id,
      account_id: account.id,
      wallets: account.wallets,
      capabilities: account.capabilities,
      capabilityMetadata: account.capabilityMetadata,
      capability_metadata: account.capability_metadata,
      balances,
      tokenBalances,
      rollups: {
        native: buildNativeRollups(balances),
        tokens: buildTokenRollups(tokenBalances),
      },
    },
  });
});

accountRoutes.get("/:accountId/aggregations", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const accountId = c.req.param("accountId");
  const account = await serializeAccount(tenantId, accountId);
  if (!account) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
  const rows = await db
    .select({ id: digitalAssetAccountAggregations.id })
    .from(digitalAssetAccountAggregations)
    .where(
      and(
        eq(digitalAssetAccountAggregations.tenantId, tenantId),
        eq(digitalAssetAccountAggregations.accountId, accountId),
      ),
    )
    .orderBy(digitalAssetAccountAggregations.createdAt);
  const aggregations = await Promise.all(
    rows.map((row) => serializeAggregation(tenantId, accountId, row.id)),
  );
  return c.json<ApiResponse>({
    ok: true,
    data: {
      aggregations: aggregations.filter(
        (aggregation): aggregation is NonNullable<typeof aggregation> => !!aggregation,
      ),
    },
  });
});

accountRoutes.post("/:accountId/aggregations", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const accountId = c.req.param("accountId");
  const account = await serializeAccount(tenantId, accountId);
  if (!account) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);

  const body = await safeJsonParse<AccountAggregationMutationBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  const aggregationId = normalizeAggregationId(body.id);
  if (!aggregationId) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid aggregation id" }, 400);
  }
  let displayName: string | null | undefined;
  let metadata: Record<string, unknown> | undefined;
  try {
    displayName = normalizeOptionalDisplayName(body.display_name ?? body.displayName);
    metadata = normalizeMetadata(body.metadata);
  } catch (error) {
    return c.json<ApiResponse>({ ok: false, error: (error as Error).message }, 400);
  }
  const walletIds = [...new Set(account.wallets.map((wallet) => wallet.walletId))];
  const chainFamilies = [...new Set(account.wallets.map((wallet) => wallet.chainFamily))];
  try {
    await db.insert(digitalAssetAccountAggregations).values({
      id: aggregationId,
      tenantId,
      accountId,
      displayName,
      walletAgentIds: walletIds,
      chainFamilies,
      metadata: metadata ?? {},
    });
    await writeAccountAudit({
      tenantId,
      actorType: "api-key",
      action: "account.aggregation.create",
      resourceType: "account_aggregation",
      resourceId: aggregationId,
      metadata: { accountId, walletCount: walletIds.length },
    });
  } catch (error) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: error instanceof Error ? error.message : "Failed to create account aggregation",
      },
      400,
    );
  }

  const aggregation = await serializeAggregation(tenantId, accountId, aggregationId);
  return c.json<ApiResponse>({ ok: true, data: aggregation }, 201);
});

accountRoutes.get("/:accountId/aggregations/:aggregationId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const accountId = c.req.param("accountId");
  const account = await serializeAccount(tenantId, accountId);
  if (!account) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
  const aggregation = await serializeAggregation(tenantId, accountId, c.req.param("aggregationId"));
  if (!aggregation) {
    return c.json<ApiResponse>({ ok: false, error: "Account aggregation not found" }, 404);
  }
  return c.json<ApiResponse>({ ok: true, data: aggregation });
});

accountRoutes.delete("/:accountId/aggregations/:aggregationId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const accountId = c.req.param("accountId");
  const account = await serializeAccount(tenantId, accountId);
  if (!account) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
  const aggregationId = c.req.param("aggregationId");
  const deleted = await db
    .delete(digitalAssetAccountAggregations)
    .where(
      and(
        eq(digitalAssetAccountAggregations.tenantId, tenantId),
        eq(digitalAssetAccountAggregations.accountId, accountId),
        eq(digitalAssetAccountAggregations.id, aggregationId),
      ),
    )
    .returning({ id: digitalAssetAccountAggregations.id });
  if (deleted.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "Account aggregation not found" }, 404);
  }
  await writeAccountAudit({
    tenantId,
    actorType: "api-key",
    action: "account.aggregation.delete",
    resourceType: "account_aggregation",
    resourceId: aggregationId,
    metadata: { accountId },
  });
  return c.json<ApiResponse>({ ok: true, data: { id: aggregationId, deleted: true } });
});

accountRoutes.patch("/:accountId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const accountId = c.req.param("accountId");
  const existing = await serializeAccount(tenantId, accountId);
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);

  const body = await safeJsonParse<AccountMutationBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  const updates: Partial<typeof digitalAssetAccounts.$inferInsert> = {};
  const baseMetadata = existing.metadata ?? {};
  try {
    const displayName = normalizeOptionalDisplayName(body.display_name ?? body.displayName);
    if (displayName !== undefined) updates.displayName = displayName;
    const metadata = normalizeMetadata(body.metadata);
    if (metadata !== undefined) updates.metadata = metadata;
  } catch (error) {
    return c.json<ApiResponse>({ ok: false, error: (error as Error).message }, 400);
  }
  const metadataAuthorizationError = accountAuthorizationInputError(
    updates.metadata as Record<string, unknown> | undefined,
  );
  if (metadataAuthorizationError) {
    return c.json<ApiResponse>({ ok: false, error: metadataAuthorizationError }, 400);
  }

  let memberships: AccountMembershipInput[] | undefined | string;
  const createdWalletAgentIds: string[] = [];
  try {
    memberships = await buildMemberships(tenantId, accountId, body, createdWalletAgentIds);
  } catch (error) {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>({ ok: false, error: (error as Error).message }, 400);
  }
  if (typeof memberships === "string") {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>({ ok: false, error: memberships }, 400);
  }
  const walletAgentIds =
    memberships !== undefined
      ? memberships.map((membership) => membership.walletAgentId)
      : await walletAgentIdsForAccount(tenantId, accountId);
  const authorization = await normalizeAccountAuthorization(
    tenantId,
    body,
    baseMetadata,
    walletAgentIds,
    { validateExisting: memberships !== undefined },
  );
  if (typeof authorization === "string") {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>({ ok: false, error: authorization }, 400);
  }
  if (authorization !== undefined) {
    updates.metadata = mergeAccountAuthorizationMetadata(
      (updates.metadata as Record<string, unknown> | undefined) ?? baseMetadata,
      authorization,
    );
  } else if (updates.metadata !== undefined) {
    updates.metadata = mergeAccountAuthorizationMetadata(
      updates.metadata as Record<string, unknown>,
      accountAuthorizationFromMetadata(baseMetadata),
    );
  }

  try {
    await applyAccountUpdates(tenantId, accountId, updates, memberships);
  } catch (error) {
    await cleanupCreatedAccountWallets(tenantId, createdWalletAgentIds);
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Failed to update account" },
      400,
    );
  }
  await writeAccountAudit({
    tenantId,
    actorType: "api-key",
    action: "account.update",
    resourceType: "account",
    resourceId: accountId,
    metadata: {
      walletCount: memberships?.length ?? existing.wallets.length,
      fields: Object.keys(updates),
    },
  });

  const account = await serializeAccount(tenantId, accountId);
  return c.json<ApiResponse>({ ok: true, data: account });
});

accountRoutes.delete("/:accountId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level authentication required" }, 403);
  }
  const tenantId = c.get("tenantId");
  const accountId = c.req.param("accountId");
  const deleted = await db
    .delete(digitalAssetAccounts)
    .where(and(eq(digitalAssetAccounts.tenantId, tenantId), eq(digitalAssetAccounts.id, accountId)))
    .returning({ id: digitalAssetAccounts.id });
  if (deleted.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
  }
  await writeAccountAudit({
    tenantId,
    actorType: "api-key",
    action: "account.delete",
    resourceType: "account",
    resourceId: accountId,
    metadata: {},
  });
  return c.json<ApiResponse>({ ok: true, data: { id: accountId, deleted: true } });
});
