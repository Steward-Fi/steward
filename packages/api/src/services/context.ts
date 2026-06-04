/**
 * Shared application context — singletons and utilities used across route modules.
 *
 * This module centralises the database, vault, policy engine, webhook dispatcher,
 * tenant config cache, and helper functions so that route files don't each
 * re-instantiate them (which would lead to duplicate connections / inconsistent state).
 */

import {
  ACCESS_TOKEN_EXPIRY,
  assertTokenNotRevoked,
  signAccessToken,
  signAgentToken,
  validateApiKey,
  verifyToken,
} from "@stwd/auth";
import {
  conditionSetItems,
  conditionSets,
  getDb,
  inArray,
  policies,
  sessionSigners,
  tenantAppClientSecrets,
  tenantAppClients,
  tenants,
  toPolicyRule,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import {
  type AggregationLookup,
  aggregationLookupFromMap,
  aggregationQueriesForPolicies,
  aggregationQueryKey,
  PolicyEngine,
} from "@stwd/policy-engine";
import { getAggregationSnapshot } from "@stwd/redis";
import {
  type AgentIdentity,
  type ApiResponse,
  createPriceOracle,
  type PolicyRule,
  type PriceOracle,
  type SignRequest,
  type Tenant,
  type TenantConfig,
} from "@stwd/shared";
import { Vault } from "@stwd/vault";
import { WebhookDispatcher } from "@stwd/webhooks";
import { and, eq, gte, sql } from "drizzle-orm";
import type { Context, Next } from "hono";

// ─── Constants ────────────────────────────────────────────────────────────────

export const API_VERSION = process.env.API_VERSION || "0.3.0";
export const DEFAULT_TENANT_ID = "default";

/**
 * Read a positive-integer env override, falling back to a safe default when the
 * variable is unset or malformed. Used for operator-tunable limits so a bad
 * value can never silently disable a guard — it just reverts to the default.
 */
function positiveIntEnv(name: string, fallback: number): number {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return parsed;
}

// Global in-memory request rate limit (Bun entry only). Operator-tunable via env
// so load tests and local e2e suites — which hammer a single socket IP far harder
// than any real client — can raise the ceiling without changing the production
// default (100 requests / 60s per client IP). A missing or invalid override
// falls back to that default, so this can never weaken the guard unintentionally.
export const RATE_LIMIT_WINDOW_MS = positiveIntEnv("STEWARD_RATE_LIMIT_WINDOW_MS", 60_000);
export const RATE_LIMIT_MAX_REQUESTS = positiveIntEnv("STEWARD_RATE_LIMIT_MAX_REQUESTS", 100);
export const AGENT_TOKEN_EXPIRY = process.env.AGENT_TOKEN_EXPIRY || "30d";
export const isWorkersRuntime =
  process.env.STEWARD_RUNTIME === "workers" ||
  (typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers");

// ─── JWT helpers ──────────────────────────────────────────────────────────────

/**
 * User access token TTL. Refresh tokens (30d) handle long-lived sessions.
 */
export const JWT_EXPIRY = ACCESS_TOKEN_EXPIRY;
export const AGENT_SCOPE = "agent";
export const PROXY_SCOPE = "api:proxy";

export function normalizeAgentTokenScopes(scopes?: string[]): string[] {
  if (!scopes || scopes.length === 0) return [AGENT_SCOPE];
  const normalized = new Set<string>();
  for (const scope of scopes ?? []) {
    if (typeof scope === "string" && scope.trim()) {
      normalized.add(scope.trim());
    }
  }
  return normalized.size > 0 ? [...normalized] : [AGENT_SCOPE];
}

export function parseAgentTokenScopes(value: unknown): string[] | null {
  if (value === undefined || value === null || value === "") {
    return [AGENT_SCOPE];
  }

  const requested = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(",")
      : null;

  if (!requested || !requested.every((scope) => typeof scope === "string")) return null;

  const scopes = normalizeAgentTokenScopes(requested.map((scope) => scope.trim()).filter(Boolean));
  return scopes.every((scope) => scope === AGENT_SCOPE || scope === PROXY_SCOPE) ? scopes : null;
}

export function hasAgentTokenScope(
  scopes: readonly string[] | undefined,
  required = AGENT_SCOPE,
): boolean {
  return Boolean(scopes?.includes(required));
}

export function setNoStoreHeaders(c: Pick<Context, "header">): void {
  c.header("Cache-Control", "no-store, max-age=0");
  c.header("Pragma", "no-cache");
  c.header("Expires", "0");
}

export async function createSessionToken(address: string, tenantId: string): Promise<string> {
  return signAccessToken({ address, tenantId }, JWT_EXPIRY);
}

export async function createAgentToken(
  agentId: string,
  tenantId: string,
  expiresIn?: string,
  scopes?: string[],
): Promise<string> {
  const tokenScopes = normalizeAgentTokenScopes(scopes);
  return signAgentToken(
    { agentId, tenantId, scopes: tokenScopes },
    expiresIn || AGENT_TOKEN_EXPIRY,
  );
}

export async function verifySessionToken(token: string) {
  try {
    const payload = (await verifyToken(token)) as {
      address: string;
      tenantId: string;
      agentId?: string;
      scope?: string;
      scopes?: string[];
      typ?: string;
      userId?: string;
      email?: string;
      mfaVerifiedAt?: number;
      mfaMethod?: string;
      jti?: string;
      exp?: number;
    };
    if (payload.typ === "identity") return null;
    await assertTokenNotRevoked(payload);
    if (payload.userId) {
      const [user] = await getDb()
        .select({
          deactivatedAt: users.deactivatedAt,
          isGuest: users.isGuest,
          guestExpiresAt: users.guestExpiresAt,
        })
        .from(users)
        .where(eq(users.id, payload.userId));
      if (!user || user.deactivatedAt) return null;
      // Fail-closed guest expiry: enforce the guest's hard expiry against the
      // authoritative DB column, not just the access-token `exp`. A refreshed
      // access token (or one minted with a longer TTL) is still rejected once
      // the guest window has elapsed. Full accounts have guestExpiresAt = null.
      if (user.isGuest && user.guestExpiresAt && user.guestExpiresAt.getTime() <= Date.now()) {
        return null;
      }
      if (payload.tenantId) {
        const [membership] = await getDb()
          .select({ role: userTenants.role })
          .from(userTenants)
          .where(
            and(eq(userTenants.userId, payload.userId), eq(userTenants.tenantId, payload.tenantId)),
          );
        if (!membership) return null;
      }
    }
    return payload;
  } catch {
    return null;
  }
}

// ─── SIWE nonce store ─────────────────────────────────────────────────────────

export const nonceStore = new Map<string, { nonce: string; expiresAt: number }>();

export const nonceCleanupTimer = isWorkersRuntime
  ? undefined
  : setInterval(
      () => {
        const now = Date.now();
        for (const [key, entry] of nonceStore.entries()) {
          if (entry.expiresAt <= now) nonceStore.delete(key);
        }
      },
      5 * 60 * 1000,
    );

// ─── Input validation helpers ─────────────────────────────────────────────────

const AGENT_ID_RE = /^[a-zA-Z0-9_\-.:]{1,128}$/;
const TENANT_ID_RE = /^[a-zA-Z0-9_\-.:]{1,64}$/;

export function isValidAgentId(id: unknown): id is string {
  return typeof id === "string" && AGENT_ID_RE.test(id);
}

export function isValidTenantId(id: unknown): id is string {
  return typeof id === "string" && TENANT_ID_RE.test(id);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

export function isValidAddress(value: unknown): boolean {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

export function isValidSolanaAddress(value: unknown): boolean {
  return typeof value === "string" && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value);
}

export function isValidAnyAddress(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return value.startsWith("0x") ? isValidAddress(value) : isValidSolanaAddress(value);
}

export async function safeJsonParse<T>(c: Context): Promise<T | null> {
  try {
    return await c.req.json<T>();
  } catch {
    return null;
  }
}

export function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    const safe = ["already exists", "not found", "Unsupported chain"];
    if (safe.some((s) => error.message.includes(s))) return error.message;
  }
  return "Internal server error";
}

export function isRpcError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const msg = error.message.toLowerCase();
  const rpcIndicators = [
    "insufficient funds",
    "insufficient balance",
    "nonce too low",
    "nonce too high",
    "gas too low",
    "gas limit",
    "underpriced",
    "replacement transaction",
    "exceeds block gas limit",
    "execution reverted",
    "out of gas",
    "invalid sender",
    "invalid signature",
    "account not found",
    "blockhash not found",
    "transaction simulation failed",
    "instruction error",
    "custom program error",
    "rpc error",
    "failed to send transaction",
    "transaction failed",
    "0x",
  ];
  return rpcIndicators.some((indicator) => msg.includes(indicator));
}

export function extractRpcErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    const innerMatch = error.message.match(/message["\s:]+([^"]+)/i);
    if (innerMatch) return innerMatch[1].trim();
    return error.message;
  }
  return "RPC error";
}

// ─── Environment ──────────────────────────────────────────────────────────────

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const isPGLiteRuntime =
  process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true";

export const DATABASE_URL =
  process.env.DATABASE_URL?.trim() || (isPGLiteRuntime ? "" : requireEnv("DATABASE_URL"));
export const MASTER_PASSWORD = requireEnv("STEWARD_MASTER_PASSWORD");

if (process.env.DATABASE_URL) {
  process.env.DATABASE_URL = DATABASE_URL;
}

// ─── Singletons ───────────────────────────────────────────────────────────────

// `db` is a late-bound Proxy over getDb() rather than a captured handle.
//
// In production this is behaviorally identical to `const db = getDb()`:
// getDb() memoizes a single `globalDb` connection on first call and returns
// that same handle on every subsequent call, so each property access resolves
// to the one real connection.
//
// The reason for the Proxy is the test harness: the api suite runs all ~135
// test files in ONE `bun test` process, and Bun shares the module registry, so
// context.ts evaluates exactly once — a captured `const db = getDb()` would
// freeze whichever file imported a route first and route every later file's
// writes to that stale db. Resolving getDb() per access instead picks up each
// file's own setPGLiteOverride(). Methods are bound to the live handle so
// Drizzle's internal `this` (private session/dialect fields) stays intact.
type DbHandle = ReturnType<typeof getDb>;
export const db: DbHandle = new Proxy({} as DbHandle, {
  get(_target, property) {
    const active = getDb() as unknown as Record<PropertyKey, unknown>;
    const value = active[property];
    return typeof value === "function"
      ? (value as (...args: unknown[]) => unknown).bind(active)
      : value;
  },
});

// `vault` is a late-bound Proxy resolving the Vault for the CURRENT master
// password, memoized per password. In production STEWARD_MASTER_PASSWORD is
// fixed before this module loads, so exactly one Vault is ever built and every
// access returns it — behaviorally identical to `const vault = new Vault(...)`.
//
// In the single-process api test suite, individual files set their own
// STEWARD_MASTER_PASSWORD in beforeAll, and a few construct their OWN Vault with
// that password to seal keys directly into their per-file PGLite db. A captured
// singleton would have frozen the first (preload) password, so the route-level
// vault could not decrypt keys those files sealed under a different password —
// surfacing as AES-GCM "Unsupported state or unable to authenticate data". A
// per-password memo keeps the route vault in lockstep with whatever password
// sealed each key. MASTER_PASSWORD (captured at import) is the fallback when the
// env var is transiently unset (e.g. another file's afterAll deleted it).
const vaultsByPassword = new Map<string, Vault>();
function activeVault(): Vault {
  const masterPassword = process.env.STEWARD_MASTER_PASSWORD?.trim() || MASTER_PASSWORD;
  let resolved = vaultsByPassword.get(masterPassword);
  if (!resolved) {
    resolved = new Vault({
      masterPassword,
      rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
      chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
    });
    vaultsByPassword.set(masterPassword, resolved);
  }
  return resolved;
}
export const vault: Vault = new Proxy({} as Vault, {
  get(_target, property) {
    const active = activeVault() as unknown as Record<PropertyKey, unknown>;
    const value = active[property];
    return typeof value === "function"
      ? (value as (...args: unknown[]) => unknown).bind(active)
      : value;
  },
  // Forward assignments to the live instance. Production never mutates the
  // vault; this exists so tests that monkeypatch a method (e.g.
  // `context.vault.getBalance = mock`) and restore it in a `finally` land on
  // the same per-password instance the get trap resolves — without a set trap
  // the assignment would silently write to the empty Proxy target and the get
  // trap would keep returning the real method.
  set(_target, property, value) {
    (activeVault() as unknown as Record<PropertyKey, unknown>)[property] = value;
    return true;
  },
});

export const policyEngine = new PolicyEngine();
export const priceOracle: PriceOracle = createPriceOracle({
  cacheTtlMs: 60_000,
});
export const webhookDispatcher = new WebhookDispatcher();

// ─── Tenant config cache ──────────────────────────────────────────────────────

const defaultTenantConfig: TenantConfig = {
  id: DEFAULT_TENANT_ID,
  name: "Default Tenant",
};

export const tenantConfigs = new Map<string, TenantConfig>([
  [defaultTenantConfig.id, defaultTenantConfig],
]);

export const defaultTenantReady = db
  .insert(tenants)
  .values({
    id: DEFAULT_TENANT_ID,
    name: "Default Tenant",
    apiKeyHash: process.env.STEWARD_DEFAULT_TENANT_KEY || "",
  })
  .onConflictDoNothing();

// ─── App variable types ───────────────────────────────────────────────────────

export type AuthenticatedPrincipal = {
  type: "tenant" | "user" | "agent";
  id: string;
};

export type AppVariables = {
  tenant: Tenant;
  tenantConfig: TenantConfig;
  tenantId: string;
  userId?: string;
  tenantRole?: string;
  sessionMfaVerifiedAt?: number;
  sessionMfaMethod?: string;
  agentScope?: string;
  agentScopes?: string[];
  agentSubject?: string;
  authType?: "api-key" | "app-secret" | "session-jwt" | "agent-token" | "dashboard-jwt";
  requestSignatureVerified?: boolean;
  requestId?: string;
  platformKeyHash?: string;
  platformScopes?: string[];
  agentPolicyIds?: string[];
};

// ─── Shared query helpers ─────────────────────────────────────────────────────

export function getTenantPayload(tenant: Tenant): Omit<Tenant, "apiKeyHash"> & TenantConfig {
  const config = tenantConfigs.get(tenant.id);
  const { apiKeyHash: _apiKeyHash, ...safeTenant } = tenant;
  return {
    ...safeTenant,
    name: config?.name || tenant.name,
    webhookUrl: config?.webhookUrl,
    defaultPolicies: config?.defaultPolicies,
  };
}

function parseAppId(
  value: string | undefined | null,
): { tenantId: string; clientId: string } | null {
  if (!value) return null;
  const index = value.lastIndexOf("/");
  if (index <= 0 || index >= value.length - 1) return null;
  const tenantId = value.slice(0, index);
  const clientId = value.slice(index + 1);
  if (!isValidTenantId(tenantId) || !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(clientId)) return null;
  return { tenantId, clientId };
}

function parseBasicAuth(
  value: string | undefined | null,
): { username: string; password: string } | null {
  if (!value?.startsWith("Basic ")) return null;
  let decoded = "";
  try {
    decoded = atob(value.slice(6));
  } catch {
    return null;
  }
  const separator = decoded.indexOf(":");
  if (separator <= 0) return null;
  return {
    username: decoded.slice(0, separator),
    password: decoded.slice(separator + 1),
  };
}

export async function findTenant(tenantId: string): Promise<Tenant | undefined> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.id, tenantId));
  return tenant;
}

async function findUserTenantMembership(userId: string, tenantId: string) {
  const [membership] = await db
    .select({ role: userTenants.role })
    .from(userTenants)
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));
  return membership ?? null;
}

export async function ensureAgentForTenant(
  tenantId: string,
  agentId: string,
): Promise<AgentIdentity | undefined> {
  return vault.getAgent(tenantId, agentId);
}

export async function getPolicySet(tenantId: string, agentId: string): Promise<PolicyRule[]> {
  const storedPolicies = await db.select().from(policies).where(eq(policies.agentId, agentId));

  if (storedPolicies.length > 0) return storedPolicies.map(toPolicyRule);
  return tenantConfigs.get(tenantId)?.defaultPolicies || [];
}

export async function getScopedPolicySet(
  tenantId: string,
  agentId: string,
  policyIds: readonly string[] | undefined,
): Promise<PolicyRule[]> {
  if (!policyIds || policyIds.length === 0) return getPolicySet(tenantId, agentId);

  const uniquePolicyIds = [...new Set(policyIds.filter((id) => typeof id === "string" && id))];
  if (uniquePolicyIds.length === 0) return [];

  const storedPolicies = await db
    .select()
    .from(policies)
    .where(and(eq(policies.agentId, agentId), inArray(policies.id, uniquePolicyIds)));

  return storedPolicies.map(toPolicyRule);
}

export async function loadConditionSetsForPolicies(
  tenantId: string,
  policySet: PolicyRule[],
): Promise<Record<string, string[]>> {
  const ids = getConditionSetIdsFromPolicies(policySet);

  if (ids.length === 0) return {};

  const existingSets = await db
    .select({ id: conditionSets.id })
    .from(conditionSets)
    .where(and(eq(conditionSets.tenantId, tenantId), inArray(conditionSets.id, ids)));
  const existingIds = existingSets.map((row) => row.id);

  if (existingIds.length === 0) return {};

  const rows = await db
    .select({
      conditionSetId: conditionSetItems.conditionSetId,
      value: conditionSetItems.value,
    })
    .from(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.tenantId, tenantId),
        inArray(conditionSetItems.conditionSetId, existingIds),
      ),
    );

  const loaded: Record<string, string[]> = {};
  for (const id of existingIds) loaded[id] = [];
  for (const row of rows) loaded[row.conditionSetId].push(row.value);
  return loaded;
}

export function getConditionSetIdsFromPolicies(policySet: PolicyRule[]): string[] {
  return Array.from(
    new Set(
      policySet
        .filter((policy) => policy.type === "condition-set")
        .map((policy) => policy.config.conditionSetId)
        .filter((id): id is string => typeof id === "string" && id.length > 0),
    ),
  );
}

export async function getConditionSetReferenceValidationError(
  tenantId: string,
  policySet: PolicyRule[],
): Promise<string | null> {
  const ids = getConditionSetIdsFromPolicies(policySet);
  if (ids.length === 0) return null;

  const existingRows = await db
    .select({ id: conditionSets.id })
    .from(conditionSets)
    .where(and(eq(conditionSets.tenantId, tenantId), inArray(conditionSets.id, ids)));
  const existingIds = new Set(existingRows.map((row) => row.id));
  const missingIds = ids.filter((id) => !existingIds.has(id));

  if (missingIds.length > 0) {
    return `condition-set.conditionSetId not found for tenant: ${missingIds.join(", ")}`;
  }

  return null;
}

/**
 * Materialise the rolling-aggregate lookup for a policy set's `aggregation`
 * conditions. Snapshots are computed from the authoritative Redis tracker —
 * never from caller-supplied request fields — and exposed to the engine as a
 * synchronous lookup. Any snapshot that cannot be sourced is simply omitted
 * from the map, which makes the evaluator fail closed (deny) for that
 * condition.
 *
 * Callers wire the returned lookup onto the `aggregations` field of the
 * evaluation context. The recording side (recordAggregationEvent) must be
 * driven on transaction commit, inside the same per-agent serialization window
 * used for spend caps, so the aggregate cannot be raced.
 */
export async function loadAggregationsForPolicies(
  policySet: PolicyRule[],
  request: SignRequest,
  now: number = Date.now(),
): Promise<AggregationLookup> {
  const queries = aggregationQueriesForPolicies(policySet, request);
  if (queries.length === 0) return aggregationLookupFromMap(new Map());

  const snapshots = new Map<string, bigint>();
  await Promise.all(
    queries.map(async (query) => {
      const value = await getAggregationSnapshot(
        {
          agentId: query.agentId,
          metric: query.metric,
          windowSeconds: query.windowSeconds,
          scope: query.scope,
          scopeKey: query.scopeKey,
        },
        now,
      );
      // null → unavailable; leave it out so the evaluator denies that condition.
      if (value !== null) snapshots.set(aggregationQueryKey(query), value);
    }),
  );

  return aggregationLookupFromMap(snapshots);
}

export async function getTransactionStats(agentId: string) {
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 3600_000);
  const oneDayAgo = new Date(now.getTime() - 86400_000);
  const oneWeekAgo = new Date(now.getTime() - 604800_000);

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
        gte(transactions.createdAt, oneWeekAgo),
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

// ─── Auth middleware ──────────────────────────────────────────────────────────

export async function tenantAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
  options?: { requireTenantMatch?: string },
) {
  await defaultTenantReady;

  const authHeader = c.req.header("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    const payload = await verifySessionToken(token);
    if (payload?.tenantId) {
      const headerTenant = c.req.header("X-Steward-Tenant");
      if (headerTenant && headerTenant !== payload.tenantId) {
        return c.json<ApiResponse>({ ok: false, error: "Tenant header does not match token" }, 403);
      }
      const jwtTenant = await findTenant(payload.tenantId);
      if (jwtTenant) {
        if (options?.requireTenantMatch && payload.tenantId !== options.requireTenantMatch) {
          return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
        }

        const isAgentToken = payload.scope === "agent" && typeof payload.agentId === "string";
        if (isAgentToken) {
          const agent = await ensureAgentForTenant(payload.tenantId, payload.agentId as string);
          if (!agent) {
            return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 403);
          }
          if (typeof payload.jti === "string" && payload.jti) {
            const [sessionSigner] = await db
              .select({
                id: sessionSigners.id,
                tenantId: sessionSigners.tenantId,
                agentId: sessionSigners.agentId,
                policyIds: sessionSigners.policyIds,
                expiresAt: sessionSigners.expiresAt,
                revokedAt: sessionSigners.revokedAt,
              })
              .from(sessionSigners)
              .where(eq(sessionSigners.jti, payload.jti));

            if (sessionSigner) {
              if (
                sessionSigner.tenantId !== payload.tenantId ||
                sessionSigner.agentId !== payload.agentId
              ) {
                return c.json<ApiResponse>(
                  { ok: false, error: "Session signer does not match token subject" },
                  403,
                );
              }
              if (sessionSigner.revokedAt || sessionSigner.expiresAt.getTime() <= Date.now()) {
                return c.json<ApiResponse>(
                  { ok: false, error: "Session signer is revoked or expired" },
                  401,
                );
              }
              if (sessionSigner.policyIds.length > 0) {
                c.set("agentPolicyIds", sessionSigner.policyIds);
              }
              try {
                await db
                  .update(sessionSigners)
                  .set({ lastUsedAt: new Date() })
                  .where(eq(sessionSigners.id, sessionSigner.id));
              } catch (err) {
                console.error(
                  `[session-signer] failed to update lastUsedAt for ${sessionSigner.id}:`,
                  err,
                );
              }
            }
          }
        } else {
          if (!payload.userId) {
            return c.json<ApiResponse>(
              { ok: false, error: "User session token is missing userId" },
              401,
            );
          }

          const membership = await findUserTenantMembership(payload.userId, payload.tenantId);
          if (!membership) {
            return c.json<ApiResponse>({ ok: false, error: "Not a member of this tenant" }, 403);
          }
          c.set("tenantRole", membership.role);
        }

        c.set("tenantId", payload.tenantId);
        c.set("tenant", jwtTenant);
        c.set(
          "tenantConfig",
          tenantConfigs.get(payload.tenantId) || {
            id: jwtTenant.id,
            name: jwtTenant.name,
          },
        );

        if (payload.userId) c.set("userId", payload.userId);
        if (isAgentToken) {
          c.set("agentScope", payload.agentId);
          c.set("agentScopes", normalizeAgentTokenScopes(payload.scopes));
          const tokenSubject = (payload as { sub?: unknown }).sub;
          c.set(
            "agentSubject",
            typeof tokenSubject === "string" ? tokenSubject : `agent:${payload.agentId}`,
          );
          c.set("authType", "agent-token");
        } else {
          if (typeof payload.mfaVerifiedAt === "number") {
            c.set("sessionMfaVerifiedAt", payload.mfaVerifiedAt);
          }
          if (typeof payload.mfaMethod === "string") {
            c.set("sessionMfaMethod", payload.mfaMethod);
          }
          c.set("authType", "session-jwt");
        }
        return next();
      }
    }
  }

  const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
  const appId = c.req.header("X-Steward-App-Id");
  const basic = parseBasicAuth(authHeader);
  if (appId || basic) {
    if (!appId || !basic) {
      return c.json<ApiResponse>(
        { ok: false, error: "App secret auth requires Basic auth and X-Steward-App-Id" },
        401,
      );
    }
    if (basic.username !== appId) {
      return c.json<ApiResponse>({ ok: false, error: "App id mismatch" }, 403);
    }
    const parsedAppId = parseAppId(appId);
    if (!parsedAppId) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid app id" }, 400);
    }
    if (options?.requireTenantMatch && parsedAppId.tenantId !== options.requireTenantMatch) {
      return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
    }
    const appTenant = await findTenant(parsedAppId.tenantId);
    if (!appTenant) return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
    const now = new Date();
    const rows = await getDb()
      .select({
        secretHash: tenantAppClientSecrets.secretHash,
        status: tenantAppClientSecrets.status,
        expiresAt: tenantAppClientSecrets.expiresAt,
        revokedAt: tenantAppClientSecrets.revokedAt,
        clientEnabled: tenantAppClients.enabled,
      })
      .from(tenantAppClientSecrets)
      .innerJoin(
        tenantAppClients,
        and(
          eq(tenantAppClients.tenantId, tenantAppClientSecrets.tenantId),
          eq(tenantAppClients.id, tenantAppClientSecrets.clientId),
        ),
      )
      .where(
        and(
          eq(tenantAppClientSecrets.tenantId, parsedAppId.tenantId),
          eq(tenantAppClientSecrets.clientId, parsedAppId.clientId),
          inArray(tenantAppClientSecrets.status, ["active", "retiring"]),
          eq(tenantAppClients.enabled, true),
        ),
      );

    const match = rows.some((row) => {
      if (!row.clientEnabled || row.revokedAt) return false;
      if (row.expiresAt && row.expiresAt <= now) return false;
      return validateApiKey(basic.password, row.secretHash);
    });
    if (!match) return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);

    c.set("tenantId", parsedAppId.tenantId);
    c.set("tenant", appTenant);
    c.set(
      "tenantConfig",
      tenantConfigs.get(parsedAppId.tenantId) || { id: appTenant.id, name: appTenant.name },
    );
    c.set("authType", "app-secret");
    await next();
    return;
  }

  const tenant = await findTenant(tenantId);

  if (!tenant) return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);

  if (options?.requireTenantMatch && tenantId !== options.requireTenantMatch) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  const apiKey = c.req.header("X-Steward-Key") || "";

  if (!tenant.apiKeyHash || !validateApiKey(apiKey, tenant.apiKeyHash)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  c.set("tenantId", tenantId);
  c.set("tenant", tenant);
  c.set("tenantConfig", tenantConfigs.get(tenantId) || { id: tenant.id, name: tenant.name });
  c.set("authType", "api-key");

  await next();
}

export async function sessionAuth(c: Context<{ Variables: AppVariables }>, next: Next) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json<ApiResponse>({ ok: false, error: "Authorization header required" }, 401);
  }

  const token = authHeader.slice(7);
  const payload = await verifySessionToken(token);
  if (!payload) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired session token" }, 401);
  }

  const tenant = await findTenant(payload.tenantId);
  if (!tenant) return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);

  c.set("tenantId", payload.tenantId);
  c.set("tenant", tenant);
  c.set(
    "tenantConfig",
    tenantConfigs.get(payload.tenantId) || { id: tenant.id, name: tenant.name },
  );

  await next();
}

export function getAuthenticatedPrincipal(
  c: Context<{ Variables: AppVariables }>,
): AuthenticatedPrincipal {
  const authType = c.get("authType");
  if (authType === "agent-token") {
    return { type: "agent", id: c.get("agentScope") || c.req.param("agentId") || "unknown" };
  }

  const userId = c.get("userId");
  if ((authType === "session-jwt" || authType === "dashboard-jwt") && userId) {
    return { type: "user", id: userId };
  }

  return { type: "tenant", id: c.get("tenantId") || DEFAULT_TENANT_ID };
}

export function isSameAuthenticatedPrincipal(
  left: { type: string; id: string },
  right: { type: string; id: string },
): boolean {
  return left.type === right.type && left.id === right.id;
}

export function formatAuthenticatedPrincipal(principal: AuthenticatedPrincipal): string {
  return `${principal.type}:${principal.id}`;
}

export function requireAgentAccess(c: Context<{ Variables: AppVariables }>): boolean {
  const agentScope = c.get("agentScope");
  if (agentScope) {
    return agentScope === c.req.param("agentId") && hasAgentTokenScope(c.get("agentScopes"));
  }
  return requireTenantLevel(c);
}

export function requireTenantLevel(c: Context<{ Variables: AppVariables }>): boolean {
  const authType = c.get("authType");
  if (authType === "api-key") return true;
  if (authType === "agent-token") return false;

  const tenantRole = c.get("tenantRole");
  return tenantRole === "owner" || tenantRole === "admin";
}

/**
 * dashboardAuthMiddleware
 * Accepts a session JWT (Bearer token) issued by the auth routes.
 * Extracts userId and tenantId, looks up the tenant, and sets context variables
 * so dashboard routes can make authenticated API calls on behalf of the user.
 *
 * The dashboard is user-centric (not API-key-centric) so only session JWTs are
 * accepted here — no API key fallback.
 */
export async function dashboardAuthMiddleware(c: Context<{ Variables: AppVariables }>, next: Next) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json<ApiResponse>({ ok: false, error: "Authorization header required" }, 401);
  }

  const token = authHeader.slice(7);
  const payload = await verifySessionToken(token);

  if (!payload?.tenantId) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired session token" }, 401);
  }
  const headerTenant = c.req.header("X-Steward-Tenant");
  if (headerTenant && headerTenant !== payload.tenantId) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant header does not match token" }, 403);
  }

  if (payload.scope === "agent" || payload.agentId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Dashboard routes do not accept agent tokens" },
      403,
    );
  }

  if (!payload.userId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Dashboard routes require a user session token" },
      401,
    );
  }

  const tenant = await findTenant(payload.tenantId);
  if (!tenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  }

  const membership = await findUserTenantMembership(payload.userId, payload.tenantId);
  if (!membership) {
    return c.json<ApiResponse>({ ok: false, error: "Not a member of this tenant" }, 403);
  }

  c.set("tenantId", payload.tenantId);
  c.set("tenant", tenant);
  c.set(
    "tenantConfig",
    tenantConfigs.get(payload.tenantId) || { id: tenant.id, name: tenant.name },
  );
  c.set("authType", "dashboard-jwt");
  c.set("tenantRole", membership.role);
  if (payload.userId) c.set("userId", payload.userId);
  if (typeof payload.mfaVerifiedAt === "number") {
    c.set("sessionMfaVerifiedAt", payload.mfaVerifiedAt);
  }
  if (typeof payload.mfaMethod === "string") {
    c.set("sessionMfaMethod", payload.mfaMethod);
  }

  return next();
}

// Re-export drizzle schemas used in route modules
export {
  agentKeyQuorums,
  agentSigners,
  agents,
  agentWallets,
  approvalQueue,
  autoApprovalRules,
  conditionSetItems,
  conditionSets,
  encryptedChainKeys,
  encryptedKeys,
  intents,
  policies,
  tenants,
  toPolicyRule,
  toSignRequest,
  toTxRecord,
  transactions,
  webhookConfigs,
  webhookDeliveries,
} from "@stwd/db";

export type {
  AgentBalance,
  AgentIdentity,
  ApiResponse,
  PolicyRule,
  RpcRequest,
  RpcResponse,
  SignRequest,
  SignSolanaTransactionRequest,
  SignTypedDataRequest,
  Tenant,
  TenantConfig,
} from "@stwd/shared";
