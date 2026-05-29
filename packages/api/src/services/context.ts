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
  tenantAppClientSecrets,
  tenantAppClients,
  tenants,
  toPolicyRule,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { PolicyEngine } from "@stwd/policy-engine";
import {
  type AgentIdentity,
  type ApiResponse,
  createPriceOracle,
  type PolicyRule,
  type PriceOracle,
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
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const RATE_LIMIT_MAX_REQUESTS = 100;
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
    };
    if (payload.typ === "identity") return null;
    await assertTokenNotRevoked(payload);
    if (payload.userId) {
      const [user] = await getDb()
        .select({ deactivatedAt: users.deactivatedAt })
        .from(users)
        .where(eq(users.id, payload.userId));
      if (!user || user.deactivatedAt) return null;
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

export const db = getDb();

export const vault = new Vault({
  masterPassword: MASTER_PASSWORD,
  rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
  chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
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
  authType?: "api-key" | "app-secret" | "session-jwt" | "agent-token" | "dashboard-jwt";
  requestSignatureVerified?: boolean;
  requestId?: string;
  platformKeyHash?: string;
  platformScopes?: string[];
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

function parseAppId(value: string | undefined | null): { tenantId: string; clientId: string } | null {
  if (!value) return null;
  const index = value.lastIndexOf("/");
  if (index <= 0 || index >= value.length - 1) return null;
  const tenantId = value.slice(0, index);
  const clientId = value.slice(index + 1);
  if (!isValidTenantId(tenantId) || !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(clientId)) return null;
  return { tenantId, clientId };
}

function parseBasicAuth(value: string | undefined | null): { username: string; password: string } | null {
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
