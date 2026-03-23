import { and, eq, gte, sql } from "drizzle-orm";
import { Hono, type Context, type Next } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { SignJWT, jwtVerify } from "jose";
import { generateNonce, SiweMessage } from "siwe";

import { generateApiKey, hashApiKey, validateApiKey } from "@stwd/auth";
import {
  agents,
  approvalQueue,
  closeDb,
  getDb,
  policies,
  tenants,
  toPolicyRule,
  toSignRequest,
  toTxRecord,
  transactions,
} from "@stwd/db";
import { PolicyEngine } from "@stwd/policy-engine";
import type {
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
import { Vault } from "@stwd/vault";
import { WebhookDispatcher } from "@stwd/webhooks";

const API_VERSION = process.env.API_VERSION || "0.1.0";
const startTime = Date.now();
const PORT = parseInt(process.env.PORT || "3200", 10);
const DEFAULT_TENANT_ID = "default";
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 100;

// ─── SIWE nonce store & JWT helpers ────────────────────────────────────────────

const nonceStore = new Map<string, { nonce: string; expiresAt: number }>();

// JWT secret: prefer dedicated STEWARD_JWT_SECRET, fall back to master password with warning
const jwtSecretSource = process.env.STEWARD_JWT_SECRET || process.env.STEWARD_MASTER_PASSWORD;
if (!process.env.STEWARD_JWT_SECRET && process.env.STEWARD_MASTER_PASSWORD) {
  console.warn("⚠️ STEWARD_JWT_SECRET not set, falling back to master password. Set a separate JWT secret for production.");
}
const JWT_SECRET = new TextEncoder().encode(jwtSecretSource || "dev-secret");
const JWT_ISSUER = "steward";
const JWT_EXPIRY = "24h";
const AGENT_TOKEN_EXPIRY = process.env.AGENT_TOKEN_EXPIRY || "30d";

async function createSessionToken(
  address: string,
  tenantId: string
): Promise<string> {
  return new SignJWT({ address, tenantId })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setExpirationTime(JWT_EXPIRY)
    .sign(JWT_SECRET);
}

/**
 * Create an agent-scoped JWT. The token carries the agentId, tenantId,
 * and a `scope: "agent"` claim so middleware can distinguish it from
 * session JWTs and restrict access to that agent's own resources.
 */
async function createAgentToken(
  agentId: string,
  tenantId: string,
  expiresIn?: string
): Promise<string> {
  return new SignJWT({ agentId, tenantId, scope: "agent" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setExpirationTime(expiresIn || AGENT_TOKEN_EXPIRY)
    .sign(JWT_SECRET);
}

async function verifySessionToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
    });
    return payload as { address: string; tenantId: string; agentId?: string; scope?: string };
  } catch {
    return null;
  }
}

// Clean up expired nonces every 5 minutes
const nonceCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of nonceStore.entries()) {
    if (entry.expiresAt <= now) {
      nonceStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

// ─── Input validation helpers ─────────────────────────────────────────────────

const AGENT_ID_RE = /^[a-zA-Z0-9_\-.:]{1,128}$/;
const TENANT_ID_RE = /^[a-zA-Z0-9_\-.:]{1,64}$/;

function isValidAgentId(id: unknown): id is string {
  return typeof id === "string" && AGENT_ID_RE.test(id);
}

function isValidTenantId(id: unknown): id is string {
  return typeof id === "string" && TENANT_ID_RE.test(id);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isValidAddress(value: unknown): boolean {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

/**
 * Validate a Solana address: base58 encoding, 32–44 characters.
 * Base58 excludes 0 (zero), O (capital o), I (capital i), l (lowercase L).
 */
function isValidSolanaAddress(value: unknown): boolean {
  return typeof value === "string" && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value);
}

/**
 * Validate an address that may be either EVM or Solana.
 * Detects by prefix: "0x" → EVM, otherwise → Solana base58.
 */
function isValidAnyAddress(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return value.startsWith("0x") ? isValidAddress(value) : isValidSolanaAddress(value);
}

/** Safely parse JSON body, returning null on failure instead of throwing. */
async function safeJsonParse<T>(c: Context): Promise<T | null> {
  try {
    return await c.req.json<T>();
  } catch {
    return null;
  }
}

/** Mask internal error details for 500 responses — log the real error server-side. */
function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Allow known, safe error messages through
    const safe = [
      "already exists",
      "not found",
      "Unsupported chain",
    ];
    if (safe.some((s) => error.message.includes(s))) {
      return error.message;
    }
  }
  return "Internal server error";
}

/**
 * Check if an error is an RPC/blockchain error (as opposed to internal server error).
 * RPC errors should be passed through with their actual message.
 */
function isRpcError(error: unknown): boolean {
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
    "0x", // Solidity error selectors
  ];
  return rpcIndicators.some((indicator) => msg.includes(indicator));
}

/**
 * Extract a user-friendly message from an RPC error.
 */
function extractRpcErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Try to extract inner error message if present
    const innerMatch = error.message.match(/message["\s:]+([^"]+)/i);
    if (innerMatch) {
      return innerMatch[1].trim();
    }
    return error.message;
  }
  return "RPC error";
}

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

const DATABASE_URL = requireEnv("DATABASE_URL");
const MASTER_PASSWORD = requireEnv("STEWARD_MASTER_PASSWORD");

if (!Number.isInteger(PORT) || PORT <= 0) {
  throw new Error("PORT must be a positive integer");
}

process.env.DATABASE_URL = DATABASE_URL;

const db = getDb();
const vault = new Vault({
  masterPassword: MASTER_PASSWORD,
  rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
  chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
});
const policyEngine = new PolicyEngine();
const webhookDispatcher = new WebhookDispatcher();

const defaultTenantConfig: TenantConfig = {
  id: DEFAULT_TENANT_ID,
  name: "Default Tenant",
};

const tenantConfigs = new Map<string, TenantConfig>([[defaultTenantConfig.id, defaultTenantConfig]]);

const defaultTenantReady = db
  .insert(tenants)
  .values({
    id: DEFAULT_TENANT_ID,
    name: "Default Tenant",
    apiKeyHash: process.env.STEWARD_DEFAULT_TENANT_KEY || "",
  })
  .onConflictDoNothing();

type AppVariables = {
  tenant: Tenant;
  tenantConfig: TenantConfig;
  tenantId: string;
  agentScope?: string;   // agentId from agent-scoped JWT, if present
  authType?: "api-key" | "session-jwt" | "agent-token";
};

const app = new Hono<{ Variables: AppVariables }>();
const requestLog = new Map<string, { count: number; resetAt: number }>();
let isShuttingDown = false;

// ─── Global error handler — catches unhandled throws (bad JSON, etc.) ─────────
app.onError((err, c) => {
  const requestId = c.get("requestId") || "unknown";

  // JSON parse errors from c.req.json()
  if (err instanceof SyntaxError || err.message?.includes("JSON")) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  console.error(`[${requestId}] Unhandled API error:`, err);
  return c.json<ApiResponse>({ ok: false, error: "Internal server error" }, 500);
});

// ─── 404 fallback ─────────────────────────────────────────────────────────────
app.notFound((c) =>
  c.json<ApiResponse>({ ok: false, error: `Not found: ${c.req.method} ${c.req.path}` }, 404)
);

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "X-Steward-Tenant", "X-Steward-Key", "X-Steward-Platform-Key", "Authorization"],
  exposeHeaders: ["Content-Length", "X-Request-Id"],
  maxAge: 86400,
}));
app.use("*", logger());

// ─── Request correlation IDs ──────────────────────────────────────────────────
app.use("*", correlationId);

// ─── Body size limit (1MB) ────────────────────────────────────────────────────
app.use("*", bodyLimit({
  maxSize: 1024 * 1024, // 1MB
  onError: (c) => c.json<ApiResponse>({ ok: false, error: "Request body too large (max 1MB)" }, 413),
}));
app.use("*", async (c, next) => {
  if (c.req.path === "/health") {
    return next();
  }

  if (isShuttingDown) {
    return c.json<ApiResponse>({ ok: false, error: "Server is shutting down" }, 503);
  }

  const forwardedFor = c.req.header("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || c.req.header("x-real-ip") || "unknown";
  const now = Date.now();
  const current = requestLog.get(ip);

  if (!current || current.resetAt <= now) {
    requestLog.set(ip, {
      count: 1,
      resetAt: now + RATE_LIMIT_WINDOW_MS,
    });
    return next();
  }

  if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
    c.header("Retry-After", Math.ceil((current.resetAt - now) / 1000).toString());
    return c.json<ApiResponse>({ ok: false, error: "Rate limit exceeded" }, 429);
  }

  current.count += 1;
  requestLog.set(ip, current);

  return next();
});

const requestLogCleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [ip, entry] of requestLog.entries()) {
    if (entry.resetAt <= now) {
      requestLog.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

function getTenantPayload(tenant: Tenant): Tenant & TenantConfig {
  const config = tenantConfigs.get(tenant.id);
  return {
    ...tenant,
    name: config?.name || tenant.name,
    webhookUrl: config?.webhookUrl,
    defaultPolicies: config?.defaultPolicies,
  };
}

async function findTenant(tenantId: string): Promise<Tenant | undefined> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.id, tenantId));
  return tenant;
}

async function ensureAgentForTenant(
  tenantId: string,
  agentId: string
): Promise<AgentIdentity | undefined> {
  return vault.getAgent(tenantId, agentId);
}

async function tenantAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
  options?: { requireTenantMatch?: string }
) {
  await defaultTenantReady;

  // ── JWT Bearer auth (passkey / email login / agent-scoped) ────────────────
  const authHeader = c.req.header("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    const payload = await verifySessionToken(token);
    if (payload?.tenantId) {
      const jwtTenant = await findTenant(payload.tenantId);
      if (jwtTenant) {
        if (options?.requireTenantMatch && payload.tenantId !== options.requireTenantMatch) {
          return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
        }
        c.set("tenantId", payload.tenantId);
        c.set("tenant", jwtTenant);
        c.set("tenantConfig", tenantConfigs.get(payload.tenantId) || { id: jwtTenant.id, name: jwtTenant.name });

        // Store agent scope info for downstream middleware
        if (payload.scope === "agent" && payload.agentId) {
          c.set("agentScope", payload.agentId);
          c.set("authType", "agent-token");
        } else {
          c.set("authType", "session-jwt");
        }

        return next();
      }
    }
    // Invalid/expired JWT — fall through to header auth so existing tooling still works
  }

  // ── Legacy X-Steward-Tenant / X-Steward-Key header auth ──────────────────
  const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
  const tenant = await findTenant(tenantId);

  if (!tenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  }

  if (options?.requireTenantMatch && tenantId !== options.requireTenantMatch) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  const apiKey = c.req.header("X-Steward-Key") || "";
  
  // If tenant has an API key hash configured, validate the provided key
  if (tenant.apiKeyHash) {
    if (!validateApiKey(apiKey, tenant.apiKeyHash)) {
      return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
    }
  } else {
    // No API key hash configured — require explicit auth (no anonymous access)
    // This prevents the default tenant from being unprotected when STEWARD_DEFAULT_TENANT_KEY is empty
    if (!apiKey) {
      return c.json<ApiResponse>({ ok: false, error: "API key required" }, 401);
    }
    // If a key was provided but tenant has no hash, reject (can't validate)
    return c.json<ApiResponse>({ ok: false, error: "Tenant not configured for API key auth" }, 403);
  }

  c.set("tenantId", tenantId);
  c.set("tenant", tenant);
  c.set("tenantConfig", tenantConfigs.get(tenantId) || { id: tenant.id, name: tenant.name });
  c.set("authType", "api-key");

  await next();
}

/**
 * Middleware that enforces agent-scoped access.
 * If the request was authenticated with an agent-scoped JWT, verifies that
 * the JWT's agentId matches the `:agentId` route parameter.
 * Tenant API keys and session JWTs pass through unrestricted (backward compatible).
 */
function requireAgentAccess(
  c: Context<{ Variables: AppVariables }>,
): boolean {
  const agentScope = c.get("agentScope");
  if (!agentScope) {
    // Authenticated via tenant API key or session JWT — full access
    return true;
  }

  // Agent-scoped JWT — must match the route's agentId
  const routeAgentId = c.req.param("agentId");
  return agentScope === routeAgentId;
}

/**
 * Middleware that blocks agent-scoped tokens entirely.
 * Used for sensitive endpoints (e.g., key import) that require tenant-level auth.
 */
function requireTenantLevel(
  c: Context<{ Variables: AppVariables }>,
): boolean {
  const authType = c.get("authType");
  return authType !== "agent-token";
}

async function getPolicySet(tenantId: string, agentId: string): Promise<PolicyRule[]> {
  const storedPolicies = await db
    .select()
    .from(policies)
    .where(eq(policies.agentId, agentId));

  if (storedPolicies.length > 0) {
    return storedPolicies.map(toPolicyRule);
  }

  return tenantConfigs.get(tenantId)?.defaultPolicies || [];
}

async function getTransactionStats(agentId: string) {
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 3600_000);
  const oneDayAgo = new Date(now.getTime() - 86400_000);
  const oneWeekAgo = new Date(now.getTime() - 604800_000);

  // ISO strings for raw sql`` templates (postgres.js can't serialize Date objects)
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
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`
      )
    );

  return {
    recentTxCount1h: Number(stats?.recentTxCount1h ?? 0),
    recentTxCount24h: Number(stats?.recentTxCount24h ?? 0),
    spentToday: BigInt(stats?.spentToday ?? "0"),
    spentThisWeek: BigInt(stats?.spentThisWeek ?? "0"),
  };
}

app.use("/agents", (c, next) => tenantAuth(c, next));
app.use("/agents/*", (c, next) => tenantAuth(c, next));
app.use("/vault/*", (c, next) => tenantAuth(c, next));
app.use("/tenants/:id", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") })
);
app.use("/tenants/:id/webhook", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") })
);

app.get("/", (c) => c.json({ name: "steward", version: API_VERSION, status: "running" }));
app.get("/health", (c) =>
  c.json({
    status: "ok",
    version: API_VERSION,
    uptime: Math.floor((Date.now() - startTime) / 1000),
  })
);

// ─── Route Modules ────────────────────────────────────────────────────────────
import { correlationId } from "./middleware/correlation";
import { authRoutes } from "./routes/auth";
import { platformRoutes } from "./routes/platform";
import { userRoutes } from "./routes/user";

// authRoutes is mounted first so its /session handler (which supports both
// SIWE and user-session JWTs) takes precedence over the legacy inline version.
app.route("/auth", authRoutes);
app.route("/platform", platformRoutes);
app.route("/user", userRoutes);

// ─── SIWE Auth Endpoints (legacy inline — superseded by /routes/auth.ts) ──────

app.get("/auth/nonce", (c) => {
  const nonce = generateNonce();
  nonceStore.set(nonce, {
    nonce,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5-minute expiry
  });
  return c.json({ nonce });
});

app.post("/auth/verify", async (c) => {
  const body = await safeJsonParse<{ message: string; signature: string }>(c);
  if (!body || !body.message || !body.signature) {
    return c.json<ApiResponse>(
      { ok: false, error: "message and signature are required" },
      400
    );
  }

  let siweMessage: SiweMessage;
  try {
    siweMessage = new SiweMessage(body.message);
  } catch {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid SIWE message format" },
      400
    );
  }

  // Verify the nonce exists and hasn't expired
  const storedNonce = nonceStore.get(siweMessage.nonce);
  if (!storedNonce || storedNonce.expiresAt <= Date.now()) {
    nonceStore.delete(siweMessage.nonce);
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid or expired nonce" },
      401
    );
  }

  // Verify the SIWE signature
  try {
    await siweMessage.verify({ signature: body.signature });
  } catch {
    nonceStore.delete(siweMessage.nonce);
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid signature" },
      401
    );
  }

  // Nonce used — delete it
  nonceStore.delete(siweMessage.nonce);

  const address = siweMessage.address;
  let isNewTenant = false;
  let rawApiKey: string | undefined;

  // Look up tenant by owner_address
  const [existingTenant] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.ownerAddress, address));

  let tenant = existingTenant;

  if (!tenant) {
    // Auto-create tenant
    isNewTenant = true;
    const tenantId = `t-${address.slice(2, 10).toLowerCase()}`;
    const tenantName = `${address.slice(0, 6)}...${address.slice(-4)}`;
    const apiKeyPair = generateApiKey();
    rawApiKey = apiKeyPair.key;

    const [newTenant] = await db
      .insert(tenants)
      .values({
        id: tenantId,
        name: tenantName,
        apiKeyHash: apiKeyPair.hash,
        ownerAddress: address,
      })
      .onConflictDoNothing()
      .returning();

    if (!newTenant) {
      // Conflict — tenant with that id already exists, try fetching by address again
      const [retryTenant] = await db
        .select()
        .from(tenants)
        .where(eq(tenants.ownerAddress, address));
      if (retryTenant) {
        tenant = retryTenant;
        isNewTenant = false;
      } else {
        return c.json<ApiResponse>(
          { ok: false, error: "Failed to create tenant" },
          500
        );
      }
    } else {
      tenant = newTenant;
      // Also register it in the in-memory config
      tenantConfigs.set(tenantId, { id: tenantId, name: tenantName });
    }
  }

  const token = await createSessionToken(address, tenant.id);

  const response: Record<string, unknown> = {
    ok: true,
    token,
    address,
    tenant: {
      id: tenant.id,
      name: tenant.name,
    },
  };

  // Only return raw API key on first creation
  if (isNewTenant && rawApiKey) {
    (response.tenant as Record<string, unknown>).apiKey = rawApiKey;
  }

  return c.json(response);
});

app.get("/auth/session", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ authenticated: false });
  }

  const token = authHeader.slice(7);
  const payload = await verifySessionToken(token);

  if (!payload) {
    return c.json({ authenticated: false });
  }

  return c.json({
    authenticated: true,
    address: payload.address,
    tenantId: payload.tenantId,
  });
});

app.post("/auth/logout", (c) => {
  return c.json({ ok: true });
});

// ─── Session Auth Middleware (for dashboard routes) ───────────────────────────

async function sessionAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next
) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json<ApiResponse>(
      { ok: false, error: "Authorization header required" },
      401
    );
  }

  const token = authHeader.slice(7);
  const payload = await verifySessionToken(token);
  if (!payload) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid or expired session token" },
      401
    );
  }

  const tenant = await findTenant(payload.tenantId);
  if (!tenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  }

  c.set("tenantId", payload.tenantId);
  c.set("tenant", tenant);
  c.set(
    "tenantConfig",
    tenantConfigs.get(payload.tenantId) || {
      id: tenant.id,
      name: tenant.name,
    }
  );

  await next();
}

// ─── Tenant Auth Middleware (API key based — for SDK/programmatic access) ─────

app.post("/tenants", async (c) => {
  const body = await safeJsonParse<{
    id: string;
    name: string;
    apiKeyHash: string;
    webhookUrl?: string;
    defaultPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isValidTenantId(body.id)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid tenant id — must be 1-64 alphanumeric characters (plus _ - . :)" },
      400,
    );
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>({ ok: false, error: "name is required and must be a non-empty string" }, 400);
  }

  if (typeof body.apiKeyHash !== "string") {
    return c.json<ApiResponse>({ ok: false, error: "apiKeyHash is required" }, 400);
  }

  const existingTenant = await findTenant(body.id);
  if (existingTenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant already exists" }, 400);
  }

  // If caller passes a raw key (stw_…) instead of a hash, hash it now
  const apiKeyHash =
    body.apiKeyHash && !body.apiKeyHash.match(/^[0-9a-f]{64}$/)
      ? hashApiKey(body.apiKeyHash)
      : body.apiKeyHash;

  const [tenant] = await db
    .insert(tenants)
    .values({
      id: body.id,
      name: body.name,
      apiKeyHash,
    })
    .returning();

  tenantConfigs.set(body.id, {
    id: body.id,
    name: body.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies,
  });

  return c.json<ApiResponse<Tenant & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

app.get("/tenants/:id", (c) => {
  const tenant = c.get("tenant");
  return c.json<ApiResponse<Tenant & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

app.put("/tenants/:id/webhook", async (c) => {
  const tenant = c.get("tenant");
  const tenantConfig = c.get("tenantConfig");
  const body = await safeJsonParse<{ webhookUrl?: string; defaultPolicies?: PolicyRule[] }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (body.webhookUrl !== undefined && typeof body.webhookUrl !== "string") {
    return c.json<ApiResponse>({ ok: false, error: "webhookUrl must be a string" }, 400);
  }

  if (body.defaultPolicies !== undefined && !Array.isArray(body.defaultPolicies)) {
    return c.json<ApiResponse>({ ok: false, error: "defaultPolicies must be an array" }, 400);
  }

  const updatedConfig: TenantConfig = {
    ...tenantConfig,
    id: tenant.id,
    name: tenant.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies ?? tenantConfig.defaultPolicies,
  };

  tenantConfigs.set(tenant.id, updatedConfig);

  return c.json<ApiResponse<TenantConfig>>({
    ok: true,
    data: updatedConfig,
  });
});

app.post("/agents", async (c) => {
  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{ id: string; name: string; platformId?: string }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isValidAgentId(body.id)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)" },
      400,
    );
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>({ ok: false, error: "name is required and must be a non-empty string" }, 400);
  }

  try {
    const identity = await vault.createAgent(tenantId, body.id, body.name, body.platformId);
    return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: identity });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

app.get("/agents", async (c) => {
  const tenantId = c.get("tenantId");
  const tenantAgents = await vault.listAgentsByTenant(tenantId);
  return c.json<ApiResponse<AgentIdentity[]>>({ ok: true, data: tenantAgents });
});

// ─── Agent Token Generation ───────────────────────────────────────────────
app.post("/agents/:agentId/token", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  // Only tenant-level auth can generate agent tokens
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Agent tokens cannot generate other agent tokens" }, 403);
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{ expiresIn?: string }>(c);
  const expiresIn = body?.expiresIn || AGENT_TOKEN_EXPIRY;

  try {
    const token = await createAgentToken(agentId, tenantId, expiresIn);
    return c.json<ApiResponse<{ token: string; agentId: string; tenantId: string; scope: string; expiresIn: string }>>({
      ok: true,
      data: { token, agentId, tenantId, scope: "agent", expiresIn },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Failed to generate agent token for ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: "Failed to generate token" }, 500);
  }
});

app.get("/agents/:agentId", async (c) => {
  const tenantId = c.get("tenantId");
  const agent = await vault.getAgent(tenantId, c.req.param("agentId"));
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: agent });
});

app.get("/agents/:agentId/balance", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const chainIdParam = c.req.query("chainId");
  const chainId = chainIdParam ? parseInt(chainIdParam, 10) : undefined;

  try {
    const balance = await vault.getBalance(tenantId, agentId, chainId);
    return c.json<ApiResponse<AgentBalance>>({
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

app.post("/agents/batch", async (c) => {
  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    agents: Array<{ id: string; name: string; platformId?: string }>;
    applyPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!Array.isArray(body.agents) || body.agents.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "agents array is required and must not be empty" }, 400);
  }

  // Validate each agent spec
  for (const agentSpec of body.agents) {
    if (!isValidAgentId(agentSpec.id)) {
      return c.json<ApiResponse>(
        { ok: false, error: `Invalid agent id "${String(agentSpec.id)}" — must be 1-128 alphanumeric characters (plus _ - . :)` },
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

  const created: AgentIdentity[] = [];
  const errors: Array<{ id: string; error: string }> = [];

  for (const agentSpec of body.agents) {
    try {
      const identity = await vault.createAgent(tenantId, agentSpec.id, agentSpec.name, agentSpec.platformId);

      if (body.applyPolicies && body.applyPolicies.length > 0) {
        await db.delete(policies).where(eq(policies.agentId, agentSpec.id));
        await db.insert(policies).values(
          body.applyPolicies.map((policy) => ({
            id: policy.id || crypto.randomUUID(),
            agentId: agentSpec.id,
            type: policy.type,
            enabled: policy.enabled,
            config: policy.config,
          }))
        );
      }

      created.push(identity);
    } catch (e: unknown) {
      errors.push({ id: agentSpec.id, error: e instanceof Error ? e.message : "Unknown error" });
    }
  }

  return c.json<ApiResponse<{ created: AgentIdentity[]; errors: Array<{ id: string; error: string }> }>>({
    ok: true,
    data: { created, errors },
  });
});

app.get("/agents/:agentId/policies", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const agentPolicies = await db
    .select()
    .from(policies)
    .where(eq(policies.agentId, agentId));

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: agentPolicies.map(toPolicyRule),
  });
});

app.put("/agents/:agentId/policies", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const nextPolicies = await safeJsonParse<PolicyRule[]>(c);

  if (!nextPolicies || !Array.isArray(nextPolicies)) {
    return c.json<ApiResponse>({ ok: false, error: "Request body must be a JSON array of policies" }, 400);
  }

  // Validate each policy
  const validPolicyTypes = ["spending-limit", "approved-addresses", "auto-approve-threshold", "time-window", "rate-limit", "allowed-chains"];
  for (const policy of nextPolicies) {
    if (!isNonEmptyString(policy.type)) {
      return c.json<ApiResponse>({ ok: false, error: "Each policy must have a non-empty 'type' field" }, 400);
    }
    if (!validPolicyTypes.includes(policy.type)) {
      return c.json<ApiResponse>(
        { ok: false, error: `Unknown policy type "${policy.type}" — supported types: ${validPolicyTypes.join(", ")}` },
        400,
      );
    }
    if (typeof policy.enabled !== "boolean") {
      return c.json<ApiResponse>({ ok: false, error: `Policy "${policy.id || policy.type}": enabled must be a boolean` }, 400);
    }
    if (typeof policy.config !== "object" || policy.config === null || Array.isArray(policy.config)) {
      return c.json<ApiResponse>({ ok: false, error: `Policy "${policy.id || policy.type}": config must be an object` }, 400);
    }
  }

  await db.delete(policies).where(eq(policies.agentId, agentId));

  if (nextPolicies.length > 0) {
    await db.insert(policies).values(
      nextPolicies.map((policy) => ({
        id: policy.id || crypto.randomUUID(),
        agentId,
        type: policy.type,
        enabled: policy.enabled,
        config: policy.config,
      }))
    );
  }

  const storedPolicies = await db
    .select()
    .from(policies)
    .where(eq(policies.agentId, agentId));

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: storedPolicies.map(toPolicyRule),
  });
});

app.post("/vault/:agentId/sign", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
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
    // Give a specific error message based on whether it looks like a malformed EVM or Solana address
    const errMsg = request.to.startsWith("0x")
      ? "'to' must be a valid Ethereum address (0x + 40 hex chars)"
      : "'to' must be a valid Ethereum address (0x + 40 hex chars) or a valid Solana address (base58, 32–44 chars)";
    return c.json<ApiResponse>({ ok: false, error: errMsg }, 400);
  }
  if (request.value === undefined || request.value === null) {
    return c.json<ApiResponse>({ ok: false, error: "'value' is required (wei amount as string)" }, 400);
  }

  // Resolve chainId BEFORE policy evaluation — if omitted, use the vault default
  const resolvedChainId = request.chainId || parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = { ...request, tenantId, agentId, chainId: resolvedChainId };
  const policySet = await getPolicySet(tenantId, agentId);
  const stats = await getTransactionStats(agentId);

  const evaluation = policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "pending",
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
      });

      await db.insert(approvalQueue).values({
        id: crypto.randomUUID(),
        txId,
        agentId,
        status: "pending",
      });

      const webhookUrlApproval = tenantConfigs.get(tenantId)?.webhookUrl;
      if (webhookUrlApproval) {
        webhookDispatcher
          .dispatch(
            { type: "approval_required", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
            webhookUrlApproval
          )
          .catch(console.error);
      }

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: { txId, results: evaluation.results, status: "pending_approval" },
        },
        202
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

    const webhookUrlRejected = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlRejected) {
      webhookDispatcher
        .dispatch(
          { type: "tx_rejected", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
          webhookUrlRejected
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403
    );
  }

  try {
    const txId = crypto.randomUUID();
    const shouldBroadcast = signRequest.broadcast !== false;
    const result = await vault.signTransaction(signRequest, {
      txId,
      policyResults: evaluation.results,
      status: "signed",
    });

    await db
      .update(transactions)
      .set({
        status: "signed",
        txHash: shouldBroadcast ? result : undefined,
        policyResults: evaluation.results,
        signedAt: new Date(),
      })
      .where(eq(transactions.id, txId));

    const webhookUrlSigned = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlSigned) {
      webhookDispatcher
        .dispatch(
          { type: "tx_signed", tenantId, agentId, data: { txId, txHash: shouldBroadcast ? result : undefined }, timestamp: new Date() },
          webhookUrlSigned
        )
        .catch(console.error);
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

    const webhookUrlFailed = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlFailed) {
      webhookDispatcher
        .dispatch(
          { type: "tx_failed", tenantId, agentId, data: { error: rawMessage, requestId }, timestamp: new Date() },
          webhookUrlFailed
        )
        .catch(console.error);
    }

    // Return 502 for RPC/blockchain errors with the actual error message
    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

app.post("/vault/:agentId/approve/:txId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction approval requires tenant-level authentication" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [transaction] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
  if (!transaction) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  // Atomically claim the pending approval — only one concurrent request can succeed.
  // We transition directly to "approved" (the schema has no "processing" value) and
  // revert to "pending" inside the catch block if signing fails, so the request can be retried.
  const resolvedAt = new Date();
  const claimResult = await db
    .update(approvalQueue)
    .set({
      status: "approved",
      resolvedAt,
      resolvedBy: tenantId,
    })
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending")
      )
    )
    .returning({ id: approvalQueue.id });

  if (claimResult.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction already processed or not found" }, 409);
  }

  try {
    // Solana transactions (chainId 101 = mainnet, 102 = devnet) must be replayed
    // via signSolanaTransaction using the original serialized blob stored in `data`.
    // EVM transactions use the standard signTransaction path.
    const isSolana = transaction.chainId === 101 || transaction.chainId === 102;

    let txHash: string;

    if (isSolana) {
      if (!transaction.data) {
        return c.json<ApiResponse>(
          { ok: false, error: "Solana transaction blob not found — cannot replay approval" },
          500
        );
      }

      const result = await vault.signSolanaTransaction({
        agentId,
        tenantId,
        transaction: transaction.data,
        chainId: transaction.chainId,
        broadcast: true,
      });

      txHash = result.signature;
    } else {
      txHash = await vault.signTransaction(
        { ...toSignRequest(transaction), tenantId },
        {
          txId,
          policyResults: transaction.policyResults,
          status: "signed",
        }
      );
    }

    // approvalQueue already updated atomically above; just update the transaction record.
    await db
      .update(transactions)
      .set({
        status: "signed",
        txHash,
        signedAt: resolvedAt,
      })
      .where(eq(transactions.id, txId));

    const webhookUrlApproved = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlApproved) {
      webhookDispatcher
        .dispatch(
          { type: "tx_signed", tenantId, agentId, data: { txId, txHash }, timestamp: new Date() },
          webhookUrlApproved
        )
        .catch(console.error);
    }

    return c.json<ApiResponse<{ txId: string; txHash: string }>>({
      ok: true,
      data: { txId, txHash },
    });
  } catch (e: unknown) {
    // Revert the atomic claim so the approval can be retried
    await db
      .update(approvalQueue)
      .set({ status: "pending", resolvedAt: null, resolvedBy: null })
      .where(
        and(
          eq(approvalQueue.txId, txId),
          eq(approvalQueue.agentId, agentId)
        )
      );

    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Approve transaction failed for agent ${agentId}, tx ${txId}:`, e);

    const webhookUrlFailed = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlFailed) {
      webhookDispatcher
        .dispatch(
          { type: "tx_failed", tenantId, agentId, data: { txId, error: rawMessage, requestId }, timestamp: new Date() },
          webhookUrlFailed
        )
        .catch(console.error);
    }

    // Return 502 for RPC/blockchain errors with the actual error message
    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

app.post("/vault/:agentId/reject/:txId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction approval requires tenant-level authentication" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  // Atomically transition from "pending" → "rejected"; prevents concurrent approve/reject races.
  const rejectResult = await db
    .update(approvalQueue)
    .set({
      status: "rejected",
      resolvedAt: new Date(),
      resolvedBy: tenantId,
    })
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending")
      )
    )
    .returning({ id: approvalQueue.id });

  if (rejectResult.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction already processed or not found" }, 409);
  }

  await db
    .update(transactions)
    .set({
      status: "rejected",
    })
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));

  return c.json<ApiResponse>({ ok: true });
});

app.get("/vault/:agentId/pending", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

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
        eq(transactions.agentId, agentId)
      )
    );

  return c.json<ApiResponse>({
    ok: true,
    data: pendingTransactions.map((entry) => ({
      queueId: entry.queueId,
      status: entry.status,
      requestedAt: entry.requestedAt,
      transaction: toTxRecord(entry.transaction),
    })),
  });
});

app.get("/vault/:agentId/history", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const history = await db
    .select()
    .from(transactions)
    .where(eq(transactions.agentId, agentId));

  return c.json<ApiResponse>({
    ok: true,
    data: history.map(toTxRecord),
  });
});

// ─── EIP-712 Typed Data Signing ───────────────────────────────────────────
app.post("/vault/:agentId/sign-typed-data", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

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
    return c.json<ApiResponse>({ ok: false, error: "'domain' is required and must be an object" }, 400);
  }
  if (!body.types || typeof body.types !== "object") {
    return c.json<ApiResponse>({ ok: false, error: "'types' is required and must be an object" }, 400);
  }
  if (!isNonEmptyString(body.primaryType)) {
    return c.json<ApiResponse>({ ok: false, error: "'primaryType' is required" }, 400);
  }
  if (!body.value || typeof body.value !== "object") {
    return c.json<ApiResponse>({ ok: false, error: "'value' is required and must be an object" }, 400);
  }

  // ── Policy evaluation ────────────────────────────────────────────────────
  // Typed data has no direct ETH value, but must still pass rate-limit,
  // allowed-chains, and time-window policies. Use value "0" so spending-limit
  // policies treat this as a zero-value operation (correct — permit() grants
  // token allowances at the ERC-20 level, not direct ETH).
  // Resolve chainId BEFORE policy evaluation — if omitted from domain, use the vault default
  const resolvedChainId = (typeof body.domain.chainId === "number" ? body.domain.chainId : 0) || parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: "0x0000000000000000000000000000000000000000",
    value: "0",
    chainId: resolvedChainId,
  };

  const policySet = await getPolicySet(tenantId, agentId);
  const stats = await getTransactionStats(agentId);

  const evaluation = policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "pending",
        toAddress: signRequest.to,
        value: signRequest.value,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
      });

      await db.insert(approvalQueue).values({
        id: crypto.randomUUID(),
        txId,
        agentId,
        status: "pending",
      });

      const webhookUrlApproval = tenantConfigs.get(tenantId)?.webhookUrl;
      if (webhookUrlApproval) {
        webhookDispatcher
          .dispatch(
            { type: "approval_required", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
            webhookUrlApproval
          )
          .catch(console.error);
      }

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: { txId, results: evaluation.results, status: "pending_approval" },
        },
        202
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

    const webhookUrlRejected = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlRejected) {
      webhookDispatcher
        .dispatch(
          { type: "tx_rejected", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
          webhookUrlRejected
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403
    );
  }

  // ── Policy approved — sign ───────────────────────────────────────────────
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

    const webhookUrlSigned = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlSigned) {
      webhookDispatcher
        .dispatch(
          { type: "tx_signed", tenantId, agentId, data: { txId }, timestamp: new Date() },
          webhookUrlSigned
        )
        .catch(console.error);
    }

    return c.json<ApiResponse<{ signature: string; txId: string }>>({
      ok: true,
      data: { signature, txId },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Sign typed data failed for agent ${agentId}:`, e);

    const webhookUrlFailed = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlFailed) {
      webhookDispatcher
        .dispatch(
          { type: "tx_failed", tenantId, agentId, data: { txId, error: rawMessage, requestId }, timestamp: new Date() },
          webhookUrlFailed
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Solana Transaction Signing ───────────────────────────────────────────
//
// NOTE: Policy enforcement mirrors the EVM /vault/:agentId/sign route exactly.
// Every Solana signing request goes through the policy engine, is recorded in
// the transactions table, and triggers the same webhook events.
//
// `to` and `value` are REQUIRED fields. They carry the recipient address and
// lamport amount so that spending-limit and approved-addresses policies
// evaluate against the real transaction intent rather than defaulting to
// empty/zero values that would silently bypass policy checks.
//
// The raw base64 transaction blob is persisted in the `data` column so that
// queued-for-approval transactions can be replayed by the approve endpoint.
app.post("/vault/:agentId/sign-solana", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
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
    /** Recipient address — used for approved-addresses policy evaluation. */
    to?: string;
    /** Transfer amount in lamports (as string) — used for spending-limit policy evaluation. */
    value?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.transaction)) {
    return c.json<ApiResponse>({ ok: false, error: "'transaction' is required (base64-encoded serialized Solana transaction)" }, 400);
  }

  // Validate optional `to` address when provided
  if (body.to !== undefined && body.to !== "") {
    if (!isValidSolanaAddress(body.to) && !isValidAddress(body.to)) {
      return c.json<ApiResponse>({ ok: false, error: "'to' must be a valid Solana address (base58, 32–44 chars) or Ethereum address" }, 400);
    }
  }

  // `to` and `value` are required for policy evaluation. Without them,
  // spending-limit policies would always pass (value = "0") and
  // approved-addresses policies would be meaningless (empty string matches
  // nothing), allowing the actual Solana transaction to bypass policy checks.
  if (!body.to || !body.value) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Solana signing requires 'to' (recipient address) and 'value' (lamports as string) for policy evaluation",
      },
      400
    );
  }

  const chainId = body.chainId ?? 101;
  const toAddress = body.to;
  const txValue = body.value;

  // Build a SignRequest-shaped object for the policy engine.
  const signRequest = {
    agentId,
    tenantId,
    to: toAddress,
    value: txValue,
    chainId,
  };

  // ── 1. Fetch policies ────────────────────────────────────────────────────
  const policySet = await getPolicySet(tenantId, agentId);
  const stats = await getTransactionStats(agentId);

  // ── 2. Evaluate policies ─────────────────────────────────────────────────
  const evaluation = policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
  });

  // ── 3. Handle non-approved outcomes ─────────────────────────────────────
  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      // Insert pending transaction record.
      // Store the base64 transaction blob in `data` so the approve endpoint
      // can replay the exact transaction without re-serializing it.
      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "pending",
        toAddress,
        value: txValue,
        data: body.transaction,
        chainId,
        policyResults: evaluation.results,
      });

      await db.insert(approvalQueue).values({
        id: crypto.randomUUID(),
        txId,
        agentId,
        status: "pending",
      });

      const webhookUrlApproval = tenantConfigs.get(tenantId)?.webhookUrl;
      if (webhookUrlApproval) {
        webhookDispatcher
          .dispatch(
            { type: "approval_required", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
            webhookUrlApproval
          )
          .catch(console.error);
      }

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: { txId, results: evaluation.results, status: "pending_approval" },
        },
        202
      );
    }

    // Hard policy rejection
    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress,
      value: txValue,
      chainId,
      policyResults: evaluation.results,
    });

    const webhookUrlRejected = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlRejected) {
      webhookDispatcher
        .dispatch(
          { type: "tx_rejected", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
          webhookUrlRejected
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403
    );
  }

  // ── 4. Policy approved — sign the transaction ────────────────────────────
  try {
    const txId = crypto.randomUUID();

    const result = await vault.signSolanaTransaction({
      agentId,
      tenantId,
      transaction: body.transaction,
      chainId,
      broadcast: body.broadcast,
    });

    // Record the completed transaction
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

    const webhookUrlSigned = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlSigned) {
      webhookDispatcher
        .dispatch(
          {
            type: "tx_signed",
            tenantId,
            agentId,
            data: { txId, txHash: result.broadcast ? result.signature : undefined },
            timestamp: new Date(),
          },
          webhookUrlSigned
        )
        .catch(console.error);
    }

    return c.json<ApiResponse<{ txId: string; signature: string; broadcast: boolean; chainId: number; caip2?: string }>>({
      ok: true,
      data: { txId, ...result },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Solana sign failed for agent ${agentId}:`, e);

    const webhookUrlFailed = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlFailed) {
      webhookDispatcher
        .dispatch(
          {
            type: "tx_failed",
            tenantId,
            agentId,
            data: { error: e instanceof Error ? e.message : "Unknown error", requestId },
            timestamp: new Date(),
          },
          webhookUrlFailed
        )
        .catch(console.error);
    }

    // Return 502 for RPC/blockchain errors with the actual error message
    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Generic RPC Passthrough ──────────────────────────────────────────────
app.post("/vault/:agentId/rpc", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
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

  if (!body.chainId || typeof body.chainId !== "number") {
    return c.json<ApiResponse>({ ok: false, error: "'chainId' is required and must be a number" }, 400);
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

// ─── Multi-Wallet Address List ────────────────────────────────────────────
/**
 * GET /vault/:agentId/addresses
 *
 * Returns all wallet addresses for an agent across all chain families.
 * For agents created with multi-wallet support, returns both EVM and Solana
 * addresses. For legacy agents, returns only the EVM address.
 */
app.get("/vault/:agentId/addresses", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: token scope does not match agent" }, 403);
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const addresses = await vault.getAddresses(tenantId, agentId);
    return c.json<ApiResponse<{
      agentId: string;
      addresses: Array<{ chainFamily: "evm" | "solana"; address: string }>;
    }>>({
      ok: true,
      data: { agentId, addresses },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] getAddresses failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Import ───────────────────────────────────────────────────────────
app.post("/vault/:agentId/import", async (c) => {
  // Only tenant-level auth can import keys
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Key import requires tenant-level authentication" }, 403);
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!isValidAgentId(agentId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)" },
      400,
    );
  }

  const body = await safeJsonParse<{ privateKey: string; chain: "evm" | "solana" }>(c);
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
    const result = await vault.importKey(tenantId, agentId, body.privateKey, body.chain);
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

const BIND_HOST = process.env.STEWARD_BIND_HOST || "127.0.0.1";

const server = Bun.serve({
  hostname: BIND_HOST,
  port: PORT,
  fetch: (request) => app.fetch(request),
  idleTimeout: 30,
});

const shutdown = async (signal: string) => {
  if (isShuttingDown) {
    return;
  }

  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down Steward API`);

  server.stop(true);
  clearInterval(requestLogCleanupTimer);
  clearInterval(nonceCleanupTimer);
  requestLog.clear();
  nonceStore.clear();

  try {
    await closeDb();
  } catch (error) {
    console.error("Failed to close database connection cleanly", error);
  }

  process.exit(0);
};

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

console.log(`Steward API running on ${server.hostname}:${server.port}`);
