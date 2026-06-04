import type { Context, Next } from "hono";
import { errors, importJWK, type JWTPayload, jwtVerify } from "jose";
import { recordAgentTokenExp } from "../services/agent-token-status";
import { trackAuditEvent } from "../services/audit";
import type { ApiResponse, AppVariables, Tenant } from "../services/context";
import { DEFAULT_TENANT_ID, findTenant, tenantConfigs } from "../services/context";

type JwksKey = JsonWebKey & { kid?: string; alg?: string; use?: string };
type Jwks = { keys?: JwksKey[] };

type CacheEntry = {
  keys: Map<string, Awaited<ReturnType<typeof importJWK>>>;
  expiresAt: number;
};

const JWKS_CACHE_MS = 5 * 60 * 1000;
const AGENT_TOKEN_EXPIRING_THRESHOLD_SECONDS = 5 * 60;
const ELIZA_CLOUD_JWKS_URL =
  process.env.ELIZA_CLOUD_JWKS_URL || "https://milady.shad0w.xyz/.well-known/jwks.json";

let jwksCache: CacheEntry | null = null;

function invalid(c: Context, reason: string) {
  return c.json({ code: "invalid-jwt", reason }, 401);
}

async function loadJwks(): Promise<Map<string, Awaited<ReturnType<typeof importJWK>>>> {
  const now = Date.now();
  if (jwksCache && jwksCache.expiresAt > now) return jwksCache.keys;

  const response = await fetch(ELIZA_CLOUD_JWKS_URL, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`jwks-fetch-failed:${response.status}`);
  }

  const jwks = (await response.json()) as Jwks;
  const keys = new Map<string, Awaited<ReturnType<typeof importJWK>>>();
  for (const jwk of jwks.keys ?? []) {
    if (!jwk.kid) continue;
    keys.set(jwk.kid, await importJWK(jwk, jwk.alg ?? "RS256"));
  }

  jwksCache = { keys, expiresAt: now + JWKS_CACHE_MS };
  return keys;
}

function getBearer(c: Context): string | null {
  const auth = c.req.header("Authorization");
  return auth?.startsWith("Bearer ") ? auth.slice(7) : null;
}

function base64UrlDecode(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return atob(padded);
}

function decodeJwtHeader(token: string): { kid?: string; alg?: string } | null {
  try {
    const [header] = token.split(".");
    if (!header) return null;
    return JSON.parse(base64UrlDecode(header));
  } catch {
    return null;
  }
}

function decodeJwtPayload(token: string): JWTPayload | null {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    return JSON.parse(base64UrlDecode(payload));
  } catch {
    return null;
  }
}

function agentIdFromPayload(payload: JWTPayload): string | null {
  const agentId = payload.agent_id;
  if (typeof agentId !== "string" || !agentId.trim()) return null;
  if (payload.sub !== `agent:${agentId}`) return null;
  return agentId;
}

async function setTenantContext(
  c: Context<{ Variables: AppVariables }>,
  tenant: Tenant,
  tenantId: string,
  agentId: string,
) {
  c.set("tenantId", tenantId);
  c.set("tenant", tenant);
  c.set("tenantConfig", tenantConfigs.get(tenantId) || { id: tenant.id, name: tenant.name });
  c.set("agentScope", agentId);
  c.set("authType", "agent-token");
}

function emitAgentTokenEvent(
  tenantId: string,
  agentId: string,
  action: "agent.token.expiring" | "agent.token.expired",
  metadata: Record<string, unknown>,
) {
  trackAuditEvent({
    tenantId,
    actorType: "agent",
    actorId: agentId,
    action,
    resourceType: "agent-token",
    resourceId: agentId,
    metadata,
  });
}

async function observeAgentTokenExpiry(
  tenantId: string,
  agentId: string,
  exp: JWTPayload["exp"],
): Promise<void> {
  if (typeof exp !== "number") return;

  await recordAgentTokenExp(agentId, exp);

  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresInSeconds = exp - nowSeconds;
  if (expiresInSeconds > AGENT_TOKEN_EXPIRING_THRESHOLD_SECONDS) return;

  const metadata = { agentId, expiresInSeconds, exp };
  console.warn("[steward:agent-token] agent token expiring", metadata);
  emitAgentTokenEvent(tenantId, agentId, "agent.token.expiring", metadata);
}

function observeExpiredAgentToken(c: Context, token: string): void {
  const payload = decodeJwtPayload(token);
  if (!payload) return;
  const agentId = agentIdFromPayload(payload);
  if (!agentId) return;

  const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
  const exp = typeof payload.exp === "number" ? payload.exp : undefined;
  const expiresInSeconds =
    typeof exp === "number" ? exp - Math.floor(Date.now() / 1000) : undefined;
  const metadata = { agentId, expiresInSeconds, exp };
  console.warn("[steward:agent-token] agent token expired", metadata);
  emitAgentTokenEvent(tenantId, agentId, "agent.token.expired", metadata);
}

export async function requireAgentJwt(c: Context<{ Variables: AppVariables }>, next: Next) {
  const token = getBearer(c);
  if (!token) return invalid(c, "missing bearer token");

  const header = decodeJwtHeader(token);
  if (!header?.kid) return invalid(c, "missing kid");
  if (header.alg !== "RS256") return invalid(c, "unsupported alg");

  try {
    const keys = await loadJwks();
    const key = keys.get(header.kid);
    if (!key) return invalid(c, "unknown kid");

    const { payload } = await jwtVerify(token, key, {
      issuer: "eliza-cloud",
      audience: "steward",
      algorithms: ["RS256"],
    });
    const agentId = agentIdFromPayload(payload);
    if (!agentId) return invalid(c, "invalid agent claims");

    const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
    const tenant = await findTenant(tenantId);
    if (!tenant) return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);

    await observeAgentTokenExpiry(tenantId, agentId, payload.exp);
    await setTenantContext(c, tenant, tenantId, agentId);
    return next();
  } catch (error) {
    if (error instanceof errors.JWTExpired) observeExpiredAgentToken(c, token);
    const reason = error instanceof Error ? error.message : "verification failed";
    return invalid(c, reason);
  }
}

export function clearAgentJwksCacheForTests() {
  jwksCache = null;
}
