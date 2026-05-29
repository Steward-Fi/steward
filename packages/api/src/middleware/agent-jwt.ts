import type { Context, Next } from "hono";
import { importJWK, type JWTPayload, jwtVerify } from "jose";
import type { ApiResponse, AppVariables, Tenant } from "../services/context";
import {
  AGENT_SCOPE,
  DEFAULT_TENANT_ID,
  ensureAgentForTenant,
  findTenant,
  tenantConfigs,
} from "../services/context";

type JwksKey = JsonWebKey & { kid?: string; alg?: string; use?: string };
type Jwks = { keys?: JwksKey[] };

type CacheEntry = {
  keys: Map<string, Awaited<ReturnType<typeof importJWK>>>;
  expiresAt: number;
};

const JWKS_CACHE_MS = 5 * 60 * 1000;
const DEFAULT_ELIZA_CLOUD_JWKS_URL = "https://milady.shad0w.xyz/.well-known/jwks.json";
const ELIZA_CLOUD_JWKS_URL = process.env.ELIZA_CLOUD_JWKS_URL || DEFAULT_ELIZA_CLOUD_JWKS_URL;
const TRADE_ORDER_SCOPE = "trade:order";

let jwksCache: CacheEntry | null = null;

function invalid(c: Context, reason: string) {
  return c.json({ code: "invalid-jwt", reason }, 401);
}

async function loadJwks(): Promise<Map<string, Awaited<ReturnType<typeof importJWK>>>> {
  if (process.env.NODE_ENV === "production" && !process.env.ELIZA_CLOUD_JWKS_URL) {
    throw new Error("jwks-url-required");
  }
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

function agentIdFromPayload(payload: JWTPayload): string | null {
  const agentId = payload.agent_id;
  if (typeof agentId !== "string" || !agentId.trim()) return null;
  if (payload.sub !== `agent:${agentId}`) return null;
  return agentId;
}

function stringClaim(payload: JWTPayload, ...names: string[]): string | null {
  const claims = payload as Record<string, unknown>;
  for (const name of names) {
    const value = claims[name];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function stringArrayClaim(payload: JWTPayload, ...names: string[]): string[] {
  const claims = payload as Record<string, unknown>;
  for (const name of names) {
    const value = claims[name];
    if (Array.isArray(value)) {
      return value.filter(
        (item): item is string => typeof item === "string" && item.trim().length > 0,
      );
    }
    if (typeof value === "string" && value.trim()) {
      return value.split(/[,\s]+/).filter(Boolean);
    }
  }
  return [];
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
  c.set("agentScopes", [AGENT_SCOPE]);
  c.set("authType", "agent-token");
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
    const scopes = stringArrayClaim(payload, "scopes", "scope");
    if (!scopes.includes(TRADE_ORDER_SCOPE)) {
      return c.json<ApiResponse>(
        { ok: false, error: `Token missing required ${TRADE_ORDER_SCOPE} scope` },
        403,
      );
    }

    const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
    const tokenTenantId = stringClaim(payload, "tenant_id", "tenantId");
    if (!tokenTenantId || tokenTenantId !== tenantId) {
      return invalid(c, "invalid tenant claims");
    }
    const tenant = await findTenant(tenantId);
    if (!tenant) return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: agent is not registered for tenant" },
        403,
      );
    }
    const tokenPlatformId = stringClaim(payload, "platform_id", "platformId");
    if (agent.platformId && tokenPlatformId !== agent.platformId) {
      return invalid(c, "invalid platform claims");
    }

    await setTenantContext(c, tenant, tenantId, agentId);
    c.set("agentScopes", [AGENT_SCOPE, ...scopes]);
    return next();
  } catch (error) {
    const reason = error instanceof Error ? error.message : "verification failed";
    return invalid(c, reason);
  }
}

export function clearAgentJwksCacheForTests() {
  jwksCache = null;
}
