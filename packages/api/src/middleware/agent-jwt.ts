import type { VerifiedAgentPrincipal } from "@stwd/shared";
import type { Context, Next } from "hono";
import { errors, importJWK, type JWTPayload, jwtVerify } from "jose";
import { recordAgentTokenExp } from "../services/agent-token-status";
import { trackAuditEvent } from "../services/audit";
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
  url: string;
  keys: Map<string, Awaited<ReturnType<typeof importJWK>>>;
  expiresAt: number;
};

const JWKS_CACHE_MS = 5 * 60 * 1000;
const JWKS_MISS_REFRESH_MIN_INTERVAL_MS = 10 * 1000;
const AGENT_TOKEN_EXPIRING_THRESHOLD_SECONDS = 5 * 60;
const MAX_IAT_CLOCK_SKEW_SECONDS = 60;
// Dev convenience trust anchor. SEC-069: only honored behind an explicit
// opt-in (STEWARD_ALLOW_DEFAULT_ELIZA_JWKS=true) outside production — domain
// takeover/compromise of this host would otherwise silently become a minting
// oracle for any staging/self-hosted deployment that forgot to configure
// ELIZA_CLOUD_JWKS_URL.
const DEFAULT_ELIZA_CLOUD_JWKS_URL = "https://milady.shad0w.xyz/.well-known/jwks.json";
const TRADE_ORDER_SCOPE = "trade:order";

let jwksCache: CacheEntry | null = null;
let lastJwksMissRefreshAt = 0;

function invalid(c: Context, reason: string, status: 401 = 401) {
  return c.json({ code: "invalid-jwt", reason }, status);
}

/**
 * Resolve the JWKS trust anchor. Production always requires an explicit
 * ELIZA_CLOUD_JWKS_URL; outside production the hardcoded dev anchor requires
 * the STEWARD_ALLOW_DEFAULT_ELIZA_JWKS=true opt-in. Fails closed otherwise.
 */
function resolveJwksUrl(): string {
  const configured = process.env.ELIZA_CLOUD_JWKS_URL?.trim();
  if (configured) return configured;
  if (
    process.env.NODE_ENV !== "production" &&
    process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS === "true"
  ) {
    return DEFAULT_ELIZA_CLOUD_JWKS_URL;
  }
  throw new Error("jwks-url-required");
}

async function loadJwks(
  forceRefresh = false,
  jwksUrl = resolveJwksUrl(),
): Promise<Map<string, Awaited<ReturnType<typeof importJWK>>>> {
  const now = Date.now();
  if (!forceRefresh && jwksCache?.url === jwksUrl && jwksCache.expiresAt > now) {
    return jwksCache.keys;
  }

  const response = await fetch(jwksUrl, {
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

  jwksCache = { url: jwksUrl, keys, expiresAt: now + JWKS_CACHE_MS };
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

/**
 * The result of authenticating an agent JWT: the verified identity + resolved
 * tenant/agent rows + observed claims. This is PURE authentication — it carries
 * NO business-scope decision (no `trade:order` check, no provider authority).
 * `requireAgentJwt` (legacy) layers the `trade:order` gate on top; provider
 * routes use `requireProviderAgentJwt` which does not.
 */
export interface AgentJwtAuthenticationResult {
  tenant: Tenant;
  tenantId: string;
  agentId: string;
  /** All scopes observed on the token (evidence only, never provider authority). */
  scopes: string[];
  issuer: string;
  subject: string;
  tokenId: string | null;
  platformId: string | null;
  exp: number | null;
  iat: number | null;
}

/**
 * A typed failure from `authenticateAgentJwt`. The caller renders the response;
 * the authenticator never writes a body itself so both the legacy and provider
 * middlewares share identical authN behavior yet keep their OWN response shapes.
 *
 * `kind` classifies the failure so each middleware renders the correct wire
 * response. The LEGACY `requireAgentJwt` preserves its exact prior behavior
 * (`invalid-token`→401 `{code,reason}`, `tenant-not-found`→404 ApiResponse,
 * `agent-not-registered`→403 ApiResponse, and tenant/platform-mismatch→401
 * `invalid()` as before). The provider route maps `kind` onto the spec §8 deny
 * codes (401 AUTHN_INVALID_TOKEN / AUTHN_TOKEN_EXPIRED, 403
 * AUTHN_PRINCIPAL_SCOPE_INVALID).
 */
export type AgentJwtFailureKind =
  | "invalid-token" // malformed/unverifiable/mismatched-claim token
  | "token-expired"
  | "tenant-not-found"
  | "agent-not-registered"
  | "principal-scope-invalid"; // tenant/platform claim mismatch

export interface AgentJwtAuthenticationFailure {
  kind: AgentJwtFailureKind;
  reason: string;
}

export function isAgentJwtFailure(
  v: AgentJwtAuthenticationResult | AgentJwtAuthenticationFailure,
): v is AgentJwtAuthenticationFailure {
  return "kind" in v && typeof (v as AgentJwtAuthenticationFailure).kind === "string";
}

/**
 * Verify a bearer agent JWT and resolve its tenant + agent, WITHOUT any
 * business-scope enforcement. Returns either a verified
 * {@link AgentJwtAuthenticationResult} or a typed
 * {@link AgentJwtAuthenticationFailure} the caller maps to a response.
 *
 * This is the single Eliza-Cloud RS256 authenticator (iss=eliza-cloud,
 * aud=steward). Multi-issuer discovery is deliberately outside this boundary.
 */
export async function authenticateAgentJwt(
  c: Context<{ Variables: AppVariables }>,
  options: { rejectCapabilityScopes?: boolean } = {},
): Promise<AgentJwtAuthenticationResult | AgentJwtAuthenticationFailure> {
  const token = getBearer(c);
  if (!token) return { kind: "invalid-token", reason: "missing bearer token" };

  const header = decodeJwtHeader(token);
  if (!header?.kid) return { kind: "invalid-token", reason: "missing kid" };
  if (header.alg !== "RS256") return { kind: "invalid-token", reason: "unsupported alg" };

  try {
    const jwksUrl = resolveJwksUrl();
    const hadFreshCache = Boolean(jwksCache?.url === jwksUrl && jwksCache.expiresAt > Date.now());
    let keys = await loadJwks(false, jwksUrl);
    let key = keys.get(header.kid);
    // Issuers can publish a rotated kid before this process's cache expires.
    // Refresh exactly once on a miss so rotation is prompt while an actually
    // unknown kid remains fail-closed.
    const now = Date.now();
    if (!key && hadFreshCache && now - lastJwksMissRefreshAt >= JWKS_MISS_REFRESH_MIN_INTERVAL_MS) {
      lastJwksMissRefreshAt = now;
      keys = await loadJwks(true, jwksUrl);
      key = keys.get(header.kid);
    }
    if (!key) return { kind: "invalid-token", reason: "unknown kid" };

    const { payload } = await jwtVerify(token, key, {
      issuer: "eliza-cloud",
      audience: "steward",
      algorithms: ["RS256"],
    });
    const agentId = agentIdFromPayload(payload);
    if (!agentId) return { kind: "invalid-token", reason: "invalid agent claims" };
    const scopes = stringArrayClaim(payload, "scopes", "scope");
    if (options.rejectCapabilityScopes && scopes.some((scope) => scope.startsWith("cap:"))) {
      return { kind: "invalid-token", reason: "unsupported capability scope" };
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (typeof payload.iat === "number" && payload.iat > nowSeconds + MAX_IAT_CLOCK_SKEW_SECONDS) {
      return { kind: "invalid-token", reason: "token issued in the future" };
    }

    const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
    // Tenant binding: when the token DOES carry a tenant claim it MUST match the
    // requested tenant (prevents a token minted for tenant A from acting on
    // tenant B). When the trusted issuer omits the claim (the eliza-cloud
    // single-tenant minter does not embed tenant_id), we do NOT reject — the
    // agent→tenant binding is still enforced below by ensureAgentForTenant, which
    // 403s if this agent is not registered for the requested tenant. The token is
    // already JWKS-verified (iss=eliza-cloud, aud=steward, RS256) at this point.
    const tokenTenantId = stringClaim(payload, "tenant_id", "tenantId");
    if (tokenTenantId && tokenTenantId !== tenantId) {
      return { kind: "principal-scope-invalid", reason: "invalid tenant claims" };
    }
    const tenant = await findTenant(tenantId);
    if (!tenant) return { kind: "tenant-not-found", reason: "Tenant not found" };
    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) {
      return { kind: "agent-not-registered", reason: "agent is not registered for tenant" };
    }
    // Platform binding: when the token carries a platform_id it MUST match the
    // agent's registered platform (prevents a token scoped to platform A from
    // acting as the agent on platform B). When the trusted issuer omits the claim
    // (the eliza-cloud minter does not embed platform_id), we do NOT reject — the
    // agent identity is already established via the JWKS-verified sub + the
    // tenant→agent registration check above. Symmetric with the tenant_id handling.
    const tokenPlatformId = stringClaim(payload, "platform_id", "platformId");
    if (agent.platformId && tokenPlatformId && tokenPlatformId !== agent.platformId) {
      return { kind: "principal-scope-invalid", reason: "invalid platform claims" };
    }

    const jti = stringClaim(payload, "jti");
    return {
      tenant,
      tenantId,
      agentId,
      scopes,
      issuer: typeof payload.iss === "string" ? payload.iss : "eliza-cloud",
      subject: typeof payload.sub === "string" ? payload.sub : `agent:${agentId}`,
      tokenId: jti,
      platformId: agent.platformId ?? tokenPlatformId ?? null,
      exp: typeof payload.exp === "number" ? payload.exp : null,
      iat: typeof payload.iat === "number" ? payload.iat : null,
    };
  } catch (error) {
    if (error instanceof errors.JWTExpired) {
      observeExpiredAgentToken(c, token);
      return { kind: "token-expired", reason: "token expired" };
    }
    if (error instanceof errors.JWTClaimValidationFailed) {
      if (error.claim === "iss") return { kind: "invalid-token", reason: "invalid issuer" };
      if (error.claim === "aud") return { kind: "invalid-token", reason: "invalid audience" };
      if (error.claim === "nbf") return { kind: "invalid-token", reason: "token not active" };
      return { kind: "invalid-token", reason: "invalid token claims" };
    }
    const reason = error instanceof Error ? error.message : "verification failed";
    return { kind: "invalid-token", reason };
  }
}

function epochToRfc3339(epochSeconds: number | null): string | null {
  if (epochSeconds === null || !Number.isFinite(epochSeconds)) return null;
  return new Date(epochSeconds * 1000).toISOString();
}

/**
 * Install the verified agent identity into request context. Preserves ALL
 * existing context writes (`setTenantContext` + `agentScopes`) and ADDITIONALLY
 * sets the runtime-neutral `verifiedAgentPrincipal` — the value provider-action
 * routes read to derive the immutable actor. Headers can never set it.
 */
export async function installAgentJwtContext(
  c: Context<{ Variables: AppVariables }>,
  auth: AgentJwtAuthenticationResult,
): Promise<void> {
  await observeAgentTokenExpiry(auth.tenantId, auth.agentId, auth.exp ?? undefined);
  await setTenantContext(c, auth.tenant, auth.tenantId, auth.agentId);
  c.set("agentScopes", [AGENT_SCOPE, ...auth.scopes]);
  const principal: VerifiedAgentPrincipal = {
    type: "agent",
    agentId: auth.agentId,
    tenantId: auth.tenantId,
    platformId: auth.platformId,
    issuer: auth.issuer,
    subject: auth.subject,
    tokenId: auth.tokenId,
    scopes: auth.scopes,
    authenticatedAt: new Date().toISOString(),
    expiresAt: epochToRfc3339(auth.exp),
    authnMethod: "agent-jwt-rs256",
  };
  c.set("verifiedAgentPrincipal", principal);
}

/**
 * LEGACY trading middleware. Authenticates the agent JWT, then REQUIRES the
 * `trade:order` scope, installs context, and continues. Existing routes and
 * response behavior are unchanged — this preserves the exact wire behavior the
 * trading endpoints depend on.
 */
export async function requireAgentJwt(c: Context<{ Variables: AppVariables }>, next: Next) {
  const auth = await authenticateAgentJwt(c, { rejectCapabilityScopes: true });
  if (isAgentJwtFailure(auth)) {
    // Preserve the EXACT legacy wire behavior per failure kind.
    if (auth.kind === "tenant-not-found") {
      return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
    }
    if (auth.kind === "agent-not-registered") {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: agent is not registered for tenant" },
        403,
      );
    }
    // invalid-token / token-expired / principal-scope-invalid all rendered 401
    // `invalid()` in the prior implementation.
    return invalid(c, auth.reason, 401);
  }

  if (!auth.scopes.includes(TRADE_ORDER_SCOPE)) {
    return c.json<ApiResponse>(
      { ok: false, error: `Token missing required ${TRADE_ORDER_SCOPE} scope` },
      403,
    );
  }

  await installAgentJwtContext(c, auth);
  return next();
}

/**
 * CAPABILITY middleware. Authenticates the agent JWT and installs context with
 * NO `trade:order` requirement. The agent-facing capability surface (invoke /
 * manifest / issuance) is authorized per-call by the capability grant +
 * capability-intent policy (default-deny), never by the trading scope — so
 * requiring `trade:order` here both locked out capability-only agents and
 * handed every trading agent implicit capability access (scope conflation).
 * Wire behavior matches the legacy gate this replaces on that surface.
 */
export async function requireCapabilityAgentJwt(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
) {
  const auth = await authenticateAgentJwt(c);
  if (isAgentJwtFailure(auth)) {
    if (auth.kind === "tenant-not-found") {
      return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
    }
    if (auth.kind === "agent-not-registered") {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: agent is not registered for tenant" },
        403,
      );
    }
    return invalid(c, auth.reason, 401);
  }

  await installAgentJwtContext(c, auth);
  return next();
}

/**
 * PROVIDER-ACTION middleware. Authenticates the agent JWT and installs context
 * with NO trading or proxy scope check — provider authority is decided later by
 * bindings/grants, never by token scope. ONLY provider-action routes use this.
 */
export async function requireProviderAgentJwt(c: Context<{ Variables: AppVariables }>, next: Next) {
  const auth = await authenticateAgentJwt(c, { rejectCapabilityScopes: true });
  if (isAgentJwtFailure(auth)) {
    // Map onto the spec §8 deny table for provider-action routes.
    if (auth.kind === "token-expired") {
      return c.json<ApiResponse>({ ok: false, error: "AUTHN_TOKEN_EXPIRED" }, 401);
    }
    if (auth.kind === "principal-scope-invalid" || auth.kind === "agent-not-registered") {
      return c.json<ApiResponse>({ ok: false, error: "AUTHN_PRINCIPAL_SCOPE_INVALID" }, 403);
    }
    if (auth.kind === "tenant-not-found") {
      // A provider action for an unknown tenant is a principal-scope failure, not
      // an existence oracle: collapse to 403 principal-scope-invalid.
      return c.json<ApiResponse>({ ok: false, error: "AUTHN_PRINCIPAL_SCOPE_INVALID" }, 403);
    }
    return c.json<ApiResponse>({ ok: false, error: "AUTHN_INVALID_TOKEN" }, 401);
  }
  await installAgentJwtContext(c, auth);
  return next();
}

export function clearAgentJwksCacheForTests() {
  jwksCache = null;
  lastJwksMissRefreshAt = 0;
}
