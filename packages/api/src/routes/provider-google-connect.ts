/**
 * Google Workspace provider-account OAuth connect routes.
 *
 * Mounted under `/v2/provider-accounts/connect/google`. Every route requires a human
 * session (session-jwt) with MFA verified within five minutes AND workspace
 * admin/approver authority (or tenant authority admin) for the target workspace.
 * These are the PROVIDER-CONNECTION routes (agent execution authority), distinct
 * from user login.
 *
 *   POST   /v2/provider-accounts/connect/google/initiate     -> authorize URL + token
 *   POST   /v2/provider-accounts/connect/google/callback     -> exchange + store
 *   POST   /v2/provider-accounts/connect/google/:id/refresh  -> rotate access token
 *   POST   /v2/provider-accounts/connect/google/:id/disconnect
 *
 * The callback is a POST (not a browser GET redirect): the initiating client
 * receives the provider redirect, then POSTs {code, state, connectToken} back to
 * Steward with its session credentials. This keeps the connect exchange on the
 * authenticated provider-authority plane rather than an unauthenticated browser
 * hop, matching the repo's `/oauth/exchange` hardening for sensitive flows.
 */

import { buildBackend, ChallengeStore } from "@stwd/auth";
import type { AppVariables } from "@stwd/shared";
import { SecretVault } from "@stwd/vault";
import type { Context, Hono } from "hono";
import {
  type ApiResponse,
  MASTER_PASSWORD,
  safeJsonParse,
  setNoStoreHeaders,
  tenantAuth,
} from "../services/context";
import { providerAuthorityStore } from "../services/provider-authority-store";
import {
  assertGoogleConnectStoreIsSafe,
  completeGoogleConnect,
  disconnectGoogleProviderCredential,
  GOOGLE_CONNECT_STATE_TTL_MS,
  GoogleConnectError,
  initiateGoogleConnect,
  type PendingConnectStore,
  refreshGoogleProviderCredential,
  resolveGoogleConnectConfig,
} from "../services/provider-google-connect";
import { hasRecentGoogleConnectMfa } from "../services/provider-google-connect-mfa";
import { assertAllowedOAuthRedirectUri } from "./auth";

type RouteContext = Context<{ Variables: AppVariables }>;

// ── Pending-connect state store (Redis-backed in prod, memory otherwise) ──────
// Reuses the auth challenge backend selection so connect state survives worker
// restarts and round-robin between isolates, exactly like the user-auth OAuth
// state. Lazily initialised so context can set env first.
let _connectStore: PendingConnectStore | null = null;
async function getConnectStore(): Promise<PendingConnectStore> {
  if (_connectStore) return _connectStore;
  const { getRedisClient } = await import("../middleware/redis.js");
  const redisClient = getRedisClient();
  const usePostgres = process.env.STEWARD_AUTH_STORE_BACKEND === "postgres";
  const { backend, source } = await buildBackend("challenge", redisClient, usePostgres);
  assertGoogleConnectStoreIsSafe(source);
  // TTL is fixed at construction; the store's set() ignores a per-call ttl.
  const store = new ChallengeStore({ backend, ttlMs: GOOGLE_CONNECT_STATE_TTL_MS });
  _connectStore = {
    set: (key, value) => store.set(key, value),
    get: (key) => store.get(key),
    consume: (key) => store.consume(key),
  };
  return _connectStore;
}

/** Test seam: inject an in-memory store so route tests never touch Redis. */
export function __setProviderGoogleConnectStoreForTests(store: PendingConnectStore | null): void {
  _connectStore = store;
}

let _vault: SecretVault | null = null;
function getVault(): SecretVault {
  _vault ??= new SecretVault(MASTER_PASSWORD);
  return _vault;
}

function fail(c: RouteContext, error: unknown): Response {
  if (error instanceof GoogleConnectError) {
    return c.json<ApiResponse>({ ok: false, error: error.code }, error.httpStatus as never);
  }
  throw error;
}

/**
 * Require a human session + workspace connect authority. Returns the userId, or
 * a Response to short-circuit. Mirrors provider-authority.ts's 404 parity: an
 * unauthorized caller gets 404 (resource not found) so authority state does not
 * leak, matching the approval-lifecycle conventions.
 */
async function requireConnectAuthority(
  c: RouteContext,
  workspaceId: string,
): Promise<{ userId: string } | Response> {
  const userId = c.get("userId");
  if (c.get("authType") !== "session-jwt" || !userId) {
    return c.json<ApiResponse>({ ok: false, error: "human session required" }, 403);
  }
  if (!hasRecentGoogleConnectMfa(c.get("sessionMfaVerifiedAt"))) {
    return c.json<ApiResponse>({ ok: false, error: "recent MFA verification required" }, 403);
  }
  if (!workspaceId) {
    return c.json<ApiResponse>({ ok: false, error: "resource not found" }, 404);
  }
  const authorized = await providerAuthorityStore.canConnectProviderAccounts(
    c.get("tenantId"),
    workspaceId,
    userId,
    c.get("tenantRole") ?? "",
  );
  if (!authorized) {
    return c.json<ApiResponse>({ ok: false, error: "resource not found" }, 404);
  }
  return { userId };
}

// ── Initiate ──────────────────────────────────────────────────────────────────
const handleInitiate = async (c: RouteContext): Promise<Response> => {
  const body = await safeJsonParse<{
    workspaceId?: string;
    redirectUri?: string;
    scopes?: string[];
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  const workspaceId = typeof body.workspaceId === "string" ? body.workspaceId : "";
  const redirectUri = typeof body.redirectUri === "string" ? body.redirectUri.trim() : "";
  if (!redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "redirectUri is required" }, 400);
  }

  const gate = await requireConnectAuthority(c, workspaceId);
  if (gate instanceof Response) return gate;

  // The redirect_uri is where Google sends the authorization code; it MUST be on the
  // tenant allowlist so an authorized-but-hostile workspace member cannot direct
  // the code to an attacker endpoint. Same gate as the user-auth OAuth flow.
  try {
    await assertAllowedOAuthRedirectUri(redirectUri, c.get("tenantId"));
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirect_uri" },
      400,
    );
  }

  try {
    const config = resolveGoogleConnectConfig();
    const store = await getConnectStore();
    const result = await initiateGoogleConnect({
      tenantId: c.get("tenantId"),
      workspaceId,
      initiatedByUserId: gate.userId,
      redirectUri,
      scopes: Array.isArray(body.scopes)
        ? body.scopes.filter((s): s is string => typeof s === "string")
        : undefined,
      config,
      store,
      requestId: c.get("requestId") ?? null,
    });
    return c.json({
      ok: true,
      data: {
        authorizeUrl: result.authorizeUrl,
        state: result.state,
        connectToken: result.connectToken,
      },
    });
  } catch (error) {
    return fail(c, error);
  }
};

// ── Callback (exchange + store) ───────────────────────────────────────────────
const handleCallback = async (c: RouteContext): Promise<Response> => {
  const body = await safeJsonParse<{
    workspaceId?: string;
    code?: string;
    state?: string;
    connectToken?: string;
    redirectUri?: string;
    error?: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  if (typeof body.error === "string" && body.error.length > 0) {
    const providerCode = /^[a-z0-9_.-]{1,128}$/i.test(body.error)
      ? body.error
      : "authorization_failed";
    return c.json<ApiResponse>({ ok: false, error: `Google OAuth error: ${providerCode}` }, 400);
  }
  const workspaceId = typeof body.workspaceId === "string" ? body.workspaceId : "";
  const code = typeof body.code === "string" ? body.code : "";
  const state = typeof body.state === "string" ? body.state : "";
  const connectToken = typeof body.connectToken === "string" ? body.connectToken : "";
  const redirectUri = typeof body.redirectUri === "string" ? body.redirectUri.trim() : "";
  if (!code || !state || !connectToken || !redirectUri) {
    return c.json<ApiResponse>(
      { ok: false, error: "code, state, connectToken, redirectUri are required" },
      400,
    );
  }

  const gate = await requireConnectAuthority(c, workspaceId);
  if (gate instanceof Response) return gate;

  // Re-assert the redirect_uri allowlist on callback too (defence in depth; the
  // service also binds the state's stored redirect_uri to this value).
  try {
    await assertAllowedOAuthRedirectUri(redirectUri, c.get("tenantId"));
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirect_uri" },
      400,
    );
  }

  try {
    const config = resolveGoogleConnectConfig();
    const store = await getConnectStore();
    const result = await completeGoogleConnect({
      tenantId: c.get("tenantId"),
      workspaceId,
      callerUserId: gate.userId,
      code,
      state,
      connectToken,
      redirectUri,
      config,
      store,
      vault: getVault(),
      requestId: c.get("requestId") ?? null,
    });
    return c.json({ ok: true, data: result }, result.reconnected ? 200 : 201);
  } catch (error) {
    return fail(c, error);
  }
};

// ── Refresh ───────────────────────────────────────────────────────────────────
const handleRefresh = async (c: RouteContext): Promise<Response> => {
  const body = await safeJsonParse<{ workspaceId?: string; force?: boolean }>(c);
  const workspaceId = typeof body?.workspaceId === "string" ? body.workspaceId : "";
  const accountId = c.req.param("id") ?? "";

  const gate = await requireConnectAuthority(c, workspaceId);
  if (gate instanceof Response) return gate;

  try {
    const config = resolveGoogleConnectConfig();
    const result = await refreshGoogleProviderCredential({
      tenantId: c.get("tenantId"),
      workspaceId,
      accountId,
      vault: getVault(),
      config,
      actorId: gate.userId,
      force: body?.force === true,
      requestId: c.get("requestId") ?? null,
    });
    return c.json({ ok: true, data: result });
  } catch (error) {
    return fail(c, error);
  }
};

// ── Disconnect ────────────────────────────────────────────────────────────────
const handleDisconnect = async (c: RouteContext): Promise<Response> => {
  const body = await safeJsonParse<{ workspaceId?: string }>(c);
  const workspaceId = typeof body?.workspaceId === "string" ? body.workspaceId : "";
  const accountId = c.req.param("id") ?? "";

  const gate = await requireConnectAuthority(c, workspaceId);
  if (gate instanceof Response) return gate;

  try {
    const config = resolveGoogleConnectConfig();
    const result = await disconnectGoogleProviderCredential({
      tenantId: c.get("tenantId"),
      workspaceId,
      accountId,
      callerUserId: gate.userId,
      vault: getVault(),
      config,
      requestId: c.get("requestId") ?? null,
    });
    return c.json({ ok: true, data: result });
  } catch (error) {
    return fail(c, error);
  }
};

// ── Registration ──────────────────────────────────────────────────────────────
// Registered CONCRETELY (like provider-actions / provider-approvals) and BEFORE
// the `/v2` authority sub-app so the specific connect paths win over the
// authority `/provider-accounts/:id/...` wildcards. Each path gets no-store +
// tenantAuth middleware.
export function registerProviderGoogleConnectRoutes(app: Hono<{ Variables: AppVariables }>): void {
  const base = "/v2/provider-accounts/connect/google";
  const paths = [
    `${base}/initiate`,
    `${base}/callback`,
    `${base}/:id/refresh`,
    `${base}/:id/disconnect`,
  ];
  for (const p of paths) {
    app.use(p, async (c, next) => {
      setNoStoreHeaders(c);
      await next();
    });
    app.use(p, (c, next) => tenantAuth(c, next));
  }
  app.post(`${base}/initiate`, handleInitiate);
  app.post(`${base}/callback`, handleCallback);
  app.post(`${base}/:id/refresh`, handleRefresh);
  app.post(`${base}/:id/disconnect`, handleDisconnect);
}
