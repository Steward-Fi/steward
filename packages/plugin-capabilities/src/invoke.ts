/**
 * invoke.ts - the AGENT-FACING capability invoke path (W-1c).
 *
 * POST /capabilities/:name/invoke  { args?, body?, query? }
 * POST /capabilities/:name/openai/v1/chat/completions  <OpenAI chat body>
 * GET  /capabilities/:name/openai/v1/models
 *
 * Agent identity comes from the agent token (c.get("agentScope")), never from the
 * request body. Allowed calls are delegated through @stwd/proxy-client, which
 * mints/signs the proxy call server-side so agents never receive raw upstream
 * keys or proxy HMAC material.
 */

import { signAgentToken } from "@stwd/auth";
import { secretRoutes, secrets } from "@stwd/db";
import {
  CAPABILITY_INTENT_RULE_TYPE,
  composeCapabilityIntentDecision,
  type EvaluatorContext,
  PolicyEngine,
} from "@stwd/policy-engine";
import { StewardProxyClient } from "@stwd/proxy-client";
import type { ApiResponse, AppVariables, PolicyRule, SignRequest } from "@stwd/shared";
import { Hono } from "hono";
import type { StewardAppContext } from "./context";
import { enforceCapabilityRateLimit } from "./rate-limit";
import type { Capability, InvocationDecision } from "./schema";
import { CapabilityStore } from "./store";

/** the proxy scope an invoke-minted agent token must carry. mirrors @stwd/proxy config. */
const PROXY_SCOPE = "api:proxy";
/** short-lived: the token only needs to survive the single proxied call. */
const PROXY_TOKEN_TTL = "2m";

interface ProxyEnv {
  proxyUrl: string;
  signingSecret: string;
}

export interface CapabilityInvokeRequest {
  tenantId: string;
  agentId: string;
  name: string;
  args?: Record<string, unknown>;
  body?: unknown;
  query?: unknown;
}

const INVOKE_ENVELOPE_KEYS = new Set(["args", "body", "query"]);
const MAX_QUERY_SELECTORS = 32;
const MAX_QUERY_SELECTOR_KEY_LENGTH = 128;
const MAX_QUERY_SELECTOR_VALUE_LENGTH = 2_048;
const MAX_ENCODED_QUERY_LENGTH = 8_192;

/**
 * Internal marker on Steward-wrapped ({ok:...}) gate responses. The upstream
 * passthrough (verbatim provider body) is built with a raw `new Response` and
 * therefore never carries this header, so the OpenAI adapter can distinguish a
 * Steward gate decision (translate to OpenAI-error shape) from an upstream body
 * (pass through untouched). Stripped before the response leaves the adapter.
 */
const GATE_MARKER_HEADER = "x-steward-cap-gate";

function jsonResponse(payload: ApiResponse, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json", [GATE_MARKER_HEADER]: "1" },
  });
}

/** OpenAI-error `type` bucket for a Steward gate status, so the SDK surfaces it cleanly. */
function openAIErrorType(status: number): string {
  if (status === 401) return "invalid_request_error";
  if (status === 403) return "permission_error";
  if (status === 429) return "rate_limit_error";
  if (status === 400) return "invalid_request_error";
  return "api_error";
}

/**
 * Translate a Steward-gated adapter response into an OpenAI-compatible response
 * the OpenAI SDK can parse. Upstream passthroughs (no gate marker) and the 202
 * approval envelope pass through unchanged; only Steward-wrapped {ok:false,error}
 * gate DENIALS are reshaped to {error:{message,type}} with the same status. The
 * gate marker header is always stripped.
 */
/** Strip the internal gate marker so it never leaks to a client. No-op if absent. */
function stripGateMarker(res: Response): Response {
  if (!res.headers.has(GATE_MARKER_HEADER)) return res;
  const headers = new Headers(res.headers);
  headers.delete(GATE_MARKER_HEADER);
  return new Response(res.body, { status: res.status, headers });
}

async function toOpenAICompatible(res: Response): Promise<Response> {
  const isGate = res.headers.get(GATE_MARKER_HEADER) === "1";
  if (!isGate) return res;

  const headers = new Headers(res.headers);
  headers.delete(GATE_MARKER_HEADER);

  // approval (202) and any success wrapper keep their Steward shape (there is no
  // OpenAI-error equivalent for "pending approval"); only reshape error bodies.
  if (res.ok) {
    return new Response(res.body, { status: res.status, headers });
  }

  let message = "request denied";
  try {
    const parsed = (await res.clone().json()) as { error?: unknown };
    if (typeof parsed.error === "string" && parsed.error.trim() !== "") message = parsed.error;
  } catch {
    // non-JSON gate body (should not happen): keep the default message.
  }
  headers.set("content-type", "application/json");
  return new Response(JSON.stringify({ error: { message, type: openAIErrorType(res.status) } }), {
    status: res.status,
    headers,
  });
}

function readProxyEnv(env: NodeJS.ProcessEnv = process.env): ProxyEnv | null {
  const proxyUrl = (env.STEWARD_PROXY_URL ?? "").trim();
  const signingSecret = (
    env.STEWARD_PROXY_REQUEST_SIGNING_SECRET ??
    env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS?.split(",")[0] ??
    ""
  ).trim();
  if (!proxyUrl || !signingSecret) return null;
  return { proxyUrl, signingSecret };
}

// Minimal host/path matchers mirroring @stwd/proxy matching.ts (that package is
// not a dependency here). Used ONLY to detect whether a governed route claims
// this capability's surface so we can fail closed — a broad match is acceptable
// because it only ever DENIES (never grants).
function pluginMatchHost(pattern: string, host: string): boolean {
  if (pattern === host) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return false;
}
function pluginMatchPath(pattern: string | null | undefined, path: string): boolean {
  const p = pattern ?? "/*";
  if (p === "/*" || p === "*") return true;
  if (p === path) return true;
  if (p.endsWith("/*")) return path.startsWith(p.slice(0, -1));
  return false;
}

/**
 * True when the resolved capability maps to a `governed_v2` secret route for this
 * tenant/agent (matched by host + path + method). Governed routes must NOT be
 * invokable through the plugin (spec §5.2, P03/P04). Throws are treated as
 * fail-closed by the caller.
 */
async function capabilityMapsToGovernedRoute(
  db: StewardAppContext["db"],
  tenantId: string,
  agentId: string,
  cap: Capability,
): Promise<boolean> {
  const { and, eq, gt, isNull, or } = await import("drizzle-orm");
  const now = new Date();
  // Mirror the proxy's route SELECTION (codex P2): only ENABLED governed routes
  // whose backing secret is currently active (not deleted, not expired) can ever
  // be selected by the proxy, so only those should gate the plugin. A disabled
  // governed route or one backed by a deleted/expired secret is unselectable and
  // must NOT block an otherwise-valid plugin invocation (rollback/cutover leaves
  // such stale rows). Join secrets exactly like findMatchingRoute.
  const rows = await (
    db as unknown as {
      select: (c: Record<string, unknown>) => {
        from: (t: unknown) => {
          innerJoin: (
            t: unknown,
            on: unknown,
          ) => {
            where: (w: unknown) => Promise<
              Array<{
                hostPattern: string;
                pathPattern: string | null;
                method: string | null;
                authorityMode: string | null;
              }>
            >;
          };
        };
      };
    }
  )
    .select({
      hostPattern: secretRoutes.hostPattern,
      pathPattern: secretRoutes.pathPattern,
      method: secretRoutes.method,
      authorityMode: secretRoutes.authorityMode,
    })
    .from(secretRoutes)
    .innerJoin(
      secrets,
      and(
        eq(secrets.id, secretRoutes.secretId),
        eq(secrets.tenantId, tenantId),
        isNull(secrets.deletedAt),
        or(isNull(secrets.expiresAt), gt(secrets.expiresAt, now)),
      ),
    )
    .where(
      and(
        eq(secretRoutes.tenantId, tenantId),
        eq(secretRoutes.agentId, agentId),
        eq(secretRoutes.authorityMode, "governed_v2"),
        eq(secretRoutes.enabled, true),
      ),
    );
  const capMethod = cap.method.toUpperCase();
  return rows.some(
    (r) =>
      pluginMatchHost(r.hostPattern, cap.host) &&
      pluginMatchPath(r.pathPattern, cap.pathPattern) &&
      (!r.method || r.method === "*" || r.method.toUpperCase() === capMethod),
  );
}

type NormalizedQuerySelectors = {
  args: Record<string, unknown>;
  query: Record<string, string> | undefined;
};

/**
 * Validate the agent-controlled query surface and make the exact values that
 * will be forwarded visible to capability-intent policy evaluation. A caller
 * may describe a selector once in `query`, or repeat it in `args`; a repeated
 * value must be byte-for-byte identical so authorization and dispatch cannot
 * disagree about the selected resource.
 */
function normalizeQuerySelectors(
  args: Record<string, unknown>,
  rawQuery: unknown,
): NormalizedQuerySelectors | null {
  if (rawQuery === undefined) return { args, query: undefined };
  if (rawQuery === null || typeof rawQuery !== "object" || Array.isArray(rawQuery)) return null;

  const entries = Object.entries(rawQuery as Record<string, unknown>);
  if (entries.length > MAX_QUERY_SELECTORS) return null;

  // Null-prototype records keep special JavaScript property names (notably
  // `__proto__`) as ordinary data if a provider legitimately uses them.
  const query: Record<string, string> = Object.create(null) as Record<string, string>;
  const effectiveArgs: Record<string, unknown> = Object.assign(
    Object.create(null) as Record<string, unknown>,
    args,
  );
  for (const [key, value] of entries) {
    if (
      key.length === 0 ||
      key.length > MAX_QUERY_SELECTOR_KEY_LENGTH ||
      typeof value !== "string" ||
      value.length > MAX_QUERY_SELECTOR_VALUE_LENGTH
    ) {
      return null;
    }
    if (Object.hasOwn(args, key) && args[key] !== value) return null;
    query[key] = value;
    effectiveArgs[key] = value;
  }

  const encoded = new URLSearchParams(query).toString();
  if (encoded.length > MAX_ENCODED_QUERY_LENGTH) return null;
  return { args: effectiveArgs, query: entries.length > 0 ? query : undefined };
}

function buildProxyPath(cap: Capability, query: Record<string, string> | undefined): string {
  const host = cap.host.toLowerCase();
  const basePath = cap.pathPattern.startsWith("/") ? cap.pathPattern : `/${cap.pathPattern}`;
  let path = `/proxy/${host}${basePath}`;
  if (query && Object.keys(query).length > 0) {
    const qs = new URLSearchParams(query).toString();
    if (qs) path += (path.includes("?") ? "&" : "?") + qs;
  }
  return path;
}

function syntheticSignRequest(tenantId: string, agentId: string): SignRequest {
  return {
    agentId,
    tenantId,
    to: "0x0000000000000000000000000000000000000000",
    value: "0",
    chainId: 0,
    broadcast: false,
  };
}

function isCapabilityIntentRule(rule: PolicyRule): boolean {
  return (rule.type as string) === (CAPABILITY_INTENT_RULE_TYPE as string);
}

async function recordAndJson(
  store: CapabilityStore,
  args: {
    tenantId: string;
    agentId: string;
    capabilityId: string | null;
    decision: InvocationDecision;
    status: number;
    payload: ApiResponse;
  },
): Promise<Response> {
  try {
    await store.recordInvocation({
      tenantId: args.tenantId,
      agentId: args.agentId,
      capabilityId: args.capabilityId,
      decision: args.decision,
    });
  } catch {
    // audit write failed: do NOT block the already fail-closed decision.
  }
  return jsonResponse(args.payload, args.status);
}

/**
 * Shared capability invoke core. This preserves the W-1c invariants for both the
 * envelope invoke route and the OpenAI-compatible adapter: resolve enabled
 * capability + active grant, count invocations, default-deny capability-intent
 * policy, approval 202, proxy env 503, server-side proxy signing, and exactly one
 * invocation row for every terminal outcome.
 */
export async function invokeCapabilityThroughProxy(
  ctx: StewardAppContext,
  request: CapabilityInvokeRequest,
): Promise<Response> {
  const store = new CapabilityStore(ctx.db);
  const engine = new PolicyEngine();
  const { tenantId, agentId, name } = request;

  const usable = await store.listUsableCapabilitiesForAgent(tenantId, agentId);
  const match = usable.find((u) => u.capability.name === name);
  if (!match) {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: null,
      decision: "deny",
      status: 403,
      payload: { ok: false, error: "capability not available to agent" } satisfies ApiResponse,
    });
  }
  const cap = match.capability;

  const selectors = normalizeQuerySelectors(request.args ?? {}, request.query);
  if (!selectors) {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 400,
      payload: { ok: false, error: "invalid capability query selectors" } satisfies ApiResponse,
    });
  }
  const invokeArgs = selectors.args;

  let count1h: number;
  try {
    count1h = await store.countInvocations1h(agentId, cap.id);
  } catch {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: { ok: false, error: "policy evaluation unavailable" } satisfies ApiResponse,
    });
  }

  const evaluatedAt = new Date().toISOString();
  const capabilityCtx: NonNullable<EvaluatorContext["capability"]> = {
    name: cap.name,
    args: invokeArgs,
    host: cap.host,
    path: cap.pathPattern,
    method: cap.method,
    evaluatedAt,
  };

  let policySet: PolicyRule[];
  try {
    policySet = await ctx.getPolicySet(tenantId, agentId);
  } catch {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: { ok: false, error: "policy evaluation unavailable" } satisfies ApiResponse,
    });
  }
  const capRules = policySet.filter((r) => isCapabilityIntentRule(r) && r.enabled !== false);

  const evaluatorCtx: EvaluatorContext = {
    request: syntheticSignRequest(tenantId, agentId),
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    capability: capabilityCtx,
    capabilityInvokeCount1h: count1h,
  };

  // FAIL-CLOSED OUTER BOUNDARY. Both the generic engine sweep and the canonical
  // composer are defensively non-throwing by contract (the composer wraps every
  // per-rule body; the registry describes hostile thrown values with a
  // non-throwing helper). But this invoke path is a security gate: a throw here
  // — from either call, a hostile jsonb getter deserializing `r.config`, or any
  // unforeseen path — must DENY (403), never escape as a raw 500 (which callers
  // could treat as a transient/retryable failure and which reveals nothing about
  // the gate). We therefore wrap the entire evaluate+compose region and translate
  // ANY escape into a fail-closed deny.
  let decision: ReturnType<typeof composeCapabilityIntentDecision>;
  try {
    await engine.evaluate(capRules, evaluatorCtx);

    // CANONICAL PRECEDENCE (master-plan §5.3): the policy-engine helper composes
    // ALL enabled capability-intent rules in the one true order — hard deny
    // (incl. malformed config / failed hard constraint) > approval_required >
    // allow > default-deny. This is the single source of truth: an applicable
    // require-approval can NEVER be shadowed by a matching allow, and a hard deny
    // can never be softened into an approval.
    //
    // We pass the FULL enabled capability-intent set (not a pre-filtered
    // "governing" subset): a MALFORMED rule config (e.g. a misspelled
    // `capabilities` key or an unsupported glob) makes a raw governing-match
    // filter return false, which would silently DROP the broken gate and fail
    // OPEN if a sibling allow matched. The composer instead parses every rule and
    // hard-denies on ANY malformation (fail closed), treats well-formed
    // non-governing rules as inert, and applies the effective default-deny when
    // no governing allow passes (covers the previous "no policy authorizes this
    // capability" 403).
    decision = composeCapabilityIntentDecision(
      capRules.map((r) => ({
        id: r.id,
        type: r.type as string,
        enabled: r.enabled,
        config: r.config,
      })),
      evaluatorCtx,
    );
  } catch {
    // A throw escaped the (defensively non-throwing) evaluation region. Fail
    // closed: deny, never 500. The reason is intentionally generic — it must not
    // leak internals and must not itself risk stringifying a hostile value.
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: { ok: false, error: "policy evaluation failed" } satisfies ApiResponse,
    });
  }

  if (decision.effect === "hard_deny") {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: {
        ok: false,
        error: decision.reason,
      } satisfies ApiResponse,
    });
  }

  if (decision.effect === "approval_required") {
    let approvalId: string | null = null;
    try {
      approvalId = await store.recordInvocation({
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "approval",
      });
    } catch {
      approvalId = null;
    }
    if (!approvalId) {
      return recordAndJson(store, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "deny",
        status: 403,
        payload: { ok: false, error: "approval enqueue failed" } satisfies ApiResponse,
      });
    }
    return jsonResponse({ ok: true, data: { approvalId, status: "pending" } }, 202);
  }

  // decision.effect === "allow": proceed to proxy delegation.

  const proxyEnv = readProxyEnv();
  if (!proxyEnv) {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "error",
      status: 503,
      payload: { ok: false, error: "capability delegation unavailable" } satisfies ApiResponse,
    });
  }

  // ── Governed-route plugin gate ─────────────────────────────────────────────
  // A governed_v2 route/operation cannot be invoked through the capability alias
  // or the OpenAI-compat adapter: the plugin's URLSearchParams path (G4) cannot
  // faithfully represent a governed action's duplicate-query semantics, and
  // governed actions must go through /v2/provider-actions, never a minted
  // proxy token. If the resolved capability maps to a governed route, the plugin
  // must NOT mint a proxy token; it denies with GOVERNED_ROUTE_PLUGIN_DENIED.
  try {
    const governed = await capabilityMapsToGovernedRoute(ctx.db, tenantId, agentId, cap);
    if (governed) {
      return recordAndJson(store, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "deny",
        status: 403,
        payload: {
          ok: false,
          error: "GOVERNED_ROUTE_PLUGIN_DENIED",
        } satisfies ApiResponse,
      });
    }
  } catch {
    // Fail closed: if we cannot prove the route is NOT governed, deny (X7).
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: {
        ok: false,
        error: "GOVERNED_ROUTE_PLUGIN_DENIED",
      } satisfies ApiResponse,
    });
  }

  let upstreamStatus: number;
  let upstreamBody: string;
  let upstreamContentType: string | null;
  try {
    const token = await signAgentToken(
      { agentId, tenantId, scopes: ["agent", PROXY_SCOPE] },
      PROXY_TOKEN_TTL,
    );
    const client = new StewardProxyClient({
      proxyUrl: proxyEnv.proxyUrl,
      token,
      signingSecret: proxyEnv.signingSecret,
      tenantId,
      agentId,
    });

    const method = cap.method.toUpperCase();
    const path = buildProxyPath(cap, selectors.query);
    const hasBody = method !== "GET" && method !== "HEAD" && request.body !== undefined;
    const init: RequestInit = { method };
    if (hasBody) {
      init.body = typeof request.body === "string" ? request.body : JSON.stringify(request.body);
      init.headers = { "content-type": "application/json" };
    }
    const res = await client.fetch(path, init);
    upstreamStatus = res.status;
    upstreamContentType = res.headers.get("content-type");
    upstreamBody = await res.text();
  } catch {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "error",
      status: 502,
      payload: { ok: false, error: "capability delegation failed" } satisfies ApiResponse,
    });
  }

  try {
    await store.recordInvocation({ tenantId, agentId, capabilityId: cap.id, decision: "allow" });
  } catch {
    // audit write failed: do NOT block the already-authorized upstream response.
  }

  // Return the upstream status/body passthrough verbatim (the proxy already
  // scrubbed the credential). Built with a raw Response so it never carries the
  // gate marker: the OpenAI adapter treats an unmarked response as an upstream
  // body and passes it through untouched. NOTE: the credential-injection proxy
  // fails closed on streaming (text/event-stream) responses, so this path only
  // ever carries a buffered upstream body; the OpenAI adapter rejects
  // `stream: true` up front (see createInvokeRoutes) to surface that cleanly.
  return new Response(upstreamBody, {
    status: upstreamStatus,
    headers: upstreamContentType ? { "content-type": upstreamContentType } : undefined,
  });
}

/** Active-grant check for compatibility routes that must not touch proxy/secret material. */
async function hasActiveGrant(
  ctx: StewardAppContext,
  args: CapabilityInvokeRequest,
): Promise<boolean> {
  const store = new CapabilityStore(ctx.db);
  const usable = await store.listUsableCapabilitiesForAgent(args.tenantId, args.agentId);
  return usable.some((u) => u.capability.name === args.name);
}

export function createInvokeRoutes(ctx: StewardAppContext): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();

  routes.post("/:name/invoke", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return stripGateMarker(
        jsonResponse({ ok: false, error: "agent authentication required" }, 401),
      );
    }

    // Per-agent throttle BEFORE any DB/upstream work (SEC-094); the 429 path
    // deliberately writes no invocation row (that write is the vector throttled).
    const rate = await enforceCapabilityRateLimit(ctx, "invoke", agentId);
    if (!rate.allowed) {
      const res = jsonResponse({ ok: false, error: "capability invoke rate limit exceeded" }, 429);
      res.headers.set("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
      return stripGateMarker(res);
    }

    type InvokeEnvelope = {
      args?: unknown;
      body?: unknown;
      query?: unknown;
    };
    let envelope: InvokeEnvelope = {};
    let rawBody = "";
    try {
      rawBody = await c.req.text();
    } catch {
      rawBody = "";
    }
    if (rawBody.trim() !== "") {
      try {
        const parsedBody = JSON.parse(rawBody);
        if (parsedBody === null || typeof parsedBody !== "object" || Array.isArray(parsedBody)) {
          return stripGateMarker(
            jsonResponse({ ok: false, error: "invoke body must be a JSON object" }, 400),
          );
        }
        const parsedEnvelope = parsedBody as Record<string, unknown>;
        if (Object.keys(parsedEnvelope).some((key) => !INVOKE_ENVELOPE_KEYS.has(key))) {
          return stripGateMarker(
            jsonResponse({ ok: false, error: "unknown field in capability invoke body" }, 400),
          );
        }
        envelope = parsedEnvelope as InvokeEnvelope;
      } catch {
        return stripGateMarker(
          jsonResponse({ ok: false, error: "invalid JSON in request body" }, 400),
        );
      }
    }

    if (
      envelope.args !== undefined &&
      (envelope.args === null || typeof envelope.args !== "object" || Array.isArray(envelope.args))
    ) {
      return stripGateMarker(
        jsonResponse({ ok: false, error: "capability invoke args must be a JSON object" }, 400),
      );
    }
    const args = (envelope.args ?? {}) as Record<string, unknown>;

    const res = await invokeCapabilityThroughProxy(ctx, {
      tenantId,
      agentId,
      name: c.req.param("name"),
      args,
      body: envelope.body,
      query: envelope.query,
    });
    return stripGateMarker(res);
  });

  // OpenAI-error-shaped response for the adapter's OWN inline gate errors, so the
  // OpenAI SDK surfaces them cleanly (the shared core's wrapped errors are
  // reshaped separately via toOpenAICompatible).
  const openAIError = (message: string, status: number): Response =>
    new Response(JSON.stringify({ error: { message, type: openAIErrorType(status) } }), {
      status,
      headers: { "content-type": "application/json" },
    });

  routes.post("/:name/openai/v1/chat/completions", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return openAIError("agent authentication required", 401);
    }

    // Same per-agent throttle as the envelope invoke route (SEC-094).
    const rate = await enforceCapabilityRateLimit(ctx, "invoke", agentId);
    if (!rate.allowed) {
      const res = openAIError("capability invoke rate limit exceeded", 429);
      res.headers.set("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
      return res;
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return openAIError("invalid JSON in request body", 400);
    }

    // Streaming is NOT supported through the credential-injection proxy: it blocks
    // any streaming (text/event-stream) response after a credential injection
    // (reason `credential-streaming-response-blocked`, a 502) because it cannot
    // buffer-and-verify the credential was not reflected in an un-materialized
    // stream. Reject `stream: true` at the adapter with a clean OpenAI-error so
    // the SDK surfaces a clear message instead of an opaque upstream 502.
    if (
      typeof body === "object" &&
      body !== null &&
      (body as { stream?: unknown }).stream === true
    ) {
      return openAIError(
        "streaming responses are not supported through this capability adapter; set stream: false",
        400,
      );
    }
    const query = Object.fromEntries(new URL(c.req.url).searchParams.entries());

    // Surface OpenAI request fields to the policy layer so existing
    // argEquals/argMatches capability-intent constraints can gate on them (e.g.
    // restrict `model`). Only lift scalar top-level fields (string/number/boolean)
    // — nested structures like `messages` are not policy args — and always keep
    // provider/operation. The body itself is still forwarded verbatim.
    const args: Record<string, unknown> = {};
    if (typeof body === "object" && body !== null && !Array.isArray(body)) {
      for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
        const t = typeof value;
        if (t === "string" || t === "number" || t === "boolean") args[key] = value;
      }
    }
    // provider/operation are adapter-asserted and cannot be spoofed by the body.
    args.provider = "openai";
    args.operation = "chat.completions";

    const res = await invokeCapabilityThroughProxy(ctx, {
      tenantId,
      agentId,
      name: c.req.param("name"),
      args,
      body,
      query: Object.keys(query).length > 0 ? query : undefined,
    });
    return toOpenAICompatible(res);
  });

  routes.get("/:name/openai/v1/models", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return openAIError("agent authentication required", 401);
    }
    const ok = await hasActiveGrant(ctx, { tenantId, agentId, name: c.req.param("name") });
    if (!ok) return openAIError("capability not available to agent", 403);

    return new Response(JSON.stringify({ object: "list", data: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });

  return routes;
}
