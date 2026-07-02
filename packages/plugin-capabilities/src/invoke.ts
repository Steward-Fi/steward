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
import {
  CAPABILITY_INTENT_RULE_TYPE,
  type CapabilityIntentConfig,
  type EvaluatorContext,
  evaluateCapabilityIntent,
  PolicyEngine,
} from "@stwd/policy-engine";
import { StewardProxyClient } from "@stwd/proxy-client";
import type { ApiResponse, AppVariables, PolicyRule, SignRequest } from "@stwd/shared";
import { Hono } from "hono";
import type { StewardAppContext } from "./context";
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
  query?: Record<string, string>;
}

function jsonResponse(payload: ApiResponse, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
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

function patternMatches(pattern: string, name: string): boolean {
  if (typeof pattern !== "string" || pattern.length === 0) return false;
  if (pattern.endsWith(".*")) return name.startsWith(pattern.slice(0, -1));
  return pattern === name;
}

function isCapabilityIntentRule(rule: PolicyRule): boolean {
  return (rule.type as string) === (CAPABILITY_INTENT_RULE_TYPE as string);
}

function isMatchingAllowRule(rule: PolicyRule, name: string): boolean {
  if (!isCapabilityIntentRule(rule)) return false;
  const cfg = rule.config as Partial<CapabilityIntentConfig>;
  if (cfg.effect !== "allow") return false;
  if (!Array.isArray(cfg.capabilities)) return false;
  return cfg.capabilities.some((p) => patternMatches(p, name));
}

function isGoverningRule(rule: PolicyRule, name: string): boolean {
  if (!isCapabilityIntentRule(rule)) return false;
  const cfg = rule.config as Partial<CapabilityIntentConfig>;
  if (!Array.isArray(cfg.capabilities)) return false;
  return cfg.capabilities.some((p) => patternMatches(p, name));
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
  const invokeArgs = request.args ?? {};

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

  const capabilityCtx: NonNullable<EvaluatorContext["capability"]> = {
    name: cap.name,
    args: invokeArgs,
    host: cap.host,
    path: cap.pathPattern,
    method: cap.method,
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

  await engine.evaluate(capRules, evaluatorCtx);

  const governing = capRules.filter((r) => isGoverningRule(r, cap.name));
  if (governing.length === 0) {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: { ok: false, error: "no policy authorizes this capability" } satisfies ApiResponse,
    });
  }

  let sawApproval = false;
  let matchedAllowPassed = false;
  let sawDeny = false;
  let denyReason: string | undefined;
  for (const rule of governing) {
    const result = evaluateCapabilityIntent(
      { id: rule.id, type: rule.type as string, enabled: rule.enabled, config: rule.config },
      evaluatorCtx,
    );
    if (result.requiresManualApproval) {
      sawApproval = true;
      continue;
    }
    if (!result.passed) {
      sawDeny = true;
      denyReason = result.reason ?? "denied by policy";
      continue;
    }
    if (isMatchingAllowRule(rule, cap.name)) matchedAllowPassed = true;
  }

  if (!sawDeny && matchedAllowPassed) {
    // proceed to proxy delegation.
  } else if (!sawDeny && sawApproval) {
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
  } else {
    return recordAndJson(store, {
      tenantId,
      agentId,
      capabilityId: cap.id,
      decision: "deny",
      status: 403,
      payload: {
        ok: false,
        error: denyReason ?? "capability invoke denied by policy",
      } satisfies ApiResponse,
    });
  }

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
    const path = buildProxyPath(cap, request.query);
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
      return jsonResponse({ ok: false, error: "agent authentication required" }, 401);
    }

    type InvokeEnvelope = {
      args?: Record<string, unknown>;
      body?: unknown;
      query?: Record<string, string>;
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
          return jsonResponse({ ok: false, error: "invoke body must be a JSON object" }, 400);
        }
        envelope = parsedBody as InvokeEnvelope;
      } catch {
        return jsonResponse({ ok: false, error: "invalid JSON in request body" }, 400);
      }
    }

    const args =
      envelope.args && typeof envelope.args === "object" && !Array.isArray(envelope.args)
        ? (envelope.args as Record<string, unknown>)
        : {};
    const query =
      envelope.query && typeof envelope.query === "object" && !Array.isArray(envelope.query)
        ? (envelope.query as Record<string, string>)
        : undefined;

    return invokeCapabilityThroughProxy(ctx, {
      tenantId,
      agentId,
      name: c.req.param("name"),
      args,
      body: envelope.body,
      query,
    });
  });

  routes.post("/:name/openai/v1/chat/completions", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return jsonResponse({ ok: false, error: "agent authentication required" }, 401);
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonResponse({ ok: false, error: "invalid JSON in request body" }, 400);
    }
    const query = Object.fromEntries(new URL(c.req.url).searchParams.entries());

    return invokeCapabilityThroughProxy(ctx, {
      tenantId,
      agentId,
      name: c.req.param("name"),
      args: { provider: "openai", operation: "chat.completions" },
      body,
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  });

  routes.get("/:name/openai/v1/models", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return jsonResponse({ ok: false, error: "agent authentication required" }, 401);
    }
    const ok = await hasActiveGrant(ctx, { tenantId, agentId, name: c.req.param("name") });
    if (!ok) return jsonResponse({ ok: false, error: "capability not available to agent" }, 403);

    return new Response(JSON.stringify({ object: "list", data: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });

  return routes;
}
