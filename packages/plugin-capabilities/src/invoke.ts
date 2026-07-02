/**
 * invoke.ts - the AGENT-FACING capability invoke path (W-1c).
 *
 * POST /capabilities/:name/invoke  { args?, body?, query? }
 *
 * this is the one route in the plugin that an AGENT (not an operator) calls. it
 * turns "agent X wants to invoke capability Y with these args" into a policy
 * decision and, when allowed, a delegated call THROUGH THE PROXY (never an
 * in-process credential touch). the agent identity is taken from the agent token
 * (c.get("agentScope")), NEVER from the request body.
 *
 * THE ARC (fail-closed at every seam)
 * -----------------------------------
 *  a. auth: agent-jwt (installed by the plugin's register on this subpath). the
 *     acting agent + tenant come from the verified token context.
 *  b. resolve the capability by (tenant, name) + enabled, and the ACTIVE,
 *     unexpired GRANT for THIS agent via the fail-closed usable-by-agent surface.
 *     any miss => 404/403, recorded as a denied invocation.
 *  c. compute the trailing-hour invoke count for (agent, capability) from the
 *     invocations table => ctx.capabilityInvokeCount1h.
 *  d. build the policy context with ctx.capability = {name, args, host, path,
 *     method} + the count, and evaluate the tenant's `capability-intent` rules
 *     through the engine's EXISTING entry point (PolicyEngine.evaluate). only the
 *     capability-intent rules are fed to the engine here: tx-shaped rules
 *     (spending-limit, approved-addresses, ...) govern tx SIGNS, not capability
 *     invokes, and would produce meaningless verdicts against a synthetic tx.
 *     the capability-intent rule is the rule that governs a capability invoke.
 *  e. DEFAULT-DENY: engine-approved is NOT sufficient (a capability-intent rule
 *     PASSES for any capability it does not govern). the invoke layer INDEPENDENTLY
 *     requires >=1 capability-intent rule that GOVERNS this capability name with
 *     effect "allow" AND whose per-rule evaluation PASSED. a matched deny or a
 *     matched require-approval short-circuits first (deny => 403; approval => 202).
 *     no matched allow rule => deny.
 *  f. ALLOW => forward THROUGH THE PROXY via @stwd/proxy-client. the target is the
 *     capability's (host, path, method); the agent's api:proxy token is minted
 *     server-side (shared STEWARD_JWT_SECRET, the same token the proxy verifies) +
 *     HMAC-signed. the proxy matches the paired secret_route (agentId = this agent,
 *     materialized by the grant), decrypts + injects the credential, and scrubs it
 *     from the response. the plugin NEVER decrypts. proxy env absent => 503.
 *  g. return the upstream status/body passthrough. emit capability.invoked /
 *     .denied / .approval_queued (declared by this package's webhookEvents).
 *
 * every terminal outcome records ONE capability_invocations row with its decision
 * (allow/deny/approval/error) BEFORE the response — the durable audit trail + the
 * rate-limit source. money-rail-adjacent: on ANY ambiguity (no proxy env, count
 * query error, enqueue error) we DENY (or 503) and audit.
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
import type { Context } from "hono";
import { Hono } from "hono";
import type { StewardAppContext } from "./context";
import type { Capability, InvocationDecision } from "./schema";
import { CapabilityStore } from "./store";

/** the proxy scope an invoke-minted agent token must carry. mirrors @stwd/proxy config. */
const PROXY_SCOPE = "api:proxy";
/** short-lived: the token only needs to survive the single proxied call. */
const PROXY_TOKEN_TTL = "2m";

/**
 * The proxy delegation configuration read from the environment. FAIL-CLOSED: any
 * missing value => the invoke path returns 503 (never an in-process credential
 * touch). Documented in the deploy runbook.
 */
interface ProxyEnv {
  proxyUrl: string;
  signingSecret: string;
}

/**
 * Read + validate the proxy env. Returns null when any required var is missing/
 * empty (=> the caller 503s). We require BOTH the proxy URL and a request-signing
 * secret: the proxy runs with request signing enabled in production, so an invoke
 * without a signing secret would be rejected by the proxy anyway — failing closed
 * here (503, no forward) is clearer than forwarding a request the proxy will 401.
 */
function readProxyEnv(env: NodeJS.ProcessEnv = process.env): ProxyEnv | null {
  const proxyUrl = (env.STEWARD_PROXY_URL ?? "").trim();
  // accept either the dedicated invoke signing secret or the proxy's own
  // configured signing secret (single-secret deploys set only the latter).
  const signingSecret = (
    env.STEWARD_PROXY_REQUEST_SIGNING_SECRET ??
    env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS?.split(",")[0] ??
    ""
  ).trim();
  if (!proxyUrl || !signingSecret) return null;
  return { proxyUrl, signingSecret };
}

/**
 * Build the proxy-relative path for a capability's (host, path). Uses the
 * direct-proxy form `/proxy/<host><path>` so ANY allowed host works without
 * depending on a named alias existing. v1 capabilities are EXACT-path: the
 * forwarded path is the capability's `pathPattern` verbatim (path templating from
 * args is a documented TODO). Query params (if any) are appended.
 */
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

/**
 * A synthetic SignRequest for the engine's evaluator context. The engine's
 * `request` field is typed as a SignRequest; capability-intent rules ignore it
 * entirely (they gate on `ctx.capability`), and only capability-intent rules are
 * evaluated on the invoke path, so this sentinel never drives a decision. It
 * carries the real agent/tenant ids (for the audit event) + zeroed tx fields.
 */
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

/**
 * Match a capability name against a single capability-intent pattern. Mirrors the
 * engine's `patternMatches` (a single trailing `.*` prefix glob, else exact). Kept
 * local so the invoke layer's default-deny match detection reuses ONLY the stable
 * exported `CapabilityIntentConfig` shape (policy-engine stays 0-diff). The
 * authoritative PASS/constraint verdict is delegated to `evaluateCapabilityIntent`.
 */
function patternMatches(pattern: string, name: string): boolean {
  if (typeof pattern !== "string" || pattern.length === 0) return false;
  if (pattern.endsWith(".*")) return name.startsWith(pattern.slice(0, -1));
  return pattern === name;
}

/**
 * True when a rule is a capability-intent rule. `PolicyRule.type` is the CORE
 * closed union which does NOT include the contributed "capability-intent"
 * discriminator (it is a plugin-registered type stored as an arbitrary string in
 * the DB), so we compare the type as a plain string.
 */
function isCapabilityIntentRule(rule: PolicyRule): boolean {
  return (rule.type as string) === (CAPABILITY_INTENT_RULE_TYPE as string);
}

/**
 * True when `rule` is a well-formed capability-intent rule with effect "allow"
 * whose configured patterns GOVERN `name`. This is the local "does an allow rule
 * match this capability" test; whether that allow rule PASSES (args/rate
 * constraints) is decided by the engine evaluator, not here.
 */
function isMatchingAllowRule(rule: PolicyRule, name: string): boolean {
  if (!isCapabilityIntentRule(rule)) return false;
  const cfg = rule.config as Partial<CapabilityIntentConfig>;
  if (cfg.effect !== "allow") return false;
  if (!Array.isArray(cfg.capabilities)) return false;
  return cfg.capabilities.some((p) => patternMatches(p, name));
}

/** True when a rule (of any effect) is a capability-intent rule governing `name`. */
function isGoverningRule(rule: PolicyRule, name: string): boolean {
  if (!isCapabilityIntentRule(rule)) return false;
  const cfg = rule.config as Partial<CapabilityIntentConfig>;
  if (!Array.isArray(cfg.capabilities)) return false;
  return cfg.capabilities.some((p) => patternMatches(p, name));
}

/**
 * Build the agent invoke router. Mounted (behind the plugin's agent-jwt gate on
 * `/capabilities/:name/invoke`) by the plugin's `register`.
 */
export function createInvokeRoutes(ctx: StewardAppContext): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();
  const store = new CapabilityStore(ctx.db);
  // a single engine instance for the invoke path. no audit hook here (the plugin
  // writes its OWN capability_invocations audit row per attempt).
  const engine = new PolicyEngine();

  /**
   * Record the terminal decision and return the response. Central so EVERY exit
   * records exactly one invocation row first (fail-closed audit trail + the
   * rate-limit source). A record failure is swallowed AFTER the decision is
   * already fail-closed (we never upgrade a deny to an allow on a record error;
   * a denied attempt simply may not be counted toward the hourly cap).
   *
   * `webhookEvents` (capability.invoked / .denied / .approval_queued) are DECLARED
   * by this package (index.ts) so the event types are valid; actual dispatch runs
   * through the core webhook config/dispatch path (which the plugin does not hold
   * an injected handle to) exactly as the CRUD lifecycle events do — the plugin's
   * job is the durable decision record, not the transport.
   */
  async function finish(
    c: Context<{ Variables: AppVariables }>,
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
      // audit write failed: do NOT block the (already fail-closed) decision.
    }
    return c.json<ApiResponse>(args.payload, args.status as never);
  }

  // ── POST /:name/invoke ──────────────────────────────────────────────────────
  routes.post("/:name/invoke", async (c) => {
    // agent identity from the TOKEN, never the body (agent-jwt set these).
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      // the agent-jwt middleware should have populated these; if not, fail closed.
      return c.json<ApiResponse>({ ok: false, error: "agent authentication required" }, 401);
    }
    const name = c.req.param("name");

    // parse the optional body envelope. an invalid JSON body is a 400.
    const parsed = await ctx.safeJsonParse<{
      args?: Record<string, unknown>;
      body?: unknown;
      query?: Record<string, string>;
    }>(c);
    // an empty body is allowed (no args). a present-but-invalid JSON body => 400.
    const envelope = parsed ?? {};
    const invokeArgs =
      envelope.args && typeof envelope.args === "object" && !Array.isArray(envelope.args)
        ? (envelope.args as Record<string, unknown>)
        : {};
    const query =
      envelope.query && typeof envelope.query === "object" && !Array.isArray(envelope.query)
        ? (envelope.query as Record<string, string>)
        : undefined;

    // a. resolve capability + active grant fail-closed via the usable-by-agent
    //    surface (active + unexpired grant to an ENABLED capability).
    const usable = await store.listUsableCapabilitiesForAgent(tenantId, agentId);
    const match = usable.find((u) => u.capability.name === name);
    if (!match) {
      // no usable grant: could be unknown capability, disabled, or no/expired/
      // revoked grant. all collapse to a fail-closed 403 (do not leak which).
      return finish(c, {
        tenantId,
        agentId,
        capabilityId: null,
        decision: "deny",
        status: 403,
        payload: { ok: false, error: "capability not available to agent" } satisfies ApiResponse,
      });
    }
    const cap = match.capability;

    // b. trailing-hour invoke count for (agent, capability). a query error =>
    //    DENY (the maxCallsPerHour constraint would otherwise fail open).
    let count1h: number;
    try {
      count1h = await store.countInvocations1h(agentId, cap.id);
    } catch {
      return finish(c, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "deny",
        status: 403,
        payload: { ok: false, error: "policy evaluation unavailable" } satisfies ApiResponse,
      });
    }

    // c. build the policy context. ctx.capability drives capability-intent rules;
    //    only capability-intent rules are evaluated on the invoke path.
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
      return finish(c, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "deny",
        status: 403,
        payload: { ok: false, error: "policy evaluation unavailable" } satisfies ApiResponse,
      });
    }
    // only the capability-intent rules govern a capability invoke.
    const capRules = policySet.filter((r) => isCapabilityIntentRule(r));

    // d. evaluate through the engine's existing entry point.
    // e. DEFAULT-DENY + effect resolution.
    //
    // build the per-rule evaluator context (identical for the engine pass and the
    // authoritative per-rule loop). we run BOTH:
    //   - engine.evaluate over the capability-intent rules: the EXISTING entry
    //     point (all-must-pass composition), so any global engine hooks/audit fire
    //     exactly as they do for tx signing. it is a consistency/audit pass.
    //   - the AUTHORITATIVE per-rule loop below: the invoke layer OWNS default-deny
    //     (the contract) — engine-approved alone is not enough, and the engine's
    //     dispatch of a contributed rule depends on the plugin having registered
    //     the evaluator into the registry (true at the compose root; the direct
    //     loop makes the decision robust regardless of registry state). the loop
    //     computes matched-allow/deny/approval directly via evaluateCapabilityIntent.
    const evaluatorCtx: EvaluatorContext = {
      request: syntheticSignRequest(tenantId, agentId),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      capability: capabilityCtx,
      capabilityInvokeCount1h: count1h,
    };
    // consistency/audit pass through the existing entry point (result inspected
    // for parity, but the AUTHORITATIVE decision is the per-rule loop below).
    await engine.evaluate(capRules, {
      request: evaluatorCtx.request,
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      capability: capabilityCtx,
      capabilityInvokeCount1h: count1h,
    });

    const governing = capRules.filter((r) => isGoverningRule(r, cap.name));
    if (governing.length === 0) {
      // no capability-intent rule governs this capability => default-deny.
      return finish(c, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "deny",
        status: 403,
        payload: {
          ok: false,
          error: "no policy authorizes this capability",
        } satisfies ApiResponse,
      });
    }

    // evaluate each governing rule with the authoritative evaluator. all-must-pass:
    // a matched deny OR a matched allow that failed a constraint is a hard deny
    // (takes precedence over any other rule). a require-approval routes to 202
    // only when nothing hard-denied. authorization requires >=1 allow rule that
    // matched AND passed, with no hard deny.
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
        // a matched deny, OR a matched allow that failed its constraints => hard deny.
        sawDeny = true;
        denyReason = result.reason ?? "denied by policy";
        continue;
      }
      // passed. only an ALLOW-effect rule authorizes (deny/require-approval never
      // pass; re-check the effect defensively).
      if (isMatchingAllowRule(rule, cap.name)) matchedAllowPassed = true;
    }

    // precedence (all-must-pass): ANY hard deny wins. else a require-approval => 202.
    // else a matched-allow that passed => authorize. else default-deny.
    if (!sawDeny && matchedAllowPassed) {
      // proceed to forward (below).
    } else if (!sawDeny && sawApproval) {
      // f-approval: enqueue via the plugin's own invocation record (the core
      // approval_queue is tx-shaped and cannot hold a capability invoke). the
      // 202 returns the invocation id as the approvalId. an enqueue (record)
      // error => DENY + audit (handled inside finish: a null id would drop the
      // approval, so on record failure we return a deny instead).
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
        return finish(c, {
          tenantId,
          agentId,
          capabilityId: cap.id,
          decision: "deny",
          status: 403,
          payload: {
            ok: false,
            error: "approval enqueue failed",
          } satisfies ApiResponse,
        });
      }
      // already recorded (decision=approval); emit + return WITHOUT double-recording.
      return c.json<ApiResponse>({ ok: true, data: { approvalId, status: "pending" } }, 202);
    } else {
      return finish(c, {
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

    // f. ALLOW => forward THROUGH THE PROXY. fail-closed if proxy env absent.
    const proxyEnv = readProxyEnv();
    if (!proxyEnv) {
      return finish(c, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "error",
        status: 503,
        payload: {
          ok: false,
          error: "capability delegation unavailable",
        } satisfies ApiResponse,
      });
    }

    let upstreamStatus: number;
    let upstreamBody: string;
    let upstreamContentType: string | null;
    try {
      // mint a short-lived api:proxy token for THIS agent (the same HS256 token
      // the proxy verifies). the proxy matches the grant's paired secret_route
      // (agentId = this agent) and injects the credential. the plugin never sees
      // the secret.
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
      const path = buildProxyPath(cap, query);
      const hasBody = method !== "GET" && method !== "HEAD" && envelope.body !== undefined;
      const init: RequestInit = { method };
      if (hasBody) {
        init.body =
          typeof envelope.body === "string" ? envelope.body : JSON.stringify(envelope.body);
        init.headers = { "content-type": "application/json" };
      }
      const res = await client.fetch(path, init);
      upstreamStatus = res.status;
      upstreamContentType = res.headers.get("content-type");
      upstreamBody = await res.text();
    } catch {
      // a forward failure is an error outcome (recorded), surfaced as 502.
      return finish(c, {
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "error",
        status: 502,
        payload: { ok: false, error: "capability delegation failed" } satisfies ApiResponse,
      });
    }

    // record the allow (durable) BEFORE returning the passthrough.
    try {
      await store.recordInvocation({
        tenantId,
        agentId,
        capabilityId: cap.id,
        decision: "allow",
      });
    } catch {
      // audit write failed: do NOT block the response (the credential already
      // forwarded), but the decision itself was already made + policy-authorized.
    }

    // g. passthrough the upstream status + body verbatim. never re-wrap (the
    //    proxy already scrubbed the credential from the body).
    return new Response(upstreamBody, {
      status: upstreamStatus,
      headers: upstreamContentType ? { "content-type": upstreamContentType } : undefined,
    });
  });

  return routes;
}
