/**
 * app.ts - Runtime-agnostic LEAN CORE Hono app construction.
 *
 * This module builds the LEAN core `Hono` instance: auth, vault, policy, proxy,
 * webhooks, and the rest of the always-on routes + per-route auth. It is
 * deliberately TRADING-FREE: the venue execution + trade-session routes and
 * their trade-specific middleware live in the opt-in `@stwd/plugin-trading`
 * package and are registered onto the app at the COMPOSITION ROOT (see
 * `compose.ts`), NOT here. so a third party importing `@stwd/api` gets the lean
 * core with no dependency on the trading stack; a deploy that wants trading opts
 * in by registering the plugin. see `plugin.ts` for the seam.
 *
 * It deliberately contains NO server boot code (no `Bun.serve`, no `setInterval`
 * GC, no signal handlers, no blocking `runMigrations()` call) so that it can be
 * reused by:
 *
 *   - `index.ts`   - Bun entry point (long-lived process; runs migrations,
 *                    sets up GC timers, wires SIGINT/SIGTERM, calls
 *                    `Bun.serve`).
 *   - `worker.ts`  - Cloudflare Workers entry point (per-request fetch,
 *                    no setInterval/Bun, migrations run out-of-band).
 *   - `embedded.ts`- Electrobun/desktop entry point.
 *
 * Anything that must NOT run on Workers (timers, blocking I/O at module init,
 * Node-only APIs) belongs in `index.ts`, not here.
 *
 * ── Construction is two-phase ──────────────────────────────────────────────────
 * `createApp()` registers global middleware + all CORE per-route auth, but does
 * NOT install the global idempotency middleware or mount any routes.
 * `mountCoreIdempotencyAndRoutes(app)` installs idempotency + the core routes.
 * the split exists so the composition root (compose.ts) can register an opt-in
 * plugin's AUTH MIDDLEWARE before idempotency and its ROUTES after idempotency,
 * preserving the canonical order [auth -> idempotency -> routes]. for callers that
 * just want the assembled lean core, `app` (and the default export) is the result
 * of running both phases — trading-free.
 */

import { platformAuthMiddleware } from "@stwd/auth";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { authorizationSignature } from "./middleware/authorization-signature";
import { correlationId } from "./middleware/correlation";
import { workersGlobalRateLimit } from "./middleware/global-rate-limit";
import { idempotencyMiddleware } from "./middleware/idempotency";
import { requestExpiry } from "./middleware/request-expiry";
import { requestLogger } from "./middleware/request-logger";
import { securityHeaders } from "./middleware/security-headers";
import { tenantCors } from "./middleware/tenant-cors";
import { getOpenApiSpec } from "./openapi";
import { accountRoutes } from "./routes/accounts";
import { adapterRoutes, fiatRoutes } from "./routes/adapters";
import { agentEnrollRoutes } from "./routes/agent-enroll";
import { agentRoutes, createAgentBatch } from "./routes/agents";
import { approvalRoutes } from "./routes/approvals";
import { auditRoutes } from "./routes/audit";
import { authRoutes } from "./routes/auth";
import { conditionSetRoutes } from "./routes/condition-sets";
import { dashboardRoutes } from "./routes/dashboard";
import { identityDiscoveryRoutes } from "./routes/discovery";
import { discoveryRoutes, erc8004Routes } from "./routes/erc8004";
import { globalWalletRoutes } from "./routes/global-wallet";
import { intentRoutes } from "./routes/intents";
import { kmsRoutes } from "./routes/kms";
import { metricsRoutes } from "./routes/metrics";
import { platformRoutes } from "./routes/platform";
import { policiesStandaloneRoutes } from "./routes/policies-standalone";
import { registerProviderActionRoutes } from "./routes/provider-actions";
import { registerProviderApprovalRoutes } from "./routes/provider-approvals";
import { providerAuthorityRoutes } from "./routes/provider-authority";
import { registerProviderCaseRoutes } from "./routes/provider-case";
import { registerProviderGoogleConnectRoutes } from "./routes/provider-google-connect";
import { registerProviderXConnectRoutes } from "./routes/provider-x-connect";
import { quoteRoutes } from "./routes/quote";
import { secretsRoutes } from "./routes/secrets";
import { tenantConfigRoutes } from "./routes/tenant-config";
import { tenantRoutes } from "./routes/tenants";
import { userRoutes, userSessionAuth } from "./routes/user";
import { vaultRoutes } from "./routes/vault";
import { webhookRoutes } from "./routes/webhooks";
import { MAX_ARCHIVE_CHUNK_BYTES } from "./services/audit-archive";
import {
  API_VERSION,
  type ApiResponse,
  type AppVariables,
  dashboardAuthMiddleware,
  isWorkersRuntime,
  tenantAuth,
} from "./services/context";

const startTime = Date.now();

/**
 * Build the lean core app with global middleware and all core per-route
 * auth middleware. does NOT install the global idempotency middleware and does
 * NOT mount any routes (those are phase 2: {@link mountCoreIdempotencyAndRoutes}).
 * trading is NOT part of the core — it is registered as an opt-in plugin at the
 * composition root (see compose.ts).
 */
export function createApp(): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();

  // ─── Global error handler ───────────────────────────────────────────────────

  app.onError((err, c) => {
    const requestId = c.get("requestId") || "unknown";

    if (err instanceof SyntaxError || err.message?.includes("JSON")) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
    }

    console.error(`[${requestId}] Unhandled API error`, redactedThrownDiagnostics(err));
    return c.json<ApiResponse>({ ok: false, error: "Internal server error" }, 500);
  });

  // ─── 404 fallback ───────────────────────────────────────────────────────────

  app.notFound((c) =>
    c.json<ApiResponse>({ ok: false, error: `Not found: ${c.req.method} ${c.req.path}` }, 404),
  );

  // ─── Global middleware ──────────────────────────────────────────────────────

  // SEC-068: the Bun entry enforces a global in-memory IP rate limit
  // pre-dispatch (index.ts runtimeGate), which is impossible on Workers (no
  // cross-isolate state). Mount the shared Redis-backed sliding-window limiter
  // across all routes for the Workers runtime only, so non-auth endpoints
  // there are no longer unthrottled.
  if (isWorkersRuntime) {
    app.use("*", workersGlobalRateLimit);
  }

  app.use("*", securityHeaders);
  app.use("*", tenantCors);
  // SEC-015: query-stripping logger — hono's logger() would write one-time
  // auth tokens in callback query strings to stdout.
  app.use("*", requestLogger());
  app.use("*", correlationId);

  app.use(
    "*",
    bodyLimit({
      maxSize: MAX_ARCHIVE_CHUNK_BYTES,
      onError: (c) =>
        c.json<ApiResponse>({ ok: false, error: "Request body too large (max 1MB)" }, 413),
    }),
  );

  // ─── Request freshness + signature guards (SEC-010) ────────────────────────
  // Mounted globally so freshness headers and request signatures are actually
  // verified on every sensitive mutating route (they were unmounted dead code
  // while /openapi.json and the tenant security checklist claimed enforcement).
  // Default posture is verify-when-present: a request carrying stale/invalid
  // freshness or signature headers fails closed, but the headers are not
  // required unless the operator opts in via STEWARD_REQUIRE_REQUEST_EXPIRY /
  // STEWARD_REQUIRE_AUTH_SIGNATURE. The env opt-in (not NODE_ENV) drives the
  // strict mode so browser/unsigned SDK clients keep working until an operator
  // has rolled out signing clients. Mounted here (phase 1) so they always run
  // BEFORE the idempotency middleware (phase 2).
  app.use("*", requestExpiry({ required: process.env.STEWARD_REQUIRE_REQUEST_EXPIRY === "true" }));
  app.use(
    "*",
    authorizationSignature({ required: process.env.STEWARD_REQUIRE_AUTH_SIGNATURE === "true" }),
  );

  // ─── Auth middleware per route group ────────────────────────────────────────

  app.use("/agents", (c, next) => tenantAuth(c, next));
  app.use("/agents/*", (c, next) => tenantAuth(c, next));
  app.use("/wallets/batch", (c, next) => tenantAuth(c, next));
  app.use("/v1/wallets/batch", (c, next) => tenantAuth(c, next));
  app.use("/v1/agents", (c, next) => tenantAuth(c, next));
  app.use("/v1/agents/*", (c, next) => tenantAuth(c, next));
  app.use("/accounts", (c, next) => tenantAuth(c, next));
  app.use("/accounts/*", (c, next) => tenantAuth(c, next));
  app.use("/v1/accounts", (c, next) => tenantAuth(c, next));
  app.use("/v1/accounts/*", (c, next) => tenantAuth(c, next));
  app.use("/vault/*", (c, next) => tenantAuth(c, next));
  // KMS: tenantAuth verifies the bearer (agent tokens included); the kms router
  // additionally REQUIRES an agent-token principal (fail-closed — see routes/kms.ts).
  app.use("/v1/kms/*", (c, next) => tenantAuth(c, next));
  app.use("/secrets", (c, next) => tenantAuth(c, next));
  app.use("/secrets/*", (c, next) => tenantAuth(c, next));
  app.use("/tenants/:id", (c, next) => {
    // POST /tenants (creation) is intentionally NOT gated here: this middleware
    // is keyed on `/tenants/:id`, a pattern hono never matches against the bare
    // `/tenants` path, so creation is protected solely by the route-level
    // platformAuthMiddleware() + platform scopes in routes/tenants.ts. (SEC-149:
    // a previous `POST /tenants` passthrough branch here was dead code and has
    // been removed so the guard boundary stays honest.)
    // GET /tenants/config (no id) is a public discovery endpoint used by the
    // @stwd/sdk React provider to fetch default-tenant policy/theme/feature
    // flags before the user has authenticated. The :id wildcard would otherwise
    // catch it and demand tenant auth, which isn't available pre-signin.
    const id = c.req.param("id");
    if (id === "config" && c.req.method === "GET") return next();
    return tenantAuth(c, next, { requireTenantMatch: id });
  });
  app.use("/tenants/:id/webhook", (c, next) =>
    tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
  );
  app.use("/tenants/:id/config", (c, next) =>
    tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
  );
  app.use("/tenants/:id/config/*", (c, next) =>
    tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
  );
  app.use("/dashboard/*", (c, next) => dashboardAuthMiddleware(c, next));
  app.use("/platform", platformAuthMiddleware());
  app.use("/platform/*", platformAuthMiddleware());
  app.use("/user", (c, next) => userSessionAuth(c as never, next));
  app.use("/user/*", (c, next) => userSessionAuth(c as never, next));
  app.use("/webhooks", (c, next) => tenantAuth(c, next));
  app.use("/webhooks/*", (c, next) => tenantAuth(c, next));
  app.use("/approvals", (c, next) => tenantAuth(c, next));
  app.use("/approvals/*", (c, next) => tenantAuth(c, next));
  app.use("/intents", (c, next) => tenantAuth(c, next));
  app.use("/intents/*", (c, next) => tenantAuth(c, next));
  app.use("/audit", (c, next) => tenantAuth(c, next));
  app.use("/audit/*", (c, next) => tenantAuth(c, next));
  app.use("/adapters", (c, next) => tenantAuth(c, next));
  app.use("/adapters/*", (c, next) => tenantAuth(c, next));
  app.use("/v1/adapters", (c, next) => tenantAuth(c, next));
  app.use("/v1/adapters/*", (c, next) => tenantAuth(c, next));
  app.use("/v1/users/*", (c, next) => tenantAuth(c, next));
  app.use("/policies", (c, next) => tenantAuth(c, next));
  app.use("/policies/*", (c, next) => tenantAuth(c, next));
  app.use("/condition-sets", (c, next) => tenantAuth(c, next));
  app.use("/condition-sets/*", (c, next) => tenantAuth(c, next));
  app.use("/condition_sets", (c, next) => tenantAuth(c, next));
  app.use("/condition_sets/*", (c, next) => tenantAuth(c, next));
  app.use("/v1/condition_sets", (c, next) => tenantAuth(c, next));
  app.use("/v1/condition_sets/*", (c, next) => tenantAuth(c, next));
  app.use("/v2/workspaces", (c, next) => tenantAuth(c, next));
  app.use("/v2/workspaces/*", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-accounts", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-accounts/*", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-role-bindings", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-role-bindings/*", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-grants", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-grants/*", (c, next) => tenantAuth(c, next));
  app.use("/v2/provider-access/check", (c, next) => tenantAuth(c, next));

  return app;
}

/**
 * Install the global idempotency middleware and mount all core routes onto
 * an app produced by {@link createApp}. KEPT SEPARATE from phase 1 so the
 * composition root can slot an opt-in plugin's auth middleware in BEFORE
 * idempotency (phase-1 boundary) and its routes AFTER idempotency (this phase).
 * the registration order here is identical to the pre-refactor app.ts, minus
 * trading (which the plugin contributes).
 */
export function mountCoreIdempotencyAndRoutes(
  app: Hono<{ Variables: AppVariables }>,
): Hono<{ Variables: AppVariables }> {
  app.use("*", idempotencyMiddleware());

  // ─── Health & root ────────────────────────────────────────────────────────

  app.get("/", (c) => c.json({ name: "steward", version: API_VERSION, status: "running" }));
  app.get("/openapi.json", (c) => c.json(getOpenApiSpec()));
  app.get("/health", (c) =>
    c.json({
      status: "ok",
      version: API_VERSION,
      uptime: Math.floor((Date.now() - startTime) / 1000),
    }),
  );
  app.route("/metrics", metricsRoutes);
  app.route("/quote", quoteRoutes);

  // ─── Route modules ──────────────────────────────────────────────────────────

  app.route("/", identityDiscoveryRoutes);
  app.route("/auth", authRoutes);
  app.route("/platform", platformRoutes);
  app.route("/user", userRoutes);
  app.route("/global-wallet", globalWalletRoutes);
  app.route("/accounts", accountRoutes);
  app.route("/v1/accounts", accountRoutes);
  // PUBLIC: keypair-only agent enrollment (no tenant/agent token yet). Mounted
  // outside the /agents tenant gate; identity is proven by signature and the
  // tenant is resolved server-side from agent_signers.
  app.route("/agent-enroll", agentEnrollRoutes);
  app.route("/v1/agent-enroll", agentEnrollRoutes);
  app.route("/agents", agentRoutes);
  app.route("/v1/agents", agentRoutes);
  app.post("/wallets/batch", createAgentBatch);
  app.post("/v1/wallets/batch", createAgentBatch);
  app.route("/vault", vaultRoutes);
  app.route("/secrets", secretsRoutes);
  app.route("/v1/kms", kmsRoutes);
  // tenantConfigRoutes mounted FIRST so its literal `/config` discovery handler
  // is matched before tenantRoutes' `/:id` wildcard would catch "config" as an id.
  app.route("/tenants", tenantConfigRoutes);
  app.route("/tenants", tenantRoutes);
  app.route("/dashboard", dashboardRoutes);
  app.route("/webhooks", webhookRoutes);
  app.route("/approvals", approvalRoutes);
  app.route("/intents", intentRoutes);
  app.route("/audit", auditRoutes);
  app.route("/adapters", adapterRoutes);
  app.route("/v1/adapters", adapterRoutes);
  app.route("/v1/users", fiatRoutes);
  app.route("/policies", policiesStandaloneRoutes);
  // provider-account X OAuth connect (#195 workstream A). Registered CONCRETELY
  // and BEFORE the `/v2` authority sub-app so the specific connect paths win
  // over the authority `/provider-accounts/:id/...` wildcards.
  registerProviderXConnectRoutes(app);
  registerProviderGoogleConnectRoutes(app);
  // Evidence case/evidence routes are registered concretely before the `/v2`
  // authority sub-app so the specific /provider-actions/:id/{case,evidence}
  // paths win over the authority wildcards (same pattern as provider-actions).
  registerProviderCaseRoutes(app);
  app.route("/v2", providerAuthorityRoutes);
  // provider-actions registers its concrete `/v2/provider-actions` handler + auth
  // middleware directly on the app (see registerProviderActionRoutes) to avoid a
  // second `/v2` sub-app mount colliding with the authority wildcard.
  registerProviderActionRoutes(app);
  // Approval and safe-resume routes are registered directly to avoid the
  // /v2 authority-wildcard collision).
  registerProviderApprovalRoutes(app);

  app.route("/condition-sets", conditionSetRoutes);
  app.route("/condition_sets", conditionSetRoutes);
  app.route("/v1/condition_sets", conditionSetRoutes);
  app.route("/agents", erc8004Routes);
  app.route("/discovery", discoveryRoutes);

  return app;
}

/**
 * The assembled LEAN CORE app (both phases run, trading-free). default export +
 * named `app` for callers/tests that want the core directly. THIS repo's
 * deployable server does NOT use this — it uses `composeApp()` (compose.ts) which
 * also registers the trading plugin.
 */
const app = mountCoreIdempotencyAndRoutes(createApp());

export { app, startTime };
export default app;
