/**
 * Cloudflare Workers entry point for the Steward API.
 *
 * The Hono app itself is built in `./app.ts` and is runtime-agnostic. This
 * file is the thin Workers shim that:
 *
 *   - Forwards the `fetch` event to the Hono app.
 *   - Surfaces `env` to per-request middleware via `app.fetch(request, env, ctx)`
 *     (Hono passes them through as `c.env` and `c.executionCtx`).
 *   - Does NOT call `setInterval` (rate-limit GC, nonce GC) — TTLs handle expiry.
 *   - Does NOT call `runMigrations()` — migrations are run out-of-band via
 *     `drizzle-kit migrate` against the Neon URL (see `packages/db/CLOUDFLARE.md`).
 *   - Does NOT register `process.on(SIGINT|SIGTERM)` — Workers are stateless.
 *   - Does NOT have any top-level `await` that hits the network at module init.
 *
 * Global rate limiting on this entry is provided by the shared Redis-backed
 * sliding-window limiter that app.ts mounts when it detects the Workers
 * runtime (SEC-068, see middleware/global-rate-limit.ts).
 *
 * Required bindings (set via `wrangler secret put` or `vars` in wrangler.toml):
 *   - DATABASE_URL                  Neon HTTP connection string
 *   - DATABASE_DRIVER=neon-http     Selects the HTTP-based postgres driver
 *   - REDIS_DRIVER=upstash          Selects the Upstash REST adapter
 *   - KV_REST_API_URL               Upstash REST endpoint
 *   - KV_REST_API_TOKEN             Upstash REST token
 *   - SKIP_MIGRATIONS=1             Migrations run via wrangler-driven CI script
 *   - STEWARD_SESSION_SECRET        HS256 JWT signing secret
 *   - STEWARD_MASTER_PASSWORD       Vault keystore master password
 *   - RESEND_API_KEY                Magic-link email provider
 *   - GOOGLE/DISCORD/GITHUB/TWITTER OAuth client IDs + secrets
 *   - PASSKEY_RP_ID, PASSKEY_ORIGIN, PASSKEY_RP_NAME
 *
 * Optional client-IP trust bindings (auth rate limiting):
 *   - STEWARD_TRUSTED_PROXY_HOPS    Trusted proxies appending to x-forwarded-for
 *   - STEWARD_TRUST_CLOUDFLARE      "true" only when ingress is locked to
 *                                   Cloudflare; trusts cf-connecting-ip
 *   - STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX
 *                                   Bounded auth admissions/min/isolate while a
 *                                   configured Redis is unreachable
 */

import { initRedis } from "./middleware/redis";

export interface Env {
  DATABASE_URL: string;
  DATABASE_DRIVER?: string;
  REDIS_DRIVER?: string;
  KV_REST_API_URL?: string;
  KV_REST_API_TOKEN?: string;
  SKIP_MIGRATIONS?: string;
  STEWARD_SESSION_SECRET?: string;
  STEWARD_MASTER_PASSWORD?: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  APP_URL?: string;
  EMAIL_AUTH_REDIRECT_BASE_URL?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  DISCORD_CLIENT_ID?: string;
  DISCORD_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  TWITTER_CLIENT_ID?: string;
  TWITTER_CLIENT_SECRET?: string;
  PASSKEY_RP_ID?: string;
  PASSKEY_ORIGIN?: string;
  PASSKEY_RP_NAME?: string;
  STEWARD_TRUSTED_PROXY_HOPS?: string;
  STEWARD_TRUST_CLOUDFLARE?: string;
  STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX?: string;
  [key: string]: unknown;
}

type WorkerLeaseSweepResult = {
  unknown: number;
  revoked: number;
  attention: number;
  expired: number;
  remaining?: boolean;
};

/**
 * Run one autonomous, globally-scoped recovery pass from a Worker Cron Trigger.
 * Cloudflare cron has a one-minute minimum cadence, so this is recovery for
 * pre-existing leases, not the Bun scheduler's <=15-second authority guarantee.
 * New Worker issuance still runs tenant recovery synchronously before issuing.
 */
export async function runWorkerUpstreamCredentialLeaseSweep(
  env: Env,
  options?: {
    capabilitiesEnabled?: boolean;
    sweep?: () => Promise<WorkerLeaseSweepResult>;
  },
): Promise<WorkerLeaseSweepResult | null> {
  hydrateProcessEnv(env);
  const capabilitiesEnabled =
    options?.capabilitiesEnabled ??
    (await import("./plugin-config")).resolveEnabledPlugins().has("capabilities");
  if (!capabilitiesEnabled || process.env.STEWARD_UPSTREAM_LEASE_SWEEPER === "false") return null;
  const sweep =
    options?.sweep ??
    (await import("./services/upstream-credential-lease-scheduler"))
      .runUpstreamCredentialLeaseSweep;
  return sweep();
}

/**
 * Pull Worker `env` bindings into `globalThis.process.env` so any code that
 * reads `process.env.X` at request time (e.g. JWT secret, RPC URL) can find it.
 *
 * Workers expose `nodejs_compat`'s `process.env` as an empty object on cold
 * boot — bindings come in via the `fetch` handler's `env` argument instead.
 * This runs on EVERY request (SEC-148): Workers may reuse isolates across
 * different deployments (and therefore different binding sets), and rotated
 * bindings/secrets must take effect without waiting for an isolate recycle.
 * Keys we hydrated that disappear from a later binding set are deleted again
 * so stale values cannot linger. Module-init-time readers still see only the
 * first binding set an isolate ever served (imports are cached per isolate) —
 * that is inherent to the module registry and unchanged by this.
 *
 * Known trade-off (accepted, SEC-148): string bindings — including secrets —
 * are copied onto the global `process.env`, because the entire codebase reads
 * configuration through `process.env`. Moving every reader onto per-request
 * binding access is out of scope; per-request hydration at least keeps the
 * values current and bounded to the current binding set.
 */
const hydratedEnvKeys = new Set<string>();

export function hydrateProcessEnv(env: Env): void {
  const target = (globalThis as any).process?.env;
  if (!target) return;

  const present = new Set<string>();
  for (const key of Object.keys(env)) {
    if (key === "STEWARD_RUNTIME") continue;
    const value = env[key];
    if (typeof value === "string") {
      target[key] = value;
      present.add(key);
    }
  }
  for (const key of hydratedEnvKeys) {
    if (!present.has(key)) delete target[key];
  }
  hydratedEnvKeys.clear();
  for (const key of present) hydratedEnvKeys.add(key);
  target.STEWARD_RUNTIME = "workers";
}

let workerInit: Promise<void> | null = null;

async function ensureWorkerInit(env: Env): Promise<void> {
  if (workerInit) return workerInit;
  workerInit = (async () => {
    // Workers bindings are only available inside fetch(). Hydrate process.env
    // before importing app modules that read required env at module init.
    hydrateProcessEnv(env);
    const redisOk = await initRedis(env);
    // Auth stores (passkey challenges, magic-link tokens, SIWE/SIWS nonces)
    // must be initialized too — without this they stay on the lazy memory
    // backend and one-time state is lost across isolates / cold starts.
    const { trackAuditEvent } = await import("./services/audit");
    const { isHstsEnabled } = await import("./middleware/security-headers");
    const dbUrl = (env.DATABASE_URL || "").toLowerCase();
    // Best-effort boot telemetry (a one-time observability breadcrumb of the
    // TLS/HSTS posture at cold start) — NOT a security mutation or a tamper-
    // evident control event, and there is no client action to deny. So this
    // intentionally stays fire-and-forget: a write failure here must not abort
    // worker init. Security/compliance events use awaited writeAuditEvent.
    trackAuditEvent({
      tenantId: "system",
      actorType: "system",
      action: "system.tls.config",
      metadata: {
        dbTlsEnforced:
          dbUrl.includes("sslmode=require") ||
          dbUrl.includes("sslmode=verify-ca") ||
          dbUrl.includes("sslmode=verify-full"),
        hstsEnabled: isHstsEnabled(),
        insecureDbAllowed: process.env.STEWARD_ALLOW_INSECURE_DB === "true",
        runtime: "workers",
      },
    });
    const { assertAuthStoresAreSafe, initAuthStores } = await import("./routes/auth");
    // usePostgres=false: Workers deployments do not run migrations on startup
    // (SKIP_MIGRATIONS=1 in wrangler.toml) so auth_kv_store may not exist;
    // Redis is the canonical store on Workers.
    await initAuthStores(false);
    assertAuthStoresAreSafe();
    const { getAuthStoreSources } = await import("./routes/auth");
    const { importSession } = getAuthStoreSources();
    if (importSession === "memory") {
      console.warn(
        "[steward:workers] encrypted import sessions are using memory storage; configure Redis for durable one-time import sessions across isolates",
      );
    }
    if (!redisOk) {
      console.warn(
        "[steward:workers] Redis not initialized — passkey/magic-link/SIWE flows will use in-memory backend per isolate",
      );
    }
  })();
  return workerInit;
}

// Compose the deployable app once per isolate: lean core + this repo's opt-in
// plugins (trading). cached so we don't re-register plugins on every request.
// composeApp() dynamically imports the trading plugin so the lean core graph
// never statically references the trading stack.
let composedApp: Awaited<ReturnType<typeof import("./compose").composeApp>> | null = null;

async function getComposedApp() {
  if (composedApp) return composedApp;
  const { composeApp } = await import("./compose");
  composedApp = await composeApp();
  return composedApp;
}

export default {
  async fetch(request: Request, env: Env, ctx: unknown): Promise<Response> {
    // SEC-148: refresh process.env from the CURRENT request's bindings on every
    // request (not once per isolate) so rotated bindings take effect promptly;
    // the once-per-isolate init below only bootstraps stores/imports.
    hydrateProcessEnv(env);
    await ensureWorkerInit(env);
    const app = await getComposedApp();
    return app.fetch(request, env, ctx as never);
  },
  async scheduled(
    _controller: unknown,
    env: Env,
    ctx: { waitUntil(promise: Promise<unknown>): void },
  ) {
    ctx.waitUntil(runWorkerUpstreamCredentialLeaseSweep(env));
  },
};
