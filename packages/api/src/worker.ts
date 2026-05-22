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
  [key: string]: unknown;
}

/**
 * Pull Worker `env` bindings into `globalThis.process.env` so any code that
 * reads `process.env.X` at request time (e.g. JWT secret, RPC URL) can find it.
 *
 * Workers expose `nodejs_compat`'s `process.env` as an empty object on cold
 * boot — bindings come in via the `fetch` handler's `env` argument instead.
 * We do this on each request because Workers may reuse isolates across
 * different deployments (and therefore different binding sets).
 */
function hydrateProcessEnv(env: Env): void {
  const target = (globalThis as any).process?.env;
  if (!target) return;

  target.STEWARD_RUNTIME = "workers";
  for (const key of Object.keys(env)) {
    const value = env[key];
    if (typeof value === "string") {
      target[key] = value;
    }
  }
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
    const { initAuthStores } = await import("./routes/auth");
    // usePostgres=false: Workers deployments do not run migrations on startup
    // (SKIP_MIGRATIONS=1 in wrangler.toml) so auth_kv_store may not exist;
    // Redis is the canonical store on Workers.
    await initAuthStores(false).catch((err) => {
      console.warn("[steward:workers] initAuthStores failed; auth flows may degrade:", err);
    });
    if (!redisOk) {
      console.warn(
        "[steward:workers] Redis not initialized — passkey/magic-link/SIWE flows will use in-memory backend per isolate",
      );
    }
  })();
  return workerInit;
}

export default {
  async fetch(request: Request, env: Env, ctx: unknown): Promise<Response> {
    await ensureWorkerInit(env);
    const { app } = await import("./app");
    return app.fetch(request, env, ctx as never);
  },
};
