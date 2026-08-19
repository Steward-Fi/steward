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
 *   - STEWARD_JWT_SECRET            Canonical HS256 JWT signing secret
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

// Import the dependency-light JWT module directly. Importing the auth barrel
// here would evaluate Worker-sensitive auth modules before cold initialization.
import { validateJwtSecretEnv } from "@stwd/auth/jwt";
import {
  createDbForRequest,
  createNeonTransactionDbForRequest,
  getDb,
  type NeonTransactionDbHandle,
  withRequestDatabase,
} from "@stwd/db";
import { runtimeEnvironmentValue, withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { initRedis } from "./middleware/redis";

export interface Env {
  DATABASE_URL: string;
  DATABASE_DRIVER?: string;
  NODE_ENV?: string;
  STEWARD_ALLOW_INSECURE_DB?: string;
  STEWARD_ALLOW_UNVERIFIED_DB_TLS?: string;
  REDIS_DRIVER?: string;
  KV_REST_API_URL?: string;
  KV_REST_API_TOKEN?: string;
  SKIP_MIGRATIONS?: string;
  STEWARD_JWT_SECRET?: string;
  /** Deprecated compatibility fallback for existing Worker deployments. */
  STEWARD_SESSION_SECRET?: string;
  STEWARD_MASTER_PASSWORD?: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  APP_URL?: string;
  EMAIL_AUTH_REDIRECT_BASE_URL?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GOOGLE_PROVIDER_CLIENT_ID?: string;
  GOOGLE_PROVIDER_CLIENT_SECRET?: string;
  DISCORD_CLIENT_ID?: string;
  DISCORD_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  TWITTER_CLIENT_ID?: string;
  TWITTER_CLIENT_SECRET?: string;
  X_CLIENT_ID?: string;
  X_CLIENT_SECRET?: string;
  PASSKEY_RP_ID?: string;
  PASSKEY_ORIGIN?: string;
  PASSKEY_RP_NAME?: string;
  STEWARD_TRUSTED_PROXY_HOPS?: string;
  STEWARD_TRUST_CLOUDFLARE?: string;
  STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX?: string;
  [key: string]: unknown;
}

type WorkerDatabaseHandleFactory = (env: {
  DATABASE_URL?: string;
  DATABASE_DRIVER?: string;
  NODE_ENV?: string;
  STEWARD_ALLOW_INSECURE_DB?: string;
  STEWARD_ALLOW_UNVERIFIED_DB_TLS?: string;
}) => NeonTransactionDbHandle;
type WorkerHttpDatabaseFactory = (env: {
  DATABASE_URL?: string;
  DATABASE_DRIVER?: string;
}) => ReturnType<typeof getDb>;

/**
 * Run one Worker unit of work with its request-owned database handle.
 *
 * neon-http remains the shipped default and needs no persistent cleanup. The
 * transaction-capable WebSocket driver is explicit: its handle is bound to the
 * async request so every legacy getDb() call resolves the same Drizzle object,
 * then close() is awaited on success and failure. No handle is cached on the
 * isolate.
 */
export async function withWorkerRequestDatabase<T>(
  env: Env,
  callback: () => Promise<T>,
  options?: {
    createHandle?: WorkerDatabaseHandleFactory;
    createHttpDb?: WorkerHttpDatabaseFactory;
    waitUntil?: (promise: Promise<unknown>) => void;
  },
): Promise<T> {
  const driver = env.DATABASE_DRIVER?.trim().toLowerCase();
  if (driver !== "neon-http" && driver !== "neon-websocket") {
    throw new Error(
      "WORKER_DATABASE_DRIVER_UNSUPPORTED: DATABASE_DRIVER must be neon-http or neon-websocket",
    );
  }
  if (driver === "neon-http") {
    const db = (options?.createHttpDb ?? createDbForRequest)(env);
    return withRequestDatabase(
      db as unknown as ReturnType<typeof getDb>,
      callback,
      options?.waitUntil ? { deferCleanup: options.waitUntil } : undefined,
    );
  }
  const handle = (options?.createHandle ?? createNeonTransactionDbForRequest)(env);
  const noCallbackError = Symbol("no-callback-error");
  let callbackError: unknown | typeof noCallbackError = noCallbackError;
  let result: T | undefined;
  let closeDeferred = false;
  let deferredClose: Promise<void> | null = null;
  try {
    result = await withRequestDatabase(
      handle.db as unknown as ReturnType<typeof getDb>,
      callback,
      options?.waitUntil
        ? {
            deferCleanup(cleanup) {
              deferredClose = cleanup.then(async () => {
                try {
                  await handle.close();
                } catch {
                  throw new Error("WORKER_DATABASE_CLOSE_FAILED");
                }
              });
              options.waitUntil?.(deferredClose);
              closeDeferred = true;
            },
          }
        : undefined,
    );
  } catch (error) {
    callbackError = error;
  }
  if (!closeDeferred) {
    try {
      // `waitUntil` may throw after the close promise has already been
      // created. Await that exact promise so the handle closes once and its
      // rejection is observed instead of racing a second close.
      if (deferredClose) await deferredClose;
      else await handle.close();
    } catch {
      if (callbackError === noCallbackError) throw new Error("WORKER_DATABASE_CLOSE_FAILED");
    }
  }
  if (callbackError !== noCallbackError) throw callbackError;
  return result as T;
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
  return withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, async () => {
    const capabilitiesEnabled =
      options?.capabilitiesEnabled ??
      (await import("./plugin-config"))
        .resolveEnabledPlugins({
          STEWARD_PLUGINS: runtimeEnvironmentValue("STEWARD_PLUGINS"),
          STEWARD_ENABLE_TRADING: runtimeEnvironmentValue("STEWARD_ENABLE_TRADING"),
        })
        .has("capabilities");
    if (
      !capabilitiesEnabled ||
      runtimeEnvironmentValue("STEWARD_UPSTREAM_LEASE_SWEEPER") === "false"
    )
      return null;
    const sweep =
      options?.sweep ??
      (await import("./services/upstream-credential-lease-scheduler"))
        .runUpstreamCredentialLeaseSweep;
    return sweep();
  });
}

export async function runWorkerGoogleCredentialLifecycleSweep(
  env: Env,
  options?: { sweep?: () => Promise<unknown> },
): Promise<unknown | null> {
  return withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, async () => {
    if (
      runtimeEnvironmentValue("STEWARD_GOOGLE_LIFECYCLE_SWEEPER") === "false" ||
      !runtimeEnvironmentValue("GOOGLE_PROVIDER_CLIENT_ID") ||
      !runtimeEnvironmentValue("GOOGLE_PROVIDER_CLIENT_SECRET")
    ) {
      return null;
    }
    const sweep =
      options?.sweep ??
      (await import("./services/provider-google-lifecycle-scheduler"))
        .runGoogleCredentialLifecycleRecoverySweep;
    return sweep();
  });
}

export async function runWorkerXCredentialLifecycleSweep(
  env: Env,
  options?: { sweep?: () => Promise<unknown> },
): Promise<unknown | null> {
  return withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, async () => {
    if (
      runtimeEnvironmentValue("STEWARD_X_LIFECYCLE_SWEEPER") === "false" ||
      !runtimeEnvironmentValue("X_CLIENT_ID") ||
      !runtimeEnvironmentValue("X_CLIENT_SECRET") ||
      !runtimeEnvironmentValue("STEWARD_MASTER_PASSWORD")
    ) {
      return null;
    }
    const sweep =
      options?.sweep ??
      (await import("./services/provider-x-lifecycle-scheduler"))
        .runXCredentialLifecycleRecoverySweep;
    return sweep();
  });
}

/**
 * Pull the first Worker's bindings into `globalThis.process.env` for legacy
 * modules that capture process settings during cold initialization.
 *
 * Workers expose `nodejs_compat`'s `process.env` as an empty object on cold
 * boot — bindings come in via the `fetch` handler's `env` argument instead.
 * This compatibility bridge runs only during isolate initialization. Request-
 * time security settings use an immutable async-local binding snapshot; they
 * must never depend on this isolate-global object.
 *
 * Legacy module-init readers still require process.env until they are migrated.
 * Re-running this bridge per request would create cross-request binding races.
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

function validateWorkerSecurityEnv(): void {
  // Validate authentication-critical bindings before opening a database
  // connection. The async-local environment belongs to this event, so another
  // concurrent request cannot replace the bindings being checked.
  validateJwtSecretEnv();
}

async function ensureWorkerInit(env: Env): Promise<void> {
  if (workerInit) return workerInit;
  workerInit = (async () => {
    // Workers bindings are only available inside fetch(). Hydrate process.env
    // before importing app modules that read required env at module init.
    hydrateProcessEnv(env);
    // SEC-134: the Bun entry (index.ts) runs validateJwtSecretEnv() at startup;
    // run the same validation on the Workers boot path so a bad/missing JWT
    // secret or malformed AGENT_TOKEN_EXPIRY fails closed at cold start instead
    // of surfacing at first token sign/verify.
    validateWorkerSecurityEnv();
    const redisOk = await initRedis(env);
    // Auth stores (passkey challenges, magic-link tokens, SIWE/SIWS nonces)
    // must be initialized too — without this they stay on the lazy memory
    // backend and one-time state is lost across isolates / cold starts.
    const { trackAuditEvent } = await import("./services/audit");
    const { isHstsEnabled } = await import("./middleware/security-headers");
    const dbUrl = (env.DATABASE_URL || "").toLowerCase();
    // Best-effort boot telemetry (a one-time observability breadcrumb of the
    // TLS/HSTS posture at cold start) — NOT a security mutation or a tamper-
    // evident control event, and there is no client action to deny. A write
    // failure here must not abort worker init. Security/compliance events use
    // awaited writeAuditEvent.
    // Await even this best-effort breadcrumb before releasing a request-owned
    // WebSocket handle. trackAuditEvent absorbs/logs its own failure, so boot
    // still proceeds without leaving background DB work on a closed handle.
    await trackAuditEvent({
      tenantId: "system",
      actorType: "system",
      action: "system.tls.config",
      metadata: {
        dbTlsEnforced:
          dbUrl.includes("sslmode=require") ||
          dbUrl.includes("sslmode=verify-ca") ||
          dbUrl.includes("sslmode=verify-full"),
        hstsEnabled: isHstsEnabled(),
        insecureDbAllowed: runtimeEnvironmentValue("STEWARD_ALLOW_INSECURE_DB") === "true",
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
    return withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, async () => {
      validateWorkerSecurityEnv();
      const executionCtx = ctx as { waitUntil?: (promise: Promise<unknown>) => void };
      const waitUntil =
        typeof executionCtx?.waitUntil === "function"
          ? executionCtx.waitUntil.bind(executionCtx)
          : undefined;
      return withWorkerRequestDatabase(
        env,
        async () => {
          await ensureWorkerInit(env);
          const app = await getComposedApp();
          return app.fetch(request, env, ctx as never);
        },
        waitUntil ? { waitUntil } : undefined,
      );
    });
  },
  async scheduled(
    _controller: unknown,
    env: Env,
    ctx: { waitUntil(promise: Promise<unknown>): void },
  ) {
    withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, () => {
      validateWorkerSecurityEnv();
      ctx.waitUntil(
        Promise.all([
          withWorkerRequestDatabase(env, () => runWorkerUpstreamCredentialLeaseSweep(env)),
          withWorkerRequestDatabase(env, () => runWorkerGoogleCredentialLifecycleSweep(env)),
          withWorkerRequestDatabase(env, () => runWorkerXCredentialLifecycleSweep(env)),
        ]),
      );
    });
  },
};
