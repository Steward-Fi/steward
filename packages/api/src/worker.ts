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
 *   - DATABASE_DRIVER=neon-websocket Selects the request-owned transaction-capable driver
 *   - REDIS_DRIVER=upstash          Selects the Upstash REST adapter
 *   - KV_REST_API_URL               Upstash REST endpoint
 *   - KV_REST_API_TOKEN             Upstash REST token
 *   - SKIP_MIGRATIONS=1             Migrations run via wrangler-driven CI script
 *   - NODE_ENV=production           Enables production validation in every deploy environment
 *   - STEWARD_JWT_SECRET            Canonical HS256 JWT signing secret
 *   - STEWARD_MASTER_PASSWORD       Vault keystore master password
 *   - STEWARD_KDF_SALT              Per-deployment vault KDF salt
 *   - STEWARD_AUDIT_HMAC_KEY        Tamper-evident audit-chain HMAC root
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
// here would evaluate Worker-sensitive auth modules before bindings are
// hydrated into process.env.
import {
  createJwtRuntimeAuthority,
  type JwtRuntimeEnvironment,
  validateJwtSecretEnv,
  withJwtRuntimeAuthority,
} from "@stwd/auth/jwt";
import {
  assertRlsDeploymentSafety,
  createDbForRequest,
  createNeonTransactionDbForRequest,
  getDb,
  type NeonTransactionDbHandle,
  withRequestDatabase,
} from "@stwd/db";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { initRedis } from "./middleware/redis";

export interface Env {
  DATABASE_URL: string;
  DATABASE_DRIVER?: string;
  NODE_ENV?: string;
  STEWARD_APP_DATABASE_ROLE?: string;
  STEWARD_PLATFORM_DATABASE_URL?: string;
  STEWARD_PLATFORM_DATABASE_ROLE?: string;
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
  STEWARD_EMBEDDED?: string;
  STEWARD_EMBEDDED_MODE?: string;
  STEWARD_DB_MODE?: string;
  STEWARD_ALLOW_DEV_SECRETS?: string;
  STEWARD_ALLOW_DEV_SECRET?: string;
  AGENT_TOKEN_EXPIRY?: string;
  STEWARD_IDENTITY_JWT_ALG?: string;
  STEWARD_IDENTITY_JWT_PRIVATE_KEY?: string;
  STEWARD_IDENTITY_JWT_KID?: string;
  STEWARD_IDENTITY_JWT_ISSUER?: string;
  STEWARD_IDENTITY_JWT_AUDIENCE?: string;
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
 * neon-websocket is the shipped driver: its handle is bound to the
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
    if (env.NODE_ENV !== "development" && env.NODE_ENV !== "test") {
      throw new Error(
        "WORKER_DATABASE_DRIVER_NOT_TRANSACTIONAL: Workers require neon-websocket unless NODE_ENV is explicitly development or test",
      );
    }
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

export async function runWorkerGoogleCredentialLifecycleSweep(
  env: Env,
  options?: { sweep?: () => Promise<unknown> },
): Promise<unknown | null> {
  hydrateProcessEnv(env);
  if (
    process.env.STEWARD_GOOGLE_LIFECYCLE_SWEEPER === "false" ||
    !process.env.GOOGLE_PROVIDER_CLIENT_ID ||
    !process.env.GOOGLE_PROVIDER_CLIENT_SECRET
  ) {
    return null;
  }
  const sweep =
    options?.sweep ??
    (await import("./services/provider-google-lifecycle-scheduler"))
      .runGoogleCredentialLifecycleRecoverySweep;
  return sweep();
}

export async function runWorkerXCredentialLifecycleSweep(
  env: Env,
  options?: { sweep?: () => Promise<unknown> },
): Promise<unknown | null> {
  hydrateProcessEnv(env);
  if (
    process.env.STEWARD_X_LIFECYCLE_SWEEPER === "false" ||
    !process.env.X_CLIENT_ID ||
    !process.env.X_CLIENT_SECRET ||
    !process.env.STEWARD_MASTER_PASSWORD
  ) {
    return null;
  }
  const sweep =
    options?.sweep ??
    (await import("./services/provider-x-lifecycle-scheduler"))
      .runXCredentialLifecycleRecoverySweep;
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

function workerJwtEnvironment(env: Env): Readonly<JwtRuntimeEnvironment> {
  return Object.freeze({
    // Workers are internet-facing deployments even when operators omit the
    // conventional Node-only NODE_ENV binding. Never inherit development
    // fallbacks from that omission.
    NODE_ENV: env.NODE_ENV?.trim() || "production",
    STEWARD_JWT_SECRET: env.STEWARD_JWT_SECRET,
    STEWARD_SESSION_SECRET: env.STEWARD_SESSION_SECRET,
    STEWARD_MASTER_PASSWORD: env.STEWARD_MASTER_PASSWORD,
    STEWARD_EMBEDDED: env.STEWARD_EMBEDDED,
    STEWARD_EMBEDDED_MODE: env.STEWARD_EMBEDDED_MODE,
    STEWARD_DB_MODE: env.STEWARD_DB_MODE,
    DATABASE_URL: env.DATABASE_URL,
    STEWARD_ALLOW_DEV_SECRETS: env.STEWARD_ALLOW_DEV_SECRETS,
    STEWARD_ALLOW_DEV_SECRET: env.STEWARD_ALLOW_DEV_SECRET,
    AGENT_TOKEN_EXPIRY: env.AGENT_TOKEN_EXPIRY,
    STEWARD_IDENTITY_JWT_ALG: env.STEWARD_IDENTITY_JWT_ALG,
    STEWARD_IDENTITY_JWT_PRIVATE_KEY: env.STEWARD_IDENTITY_JWT_PRIVATE_KEY,
    STEWARD_IDENTITY_JWT_KID: env.STEWARD_IDENTITY_JWT_KID,
    STEWARD_IDENTITY_JWT_ISSUER: env.STEWARD_IDENTITY_JWT_ISSUER,
    STEWARD_IDENTITY_JWT_AUDIENCE: env.STEWARD_IDENTITY_JWT_AUDIENCE,
    APP_URL: env.APP_URL,
  });
}

/**
 * Bind authentication-critical Worker configuration before any request code
 * can yield. Downstream JWT signing and verification resolve this immutable
 * authority rather than the isolate-wide process.env compatibility mirror.
 */
export function withWorkerJwtAuthority<T>(env: Env, callback: () => T): T {
  const authority = createJwtRuntimeAuthority(workerJwtEnvironment(env));
  return withJwtRuntimeAuthority(authority, callback);
}

function validateWorkerSecurityEnv(): void {
  // The request authority was resolved synchronously from this invocation's
  // bindings. This validation never consults the process.env compatibility
  // mirror, even after another request hydrates a different binding set.
  validateJwtSecretEnv();
}

export async function assertWorkerMigrationReadiness(
  pluginMigrationSources?: import("./migration-readiness").EnabledPluginMigrationSource[],
): Promise<void> {
  const { readMigrationReadiness } = await import("./migration-readiness");
  const enabledSources =
    pluginMigrationSources ?? (await import("./compose")).getComposedPluginMigrationSources();
  const migrationReadiness = await readMigrationReadiness({
    db: getDb(),
    migrationsRan: true,
    pluginMigrationSources: await enabledSources,
    pglite: false,
  });
  if (
    !migrationReadiness.database.ok ||
    !migrationReadiness.migrations.ok ||
    !migrationReadiness.pluginMigrations.ok
  ) {
    throw new Error("WORKER_MIGRATION_READINESS_FAILED");
  }
}

async function ensureWorkerInit(env: Env): Promise<void> {
  if (workerInit) return workerInit;
  const pendingInit = (async () => {
    // Workers bindings are only available inside fetch(). Hydrate process.env
    // before importing app modules that read required env at module init.
    hydrateProcessEnv(env);
    // SEC-134: the Bun entry (index.ts) runs validateJwtSecretEnv() at startup;
    // run the same validation on the Workers boot path so a bad/missing JWT
    // secret or malformed AGENT_TOKEN_EXPIRY fails closed at cold start instead
    // of surfacing at first token sign/verify.
    validateWorkerSecurityEnv();
    const expectedRole = env.STEWARD_APP_DATABASE_ROLE?.trim();
    if (!expectedRole) {
      throw new Error("STEWARD_APP_DATABASE_ROLE is required on Workers");
    }
    await assertWorkerMigrationReadiness();
    await assertRlsDeploymentSafety(getDb(), { expectedRole });
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
  workerInit = pendingInit;
  try {
    await pendingInit;
  } catch (error) {
    // A release may repair a missing/stale ledger without recycling every
    // isolate. Keep concurrent callers on the same failed attempt, then allow
    // the next request to prove the corrected binding/database generation.
    if (workerInit === pendingInit) workerInit = null;
    throw error;
  }
}

// Compose the deployable app once per isolate: lean core + this repo's opt-in
// plugins (trading). cached so we don't re-register plugins on every request.
// composeApp() dynamically imports the trading plugin so the lean core graph
// never statically references the trading stack.
let composedApp: Awaited<ReturnType<typeof import("./compose").composeApp>> | null = null;

export function __setWorkerInitForTests(value: Promise<void> | null): void {
  workerInit = value;
}

async function getComposedApp() {
  if (composedApp) return composedApp;
  const { composeApp } = await import("./compose");
  composedApp = await composeApp();
  return composedApp;
}

export default {
  async fetch(request: Request, env: Env, ctx: unknown): Promise<Response> {
    return withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, async () => {
      // Keep the legacy bridge for modules not yet migrated to request-local
      // configuration. Security-sensitive OIDC settings use the immutable
      // snapshot above and cannot be replaced by an overlapping request.
      return withWorkerJwtAuthority(env, async () => {
        hydrateProcessEnv(env);
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
    });
  },
  async scheduled(
    _controller: unknown,
    env: Env,
    ctx: { waitUntil(promise: Promise<unknown>): void },
  ) {
    withRuntimeEnvironment({ ...env, STEWARD_RUNTIME: "workers" }, () => {
      return withWorkerJwtAuthority(env, () => {
        hydrateProcessEnv(env);
        validateWorkerSecurityEnv();
        const scheduledWork = withWorkerRequestDatabase(env, () => ensureWorkerInit(env)).then(() =>
          Promise.all([
            withWorkerRequestDatabase(env, () => runWorkerUpstreamCredentialLeaseSweep(env)),
            withWorkerRequestDatabase(env, () => runWorkerGoogleCredentialLifecycleSweep(env)),
            withWorkerRequestDatabase(env, () => runWorkerXCredentialLifecycleSweep(env)),
          ]),
        );
        ctx.waitUntil(scheduledWork);
      });
    });
  },
};
