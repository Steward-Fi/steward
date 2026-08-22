import { createHash, timingSafeEqual } from "node:crypto";
import type { Handler } from "hono";
import type { AuthStoreSources } from "./routes/auth";
import type { AppVariables } from "./services/context";

export type ReadinessCheck = {
  ok: boolean;
  required?: boolean;
  error?: string;
  source?: string;
  detail?: unknown;
};

export type ReadinessEnvironment = {
  allowMemoryAuthStores: boolean;
  probeToken?: string;
  requiresDurableAuthStores: boolean;
};

export type ReadinessDependencies = {
  apiVersion: string;
  startedAt: number;
  now?: () => number;
  environment: () => ReadinessEnvironment;
  checkDatabase: () => Promise<Record<string, ReadinessCheck>>;
  checkRedis: () => Promise<ReadinessCheck>;
  checkProxyClock: () => Promise<ReadinessCheck>;
  getAuthStoreSources: () => AuthStoreSources;
  isVaultConfigured: () => boolean;
  getAdditionalChecks?: () => Record<string, ReadinessCheck>;
};

function probeAuthorized(presented: string | undefined, expected: string | undefined): boolean {
  if (!expected || !presented) return false;
  const a = createHash("sha256").update(expected).digest();
  const b = createHash("sha256").update(presented).digest();
  return timingSafeEqual(a, b);
}

/**
 * Build the Bun readiness route without starting the Bun process. All I/O is
 * supplied by the entrypoint, which keeps this policy boundary mountable in
 * tests and reusable without migrations, schedulers, timers, or Bun.serve.
 */
export function createReadinessHandler(
  dependencies: ReadinessDependencies,
): Handler<{ Variables: AppVariables }> {
  return async (c) => {
    // An authorized probe can include operational diagnostics. Apply the
    // secret-bearing response policy before any dependency work so public,
    // authorized, and unexpected failure variants can never be cached or
    // replayed across callers by an intermediary.
    c.header("Cache-Control", "no-store, max-age=0");
    c.header("Pragma", "no-cache");
    c.header("Expires", "0");
    const checks: Record<string, ReadinessCheck> = {};

    try {
      Object.assign(checks, await dependencies.checkDatabase());
    } catch {
      checks.database = { ok: false, error: "Database health check failed" };
      checks.migrations = { ok: false, error: "Migration health check failed" };
    }

    try {
      checks.redis = await dependencies.checkRedis();
    } catch {
      checks.redis = { ok: false, error: "Redis health check failed" };
    }

    try {
      checks.proxyClock = await dependencies.checkProxyClock();
    } catch {
      checks.proxyClock = { ok: false, error: "Proxy health check failed" };
    }

    checks.vault = dependencies.isVaultConfigured()
      ? { ok: true }
      : { ok: false, error: "STEWARD_MASTER_PASSWORD not set" };

    const environment = dependencies.environment();
    const storeSources = dependencies.getAuthStoreSources();
    const memoryAuthStores = Object.entries(storeSources)
      .filter(([, source]) => source === "memory")
      .map(([name]) => name);
    const memoryAuthStoresAllowed =
      environment.allowMemoryAuthStores || !environment.requiresDurableAuthStores;
    checks.authStores = {
      ok: memoryAuthStores.length === 0 || memoryAuthStoresAllowed,
      source: Object.entries(storeSources)
        .map(([name, source]) => `${name}:${source}`)
        .join(","),
      ...(memoryAuthStores.length > 0 && !memoryAuthStoresAllowed
        ? { error: `Production auth stores using memory: ${memoryAuthStores.join(", ")}` }
        : {}),
    };

    if (dependencies.getAdditionalChecks) {
      Object.assign(checks, dependencies.getAdditionalChecks());
    }

    const allOk = Object.values(checks).every((check) => check.ok || check.required === false);
    const verbose = probeAuthorized(c.req.header("x-steward-probe-token"), environment.probeToken);
    const publicChecks = Object.fromEntries(
      Object.entries(checks).map(([name, check]) => [
        name,
        { ok: check.ok, ...(check.required === false ? { required: false } : {}) },
      ]),
    );
    const now = dependencies.now ?? Date.now;

    return c.json(
      {
        status: allOk ? "ready" : "not_ready",
        version: dependencies.apiVersion,
        uptime: Math.max(0, Math.floor((now() - dependencies.startedAt) / 1000)),
        checks: verbose ? checks : publicChecks,
      },
      allOk ? 200 : 503,
    );
  };
}
