import {
  inspectStewardReleaseReadiness,
  type StewardReleaseReadinessInspection,
  type StewardReleaseSchema,
} from "@stwd/db/steward-release-readiness";
import { STEWARD_SCHEMA_MIGRATIONS_MODE } from "@stwd/db/steward-schema-migrations";

export type StewardMigrationReadinessConfig =
  | { mode: "drizzle" }
  | { mode: "steward-owned"; expectedSchema: StewardReleaseSchema };

type ReadinessEnvironment = {
  NODE_ENV?: string;
  SKIP_MIGRATIONS?: string;
  STEWARD_MIGRATION_READINESS_MODE?: string;
  STEWARD_CORE_REPAIR_EXPECTED_SCHEMA?: string;
};

type InspectRelease = (options: {
  expectedSchema: StewardReleaseSchema;
}) => Promise<StewardReleaseReadinessInspection>;

export function resolveStewardMigrationReadinessConfig(
  env: ReadinessEnvironment = process.env,
): StewardMigrationReadinessConfig {
  const configuredMode = env.STEWARD_MIGRATION_READINESS_MODE?.trim();
  const skipsMigrations = env.SKIP_MIGRATIONS === "1" || env.SKIP_MIGRATIONS === "true";
  if (!configuredMode && env.NODE_ENV === "production" && skipsMigrations) {
    throw new Error(
      "Production SKIP_MIGRATIONS requires an explicit STEWARD_MIGRATION_READINESS_MODE",
    );
  }
  const mode = configuredMode || "drizzle";
  if (mode === "drizzle") return { mode };
  if (mode !== STEWARD_SCHEMA_MIGRATIONS_MODE) {
    throw new Error("STEWARD_MIGRATION_READINESS_MODE must be drizzle or steward-owned");
  }
  const expectedSchema = env.STEWARD_CORE_REPAIR_EXPECTED_SCHEMA?.trim();
  if (expectedSchema !== "public" && expectedSchema !== "steward") {
    throw new Error(
      "STEWARD_CORE_REPAIR_EXPECTED_SCHEMA is required in steward-owned mode (public or steward)",
    );
  }
  return { mode, expectedSchema };
}

/**
 * Cache the exhaustive catalog inspection briefly so public readiness probes
 * cannot turn it into an unbounded database workload. Startup forces a fresh
 * inspection before Bun opens its listener; later probes share an in-flight
 * check and revalidate periodically.
 */
export function createStewardReleaseReadinessProbe(options: {
  expectedSchema: StewardReleaseSchema;
  inspect?: InspectRelease;
  ttlMs?: number;
  failureTtlMs?: number;
  now?: () => number;
}): (force?: boolean) => Promise<StewardReleaseReadinessInspection> {
  const inspect = options.inspect ?? inspectStewardReleaseReadiness;
  const ttlMs = options.ttlMs ?? 30_000;
  const failureTtlMs = options.failureTtlMs ?? 5_000;
  const now = options.now ?? Date.now;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 300_000) {
    throw new Error("Steward release readiness cache TTL must be between 1s and 5min");
  }
  if (!Number.isSafeInteger(failureTtlMs) || failureTtlMs < 1_000 || failureTtlMs > 30_000) {
    throw new Error("Steward release readiness failure TTL must be between 1s and 30s");
  }

  let cached: { checkedAt: number; inspection: StewardReleaseReadinessInspection } | undefined;
  let cachedFailure: { checkedAt: number; error: unknown } | undefined;
  let inFlight: Promise<StewardReleaseReadinessInspection> | undefined;

  return async (force = false) => {
    const checkedAt = now();
    if (!force && cached && checkedAt - cached.checkedAt < ttlMs) {
      return cached.inspection;
    }
    if (!force && cachedFailure && checkedAt - cachedFailure.checkedAt < failureTtlMs) {
      throw cachedFailure.error;
    }
    if (inFlight) return inFlight;
    inFlight = inspect({ expectedSchema: options.expectedSchema })
      .then((inspection) => {
        cached = { checkedAt: now(), inspection };
        cachedFailure = undefined;
        return inspection;
      })
      .catch((error: unknown) => {
        cachedFailure = { checkedAt: now(), error };
        throw error;
      })
      .finally(() => {
        inFlight = undefined;
      });
    return inFlight;
  };
}
