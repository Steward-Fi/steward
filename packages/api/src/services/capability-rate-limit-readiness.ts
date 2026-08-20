import { getDb } from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { sql } from "drizzle-orm";
import { getRedisClient, isRedisConfigured } from "../middleware/redis";
import { withAuthenticatedTenantDatabase } from "./context";

export interface CapabilityRateLimitReadiness {
  ok: boolean;
  source: "memory" | "postgres" | "redis";
  error?: string;
}

const READINESS_TENANT_ID = "steward-capability-rate-readiness";

function resultRows<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: T[] } | null)?.rows ?? [])) as T[];
}

/** Exercise the selected capability throttle backend through its production
 * authority boundary. In particular, PostgreSQL readiness is not inferred from
 * table existence: the app role must successfully enter a tenant transaction,
 * observe the exact forced-RLS policy, and exercise the real DML/trigger/function
 * authority in a rolled-back PL/pgSQL subtransaction that leaves no readiness
 * state behind. */
export async function checkCapabilityRateLimitReadiness(): Promise<CapabilityRateLimitReadiness> {
  if (getRedisClient()) return { ok: true, source: "redis" };
  if (isRedisConfigured()) {
    return {
      ok: false,
      source: "redis",
      error: "Configured Redis capability rate-limit backend is unavailable",
    };
  }
  if (process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test") {
    return { ok: true, source: "memory" };
  }

  let phase = "tenant-transaction";
  try {
    return await withAuthenticatedTenantDatabase(
      READINESS_TENANT_ID,
      "capability-rate-limit-readiness",
      "system",
      async () => {
        phase = "topology";
        const [topology] = resultRows<{
          enabled: boolean;
          forced: boolean;
          policy_installed: boolean;
          tenant_id: string | null;
        }>(
          await getDb().execute(sql`
            SELECT
              relation.relrowsecurity AS enabled,
              relation.relforcerowsecurity AS forced,
              NULLIF(current_setting('steward.tenant_id', true), '') AS tenant_id,
              EXISTS (
                SELECT 1
                FROM pg_policy policy
                WHERE policy.polrelid = relation.oid
                  AND policy.polname = 'steward_tenant_isolation'
              ) AS policy_installed
            FROM pg_class relation
            WHERE relation.oid = to_regclass('public.capability_rate_limit_buckets')
          `),
        );
        if (
          !topology ||
          topology.tenant_id !== READINESS_TENANT_ID ||
          !topology.enabled ||
          !topology.forced ||
          !topology.policy_installed
        ) {
          throw new Error("capability rate-limit RLS topology is incomplete");
        }
        phase = "dml-trigger-authority";
        // The exact expected failure is emitted by the writer fence only after
        // INSERT permission, RLS WITH CHECK, trigger execution, tenant deletion
        // lock function execution, and the parent-agent KEY SHARE lookup all
        // succeeded. The inner exception block rolls that failed statement back.
        // If the trigger is absent, INSERT succeeds and the explicit P0001 makes
        // readiness fail; any ACL/function drift escapes with its own error.
        await getDb().execute(sql`
          DO $capability_rate_readiness$
          DECLARE
            writer_fence_rejected boolean := false;
          BEGIN
            BEGIN
              INSERT INTO public.capability_rate_limit_buckets (
                tenant_id, agent_id, surface, reservations
              ) VALUES (
                'steward-capability-rate-readiness',
                'steward-capability-rate-readiness-missing-agent',
                'invoke',
                ARRAY[clock_timestamp()]
              );
            EXCEPTION WHEN foreign_key_violation THEN
              writer_fence_rejected := true;
            END;
            IF NOT writer_fence_rejected THEN
              RAISE EXCEPTION 'capability rate-limit writer fence did not reject readiness probe'
                USING ERRCODE = 'P0001';
            END IF;
          END
          $capability_rate_readiness$
        `);
        return { ok: true, source: "postgres" };
      },
    );
  } catch (error) {
    console.error(
      "[steward:readiness] capability rate-limit PostgreSQL exercise failed",
      redactedThrownDiagnostics(error),
    );
    return {
      ok: false,
      source: "postgres",
      error: `Capability rate-limit backend tenant/RLS exercise failed (${phase})`,
    };
  }
}
