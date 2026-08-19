/**
 * Data retention sweeps for SOC2 (CC2 privacy / data lifecycle).
 *
 * Deletes rows past their per-table TTL from high-volume operational tables.
 * Defaults are conservative; each table is independently overridable via env.
 *
 * Audit-event retention is tenant-scoped and disabled by default. Enabled
 * policies always archive a signed JSONL prefix and durably seal its receipt
 * before a separate transaction advances the floor and removes source rows.
 *
 * All deletes use parameterized intervals (`make_interval(days := $n)`) so
 * untrusted env values can never be interpolated into SQL text.
 */

import { getDb } from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { sql } from "drizzle-orm";
import { writeAuditEvent } from "./audit";
import { runTenantAuditRetention } from "./audit-archive";
import { runInternalJobForEachTenant } from "./tenant-job";

const SYSTEM_TENANT_ID = "system";

// Defaults (days). Override via the matching env var.
const DEFAULT_PROXY_AUDIT_DAYS = 90;
const DEFAULT_REFRESH_TOKEN_GRACE_DAYS = 7;
const DEFAULT_FAILED_TX_DAYS = 365;
const MIN_DEACTIVATED_USERS_DAYS = 30;

const SWEEP_INTERVAL_MS = 24 * 60 * 60 * 1000;
const INITIAL_DELAY_MS = 5 * 60 * 1000;

export interface SweepResult {
  table: string;
  deleted: number;
  /**
   * Set when rows were deleted but the compliance audit record for the sweep
   * failed to persist. Surfaces a non-repudiation gap to callers/monitoring
   * instead of silently swallowing it (the deletion itself is irreversible, so
   * we cannot roll back — we report).
   */
  auditFailed?: boolean;
  failures?: Array<{ tenantId: string; error: string }>;
}

export interface RetentionSweepOptions {
  auditWriter?: typeof writeAuditEvent;
  /** Overrides tenant archive execution for deterministic scheduler tests. */
  auditRetentionRunner?: typeof runTenantAuditRetention;
}

interface RetentionSweepContext {
  auditWriter: typeof writeAuditEvent;
  auditRetentionRunner: typeof runTenantAuditRetention;
  tenantId: string;
}

class RetentionAuthorizationAuditError extends Error {
  constructor(
    public readonly table: string,
    options?: { cause?: unknown },
  ) {
    super(`[retention] authorization audit record for ${table} failed to persist`, options);
    this.name = "RetentionAuthorizationAuditError";
  }
}

function readPositiveInt(envName: string): number | undefined {
  const raw = process.env[envName];
  if (raw === undefined || raw === "") return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
    console.warn(`[retention] ${envName} is not a non-negative integer: ${raw}; ignoring`);
    return undefined;
  }
  return n;
}

function rowsFromExecute<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object" && Array.isArray((result as { rows?: unknown }).rows)) {
    return (result as { rows: T[] }).rows;
  }
  return [];
}

async function deleteRows(query: ReturnType<typeof sql>): Promise<number> {
  const db = getDb();
  const res = (await db.execute(query)) as unknown;
  // drizzle pg result shapes vary across drivers:
  //   - postgres-js: returns an array (empty for DELETE without RETURNING) with a `.count` property
  //   - node-pg: returns `{ rowCount }`
  //   - pglite: returns `{ affectedRows }` or similar
  if (Array.isArray(res)) {
    const count = (res as unknown as { count?: number }).count;
    if (typeof count === "number") return count;
    return res.length;
  }
  if (res && typeof res === "object") {
    const obj = res as { rowCount?: number | null; affectedRows?: number | null };
    if (typeof obj.rowCount === "number") return obj.rowCount;
    if (typeof obj.affectedRows === "number") return obj.affectedRows;
  }
  return 0;
}

async function writeRetentionAuthorization(
  table: string,
  ctx: RetentionSweepContext,
): Promise<void> {
  const ttlDays = ttlForTable(table);
  try {
    await ctx.auditWriter({
      tenantId: ctx.tenantId,
      actorType: "system",
      action: "system.retention.sweep.authorized",
      resourceType: "table",
      resourceId: table,
      metadata: {
        table,
        ttlDays: ttlDays ?? null,
        ageThreshold: ttlDays !== undefined ? `${ttlDays}d` : "per-row expires_at",
      },
    });
  } catch (cause) {
    throw new RetentionAuthorizationAuditError(table, { cause });
  }
}

async function sweepProxyAuditLog(ctx: RetentionSweepContext): Promise<SweepResult> {
  const days = readPositiveInt("STEWARD_RETENTION_PROXY_AUDIT_DAYS") ?? DEFAULT_PROXY_AUDIT_DAYS;
  await writeRetentionAuthorization("proxy_audit_log", ctx);
  const deleted = await deleteRows(sql`
    DELETE FROM proxy_audit_log
    WHERE created_at < now() - make_interval(days => ${days})
  `);
  return { table: "proxy_audit_log", deleted };
}

async function sweepRefreshTokens(ctx: RetentionSweepContext): Promise<SweepResult> {
  const days =
    readPositiveInt("STEWARD_RETENTION_REFRESH_TOKEN_GRACE_DAYS") ??
    DEFAULT_REFRESH_TOKEN_GRACE_DAYS;
  await writeRetentionAuthorization("refresh_tokens", ctx);
  const deleted = await deleteRows(sql`
    DELETE FROM refresh_tokens
    WHERE expires_at < now() - make_interval(days => ${days})
  `);
  return { table: "refresh_tokens", deleted };
}

async function sweepFailedTransactions(ctx: RetentionSweepContext): Promise<SweepResult> {
  const days = readPositiveInt("STEWARD_RETENTION_FAILED_TX_DAYS") ?? DEFAULT_FAILED_TX_DAYS;
  await writeRetentionAuthorization("transactions", ctx);
  // Only terminal-failure states. Signed/broadcast/confirmed are kept for ledger continuity.
  const deleted = await deleteRows(sql`
    DELETE FROM transactions
    WHERE status IN ('rejected', 'failed')
      AND created_at < now() - make_interval(days => ${days})
  `);
  return { table: "transactions", deleted };
}

async function sweepAuditEvents(ctx: RetentionSweepContext): Promise<SweepResult | null> {
  // Retention is now tenant-owned and disabled by default. A boolean env
  // attestation is never sufficient authority to delete a chain prefix: each
  // enabled tenant is first copied into signed, durable JSONL archive rows and
  // only a sealed receipt can authorize the transactional floor+delete step.
  const policies = rowsFromExecute<{ tenant_id: string }>(
    await getDb().execute(sql`
      SELECT tenant_id FROM audit_retention_policies WHERE enabled = true ORDER BY tenant_id
    `),
  );
  if (policies.length === 0) return null;
  await writeRetentionAuthorization("audit_events", ctx);
  let deleted = 0;
  const failures: Array<{ tenantId: string; error: string }> = [];
  for (const policy of policies) {
    try {
      const result = await ctx.auditRetentionRunner(policy.tenant_id);
      deleted += result.deleted;
    } catch (error) {
      failures.push({ tenantId: policy.tenant_id, error: "audit retention failed" });
      console.error(
        `[retention] audit retention failed for tenant ${policy.tenant_id}`,
        redactedThrownDiagnostics(error),
      );
    }
  }
  return { table: "audit_events", deleted, ...(failures.length > 0 ? { failures } : {}) };
}

async function sweepAuthKvStore(ctx: RetentionSweepContext): Promise<SweepResult> {
  // auth_kv_store rows carry their own expires_at (set per-namespace TTL by the
  // auth store backend). Anything past expiry is dead weight.
  await writeRetentionAuthorization("auth_kv_store", ctx);
  const deleted = await deleteRows(sql`
    DELETE FROM auth_kv_store
    WHERE expires_at < now()
  `);
  return { table: "auth_kv_store", deleted };
}

async function sweepDeactivatedUsers(ctx: RetentionSweepContext): Promise<SweepResult | null> {
  const days = readPositiveInt("STEWARD_RETENTION_DEACTIVATED_USERS_DAYS");
  if (days === undefined) return null;
  if (days < MIN_DEACTIVATED_USERS_DAYS) {
    throw new Error(
      `[retention] STEWARD_RETENTION_DEACTIVATED_USERS_DAYS=${days} is below the ` +
        `${MIN_DEACTIVATED_USERS_DAYS}-day floor; refusing to hard-delete users.`,
    );
  }
  if (process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED !== "true") {
    throw new Error(
      "[retention] Deactivated-user cleanup performs global hard deletes. Set " +
        "STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED=true only after account " +
        "export/recovery policy is documented.",
    );
  }
  await writeRetentionAuthorization("users.deactivated", ctx);

  const db = getDb();
  let deleted = 0;
  await db.transaction(async (tx) => {
    await tx.execute(sql`
      DELETE FROM refresh_tokens
      WHERE user_id IN (
        SELECT id FROM users
        WHERE deactivated_at IS NOT NULL
          AND deactivated_at < now() - make_interval(days => ${days})
          AND NOT EXISTS (
            SELECT 1 FROM user_tenants
            WHERE user_tenants.user_id = users.id
              AND user_tenants.role = 'owner'
          )
      )
    `);
    const removed = rowsFromExecute<{ id: string }>(
      await tx.execute(sql`
      DELETE FROM users
      WHERE deactivated_at IS NOT NULL
        AND deactivated_at < now() - make_interval(days => ${days})
        AND NOT EXISTS (
          SELECT 1 FROM user_tenants
          WHERE user_tenants.user_id = users.id
            AND user_tenants.role = 'owner'
        )
      RETURNING id
    `),
    );
    deleted = removed.length;
  });

  return { table: "users.deactivated", deleted };
}

function ttlForTable(table: string): number | undefined {
  switch (table) {
    case "proxy_audit_log":
      return readPositiveInt("STEWARD_RETENTION_PROXY_AUDIT_DAYS") ?? DEFAULT_PROXY_AUDIT_DAYS;
    case "refresh_tokens":
      return (
        readPositiveInt("STEWARD_RETENTION_REFRESH_TOKEN_GRACE_DAYS") ??
        DEFAULT_REFRESH_TOKEN_GRACE_DAYS
      );
    case "transactions":
      return readPositiveInt("STEWARD_RETENTION_FAILED_TX_DAYS") ?? DEFAULT_FAILED_TX_DAYS;
    case "audit_events":
      return undefined; // per-tenant policy; no global destructive default
    case "auth_kv_store":
      return undefined; // per-row expiry
    case "users.deactivated":
      return readPositiveInt("STEWARD_RETENTION_DEACTIVATED_USERS_DAYS");
    default:
      return undefined;
  }
}

/**
 * Run one full retention sweep across every managed table. Returns one entry
 * per table that was considered (audit_events is omitted unless an explicit
 * override enables deletion).
 */
export async function runRetentionSweep(
  options: RetentionSweepOptions = {},
): Promise<SweepResult[]> {
  const results: SweepResult[] = [];
  const shared = {
    auditWriter: options.auditWriter ?? writeAuditEvent,
    auditRetentionRunner: options.auditRetentionRunner ?? runTenantAuditRetention,
  };

  const tenantSweepers: Array<(context: RetentionSweepContext) => Promise<SweepResult | null>> = [
    sweepProxyAuditLog,
    sweepRefreshTokens,
    sweepFailedTransactions,
    sweepAuditEvents,
  ];
  const globalSweepers: Array<(context: RetentionSweepContext) => Promise<SweepResult | null>> = [
    sweepAuthKvStore,
    sweepDeactivatedUsers,
  ];

  const tenantRuns = await runInternalJobForEachTenant("data-retention", async (tenantId) => {
    const tenantResults: SweepResult[] = [];
    const ctx: RetentionSweepContext = { ...shared, tenantId };
    for (const sweeper of tenantSweepers) {
      const result = await runRetentionSweeper(sweeper, ctx);
      if (result) tenantResults.push(result);
    }
    return tenantResults;
  });
  results.push(...tenantRuns.flatMap(({ value }) => value));

  const globalContext: RetentionSweepContext = { ...shared, tenantId: SYSTEM_TENANT_ID };
  for (const sweeper of globalSweepers) {
    const result = await runRetentionSweeper(sweeper, globalContext);
    if (result) results.push(result);
  }
  return results;
}

async function runRetentionSweeper(
  sweeper: (context: RetentionSweepContext) => Promise<SweepResult | null>,
  ctx: RetentionSweepContext,
): Promise<SweepResult | null> {
  try {
    const r = await sweeper(ctx);
    if (!r) return null;
    if (r.deleted > 0) {
      const ttlDays = ttlForTable(r.table);
      // A retention deletion is a SOC2 data-lifecycle control event; its audit
      // record must be durable. Write it BLOCKING so a failure surfaces rather
      // than becoming a fire-and-forget console line. The deletion is already
      // committed and irreversible (no rollback), so on audit failure we flag
      // the result and log at error level instead of swallowing it. Other
      // sweepers still run — a background sweep should not abort wholesale on
      // one audit failure.
      try {
        await ctx.auditWriter({
          tenantId: ctx.tenantId,
          actorType: "system",
          action: "system.retention.sweep",
          resourceType: "table",
          resourceId: r.table,
          metadata: {
            table: r.table,
            deleted: r.deleted,
            ttlDays: ttlDays ?? null,
            ageThreshold: ttlDays !== undefined ? `${ttlDays}d` : "per-row expires_at",
          },
        });
      } catch (auditErr) {
        r.auditFailed = true;
        console.error(
          `[retention] audit record for sweep of ${r.table} (${r.deleted} rows deleted) FAILED to persist`,
          redactedThrownDiagnostics(auditErr),
        );
      }
    }
    return r;
  } catch (err) {
    if (err instanceof RetentionAuthorizationAuditError) {
      console.error(
        "[retention] authorization audit record failed; delete skipped",
        redactedThrownDiagnostics(err.cause ?? err),
      );
      return { table: err.table, deleted: 0, auditFailed: true };
    }
    console.error("[retention] sweep failed", redactedThrownDiagnostics(err));
    return null;
  }
}

/**
 * Start the periodic retention scheduler. First sweep runs after a 5-minute
 * delay so it doesn't compete with startup; subsequent sweeps every 24h.
 * Returns a cancel function.
 */
export function startRetentionScheduler(): () => void {
  if (process.env.STEWARD_RETENTION_DISABLED === "true") {
    console.log("[retention] STEWARD_RETENTION_DISABLED=true; scheduler not started");
    return () => {};
  }

  let interval: ReturnType<typeof setInterval> | undefined;

  const initial = setTimeout(() => {
    runRetentionSweep()
      .then((r) => {
        const total = r.reduce((acc, x) => acc + x.deleted, 0);
        console.log(`[retention] initial sweep complete: ${total} rows across ${r.length} tables`);
      })
      .catch((err) =>
        console.error("[retention] initial sweep error", redactedThrownDiagnostics(err)),
      );

    interval = setInterval(() => {
      runRetentionSweep()
        .then((r) => {
          const total = r.reduce((acc, x) => acc + x.deleted, 0);
          if (total > 0) {
            console.log(`[retention] sweep complete: ${total} rows across ${r.length} tables`);
          }
        })
        .catch((err) => console.error("[retention] sweep error", redactedThrownDiagnostics(err)));
    }, SWEEP_INTERVAL_MS);
    if (typeof interval.unref === "function") interval.unref();
  }, INITIAL_DELAY_MS);
  if (typeof initial.unref === "function") initial.unref();

  return () => {
    clearTimeout(initial);
    if (interval) clearInterval(interval);
  };
}
