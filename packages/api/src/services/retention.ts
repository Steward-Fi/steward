/**
 * Data retention sweeps for SOC2 (CC2 privacy / data lifecycle).
 *
 * Deletes rows past their per-table TTL from high-volume operational tables.
 * Defaults are conservative; each table is independently overridable via env.
 *
 * SOC2 note on `audit_events`: tamper-evident audit log entries support
 * incident-response and compliance review. We do NOT delete them by default,
 * and we emit a warning every sweep when an explicit override drops retention
 * below one year. Operators must opt in deliberately.
 *
 * All deletes use parameterized intervals (`make_interval(days := $n)`) so
 * untrusted env values can never be interpolated into SQL text.
 */

import { getDb } from "@stwd/db";
import { sql } from "drizzle-orm";
import { writeAuditEvent } from "./audit";

const SYSTEM_TENANT_ID = "system";

// Defaults (days). Override via the matching env var.
const DEFAULT_PROXY_AUDIT_DAYS = 90;
const DEFAULT_REFRESH_TOKEN_GRACE_DAYS = 7;
const DEFAULT_FAILED_TX_DAYS = 365;
const DEFAULT_AUDIT_EVENTS_DAYS = 365;
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

async function sweepProxyAuditLog(): Promise<SweepResult> {
  const days = readPositiveInt("STEWARD_RETENTION_PROXY_AUDIT_DAYS") ?? DEFAULT_PROXY_AUDIT_DAYS;
  const deleted = await deleteRows(sql`
    DELETE FROM proxy_audit_log
    WHERE created_at < now() - make_interval(days => ${days})
  `);
  return { table: "proxy_audit_log", deleted };
}

async function sweepRefreshTokens(): Promise<SweepResult> {
  const days =
    readPositiveInt("STEWARD_RETENTION_REFRESH_TOKEN_GRACE_DAYS") ??
    DEFAULT_REFRESH_TOKEN_GRACE_DAYS;
  const deleted = await deleteRows(sql`
    DELETE FROM refresh_tokens
    WHERE expires_at < now() - make_interval(days => ${days})
  `);
  return { table: "refresh_tokens", deleted };
}

async function sweepFailedTransactions(): Promise<SweepResult> {
  const days = readPositiveInt("STEWARD_RETENTION_FAILED_TX_DAYS") ?? DEFAULT_FAILED_TX_DAYS;
  // Only terminal-failure states. Signed/broadcast/confirmed are kept for ledger continuity.
  const deleted = await deleteRows(sql`
    DELETE FROM transactions
    WHERE status IN ('rejected', 'failed')
      AND created_at < now() - make_interval(days => ${days})
  `);
  return { table: "transactions", deleted };
}

async function sweepAuditEvents(): Promise<SweepResult | null> {
  const override = readPositiveInt("STEWARD_RETENTION_AUDIT_EVENTS_DAYS");
  if (override === undefined) {
    // Default: audit events are immutable — never deleted.
    return null;
  }
  // Sub-floor retention is a hard error, not a warning: silently keeping less
  // than the SOC2 floor would erode the compliance guarantee unnoticed.
  if (override < DEFAULT_AUDIT_EVENTS_DAYS) {
    throw new Error(
      `[retention] STEWARD_RETENTION_AUDIT_EVENTS_DAYS=${override} is below the ` +
        `${DEFAULT_AUDIT_EVENTS_DAYS}-day SOC2 floor; refusing to delete audit events. ` +
        "Set the retention >= 365 days (and STEWARD_RETENTION_AUDIT_ARCHIVE_CONFIRMED=true) to proceed.",
    );
  }
  // Audit rows are part of a tamper-evident chain: a plain DELETE of the prefix
  // would orphan the survivors from ZERO_HASH and make verification impossible.
  // Require an explicit operator attestation that rows were archived first.
  if (process.env.STEWARD_RETENTION_AUDIT_ARCHIVE_CONFIRMED !== "true") {
    throw new Error(
      "[retention] Deleting audit_events requires archiving first. Set " +
        "STEWARD_RETENTION_AUDIT_ARCHIVE_CONFIRMED=true only after the chain prefix " +
        "has been exported to durable storage; the sweep will then advance the " +
        "verified floor anchor so post-sweep verification still succeeds.",
    );
  }

  const db = getDb();
  let deleted = 0;
  // Per tenant: archive+drop the eligible prefix and advance the floor anchor
  // (floor_seq + floor_hmac = the newest surviving-prefix row) so verifyAuditChain
  // restarts the chain from the anchor instead of the public ZERO_HASH.
  await db.transaction(async (tx) => {
    const tenantRows = rowsFromExecute<{ tenant_id: string }>(
      await tx.execute(sql`
        SELECT DISTINCT tenant_id FROM audit_events
        WHERE created_at < now() - make_interval(days => ${override})
      `),
    );
    for (const { tenant_id } of tenantRows) {
      // New floor = highest seq among rows being dropped for this tenant.
      const anchorRows = rowsFromExecute<{ seq: number | string; hmac: unknown }>(
        await tx.execute(sql`
          SELECT seq, hmac FROM audit_events
          WHERE tenant_id = ${tenant_id}
            AND created_at < now() - make_interval(days => ${override})
          ORDER BY seq DESC LIMIT 1
        `),
      );
      const anchor = anchorRows[0];
      if (!anchor) continue;
      const floorSeq = Number(anchor.seq);
      const floorHmac = anchor.hmac as Uint8Array;

      const removed = await deleteRows(sql`
        DELETE FROM audit_events
        WHERE tenant_id = ${tenant_id}
          AND created_at < now() - make_interval(days => ${override})
      `);
      deleted += removed;

      // Persist the new verified floor. The head row already exists from append;
      // if not (legacy data) we still record the floor so verify can anchor.
      await tx.execute(sql`
        INSERT INTO audit_chain_heads (tenant_id, expected_seq, expected_count, head_hmac, floor_seq, floor_hmac, updated_at)
        VALUES (${tenant_id}, ${floorSeq}, 0, ${floorHmac}, ${floorSeq}, ${floorHmac}, now())
        ON CONFLICT (tenant_id) DO UPDATE
          SET floor_seq = ${floorSeq},
              floor_hmac = ${floorHmac},
              updated_at = now()
      `);
    }
  });
  return { table: "audit_events", deleted };
}

async function sweepAuthKvStore(): Promise<SweepResult> {
  // auth_kv_store rows carry their own expires_at (set per-namespace TTL by the
  // auth store backend). Anything past expiry is dead weight.
  const deleted = await deleteRows(sql`
    DELETE FROM auth_kv_store
    WHERE expires_at < now()
  `);
  return { table: "auth_kv_store", deleted };
}

async function sweepDeactivatedUsers(): Promise<SweepResult | null> {
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
      return readPositiveInt("STEWARD_RETENTION_AUDIT_EVENTS_DAYS");
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
export async function runRetentionSweep(): Promise<SweepResult[]> {
  const results: SweepResult[] = [];

  const sweepers: Array<() => Promise<SweepResult | null>> = [
    sweepProxyAuditLog,
    sweepRefreshTokens,
    sweepFailedTransactions,
    sweepAuditEvents,
    sweepAuthKvStore,
    sweepDeactivatedUsers,
  ];

  for (const sweeper of sweepers) {
    try {
      const r = await sweeper();
      if (!r) continue;
      results.push(r);
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
          await writeAuditEvent({
            tenantId: SYSTEM_TENANT_ID,
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
            `[retention] audit record for sweep of ${r.table} (${r.deleted} rows deleted) FAILED to persist:`,
            auditErr,
          );
        }
      }
    } catch (err) {
      console.error("[retention] sweep failed:", err);
    }
  }

  return results;
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
      .catch((err) => console.error("[retention] initial sweep error:", err));

    interval = setInterval(() => {
      runRetentionSweep()
        .then((r) => {
          const total = r.reduce((acc, x) => acc + x.deleted, 0);
          if (total > 0) {
            console.log(`[retention] sweep complete: ${total} rows across ${r.length} tables`);
          }
        })
        .catch((err) => console.error("[retention] sweep error:", err));
    }, SWEEP_INTERVAL_MS);
    if (typeof interval.unref === "function") interval.unref();
  }, INITIAL_DELAY_MS);
  if (typeof initial.unref === "function") initial.unref();

  return () => {
    clearTimeout(initial);
    if (interval) clearInterval(interval);
  };
}
