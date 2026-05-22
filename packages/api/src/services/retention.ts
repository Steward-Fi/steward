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
import { trackAuditEvent } from "./audit";

const SYSTEM_TENANT_ID = "system";

// Defaults (days). Override via the matching env var.
const DEFAULT_PROXY_AUDIT_DAYS = 90;
const DEFAULT_REFRESH_TOKEN_GRACE_DAYS = 7;
const DEFAULT_FAILED_TX_DAYS = 365;
const DEFAULT_AUDIT_EVENTS_DAYS = 365;

const SWEEP_INTERVAL_MS = 24 * 60 * 60 * 1000;
const INITIAL_DELAY_MS = 5 * 60 * 1000;

export interface SweepResult {
  table: string;
  deleted: number;
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

async function deleteRows(query: ReturnType<typeof sql>): Promise<number> {
  const db = getDb();
  const res = (await db.execute(query)) as unknown;
  // drizzle pg result shapes vary; cover both array (postgres-js) and { rowCount } (node-pg).
  if (Array.isArray(res)) return res.length;
  if (res && typeof res === "object" && "rowCount" in res) {
    const rc = (res as { rowCount: number | null }).rowCount;
    return typeof rc === "number" ? rc : 0;
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
    // Default: never delete audit events.
    return null;
  }
  if (override < DEFAULT_AUDIT_EVENTS_DAYS) {
    console.warn(
      `[retention] STEWARD_RETENTION_AUDIT_EVENTS_DAYS=${override} is below the ` +
        `${DEFAULT_AUDIT_EVENTS_DAYS}-day SOC2 floor; retaining audit events for less ` +
        `than one year may violate SOC2 CC2 / CC7 requirements.`,
    );
  }
  const deleted = await deleteRows(sql`
    DELETE FROM audit_events
    WHERE created_at < now() - make_interval(days => ${override})
  `);
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
  ];

  for (const sweeper of sweepers) {
    try {
      const r = await sweeper();
      if (!r) continue;
      results.push(r);
      if (r.deleted > 0) {
        const ttlDays = ttlForTable(r.table);
        trackAuditEvent({
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
