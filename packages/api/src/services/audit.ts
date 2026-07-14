/**
 * Tamper-evident audit log writer & verifier.
 *
 * Every audit event extends a per-tenant HMAC chain. Each row's `hmac`
 * commits to `prev_hash || canonical_json(event)` keyed by
 * STEWARD_AUDIT_HMAC_KEY. Mutating any historical row breaks verification
 * of every subsequent row.
 *
 * Trust boundary: the HMAC key is held in app config, separate from
 * Postgres credentials. An attacker with DB-only write access cannot
 * forge rows that pass verification.
 *
 * Concurrency: writers serialize chain extensions per tenant with
 * `pg_advisory_xact_lock(hashtextextended('steward_audit_'||tenant_id, 0))`.
 * Cross-tenant writes do not contend.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import {
  type AppendRequiredAudit,
  type AuditEventInput,
  appendAuditEvent,
  appendAuditEventWithinTx,
  getDb,
  withTenantAuditedTransaction,
  withTenantAuditQueue,
  writeAuditEvent,
} from "@stwd/db";
import { sql } from "drizzle-orm";

export type { AuditActorType as ActorType } from "@stwd/db";
// The tamper-evident audit-chain WRITE core (append/transaction primitives, the
// HMAC key handling, and metadata redaction) now lives in `@stwd/db` so the
// proxy package can extend the chain atomically without importing `@stwd/api`
// (which would be a dependency cycle). This file re-exports them so its existing
// importers are unaffected, and keeps the API-only READ side below
// (verifyAuditChain, evidence bundles, ActorType, trackAuditEvent).
export type { AppendRequiredAudit, AuditEventInput };
export {
  appendAuditEvent,
  appendAuditEventWithinTx,
  withTenantAuditedTransaction,
  withTenantAuditQueue,
  writeAuditEvent,
};

const ZERO_HASH = new Uint8Array(32);

function toU8(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === "string") {
    // Postgres bytea hex format: `\x...` or hex string.
    const hex = value.startsWith("\\x") ? value.slice(2) : value;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }
  throw new Error("toU8: unsupported value");
}

function u8Equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// Minimum entropy for the audit HMAC key: 32 bytes. Hex-encoded keys must be
// >= 64 hex chars (= 32 bytes); raw/passphrase keys must be >= 32 chars.
const MIN_HMAC_RAW_BYTES = 32;

let warnedDevFallback = false;
let cachedKey: Uint8Array | null = null;
function getHmacKey(): Uint8Array {
  if (cachedKey) return cachedKey;
  const env = process.env.STEWARD_AUDIT_HMAC_KEY;
  if (env && env.length > 0) {
    const isHex = /^[0-9a-fA-F]+$/.test(env) && env.length % 2 === 0;
    // Hex keys decode to env.length/2 bytes; raw keys count chars directly.
    const effectiveBytes = isHex ? env.length / 2 : env.length;
    if (effectiveBytes < MIN_HMAC_RAW_BYTES) {
      throw new Error(
        `STEWARD_AUDIT_HMAC_KEY is too weak: needs >= ${MIN_HMAC_RAW_BYTES} bytes of entropy ` +
          `(>= ${MIN_HMAC_RAW_BYTES * 2} hex chars, or >= ${MIN_HMAC_RAW_BYTES} raw chars). ` +
          "Generate with `openssl rand -hex 32`.",
      );
    }
    cachedKey =
      isHex && env.length >= MIN_HMAC_RAW_BYTES * 2 ? toU8(env) : new TextEncoder().encode(env);
    return cachedKey;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "STEWARD_AUDIT_HMAC_KEY is required in production. Generate with `openssl rand -hex 32`.",
    );
  }
  // Default-deny: the dev fallback is only allowed with an explicit opt-in
  // consistent with the rest of the repo (STEWARD_ALLOW_DEV_SECRETS).
  if (process.env.STEWARD_ALLOW_DEV_SECRETS !== "true") {
    throw new Error(
      "STEWARD_AUDIT_HMAC_KEY is required. For local development only, set " +
        "STEWARD_ALLOW_DEV_SECRETS=true to use the insecure dev key.",
    );
  }
  if (!warnedDevFallback) {
    warnedDevFallback = true;
    console.warn(
      "⚠️ [audit] STEWARD_AUDIT_HMAC_KEY not set — using INSECURE dev fallback " +
        "(STEWARD_ALLOW_DEV_SECRETS=true). Audit chain is NOT tamper-evident. Never use in production.",
    );
  }
  cachedKey = new TextEncoder().encode(
    "dev-audit-hmac-key-do-not-use-in-production-aaaaaaaaaaaaaaaaaaaaaaaa",
  );
  return cachedKey;
}

/**
 * Canonical JSON: keys sorted, no whitespace, ISO timestamps. The HMAC commits
 * to this exact byte sequence — changing any field changes the digest.
 */
function canonicalJsonValue(value: unknown): unknown {
  if (value === undefined) return null;
  if (value === null) return null;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((item) => canonicalJsonValue(item));
  if (typeof value === "object") {
    const ordered: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      ordered[key] = canonicalJsonValue((value as Record<string, unknown>)[key]);
    }
    return ordered;
  }
  return value;
}

function canonicalize(fields: Record<string, unknown>): string {
  return JSON.stringify(canonicalJsonValue(fields));
}

function computeHmac(key: Uint8Array, prevHash: Uint8Array, canonical: string): Uint8Array {
  const h = createHmac("sha256", key);
  h.update(prevHash);
  h.update(canonical);
  return new Uint8Array(h.digest());
}

function rowsFromExecute<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object" && Array.isArray((result as { rows?: unknown }).rows)) {
    return (result as { rows: T[] }).rows;
  }
  return [];
}

/**
 * Fire-and-forget audit write. Use ONLY for genuinely best-effort, low-
 * sensitivity observability where the operation has already committed and an
 * audit failure must not bubble (e.g. high-frequency telemetry, boot breadcrumbs).
 * Logs errors but does not throw.
 *
 * Do NOT use this for security-relevant mutations or tamper-evident COMPLIANCE
 * control events (auth, signing, key export, policy/signer/quorum changes,
 * credential issuance/revocation, retention/data-lifecycle, tenant admin). Those
 * MUST use the awaited `writeAuditEvent` and treat a write failure as an action
 * failure (deny / roll back / surface), so a security event cannot occur without
 * a durable record.
 */
export function trackAuditEvent(ev: AuditEventInput): void {
  writeAuditEvent(ev).catch((err) => {
    console.error(`[audit] Failed to write event ${ev.action} for tenant ${ev.tenantId}:`, err);
  });
}

/**
 * Walk the chain for a tenant and verify every HMAC.
 *
 * Returns `{ valid: true, count }` if the entire range verifies, otherwise
 * `{ valid: false, brokenAt }` pointing to the first row whose digest does
 * not match the expected value computed from its predecessor.
 */
export async function verifyAuditChain(
  tenantId: string,
  opts: { fromSeq?: number; toSeq?: number; requireHead?: boolean } = {},
): Promise<{ valid: true; count: number } | { valid: false; brokenAt: number }> {
  const key = getHmacKey();
  const db = getDb();
  const requestedFromSeq = opts.fromSeq ?? 1;
  const toSeq = opts.toSeq;

  // Out-of-band high-water-mark: persisted atomically with each append. Lets us
  // detect tail-truncation / whole-chain deletion that walking the surviving
  // rows alone cannot (an open-ended walk of a truncated chain still "verifies").
  const headRows = rowsFromExecute<{
    expected_seq: number | string;
    expected_count: number | string;
    head_hmac: unknown;
    floor_seq: number | string | null;
    floor_hmac: unknown;
  }>(
    await db.execute(
      sql`SELECT expected_seq, expected_count, head_hmac, floor_seq, floor_hmac
          FROM audit_chain_heads WHERE tenant_id = ${tenantId} LIMIT 1`,
    ),
  );
  const head = headRows[0];
  if (!head && opts.requireHead) {
    return { valid: false, brokenAt: requestedFromSeq };
  }
  const floorSeq = head?.floor_seq != null ? Number(head.floor_seq) : 0;
  const floorHmac = head?.floor_hmac != null ? toU8(head.floor_hmac) : null;

  // Genesis prevHash: after a retention archive+drop, the chain restarts from a
  // stored floor anchor rather than the public ZERO_HASH (which an attacker
  // could re-derive to forge a fresh seq=1). Below the floor, rows are gone.
  const genesisSeq = floorSeq + 1;
  let prevHash: Uint8Array = floorSeq > 0 && floorHmac ? floorHmac : ZERO_HASH;

  // Full-chain verification (request starts at or before the live genesis):
  // compare on-disk reality against the high-water-mark to catch truncation.
  const isFullChainVerify = requestedFromSeq <= genesisSeq;
  if (isFullChainVerify && head) {
    const expectedSeqHwm = Number(head.expected_seq);
    const expectedCount = Number(head.expected_count);
    const aggRows = rowsFromExecute<{ max_seq: number | string | null; cnt: number | string }>(
      await db.execute(
        sql`SELECT MAX(seq) AS max_seq, COUNT(*) AS cnt FROM audit_events WHERE tenant_id = ${tenantId} AND seq >= ${genesisSeq}`,
      ),
    );
    const actualMaxSeq = aggRows[0]?.max_seq != null ? Number(aggRows[0].max_seq) : 0;
    const actualCount = aggRows[0]?.cnt != null ? Number(aggRows[0].cnt) : 0;
    const expectedLiveCount = expectedCount - (genesisSeq - 1);
    // Missing newest rows (tail truncation) or whole-chain deletion: the stored
    // head outranks / outcounts what survives on disk. Point brokenAt at the
    // first missing seq.
    if (actualMaxSeq < expectedSeqHwm || actualCount < expectedLiveCount) {
      return {
        valid: false,
        brokenAt: actualMaxSeq + 1 < genesisSeq ? genesisSeq : actualMaxSeq + 1,
      };
    }
  }
  // A request that starts at genesis but there is NO head row yet means either a
  // never-written tenant (count 0, fine) or a head row that was itself deleted
  // alongside the chain — handled by the walk + final count comparison below.

  // Rows below the floor have been archived+dropped; never expect them on disk.
  const effectiveFromSeq = Math.max(requestedFromSeq, genesisSeq);

  if (effectiveFromSeq > genesisSeq) {
    const predecessorRows = rowsFromExecute<{ hmac: unknown }>(
      await db.execute(
        sql`SELECT hmac FROM audit_events WHERE tenant_id = ${tenantId} AND seq = ${effectiveFromSeq - 1} LIMIT 1`,
      ),
    );
    const predecessor = predecessorRows[0];
    if (predecessor) {
      prevHash = toU8(predecessor.hmac);
    }
  }

  const rows = rowsFromExecute<{
    tenant_id: string;
    seq: number | string;
    prev_hash: unknown;
    hmac: unknown;
    actor_type: string;
    actor_id: string | null;
    action: string;
    resource_type: string | null;
    resource_id: string | null;
    metadata: Record<string, unknown> | null;
    ip_address: string | null;
    user_agent: string | null;
    request_id: string | null;
    created_at: Date | string;
  }>(
    await db.execute(
      toSeq !== undefined
        ? sql`SELECT * FROM audit_events WHERE tenant_id = ${tenantId} AND seq BETWEEN ${effectiveFromSeq} AND ${toSeq} ORDER BY seq ASC`
        : sql`SELECT * FROM audit_events WHERE tenant_id = ${tenantId} AND seq >= ${effectiveFromSeq} ORDER BY seq ASC`,
    ),
  );

  let count = 0;
  let expectedSeq = effectiveFromSeq;
  for (const row of rows) {
    const rowSeq = Number(row.seq);
    if (rowSeq !== expectedSeq) {
      return { valid: false, brokenAt: expectedSeq };
    }

    const rowHmac = toU8(row.hmac);
    const rowPrev = toU8(row.prev_hash);

    if (!u8Equals(rowPrev, prevHash)) {
      return { valid: false, brokenAt: rowSeq };
    }

    const created = row.created_at instanceof Date ? row.created_at : new Date(row.created_at);
    const canonical = canonicalize({
      tenant_id: row.tenant_id,
      seq: Number(row.seq),
      actor_type: row.actor_type,
      actor_id: row.actor_id,
      action: row.action,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      metadata: row.metadata ?? {},
      ip_address: row.ip_address,
      user_agent: row.user_agent,
      request_id: row.request_id,
      created_at: created.toISOString(),
    });
    const expected = computeHmac(key, prevHash, canonical);
    if (!u8Equals(rowHmac, expected)) {
      return { valid: false, brokenAt: rowSeq };
    }

    prevHash = rowHmac;
    count++;
    expectedSeq++;
  }

  if (toSeq !== undefined && expectedSeq <= toSeq) {
    return { valid: false, brokenAt: expectedSeq };
  }

  return { valid: true, count };
}

// ─── Evidence bundle support ──────────────────────────────────────────────────

function toHex(value: unknown): string {
  const bytes = toU8(value);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * A single event as it appears in an offline-verifiable evidence bundle. All
 * fields that feed the row's canonicalization are included so an third-party
 * verifier can reconstruct linkage (prevHash === prior hmac) WITHOUT the HMAC
 * key. `prevHash`/`hmac` are hex. Row HMACs are NOT recomputable offline (that
 * needs the secret key) — the bundle proves linkage + head match, not per-row
 * recomputation.
 */
export interface BundleEvent {
  seq: number;
  prevHash: string;
  hmac: string;
  actorType: string;
  actorId: string | null;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown>;
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
  createdAt: string;
}

export interface AuditChainHeadInfo {
  /** Head sequence per the out-of-band high-water-mark. */
  expectedSeq: number;
  /** Live event count committed by the high-water-mark. */
  expectedCount: number;
  /** Hex HMAC of the head event. */
  headHmac: string;
  /** Retention floor (0 when nothing archived). */
  floorSeq: number;
}

export interface AuditBundleData {
  head: AuditChainHeadInfo | null;
  events: BundleEvent[];
  /** Hex HMAC of the newest event actually present in `events` (bundle head). */
  bundleHeadHmac: string | null;
  /** Seq of the newest event in `events`. */
  bundleHeadSeq: number | null;
}

/**
 * Read the events in [fromSeq, toSeq] for a tenant plus the chain-head
 * high-water-mark, formatted for an evidence bundle. Pure read; does not touch
 * the HMAC writer or verifier state.
 */
export async function readAuditBundleData(
  tenantId: string,
  fromSeq: number,
  toSeq: number,
): Promise<AuditBundleData> {
  const db = getDb();

  const headRows = rowsFromExecute<{
    expected_seq: number | string;
    expected_count: number | string;
    head_hmac: unknown;
    floor_seq: number | string | null;
  }>(
    await db.execute(
      sql`SELECT expected_seq, expected_count, head_hmac, floor_seq
          FROM audit_chain_heads WHERE tenant_id = ${tenantId} LIMIT 1`,
    ),
  );
  const headRow = headRows[0];
  const head: AuditChainHeadInfo | null = headRow
    ? {
        expectedSeq: Number(headRow.expected_seq),
        expectedCount: Number(headRow.expected_count),
        headHmac: toHex(headRow.head_hmac),
        floorSeq: headRow.floor_seq != null ? Number(headRow.floor_seq) : 0,
      }
    : null;

  const rows = rowsFromExecute<{
    seq: number | string;
    prev_hash: unknown;
    hmac: unknown;
    actor_type: string;
    actor_id: string | null;
    action: string;
    resource_type: string | null;
    resource_id: string | null;
    metadata: Record<string, unknown> | null;
    ip_address: string | null;
    user_agent: string | null;
    request_id: string | null;
    created_at: Date | string;
  }>(
    await db.execute(
      sql`SELECT seq, prev_hash, hmac, actor_type, actor_id, action, resource_type,
                 resource_id, metadata, ip_address, user_agent, request_id, created_at
          FROM audit_events
          WHERE tenant_id = ${tenantId} AND seq BETWEEN ${fromSeq} AND ${toSeq}
          ORDER BY seq ASC`,
    ),
  );

  const events: BundleEvent[] = rows.map((row) => {
    const created = row.created_at instanceof Date ? row.created_at : new Date(row.created_at);
    return {
      seq: Number(row.seq),
      prevHash: toHex(row.prev_hash),
      hmac: toHex(row.hmac),
      actorType: row.actor_type,
      actorId: row.actor_id,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      metadata: row.metadata ?? {},
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      requestId: row.request_id,
      createdAt: created.toISOString(),
    };
  });

  const last = events.length > 0 ? events[events.length - 1] : null;

  return {
    head,
    events,
    bundleHeadHmac: last ? last.hmac : null,
    bundleHeadSeq: last ? last.seq : null,
  };
}
