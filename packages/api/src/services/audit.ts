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

import { createHmac } from "node:crypto";
import { getDb } from "@stwd/db";
import { sql } from "drizzle-orm";

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
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

let cachedKey: Uint8Array | null = null;
function getHmacKey(): Uint8Array {
  if (cachedKey) return cachedKey;
  const env = process.env.STEWARD_AUDIT_HMAC_KEY;
  if (env && env.length > 0) {
    if (/^[0-9a-fA-F]+$/.test(env) && env.length >= 32) {
      cachedKey = toU8(env);
    } else {
      cachedKey = new TextEncoder().encode(env);
    }
    return cachedKey;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "STEWARD_AUDIT_HMAC_KEY is required in production. Generate with `openssl rand -hex 32`.",
    );
  }
  console.warn(
    "⚠️ [audit] STEWARD_AUDIT_HMAC_KEY not set — using insecure dev fallback. Set before production.",
  );
  cachedKey = new TextEncoder().encode(
    "dev-audit-hmac-key-do-not-use-in-production-aaaaaaaaaaaaaaaaaaaaaaaa",
  );
  return cachedKey;
}

export type ActorType = "user" | "agent" | "platform" | "system" | "api-key";

export interface AuditEventInput {
  tenantId: string;
  actorType: ActorType;
  actorId?: string | null;
  /** Dotted action name, e.g. "vault.sign", "auth.login", "policy.update". */
  action: string;
  resourceType?: string | null;
  resourceId?: string | null;
  metadata?: Record<string, unknown>;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
}

/**
 * Canonical JSON: keys sorted, no whitespace, ISO timestamps. The HMAC commits
 * to this exact byte sequence — changing any field changes the digest.
 */
function canonicalize(fields: Record<string, unknown>): string {
  const keys = Object.keys(fields).sort();
  const ordered: Record<string, unknown> = {};
  for (const k of keys) ordered[k] = fields[k] ?? null;
  return JSON.stringify(ordered);
}

function computeHmac(key: Uint8Array, prevHash: Uint8Array, canonical: string): Uint8Array {
  const h = createHmac("sha256", key);
  h.update(prevHash);
  h.update(canonical);
  return new Uint8Array(h.digest());
}

/**
 * Append an event to the tenant's audit chain. Throws on failure — callers
 * MUST treat audit-write failure as an action failure for sensitive
 * operations (auth, signing, policy mutations).
 *
 * For non-blocking sites, see `trackAuditEvent`.
 */
export async function writeAuditEvent(ev: AuditEventInput): Promise<void> {
  const key = getHmacKey();
  const db = getDb();
  await db.transaction(async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtextextended(${`steward_audit_${ev.tenantId}`}, 0))`,
    );

    const headResult = (await tx.execute(
      sql`SELECT seq, hmac FROM audit_events WHERE tenant_id = ${ev.tenantId} ORDER BY seq DESC LIMIT 1`,
    )) as
      | Array<{ seq: number | string; hmac: unknown }>
      | { rows?: Array<{ seq: number | string; hmac: unknown }> };
    const headRows = Array.isArray(headResult) ? headResult : (headResult.rows ?? []);
    const head = headRows[0];
    const seq = head ? Number(head.seq) + 1 : 1;
    const prevHash = head ? toU8(head.hmac) : ZERO_HASH;

    const createdAt = new Date();
    // postgres-js does not auto-stringify Date objects in raw sql template
    // params. Convert to ISO and cast on the SQL side instead. See dcf772e.
    const createdAtIso = createdAt.toISOString();
    const metadata = ev.metadata ?? {};
    const canonical = canonicalize({
      tenant_id: ev.tenantId,
      seq,
      actor_type: ev.actorType,
      actor_id: ev.actorId ?? null,
      action: ev.action,
      resource_type: ev.resourceType ?? null,
      resource_id: ev.resourceId ?? null,
      metadata,
      ip_address: ev.ipAddress ?? null,
      user_agent: ev.userAgent ?? null,
      request_id: ev.requestId ?? null,
      created_at: createdAt.toISOString(),
    });

    const hmac = computeHmac(key, prevHash, canonical);

    await tx.execute(sql`
      INSERT INTO audit_events
        (tenant_id, seq, prev_hash, hmac, actor_type, actor_id, action,
         resource_type, resource_id, metadata, ip_address, user_agent,
         request_id, created_at)
      VALUES
        (${ev.tenantId}, ${seq}, ${prevHash}, ${hmac}, ${ev.actorType},
         ${ev.actorId ?? null}, ${ev.action}, ${ev.resourceType ?? null},
         ${ev.resourceId ?? null}, ${JSON.stringify(metadata)}::jsonb,
         ${ev.ipAddress ?? null}, ${ev.userAgent ?? null},
         ${ev.requestId ?? null}, ${createdAtIso}::timestamptz)
    `);
  });
}

/**
 * Fire-and-forget audit write. Use only for high-frequency, low-sensitivity
 * sites where the operation has already committed and an audit failure
 * should not bubble. Logs errors but does not throw.
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
  opts: { fromSeq?: number; toSeq?: number } = {},
): Promise<{ valid: true; count: number } | { valid: false; brokenAt: number }> {
  const key = getHmacKey();
  const db = getDb();
  const fromSeq = opts.fromSeq ?? 1;
  const toSeq = opts.toSeq;

  let prevHash: Uint8Array = ZERO_HASH;
  if (fromSeq > 1) {
    const prevRows = (await db.execute(
      sql`SELECT hmac FROM audit_events WHERE tenant_id = ${tenantId} AND seq = ${fromSeq - 1}`,
    )) as Array<{ hmac: unknown }>;
    if (prevRows[0]) prevHash = toU8(prevRows[0].hmac);
  }

  const rows = (await db.execute(
    toSeq !== undefined
      ? sql`SELECT * FROM audit_events WHERE tenant_id = ${tenantId} AND seq BETWEEN ${fromSeq} AND ${toSeq} ORDER BY seq ASC`
      : sql`SELECT * FROM audit_events WHERE tenant_id = ${tenantId} AND seq >= ${fromSeq} ORDER BY seq ASC`,
  )) as Array<{
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
  }>;

  let count = 0;
  for (const row of rows) {
    const rowHmac = toU8(row.hmac);
    const rowPrev = toU8(row.prev_hash);

    if (!u8Equals(rowPrev, prevHash)) {
      return { valid: false, brokenAt: Number(row.seq) };
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
      return { valid: false, brokenAt: Number(row.seq) };
    }

    prevHash = rowHmac;
    count++;
  }

  return { valid: true, count };
}
