/**
 * Audit logging for proxied requests.
 *
 * Logs every proxied request to the proxy_audit_log table in the database.
 * Designed for append-only request accounting. Callers should await writes
 * before returning whenever the audit event is part of the security trail.
 */

import { getDb, proxyAuditLog } from "@stwd/db";

export interface AuditEntry {
  agentId: string;
  tenantId: string;
  targetHost: string;
  targetPath: string;
  method: string;
  statusCode: number;
  latencyMs: number;
  reason?: string;
}

/**
 * Record a proxy audit log entry.
 * Audit failures are logged to stderr but never throw to the response path.
 */
export async function recordAudit(entry: AuditEntry): Promise<void> {
  try {
    await insertAuditEntry(entry);
  } catch (err) {
    // Best-effort audit is used only after the security-critical pre-forward
    // audit has already been persisted.
    console.error("[audit] Failed to record audit entry:", err);
  }
}

/**
 * Record a security-required audit event. Call this before decrypting or
 * forwarding credentials so audit storage outages fail closed.
 */
export async function recordRequiredAudit(entry: AuditEntry): Promise<void> {
  await insertAuditEntry(entry);
}

async function insertAuditEntry(entry: AuditEntry): Promise<void> {
  const db = getDb();
  await db.insert(proxyAuditLog).values({
    agentId: entry.agentId,
    tenantId: entry.tenantId,
    targetHost: entry.targetHost,
    targetPath: entry.targetPath,
    method: entry.method,
    statusCode: entry.statusCode,
    latencyMs: entry.latencyMs,
    reason: entry.reason,
  });
}
