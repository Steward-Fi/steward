import { createHash, randomUUID } from "node:crypto";
import { auditEvents, type TradeOrderRecoveryRow, tradeOrderRecoveries } from "@stwd/db";
import { and, eq, lt, sql } from "drizzle-orm";
import type { AuditEventInput, DbHandle } from "../context";

export type TradeRecoveryVenue = "hyperliquid" | "polymarket";
export type TradeRecoveryEnvelope = {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
};

const EFFECT_LEASE_MS = 30_000;
const RELEASED_CLAIM_TIME = new Date(0);

export function tradeRecoveryHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export type BeginTradeRecoveryResult =
  | { kind: "new"; row: TradeOrderRecoveryRow; claimToken: string }
  | { kind: "existing"; row: TradeOrderRecoveryRow }
  | { kind: "conflict"; row: TradeOrderRecoveryRow };

export function isPreparedTradeRecoveryStale(
  row: TradeOrderRecoveryRow,
  now = Date.now(),
): boolean {
  return row.state === "prepared" && row.claimedAt.getTime() < now - EFFECT_LEASE_MS;
}

export async function findTradeRecovery(
  db: DbHandle,
  input: {
    tenantId: string;
    agentId: string;
    venue: TradeRecoveryVenue;
    idempotencyKey: string;
    bodyHash: string;
  },
): Promise<{ kind: "existing" | "conflict"; row: TradeOrderRecoveryRow } | null> {
  const [row] = await db
    .select()
    .from(tradeOrderRecoveries)
    .where(
      and(
        eq(tradeOrderRecoveries.tenantId, input.tenantId),
        eq(tradeOrderRecoveries.agentId, input.agentId),
        eq(tradeOrderRecoveries.venue, input.venue),
        eq(tradeOrderRecoveries.idempotencyKeyHash, tradeRecoveryHash(input.idempotencyKey)),
      ),
    )
    .limit(1);
  if (!row) return null;
  return { kind: row.bodyHash === input.bodyHash ? "existing" : "conflict", row };
}

export async function beginTradeRecovery(
  db: DbHandle,
  input: {
    tenantId: string;
    agentId: string;
    sessionId: string;
    venue: TradeRecoveryVenue;
    idempotencyKey: string;
    bodyHash: string;
  },
): Promise<BeginTradeRecoveryResult> {
  const claimToken = randomUUID();
  const idempotencyKeyHash = tradeRecoveryHash(input.idempotencyKey);
  const inserted = await db
    .insert(tradeOrderRecoveries)
    .values({
      tenantId: input.tenantId,
      agentId: input.agentId,
      sessionId: input.sessionId,
      venue: input.venue,
      idempotencyKeyHash,
      bodyHash: input.bodyHash,
      claimToken,
    })
    .onConflictDoNothing()
    .returning();
  if (inserted[0]) return { kind: "new", row: inserted[0], claimToken };

  const [existing] = await db
    .select()
    .from(tradeOrderRecoveries)
    .where(
      and(
        eq(tradeOrderRecoveries.tenantId, input.tenantId),
        eq(tradeOrderRecoveries.agentId, input.agentId),
        eq(tradeOrderRecoveries.venue, input.venue),
        eq(tradeOrderRecoveries.idempotencyKeyHash, idempotencyKeyHash),
      ),
    )
    .limit(1);
  if (!existing) throw new Error("TRADE_RECOVERY_INSERT_LOST");
  if (existing.bodyHash !== input.bodyHash) return { kind: "conflict", row: existing };

  // No venue I/O can occur before prepared -> submitting. If an owner crashes
  // in that gap, a retry may safely take over the stale prepared claim. The
  // token CAS ensures the old owner can no longer checkpoint submission.
  const reclaimed = await db
    .update(tradeOrderRecoveries)
    .set({ claimToken, claimedAt: new Date(), updatedAt: new Date() })
    .where(
      and(
        eq(tradeOrderRecoveries.id, existing.id),
        eq(tradeOrderRecoveries.bodyHash, input.bodyHash),
        eq(tradeOrderRecoveries.state, "prepared"),
        lt(tradeOrderRecoveries.claimedAt, new Date(Date.now() - EFFECT_LEASE_MS)),
      ),
    )
    .returning();
  const reclaimedRow = reclaimed?.[0];
  return reclaimedRow
    ? { kind: "new", row: reclaimedRow, claimToken }
    : { kind: "existing", row: existing };
}

export async function checkpointTradeSubmissionStart(
  db: DbHandle,
  input: { id: string; claimToken: string; venueIdentity: string },
): Promise<boolean> {
  const rows = await db
    .update(tradeOrderRecoveries)
    .set({
      state: "submitting",
      venueIdentity: input.venueIdentity,
      submitStartedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(tradeOrderRecoveries.id, input.id),
        eq(tradeOrderRecoveries.claimToken, input.claimToken),
        eq(tradeOrderRecoveries.state, "prepared"),
      ),
    )
    .returning({ id: tradeOrderRecoveries.id });
  return rows.length === 1;
}

export async function checkpointTradeResult(
  db: DbHandle,
  input: {
    id: string;
    claimToken: string;
    venueResult: Record<string, unknown>;
    envelope: TradeRecoveryEnvelope;
    rejected?: boolean;
  },
): Promise<boolean> {
  const rows = await db
    .update(tradeOrderRecoveries)
    .set({
      state: input.rejected ? "rejected" : "submitted",
      venueResult: input.venueResult,
      responseEnvelope: input.envelope as Record<string, unknown>,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(tradeOrderRecoveries.id, input.id),
        eq(tradeOrderRecoveries.claimToken, input.claimToken),
        eq(tradeOrderRecoveries.state, "submitting"),
      ),
    )
    .returning({ id: tradeOrderRecoveries.id });
  return rows.length === 1;
}

export async function checkpointTradeAmbiguous(
  db: DbHandle,
  input: { id: string; claimToken: string; envelope: TradeRecoveryEnvelope },
): Promise<boolean> {
  const rows = await db
    .update(tradeOrderRecoveries)
    .set({
      state: "ambiguous",
      responseEnvelope: input.envelope as Record<string, unknown>,
      claimedAt: RELEASED_CLAIM_TIME,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(tradeOrderRecoveries.id, input.id),
        eq(tradeOrderRecoveries.claimToken, input.claimToken),
        eq(tradeOrderRecoveries.state, "submitting"),
      ),
    )
    .returning({ id: tradeOrderRecoveries.id });
  return rows.length === 1;
}

export async function checkpointReconciledTradeResult(
  db: DbHandle,
  input: {
    id: string;
    venueResult: Record<string, unknown>;
    envelope: TradeRecoveryEnvelope;
  },
): Promise<{ claimToken: string; row: TradeOrderRecoveryRow } | null> {
  const claimToken = randomUUID();
  const staleBefore = new Date(Date.now() - EFFECT_LEASE_MS);
  const claimed = await db
    .update(tradeOrderRecoveries)
    .set({ claimToken, claimedAt: new Date(), updatedAt: new Date() })
    .where(
      and(
        eq(tradeOrderRecoveries.id, input.id),
        sql`${tradeOrderRecoveries.state} IN ('submitting','ambiguous')`,
        lt(tradeOrderRecoveries.claimedAt, staleBefore),
      ),
    )
    .returning({ id: tradeOrderRecoveries.id });
  if (claimed.length !== 1) return null;
  const updated = await db
    .update(tradeOrderRecoveries)
    .set({
      state: "submitted",
      venueResult: input.venueResult,
      responseEnvelope: input.envelope as Record<string, unknown>,
      updatedAt: new Date(),
    })
    .where(
      and(eq(tradeOrderRecoveries.id, input.id), eq(tradeOrderRecoveries.claimToken, claimToken)),
    )
    .returning();
  return updated[0] ? { claimToken, row: updated[0] } : null;
}

export function tradeRecoveryEnvelope(row: TradeOrderRecoveryRow): TradeRecoveryEnvelope | null {
  if (!row.responseEnvelope || typeof row.responseEnvelope !== "object") return null;
  const candidate = row.responseEnvelope as Record<string, unknown>;
  if (typeof candidate.status !== "number" || !("body" in candidate)) return null;
  return candidate as TradeRecoveryEnvelope;
}

async function claimRecoveryEffects(
  db: DbHandle,
  id: string,
  currentToken?: string,
): Promise<string | null> {
  const claimToken = currentToken ?? randomUUID();
  const staleBefore = new Date(Date.now() - EFFECT_LEASE_MS);
  const rows = await db
    .update(tradeOrderRecoveries)
    .set({ claimToken, claimedAt: new Date(), updatedAt: new Date() })
    .where(
      and(
        eq(tradeOrderRecoveries.id, id),
        sql`${tradeOrderRecoveries.auditDeliveredAt} IS NULL`,
        sql`${tradeOrderRecoveries.state} IN ('submitted','completed')`,
        currentToken
          ? eq(tradeOrderRecoveries.claimToken, currentToken)
          : lt(tradeOrderRecoveries.claimedAt, staleBefore),
      ),
    )
    .returning({ id: tradeOrderRecoveries.id });
  return rows.length === 1 ? claimToken : null;
}

async function requiredAuditExists(db: DbHandle, tenantId: string, recoveryId: string) {
  const rows = await db
    .select({ id: auditEvents.id })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.tenantId, tenantId),
        sql`${auditEvents.metadata}->>'tradeRecoveryId' = ${recoveryId}`,
      ),
    )
    .limit(1);
  return rows.length === 1;
}

/**
 * Drain the required submitted audit for a checkpointed venue result.
 *
 * The stable recovery id is also protected by a partial unique index on the
 * signed audit log.  If a worker dies after append but before completion, a
 * stale claimant observes the existing event and only marks the effect done.
 */
export async function drainTradeRecoveryAudit(
  db: DbHandle,
  input: {
    row: TradeOrderRecoveryRow;
    currentClaimToken?: string;
    writeAuditEvent(event: AuditEventInput): Promise<void>;
    details: Record<string, unknown>;
  },
): Promise<boolean> {
  if (input.row.auditDeliveredAt) return true;
  const claimToken = await claimRecoveryEffects(db, input.row.id, input.currentClaimToken);
  if (!claimToken) return false;
  try {
    if (!(await requiredAuditExists(db, input.row.tenantId, input.row.id))) {
      await input.writeAuditEvent({
        tenantId: input.row.tenantId,
        actorType: "agent",
        actorId: input.row.agentId,
        action: "trade.order.submitted",
        resourceType: "trade",
        resourceId: input.row.sessionId,
        requestId: input.row.sessionId,
        metadata: {
          ...input.details,
          correlationId: input.row.sessionId,
          tradeRecoveryId: input.row.id,
          occurrenceAt: input.row.occurrenceAt.toISOString(),
          venueIdentity: input.row.venueIdentity,
        },
      });
    }
    const completed = await db
      .update(tradeOrderRecoveries)
      .set({ state: "completed", auditDeliveredAt: new Date(), updatedAt: new Date() })
      .where(
        and(
          eq(tradeOrderRecoveries.id, input.row.id),
          eq(tradeOrderRecoveries.claimToken, claimToken),
          sql`${tradeOrderRecoveries.auditDeliveredAt} IS NULL`,
        ),
      )
      .returning({ id: tradeOrderRecoveries.id });
    return completed.length === 1;
  } catch {
    // A uniqueness race means another claimant committed the exact signed
    // event.  Treat it as success only after reading that immutable identity.
    if (await requiredAuditExists(db, input.row.tenantId, input.row.id)) {
      await db
        .update(tradeOrderRecoveries)
        .set({ state: "completed", auditDeliveredAt: new Date(), updatedAt: new Date() })
        .where(
          and(
            eq(tradeOrderRecoveries.id, input.row.id),
            eq(tradeOrderRecoveries.claimToken, claimToken),
          ),
        );
      return true;
    }
    await db
      .update(tradeOrderRecoveries)
      .set({ claimedAt: RELEASED_CLAIM_TIME, updatedAt: new Date() })
      .where(
        and(
          eq(tradeOrderRecoveries.id, input.row.id),
          eq(tradeOrderRecoveries.claimToken, claimToken),
        ),
      );
    return false;
  }
}

export async function refreshTradeRecovery(
  db: DbHandle,
  id: string,
): Promise<TradeOrderRecoveryRow> {
  const [row] = await db
    .select()
    .from(tradeOrderRecoveries)
    .where(eq(tradeOrderRecoveries.id, id))
    .limit(1);
  if (!row) throw new Error("TRADE_RECOVERY_NOT_FOUND");
  return row;
}
