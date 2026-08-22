import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditEvents,
  closeDb,
  getDb,
  tradeOrderRecoveries,
  writeAuditEvent,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, sql } from "drizzle-orm";
import {
  beginTradeRecovery,
  checkpointReconciledTradeResult,
  checkpointTradeAmbiguous,
  checkpointTradeResult,
  checkpointTradeSubmissionStart,
  drainTradeRecoveryAudit,
  refreshTradeRecovery,
} from "../routes/trade-recovery";

describe("durable trade order recovery", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "8".repeat(64);
    __resetAuditHmacKeyCacheForTests();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    __resetAuditHmacKeyCacheForTests();
  });

  test("checkpoints venue success before effects and concurrent replay delivers one signed audit", async () => {
    const db = getDb();
    const begun = await beginTradeRecovery(db, {
      tenantId: "recovery-tenant-a",
      agentId: "recovery-agent-a",
      sessionId: "recovery-session-a",
      venue: "hyperliquid",
      idempotencyKey: "durable-key-a",
      bodyHash: "a".repeat(64),
      effectMetadata: { venue: "hyperliquid", orderId: "venue-1" },
    });
    expect(begun.kind).toBe("new");
    if (begun.kind !== "new") throw new Error("expected new recovery");
    expect(
      await checkpointTradeSubmissionStart(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        venueIdentity: `0x${"1".repeat(32)}`,
      }),
    ).toBe(true);
    expect(
      await checkpointTradeResult(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        venueResult: { orderId: "venue-1", status: "filled" },
        envelope: { status: 200, body: { ok: true, orderId: "venue-1" } },
      }),
    ).toBe(true);

    const checkpointed = await refreshTradeRecovery(db, begun.row.id);
    expect(checkpointed.state).toBe("submitted");
    expect(checkpointed.auditDeliveredAt).toBeNull();
    expect(
      await drainTradeRecoveryAudit(db, {
        row: checkpointed,
        currentClaimToken: begun.claimToken,
        details: { venue: "hyperliquid", orderId: "venue-1" },
        writeAuditEvent: async () => {
          throw new Error("injected audit outage");
        },
      }),
    ).toBe(false);

    const replay = await refreshTradeRecovery(db, begun.row.id);
    const outcomes = await Promise.all([
      drainTradeRecoveryAudit(db, {
        row: replay,
        details: { venue: "hyperliquid", orderId: "venue-1" },
        writeAuditEvent,
      }),
      drainTradeRecoveryAudit(db, {
        row: replay,
        details: { venue: "hyperliquid", orderId: "venue-1" },
        writeAuditEvent,
      }),
    ]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    const [completed] = await db
      .select()
      .from(tradeOrderRecoveries)
      .where(eq(tradeOrderRecoveries.id, begun.row.id));
    expect(completed.state).toBe("completed");
    expect(completed.auditDeliveredAt).not.toBeNull();
    const evidence = await db
      .select()
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, begun.row.tenantId),
          sql`${auditEvents.metadata}->>'tradeRecoveryId' = ${begun.row.id}`,
        ),
      );
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.metadata.venueIdentity).toBe(`0x${"1".repeat(32)}`);
  });

  test("ambiguous submission only advances after exact venue evidence and never reopens submit", async () => {
    const db = getDb();
    const begun = await beginTradeRecovery(db, {
      tenantId: "recovery-tenant-b",
      agentId: "recovery-agent-b",
      sessionId: "recovery-session-b",
      venue: "polymarket",
      idempotencyKey: "durable-key-b",
      bodyHash: "b".repeat(64),
      effectMetadata: { venue: "polymarket", orderId: `0x${"2".repeat(64)}` },
    });
    if (begun.kind !== "new") throw new Error("expected new recovery");
    const identity = `0x${"2".repeat(64)}`;
    expect(
      await checkpointTradeSubmissionStart(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        venueIdentity: identity,
      }),
    ).toBe(true);
    expect(
      await checkpointTradeAmbiguous(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        envelope: { status: 502, body: { ok: false, retryable: true } },
      }),
    ).toBe(true);
    expect(
      await checkpointTradeSubmissionStart(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        venueIdentity: identity,
      }),
    ).toBe(false);

    const [winner, loser] = await Promise.all([
      checkpointReconciledTradeResult(db, {
        id: begun.row.id,
        tenantId: begun.row.tenantId,
        agentId: begun.row.agentId,
        venue: "polymarket",
        bodyHash: begun.row.bodyHash,
        venueIdentity: identity,
        venueResult: { orderId: identity, status: "matched" },
        envelope: { status: 200, body: { ok: true, orderId: identity } },
      }),
      checkpointReconciledTradeResult(db, {
        id: begun.row.id,
        tenantId: begun.row.tenantId,
        agentId: begun.row.agentId,
        venue: "polymarket",
        bodyHash: begun.row.bodyHash,
        venueIdentity: identity,
        venueResult: { orderId: identity, status: "matched" },
        envelope: { status: 200, body: { ok: true, orderId: identity } },
      }),
    ]);
    expect([winner, loser].filter(Boolean)).toHaveLength(1);
    const reconciled = (winner ?? loser)!;
    expect(reconciled.row.venueIdentity).toBe(identity);
    expect(reconciled.row.state).toBe("submitted");
  });

  test("one retry takes over a stale prepared claim before any venue submission", async () => {
    const db = getDb();
    const input = {
      tenantId: "recovery-tenant-prepared",
      agentId: "recovery-agent-prepared",
      sessionId: "recovery-session-prepared",
      venue: "hyperliquid" as const,
      idempotencyKey: "durable-key-prepared",
      bodyHash: "c".repeat(64),
      effectMetadata: {
        sessionId: "recovery-session-prepared",
        venue: "hyperliquid",
        walletAddress: "0x0000000000000000000000000000000000000001",
      },
    };
    const original = await beginTradeRecovery(db, input);
    if (original.kind !== "new") throw new Error("expected new recovery");
    await db
      .update(tradeOrderRecoveries)
      .set({ claimedAt: new Date(Date.now() - 60_000) })
      .where(eq(tradeOrderRecoveries.id, original.row.id));

    const contenders = await Promise.all([
      beginTradeRecovery(db, input),
      beginTradeRecovery(db, input),
    ]);
    const winners = contenders.filter((result) => result.kind === "new");
    expect(winners).toHaveLength(1);
    const winner = winners[0];
    if (!winner || winner.kind !== "new") throw new Error("expected one takeover winner");
    expect(winner.claimToken).not.toBe(original.claimToken);
    expect(
      await checkpointTradeSubmissionStart(db, {
        id: original.row.id,
        claimToken: original.claimToken,
        venueIdentity: "old-owner-must-lose",
      }),
    ).toBe(false);
    expect(
      await checkpointTradeSubmissionStart(db, {
        id: winner.row.id,
        claimToken: winner.claimToken,
        venueIdentity: "takeover-winner",
      }),
    ).toBe(true);
  });

  test("recovers after audit append but before completion without moving occurrence time", async () => {
    const db = getDb();
    const begun = await beginTradeRecovery(db, {
      tenantId: "recovery-tenant-crash",
      agentId: "recovery-agent-crash",
      sessionId: "recovery-session-crash",
      venue: "polymarket",
      idempotencyKey: "durable-key-crash",
      bodyHash: "c".repeat(64),
      effectMetadata: { venue: "polymarket", orderId: "venue-crash" },
    });
    if (begun.kind !== "new") throw new Error("expected new recovery");
    expect(
      await checkpointTradeSubmissionStart(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        venueIdentity: "venue-crash",
      }),
    ).toBe(true);
    expect(
      await checkpointTradeResult(db, {
        id: begun.row.id,
        claimToken: begun.claimToken,
        venueResult: { orderId: "venue-crash", status: "matched" },
        envelope: { status: 200, body: { ok: true, orderId: "venue-crash" } },
      }),
    ).toBe(true);
    const checkpointed = await refreshTradeRecovery(db, begun.row.id);
    await writeAuditEvent({
      tenantId: checkpointed.tenantId,
      actorType: "agent",
      actorId: checkpointed.agentId,
      action: "trade.order.submitted",
      resourceType: "trade",
      resourceId: checkpointed.sessionId,
      requestId: checkpointed.sessionId,
      metadata: {
        ...checkpointed.effectMetadata,
        correlationId: checkpointed.sessionId,
        tradeRecoveryId: checkpointed.id,
        occurrenceAt: checkpointed.occurrenceAt.toISOString(),
        venueIdentity: checkpointed.venueIdentity,
      },
    });

    // This is the process-death boundary: immutable audit committed, row still
    // says submitted. A stale retry must only finish the marker.
    await db
      .update(tradeOrderRecoveries)
      .set({ claimedAt: new Date(0) })
      .where(eq(tradeOrderRecoveries.id, checkpointed.id));
    const retry = await refreshTradeRecovery(db, checkpointed.id);
    expect(
      await drainTradeRecoveryAudit(db, {
        row: retry,
        writeAuditEvent,
        details: retry.effectMetadata,
      }),
    ).toBe(true);
    const evidence = await db
      .select({ metadata: auditEvents.metadata })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, checkpointed.tenantId),
          sql`${auditEvents.metadata}->>'tradeRecoveryId' = ${checkpointed.id}`,
        ),
      );
    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.metadata.occurrenceAt).toBe(checkpointed.occurrenceAt.toISOString());
  });
});
