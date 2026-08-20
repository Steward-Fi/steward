import { getDb, transactions } from "@stwd/db";
import { recordAggregationEvent } from "@stwd/redis";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";
import { isRedisAvailable, isRedisConfigured } from "../middleware/redis";
import { recordVaultSpend } from "../middleware/redis-enforcement";

const EFFECT_TYPE = "non_solana_vault_accounting";
const EFFECT_LEASE_MS = 60_000;
let accountingEffectFault: "after_spend" | null = null;

type JsonObject = Record<string, unknown>;

/** @internal deterministic crash point for mounted recovery tests. */
export function __setVaultAccountingEffectFaultForTests(fault: "after_spend" | null): void {
  accountingEffectFault = fault;
}

function objectPayload(value: unknown): JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? { ...(value as JsonObject) }
    : {};
}

/**
 * Attach the durable accounting intent to the same write that makes a
 * non-Solana transaction terminal. Only broadcast or outcome-unknown artifacts
 * consume spend: a signed-only artifact did not submit an on-chain effect.
 */
export function stageNonSolanaAccountingEffects(
  actionPayload: unknown,
  input: { txId: string; occurredAt: Date; shouldAccount: boolean; recordSpend?: boolean },
): JsonObject {
  const payload = objectPayload(actionPayload);
  if (!input.shouldAccount) return payload;
  if (
    payload.recoveryEffectsType === EFFECT_TYPE &&
    payload.recoveryEffectsEventId === `vault:${input.txId}` &&
    typeof payload.recoveryEffectsOccurredAt === "string" &&
    !Number.isNaN(Date.parse(payload.recoveryEffectsOccurredAt)) &&
    payload.recoveryEffectsSpendContract === "broadcast_or_outcome_unknown" &&
    payload.recoveryEffectsRecordSpend === (input.recordSpend !== false)
  ) {
    return payload;
  }
  return {
    ...payload,
    recoveryEffectsType: EFFECT_TYPE,
    recoveryEffectsVersion: 1,
    recoveryEffectsState: "pending",
    recoveryEffectsEventId: `vault:${input.txId}`,
    recoveryEffectsOccurredAt: input.occurredAt.toISOString(),
    recoveryEffectsSpendContract: "broadcast_or_outcome_unknown",
    recoveryEffectsRecordSpend: input.recordSpend !== false,
  };
}

function effectMetadata(value: unknown): JsonObject {
  return objectPayload(value);
}

/**
 * Complete the Redis spend + aggregation pair under a bounded DB claim.
 * Both Redis writers use the persisted identity/time, so retry after a partial
 * write is idempotent and cannot move the event into a newer rolling window.
 */
async function completeNonSolanaAccountingEffectsImpl(input: {
  tenantId: string;
  agentId: string;
  txId: string;
}): Promise<boolean> {
  const [row] = await getDb()
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.id, input.txId),
        eq(transactions.agentId, input.agentId),
        sql`${transactions.status} in ('broadcast', 'confirmed', 'outcome_unknown')`,
      ),
    )
    .limit(1);
  if (!row) return false;

  const metadata = effectMetadata(row.actionPayload);
  // Legacy terminal rows predate the durable protocol and may already have
  // been counted by the former fire-and-forget writer. Replaying them cannot
  // safely infer whether to debit again.
  if (metadata.recoveryEffectsType !== EFFECT_TYPE) return true;
  if (metadata.recoveryEffectsState === "complete") return true;
  const eventId = metadata.recoveryEffectsEventId;
  const occurredAtRaw = metadata.recoveryEffectsOccurredAt;
  if (typeof eventId !== "string" || typeof occurredAtRaw !== "string") return false;
  const occurredAt = new Date(occurredAtRaw);
  if (Number.isNaN(occurredAt.getTime())) return false;

  const claimToken = crypto.randomUUID();
  const claimLeaseUntil = new Date(Date.now() + EFFECT_LEASE_MS).toISOString();
  const claimableBefore = new Date().toISOString();
  const [claimed] = await getDb()
    .update(transactions)
    .set({
      actionPayload: sql`jsonb_set(jsonb_set(jsonb_set(coalesce(${transactions.actionPayload}, '{}'::jsonb), '{recoveryEffectsState}', '"processing"'::jsonb), '{recoveryEffectsToken}', ${JSON.stringify(claimToken)}::jsonb), '{recoveryEffectsLeaseUntil}', ${JSON.stringify(claimLeaseUntil)}::jsonb)`,
    })
    .where(
      and(
        eq(transactions.id, input.txId),
        eq(transactions.agentId, input.agentId),
        eq(transactions.status, row.status),
        sql`${transactions.actionPayload}->>'recoveryEffectsType' = ${EFFECT_TYPE}`,
        sql`(
          coalesce(${transactions.actionPayload}->>'recoveryEffectsState', 'pending') = 'pending'
          or (
            ${transactions.actionPayload}->>'recoveryEffectsState' = 'processing'
            and coalesce(${transactions.actionPayload}->>'recoveryEffectsLeaseUntil', '') <= ${claimableBefore}
          )
        )`,
      ),
    )
    .returning({ id: transactions.id });

  if (!claimed) {
    const [refreshed] = await getDb()
      .select({ actionPayload: transactions.actionPayload })
      .from(transactions)
      .where(and(eq(transactions.id, input.txId), eq(transactions.agentId, input.agentId)))
      .limit(1);
    return effectMetadata(refreshed?.actionPayload).recoveryEffectsState === "complete";
  }

  try {
    if (isRedisConfigured() && !isRedisAvailable()) {
      throw new Error("Configured Redis accounting backend is unavailable");
    }
    if (isRedisAvailable()) {
      if (metadata.recoveryEffectsRecordSpend !== false) {
        await recordVaultSpend(input.agentId, input.tenantId, row.value, row.chainId, {
          eventId,
          occurredAt,
          throwOnError: true,
        });
      }
      if (accountingEffectFault === "after_spend") {
        accountingEffectFault = null;
        throw new Error("injected crash after spend write");
      }
      await recordAggregationEvent({
        eventId,
        agentId: input.agentId,
        valueRaw: row.value,
        to: row.toAddress,
        chainId: row.chainId,
        timestamp: occurredAt.getTime(),
      });
    }

    const [completed] = await getDb()
      .update(transactions)
      .set({
        actionPayload: sql`jsonb_set(jsonb_set(coalesce(${transactions.actionPayload}, '{}'::jsonb), '{recoveryEffectsState}', '"complete"'::jsonb), '{recoveryEffectsCompletedAt}', ${JSON.stringify(new Date().toISOString())}::jsonb) - 'recoveryEffectsToken' - 'recoveryEffectsLeaseUntil'`,
      })
      .where(
        and(
          eq(transactions.id, input.txId),
          eq(transactions.agentId, input.agentId),
          sql`${transactions.actionPayload}->>'recoveryEffectsToken' = ${claimToken}`,
        ),
      )
      .returning({ id: transactions.id });
    return Boolean(completed);
  } catch (error) {
    console.error(
      "[vault] Durable non-Solana accounting remains pending",
      redactedThrownDiagnostics(error),
    );
    await getDb()
      .update(transactions)
      .set({
        actionPayload: sql`jsonb_set(coalesce(${transactions.actionPayload}, '{}'::jsonb), '{recoveryEffectsState}', '"pending"'::jsonb) - 'recoveryEffectsToken' - 'recoveryEffectsLeaseUntil'`,
      })
      .where(
        and(
          eq(transactions.id, input.txId),
          eq(transactions.agentId, input.agentId),
          sql`${transactions.actionPayload}->>'recoveryEffectsToken' = ${claimToken}`,
        ),
      );
    return false;
  }
}

export async function completeNonSolanaAccountingEffects(input: {
  tenantId: string;
  agentId: string;
  txId: string;
}): Promise<boolean> {
  try {
    return await completeNonSolanaAccountingEffectsImpl(input);
  } catch (error) {
    console.error(
      "[vault] Failed to complete durable non-Solana accounting",
      redactedThrownDiagnostics(error),
    );
    return false;
  }
}
