import { toCaip2 } from "@stwd/shared";
import { and, asc, eq, isNotNull, sql } from "drizzle-orm";
import { createPublicClient, http, type TransactionReceipt } from "viem";
import { writeAuditEvent } from "./audit";
import { agents, db, transactions } from "./context";
import { dispatchWebhook } from "./webhook-dispatch";

const DEFAULT_RECEIPT_POLL_INTERVAL_MS = 60_000;
const DEFAULT_RECEIPT_POLL_BATCH_SIZE = 50;
const DEFAULT_MIN_CONFIRMATIONS = 1;
const DEFAULT_STILL_PENDING_AFTER_MS = 10 * 60_000;
const DEFAULT_STILL_PENDING_INTERVAL_MS = 10 * 60_000;

const EVM_CHAIN_RPCS: Record<number, string> = {
  1: "https://eth.llamarpc.com",
  56: "https://bsc-dataseed.binance.org",
  97: "https://data-seed-prebsc-1-s1.bnbchain.org:8545",
  100: "https://rpc.gnosischain.com",
  137: "https://polygon-rpc.com",
  8453: "https://mainnet.base.org",
  42161: "https://arb1.arbitrum.io/rpc",
  84532: "https://sepolia.base.org",
};

type PollableTransaction = typeof transactions.$inferSelect & { tenantId: string };
type TransactionLifecycleEventType =
  | "transaction.confirmed"
  | "transaction.execution_reverted"
  | "transaction.provider_error"
  | "transaction.still_pending";

export interface TransactionReceiptPollerOptions {
  batchSize?: number;
  minConfirmations?: number;
  stillPendingAfterMs?: number;
  stillPendingIntervalMs?: number;
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function isHexHash(value: string | null): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function rpcEnvKey(chainId: number): string {
  return `STEWARD_RPC_${chainId}`;
}

export function resolveEvmReceiptRpcUrl(chainId: number): string | null {
  const chainSpecific = process.env[rpcEnvKey(chainId)]?.trim();
  if (chainSpecific) return chainSpecific;

  const activeChainId = parsePositiveInt(process.env.CHAIN_ID, 84532);
  const defaultRpc = process.env.RPC_URL?.trim();
  if (defaultRpc && activeChainId === chainId) return defaultRpc;

  return EVM_CHAIN_RPCS[chainId] ?? null;
}

export function classifyReceiptLifecycle(
  status: TransactionReceipt["status"],
  confirmations: number,
  minConfirmations: number,
): "transaction.confirmed" | "transaction.execution_reverted" | null {
  if (confirmations < minConfirmations) return null;
  return status === "success" ? "transaction.confirmed" : "transaction.execution_reverted";
}

function actionReferenceId(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  const referenceId = value.referenceId ?? value.reference_id;
  return typeof referenceId === "string" && referenceId.trim() ? referenceId : null;
}

function transactionRequestPayload(row: typeof transactions.$inferSelect): Record<string, unknown> {
  return {
    to: row.toAddress,
    value: row.value,
    data: row.data ?? "0x",
    chainId: row.chainId,
    ...(row.txHash ? { transaction_hash: row.txHash } : {}),
  };
}

function userOperationEventPayload(
  agentId: string,
  row: typeof transactions.$inferSelect,
  payload: {
    txHash?: string | null;
    status: "completed" | "failed";
    error?: string;
    blockNumber?: string | number;
    confirmations?: number;
  },
): Record<string, unknown> | null {
  if (row.actionType !== "user_operation" || !row.actionPayload) return null;
  const actionPayload = row.actionPayload as Record<string, unknown>;
  const userOperationHash = actionPayload.userOperationHash;
  if (typeof userOperationHash !== "string" || !userOperationHash) return null;
  const caip2 = toCaip2(row.chainId) ?? `eip155:${row.chainId}`;
  return {
    wallet_id: agentId,
    transaction_id: row.id,
    user_operation_hash: userOperationHash,
    caip2,
    status: payload.status,
    ...(typeof actionPayload.entryPoint === "string"
      ? { entry_point: actionPayload.entryPoint }
      : {}),
    ...(typeof actionPayload.sender === "string" ? { sender: actionPayload.sender } : {}),
    ...(payload.txHash ? { transaction_hash: payload.txHash } : {}),
    ...(payload.error ? { error: payload.error } : {}),
    ...(payload.blockNumber !== undefined ? { blockNumber: payload.blockNumber } : {}),
    ...(payload.confirmations !== undefined ? { confirmations: payload.confirmations } : {}),
  };
}

function mergePollingMetadata(
  payload: Record<string, unknown> | null,
  metadata: Record<string, unknown>,
): Record<string, unknown> {
  const existing = payload && typeof payload === "object" ? payload : {};
  const existingPolling =
    existing.lifecyclePolling && typeof existing.lifecyclePolling === "object"
      ? (existing.lifecyclePolling as Record<string, unknown>)
      : {};
  return {
    ...existing,
    lifecyclePolling: {
      ...existingPolling,
      ...metadata,
    },
  };
}

function shouldEmitStillPending(
  row: PollableTransaction,
  now: Date,
  afterMs: number,
  intervalMs: number,
): boolean {
  if (now.getTime() - row.createdAt.getTime() < afterMs) return false;
  const polling =
    row.actionPayload?.lifecyclePolling && typeof row.actionPayload.lifecyclePolling === "object"
      ? (row.actionPayload.lifecyclePolling as Record<string, unknown>)
      : {};
  const lastStillPendingAt = polling.lastStillPendingAt;
  if (typeof lastStillPendingAt !== "string") return true;
  const parsed = Date.parse(lastStillPendingAt);
  return !Number.isFinite(parsed) || now.getTime() - parsed >= intervalMs;
}

function dispatchTransactionLifecycleWebhook(
  row: PollableTransaction,
  type: TransactionLifecycleEventType,
  payload: {
    status?: string;
    error?: string;
    blockNumber?: string | number;
    confirmations?: number;
    transactionRequest?: Record<string, unknown> | null;
  },
): void {
  const caip2 = toCaip2(row.chainId) ?? `eip155:${row.chainId}`;
  dispatchWebhook(row.tenantId, row.agentId, type, {
    txId: row.id,
    wallet_id: row.agentId,
    transaction_id: row.id,
    ...(row.txHash ? { txHash: row.txHash, transaction_hash: row.txHash } : {}),
    chainId: row.chainId,
    caip2,
    ...(payload.status ? { status: payload.status } : {}),
    ...(payload.error ? { error: payload.error } : {}),
    ...(payload.blockNumber !== undefined ? { blockNumber: payload.blockNumber } : {}),
    ...(payload.confirmations !== undefined ? { confirmations: payload.confirmations } : {}),
    ...(actionReferenceId(row.actionPayload)
      ? { reference_id: actionReferenceId(row.actionPayload) }
      : {}),
    ...(payload.transactionRequest ? { transaction_request: payload.transactionRequest } : {}),
  });
}

async function writeSystemLifecycleAudit(
  row: PollableTransaction,
  type: TransactionLifecycleEventType,
  metadata: Record<string, unknown>,
): Promise<void> {
  await writeAuditEvent({
    tenantId: row.tenantId,
    actorType: "system",
    actorId: "transaction-receipt-poller",
    action: type,
    resourceType: "transaction",
    resourceId: row.id,
    metadata,
  });
}

async function markStillPending(row: PollableTransaction, now: Date): Promise<void> {
  const actionPayload = mergePollingMetadata(row.actionPayload ?? null, {
    lastCheckedAt: now.toISOString(),
    lastStillPendingAt: now.toISOString(),
  });
  const [updated] = await db
    .update(transactions)
    .set({ actionPayload })
    .where(
      and(
        eq(transactions.id, row.id),
        eq(transactions.agentId, row.agentId),
        eq(transactions.status, "broadcast"),
      ),
    )
    .returning();
  if (!updated) return;

  await writeSystemLifecycleAudit(row, "transaction.still_pending", {
    txHash: row.txHash,
    status: "broadcast",
    chainId: row.chainId,
  });
  dispatchTransactionLifecycleWebhook({ ...row, actionPayload }, "transaction.still_pending", {
    status: "broadcast",
    transactionRequest: transactionRequestPayload(row),
  });
}

async function finalizeReceipt(
  row: PollableTransaction,
  receipt: TransactionReceipt,
  eventType: "transaction.confirmed" | "transaction.execution_reverted",
  confirmations: number,
): Promise<void> {
  const now = new Date();
  const nextStatus = eventType === "transaction.confirmed" ? "confirmed" : "failed";
  const blockNumber = receipt.blockNumber.toString();
  const actionPayload = mergePollingMetadata(row.actionPayload ?? null, {
    lastCheckedAt: now.toISOString(),
    receiptStatus: receipt.status,
    blockNumber,
    confirmations,
    effectiveGasPrice: receipt.effectiveGasPrice?.toString(),
    gasUsed: receipt.gasUsed?.toString(),
  });

  await writeSystemLifecycleAudit(row, eventType, {
    txHash: row.txHash,
    status: nextStatus,
    chainId: row.chainId,
    blockNumber,
    confirmations,
  });

  const [updated] = await db
    .update(transactions)
    .set({
      status: nextStatus,
      confirmedAt: eventType === "transaction.confirmed" ? now : row.confirmedAt,
      actionPayload,
    })
    .where(
      and(
        eq(transactions.id, row.id),
        eq(transactions.agentId, row.agentId),
        eq(transactions.status, "broadcast"),
        sql`${transactions.txHash} = ${row.txHash}`,
      ),
    )
    .returning();
  if (!updated) return;

  dispatchTransactionLifecycleWebhook({ ...row, actionPayload }, eventType, {
    status: nextStatus,
    blockNumber,
    confirmations,
  });

  const userOperationPayload = userOperationEventPayload(row.agentId, updated, {
    txHash: row.txHash,
    status: eventType === "transaction.confirmed" ? "completed" : "failed",
    error:
      eventType === "transaction.execution_reverted" ? "Transaction execution reverted" : undefined,
    blockNumber,
    confirmations,
  });
  if (userOperationPayload) {
    dispatchWebhook(
      row.tenantId,
      row.agentId,
      eventType === "transaction.confirmed" ? "user_operation.completed" : "user_operation.failed",
      userOperationPayload,
    );
  }
}

async function pollOneTransaction(
  row: PollableTransaction,
  options: Required<TransactionReceiptPollerOptions>,
): Promise<"confirmed" | "reverted" | "pending" | "skipped"> {
  if (!isHexHash(row.txHash)) return "skipped";
  const rpcUrl = resolveEvmReceiptRpcUrl(row.chainId);
  if (!rpcUrl) return "skipped";

  const client = createPublicClient({ transport: http(rpcUrl) });
  const now = new Date();
  let receipt: TransactionReceipt | null = null;
  try {
    receipt = await client.getTransactionReceipt({ hash: row.txHash });
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error);
    if (!message.includes("not found") && !message.includes("could not find")) {
      console.warn(`[tx-poller] Receipt lookup failed for ${row.id}:`, error);
    }
  }

  if (!receipt) {
    if (
      shouldEmitStillPending(row, now, options.stillPendingAfterMs, options.stillPendingIntervalMs)
    ) {
      await markStillPending(row, now);
      return "pending";
    }
    return "skipped";
  }

  // Without a trustworthy chain head we cannot compute confirmations. Do NOT assume
  // confirmations=1 (that would finalize at the default minConfirmations=1 even when
  // the RPC head is unavailable/reorging). Treat unknown head as "not yet confirmable".
  let currentBlock: bigint | null = null;
  try {
    currentBlock = await client.getBlockNumber();
  } catch {
    currentBlock = null;
  }
  if (currentBlock === null) return "skipped";
  const confirmations =
    currentBlock >= receipt.blockNumber ? Number(currentBlock - receipt.blockNumber + 1n) : 0;
  const eventType = classifyReceiptLifecycle(
    receipt.status,
    confirmations,
    options.minConfirmations,
  );
  if (!eventType) return "skipped";

  await finalizeReceipt(row, receipt, eventType, confirmations);
  return eventType === "transaction.confirmed" ? "confirmed" : "reverted";
}

export async function pollBroadcastTransactionReceipts(
  options: TransactionReceiptPollerOptions = {},
): Promise<{
  checked: number;
  confirmed: number;
  reverted: number;
  pending: number;
  skipped: number;
}> {
  const resolvedOptions: Required<TransactionReceiptPollerOptions> = {
    batchSize: options.batchSize ?? DEFAULT_RECEIPT_POLL_BATCH_SIZE,
    minConfirmations: options.minConfirmations ?? DEFAULT_MIN_CONFIRMATIONS,
    stillPendingAfterMs: options.stillPendingAfterMs ?? DEFAULT_STILL_PENDING_AFTER_MS,
    stillPendingIntervalMs: options.stillPendingIntervalMs ?? DEFAULT_STILL_PENDING_INTERVAL_MS,
  };
  const rows = await db
    .select({
      id: transactions.id,
      agentId: transactions.agentId,
      tenantId: agents.tenantId,
      status: transactions.status,
      toAddress: transactions.toAddress,
      value: transactions.value,
      data: transactions.data,
      chainId: transactions.chainId,
      txHash: transactions.txHash,
      actionType: transactions.actionType,
      actionPayload: transactions.actionPayload,
      policyResults: transactions.policyResults,
      createdAt: transactions.createdAt,
      signedAt: transactions.signedAt,
      confirmedAt: transactions.confirmedAt,
    })
    .from(transactions)
    .innerJoin(agents, eq(transactions.agentId, agents.id))
    .where(and(eq(transactions.status, "broadcast"), isNotNull(transactions.txHash)))
    .orderBy(asc(transactions.createdAt))
    .limit(resolvedOptions.batchSize);

  const summary = { checked: rows.length, confirmed: 0, reverted: 0, pending: 0, skipped: 0 };
  for (const row of rows) {
    const result = await pollOneTransaction(row, resolvedOptions);
    summary[result] += 1;
  }
  return summary;
}

export function startTransactionReceiptPollingScheduler(): () => void {
  if (process.env.STEWARD_TRANSACTION_RECEIPT_POLLER === "false") {
    console.log("[tx-poller] Disabled by STEWARD_TRANSACTION_RECEIPT_POLLER=false");
    return () => {};
  }

  const intervalMs = parsePositiveInt(
    process.env.STEWARD_TRANSACTION_RECEIPT_POLL_INTERVAL_MS,
    DEFAULT_RECEIPT_POLL_INTERVAL_MS,
  );
  const batchSize = parsePositiveInt(
    process.env.STEWARD_TRANSACTION_RECEIPT_POLL_BATCH_SIZE,
    DEFAULT_RECEIPT_POLL_BATCH_SIZE,
  );
  const minConfirmations = parsePositiveInt(
    process.env.STEWARD_TRANSACTION_RECEIPT_CONFIRMATIONS,
    DEFAULT_MIN_CONFIRMATIONS,
  );
  const stillPendingAfterMs = parsePositiveInt(
    process.env.STEWARD_TRANSACTION_STILL_PENDING_AFTER_MS,
    DEFAULT_STILL_PENDING_AFTER_MS,
  );
  const stillPendingIntervalMs = parsePositiveInt(
    process.env.STEWARD_TRANSACTION_STILL_PENDING_INTERVAL_MS,
    DEFAULT_STILL_PENDING_INTERVAL_MS,
  );
  let running = false;

  const tick = () => {
    if (running) return;
    running = true;
    void pollBroadcastTransactionReceipts({
      batchSize,
      minConfirmations,
      stillPendingAfterMs,
      stillPendingIntervalMs,
    })
      .then((summary) => {
        if (summary.confirmed || summary.reverted || summary.pending) {
          console.log(
            `[tx-poller] checked=${summary.checked} confirmed=${summary.confirmed} reverted=${summary.reverted} pending=${summary.pending}`,
          );
        }
      })
      .catch((error) => {
        console.error("[tx-poller] Receipt polling tick failed:", error);
      })
      .finally(() => {
        running = false;
      });
  };

  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  tick();

  return () => {
    clearInterval(timer);
  };
}
