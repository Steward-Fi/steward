import { redactedThrownDiagnostics, toCaip2 } from "@stwd/shared";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { and, asc, eq, inArray, isNotNull, sql } from "drizzle-orm";
import { createPublicClient, http, type TransactionReceipt } from "viem";
import { withTenantAuditedTransaction, writeAuditEvent } from "./audit";
import { agents, db, transactions } from "./context";
import { runInternalJobForEachTenant } from "./tenant-job";
import { dispatchWebhook } from "./webhook-dispatch";

const DEFAULT_RECEIPT_POLL_INTERVAL_MS = 60_000;
const DEFAULT_RECEIPT_POLL_BATCH_SIZE = 50;
const DEFAULT_MIN_CONFIRMATIONS = 1;
// SEC-152: 1-block finality is reorg-unsafe for high-value mainnet flows. When
// the operator has not set STEWARD_TRANSACTION_RECEIPT_CONFIRMATIONS, these
// per-chain defaults apply (Ethereum L1 mainnet waits 12); everything else
// falls back to DEFAULT_MIN_CONFIRMATIONS. An explicit env value always wins.
const DEFAULT_MIN_CONFIRMATIONS_BY_CHAIN: Record<number, number> = {
  1: 12, // Ethereum L1 mainnet
};
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
  | "transaction.broadcasted"
  | "transaction.confirmed"
  | "transaction.execution_reverted"
  | "transaction.provider_error"
  | "transaction.still_pending";

export interface TransactionReceiptPollerOptions {
  batchSize?: number;
  minConfirmations?: number;
  stillPendingAfterMs?: number;
  stillPendingIntervalMs?: number;
  /** Dependency injection for deterministic tests; production uses a read-only viem client. */
  clientFactory?: (rpcUrl: string) => TransactionReceiptClient;
}

export interface TransactionReceiptClient {
  getTransactionReceipt(input: { hash: `0x${string}` }): Promise<TransactionReceipt>;
  getBlockNumber(): Promise<bigint>;
}

type ResolvedTransactionReceiptPollerOptions = Required<
  Omit<TransactionReceiptPollerOptions, "clientFactory" | "minConfirmations">
> &
  Pick<TransactionReceiptPollerOptions, "minConfirmations"> & {
    clientFactory: (rpcUrl: string) => TransactionReceiptClient;
  };

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
  const chainSpecific = runtimeEnvironmentValue(rpcEnvKey(chainId))?.trim();
  if (chainSpecific) return chainSpecific;

  const activeChainId = parsePositiveInt(runtimeEnvironmentValue("CHAIN_ID"), 84532);
  const defaultRpc = runtimeEnvironmentValue("RPC_URL")?.trim();
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

/** Confirmation threshold for a chain: explicit override wins, else the
 * per-chain default (SEC-152), else the global fallback. */
export function minConfirmationsForChain(chainId: number, override?: number): number {
  return override ?? DEFAULT_MIN_CONFIRMATIONS_BY_CHAIN[chainId] ?? DEFAULT_MIN_CONFIRMATIONS;
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

  const updated = await withTenantAuditedTransaction(
    row.tenantId,
    async (rawTx, appendRequiredAudit) => {
      const tx = rawTx as typeof db;
      const [transitioned] = await tx
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
            eq(transactions.status, row.status),
            sql`${transactions.txHash} = ${row.txHash}`,
          ),
        )
        .returning();
      if (!transitioned) return null;

      if (row.status === "outcome_unknown") {
        await appendRequiredAudit({
          tenantId: row.tenantId,
          actorType: "system",
          actorId: "transaction-receipt-poller",
          action: "transaction.broadcast.reconciled",
          resourceType: "transaction",
          resourceId: row.id,
          metadata: {
            txHash: row.txHash,
            previousStatus: "outcome_unknown",
            chainId: row.chainId,
            evidence: "transaction_receipt",
          },
        });
      }
      await appendRequiredAudit({
        tenantId: row.tenantId,
        actorType: "system",
        actorId: "transaction-receipt-poller",
        action: eventType,
        resourceType: "transaction",
        resourceId: row.id,
        metadata: {
          txHash: row.txHash,
          status: nextStatus,
          chainId: row.chainId,
          blockNumber,
          confirmations,
          previousStatus: row.status,
        },
      });
      return transitioned;
    },
  );
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

/**
 * A receipt proves that the exact, locally-derived transaction hash was
 * accepted by the chain. Promote an ambiguous outcome without ever resending
 * signed bytes. The guarded update and audit append commit atomically.
 */
async function reconcileOutcomeUnknownAsBroadcast(
  row: PollableTransaction,
  receipt: TransactionReceipt,
): Promise<PollableTransaction | null> {
  const now = new Date();
  const actionPayload = mergePollingMetadata(row.actionPayload ?? null, {
    lastCheckedAt: now.toISOString(),
    receiptStatus: receipt.status,
    blockNumber: receipt.blockNumber.toString(),
    reconciledAt: now.toISOString(),
  });
  const updated = await withTenantAuditedTransaction(
    row.tenantId,
    async (rawTx, appendRequiredAudit) => {
      const tx = rawTx as typeof db;
      const [transitioned] = await tx
        .update(transactions)
        .set({ status: "broadcast", actionPayload })
        .where(
          and(
            eq(transactions.id, row.id),
            eq(transactions.agentId, row.agentId),
            eq(transactions.status, "outcome_unknown"),
            sql`${transactions.txHash} = ${row.txHash}`,
          ),
        )
        .returning();
      if (!transitioned) return null;
      await appendRequiredAudit({
        tenantId: row.tenantId,
        actorType: "system",
        actorId: "transaction-receipt-poller",
        action: "transaction.broadcast.reconciled",
        resourceType: "transaction",
        resourceId: row.id,
        metadata: {
          txHash: row.txHash,
          previousStatus: "outcome_unknown",
          status: "broadcast",
          chainId: row.chainId,
          evidence: "transaction_receipt",
        },
      });
      return { ...transitioned, tenantId: row.tenantId } as PollableTransaction;
    },
  );
  if (!updated) return null;
  dispatchTransactionLifecycleWebhook(updated, "transaction.broadcasted", {
    status: "broadcast",
    transactionRequest: transactionRequestPayload(updated),
  });
  return updated;
}

async function pollOneTransaction(
  row: PollableTransaction,
  options: ResolvedTransactionReceiptPollerOptions,
): Promise<"confirmed" | "reverted" | "pending" | "skipped"> {
  const now = new Date();
  // Advance a durable fairness cursor before validation or I/O. A malformed
  // hash, unsupported chain, or permanently absent receipt must not monopolize
  // the oldest fixed-size batch across scheduler ticks.
  await db
    .update(transactions)
    .set({ receiptPolledAt: now })
    .where(
      and(
        eq(transactions.id, row.id),
        eq(transactions.agentId, row.agentId),
        eq(transactions.status, row.status),
      ),
    );
  if (!isHexHash(row.txHash)) return "skipped";
  const rpcUrl = resolveEvmReceiptRpcUrl(row.chainId);
  if (!rpcUrl) return "skipped";

  const client = options.clientFactory(rpcUrl);
  let receipt: TransactionReceipt | null = null;
  try {
    receipt = await client.getTransactionReceipt({ hash: row.txHash });
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error);
    if (!message.includes("not found") && !message.includes("could not find")) {
      console.warn(
        `[tx-poller] Receipt lookup failed for ${row.id}`,
        redactedThrownDiagnostics(error),
      );
    }
  }

  if (!receipt) {
    // Absence of a receipt cannot prove that an ambiguous submission failed.
    // Keep outcome_unknown terminal and, critically, never call a broadcast API.
    if (row.status === "outcome_unknown") return "skipped";
    if (
      shouldEmitStillPending(row, now, options.stillPendingAfterMs, options.stillPendingIntervalMs)
    ) {
      await markStillPending(row, now);
      return "pending";
    }
    return "skipped";
  }

  // Bind the provider-controlled response back to the exact deterministic
  // hash requested. A malicious RPC must not reconcile using another receipt.
  if (receipt.transactionHash.toLowerCase() !== row.txHash.toLowerCase()) {
    console.warn(`[tx-poller] Receipt hash mismatch for ${row.id}; refusing reconciliation`);
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
    minConfirmationsForChain(row.chainId, options.minConfirmations),
  );
  if (!eventType) {
    if (row.status === "outcome_unknown") {
      const reconciled = await reconcileOutcomeUnknownAsBroadcast(row, receipt);
      return reconciled ? "pending" : "skipped";
    }
    return "skipped";
  }

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
  const resolvedOptions: ResolvedTransactionReceiptPollerOptions = {
    batchSize: options.batchSize ?? DEFAULT_RECEIPT_POLL_BATCH_SIZE,
    // Left undefined when unset so pollOneTransaction applies the per-chain
    // default (SEC-152); an explicit value applies to every chain.
    minConfirmations: options.minConfirmations,
    stillPendingAfterMs: options.stillPendingAfterMs ?? DEFAULT_STILL_PENDING_AFTER_MS,
    stillPendingIntervalMs: options.stillPendingIntervalMs ?? DEFAULT_STILL_PENDING_INTERVAL_MS,
    clientFactory:
      options.clientFactory ??
      ((rpcUrl) => createPublicClient({ transport: http(rpcUrl) }) as TransactionReceiptClient),
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
      executionPayloadDigest: transactions.executionPayloadDigest,
      executionPolicyRevisionHash: transactions.executionPolicyRevisionHash,
      executionBackend: transactions.executionBackend,
      executionBackendIdentityDigest: transactions.executionBackendIdentityDigest,
      policyResults: transactions.policyResults,
      createdAt: transactions.createdAt,
      signedAt: transactions.signedAt,
      confirmedAt: transactions.confirmedAt,
      receiptPolledAt: transactions.receiptPolledAt,
    })
    .from(transactions)
    .innerJoin(agents, eq(transactions.agentId, agents.id))
    .where(
      and(
        inArray(transactions.status, ["broadcast", "outcome_unknown"]),
        isNotNull(transactions.txHash),
      ),
    )
    .orderBy(sql`${transactions.receiptPolledAt} ASC NULLS FIRST`, asc(transactions.createdAt))
    .limit(resolvedOptions.batchSize);

  const summary = { checked: rows.length, confirmed: 0, reverted: 0, pending: 0, skipped: 0 };
  for (const row of rows) {
    const result = await pollOneTransaction(row, resolvedOptions);
    summary[result] += 1;
  }
  return summary;
}

export async function pollBroadcastTransactionReceiptsForAllTenants(
  options: TransactionReceiptPollerOptions = {},
) {
  const tenantResults = await runInternalJobForEachTenant("transaction-receipt-poll", () =>
    pollBroadcastTransactionReceipts(options),
  );
  return tenantResults.reduce(
    (total, { value }) => ({
      checked: total.checked + value.checked,
      confirmed: total.confirmed + value.confirmed,
      reverted: total.reverted + value.reverted,
      pending: total.pending + value.pending,
      skipped: total.skipped + value.skipped,
    }),
    { checked: 0, confirmed: 0, reverted: 0, pending: 0, skipped: 0 },
  );
}

export function startTransactionReceiptPollingScheduler(): () => void {
  if (runtimeEnvironmentValue("STEWARD_TRANSACTION_RECEIPT_POLLER") === "false") {
    console.log("[tx-poller] Disabled by STEWARD_TRANSACTION_RECEIPT_POLLER=false");
    return () => {};
  }

  const intervalMs = parsePositiveInt(
    runtimeEnvironmentValue("STEWARD_TRANSACTION_RECEIPT_POLL_INTERVAL_MS"),
    DEFAULT_RECEIPT_POLL_INTERVAL_MS,
  );
  const batchSize = parsePositiveInt(
    runtimeEnvironmentValue("STEWARD_TRANSACTION_RECEIPT_POLL_BATCH_SIZE"),
    DEFAULT_RECEIPT_POLL_BATCH_SIZE,
  );
  // SEC-152: when unset (or invalid), leave undefined so each chain's default
  // applies (e.g. 12 for Ethereum L1 mainnet) instead of forcing 1 everywhere.
  const confirmationsEnv = runtimeEnvironmentValue("STEWARD_TRANSACTION_RECEIPT_CONFIRMATIONS")?.trim();
  const parsedConfirmations = confirmationsEnv ? Number(confirmationsEnv) : undefined;
  const minConfirmations =
    parsedConfirmations !== undefined &&
    Number.isInteger(parsedConfirmations) &&
    parsedConfirmations > 0
      ? parsedConfirmations
      : undefined;
  const stillPendingAfterMs = parsePositiveInt(
    runtimeEnvironmentValue("STEWARD_TRANSACTION_STILL_PENDING_AFTER_MS"),
    DEFAULT_STILL_PENDING_AFTER_MS,
  );
  const stillPendingIntervalMs = parsePositiveInt(
    runtimeEnvironmentValue("STEWARD_TRANSACTION_STILL_PENDING_INTERVAL_MS"),
    DEFAULT_STILL_PENDING_INTERVAL_MS,
  );
  let running = false;

  const tick = () => {
    if (running) return;
    running = true;
    void pollBroadcastTransactionReceiptsForAllTenants({
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
        console.error("[tx-poller] Receipt polling tick failed", redactedThrownDiagnostics(error));
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
