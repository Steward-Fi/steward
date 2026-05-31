import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const pollerSource = readFileSync(
  join(apiRoot, "services", "transaction-receipt-poller.ts"),
  "utf8",
);
const apiIndexSource = readFileSync(join(apiRoot, "index.ts"), "utf8");

describe("transaction receipt poller", () => {
  it("classifies receipts only after the configured confirmation threshold", () => {
    const classifyStart = pollerSource.indexOf("export function classifyReceiptLifecycle");
    const classifyBody = pollerSource.slice(
      classifyStart,
      pollerSource.indexOf("function actionReferenceId"),
    );
    expect(classifyStart).toBeGreaterThanOrEqual(0);
    expect(classifyBody).toContain("confirmations < minConfirmations");
    expect(classifyBody).toContain('"transaction.confirmed"');
    expect(classifyBody).toContain('"transaction.execution_reverted"');
  });

  it("polls only already-broadcast transactions with hashes", () => {
    expect(pollerSource).toContain('eq(transactions.status, "broadcast")');
    expect(pollerSource).toContain("isNotNull(transactions.txHash)");
    expect(pollerSource).toContain("isHexHash(row.txHash)");
  });

  it("does not mark transactions failed for transient RPC lookup errors", () => {
    const receiptLookup = pollerSource.slice(
      pollerSource.indexOf("try {"),
      pollerSource.indexOf("if (!receipt)"),
    );
    expect(receiptLookup).toContain("console.warn");
    expect(receiptLookup).not.toContain('status: "failed"');
    expect(receiptLookup).not.toContain("transaction.provider_error");
  });

  it("does not finalize when the chain head (current block number) is unavailable", () => {
    const blockStart = pollerSource.indexOf("let currentBlock");
    const finalizeCall = pollerSource.indexOf("await finalizeReceipt(", blockStart);
    const degradationBody = pollerSource.slice(blockStart, finalizeCall);

    expect(blockStart).toBeGreaterThanOrEqual(0);
    expect(finalizeCall).toBeGreaterThan(blockStart);
    // On getBlockNumber() failure the head is null and the cycle is skipped (no confirmations=1).
    expect(degradationBody).toContain("currentBlock = null");
    expect(degradationBody).toContain('if (currentBlock === null) return "skipped"');
    // The receipt-block fallback (confirmations forced to 1) must be gone.
    expect(degradationBody).not.toContain("receipt block as one confirmation");
  });

  it("emits transaction and user-operation lifecycle webhooks from automatic finalization", () => {
    expect(pollerSource).toContain("dispatchTransactionLifecycleWebhook");
    expect(pollerSource).toContain('"transaction.confirmed" ? "user_operation.completed"');
    expect(pollerSource).toContain('"user_operation.failed"');
    expect(pollerSource).toContain("writeSystemLifecycleAudit");
  });

  it("starts and stops the scheduler from the long-lived API runtime", () => {
    expect(apiIndexSource).toContain("import { startTransactionReceiptPollingScheduler }");
    expect(apiIndexSource).toContain(
      "cancelTransactionReceiptPolling = startTransactionReceiptPollingScheduler()",
    );
    expect(apiIndexSource).toContain(
      "if (cancelTransactionReceiptPolling) cancelTransactionReceiptPolling()",
    );
  });
});
