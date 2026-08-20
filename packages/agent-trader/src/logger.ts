/**
 * Structured JSON logger for the agent-trader service.
 *
 * Every line emitted is a self-contained JSON object so that log-shippers,
 * grep, and jq can consume the output without any parsing logic.
 */

import { redactedThrownDiagnostics } from "@stwd/shared";

export type LogLevel = "info" | "warn" | "error" | "debug";

export interface DecisionLog {
  timestamp: string;
  agentId: string;
  strategy: string;
  action: "buy" | "sell" | "hold";
  amount: string;
  reason: string;
  confidence: number;
  dryRun: boolean;
}

export interface SubmissionLog {
  timestamp: string;
  agentId: string;
  txId?: string;
  status: "submitted" | "signed" | "pending_approval" | "rejected" | "error";
  to: string;
  value: string;
  dataLen: number;
  chainId: number;
  error?: string;
}

export interface WebhookLog {
  timestamp: string;
  event: string;
  agentId?: string;
  data: Record<string, unknown>;
}

// ─── Internal emit ───────────────────────────────────────────────────────────

function emit(level: LogLevel, tag: string, payload: Record<string, unknown>): void {
  const line = JSON.stringify({ level, tag, ...payload });
  if (level === "error") {
    process.stderr.write(`${line}\n`);
  } else {
    process.stdout.write(`${line}\n`);
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function logDecision(entry: Omit<DecisionLog, "timestamp">): void {
  emit("info", "decision", { timestamp: new Date().toISOString(), ...entry });
}

export function logSubmission(entry: Omit<SubmissionLog, "timestamp">): void {
  const level: LogLevel =
    entry.status === "error" || entry.status === "rejected" ? "error" : "info";
  const { error, ...safeEntry } = entry;
  emit(level, "submission", {
    timestamp: new Date().toISOString(),
    ...safeEntry,
    ...(error === undefined ? {} : { error: "operation failed" }),
  });
}

/**
 * Field names whose values are masked before a webhook payload is logged.
 * Tx hashes/ids (txHash, txId, blockNumber, etc.) are intentionally NOT listed
 * so they remain greppable; this only scrubs obviously-sensitive material that
 * could leak keys/credentials if an upstream event ever carried them.
 */
const SENSITIVE_WEBHOOK_FIELDS = [
  "privatekey",
  "secret",
  "mnemonic",
  "seed",
  "password",
  "apikey",
  "token",
  "authorization",
  "signature",
];

const FAILURE_TEXT_FIELDS = new Set(["error", "errormessage", "errorraw", "stack"]);

function redactWebhookValue(value: unknown): unknown {
  // SEC-110: recurse into arrays too — batch-shaped payloads carry objects
  // inside arrays (e.g. `items: [{ apiKey: ... }]`) and must get the same
  // redaction as object-nested values.
  if (Array.isArray(value)) return value.map(redactWebhookValue);
  if (value && typeof value === "object") {
    return redactWebhookData(value as Record<string, unknown>);
  }
  return value;
}

function redactWebhookData(data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    const normalized = key.toLowerCase().replace(/[_-]/g, "");
    if (
      FAILURE_TEXT_FIELDS.has(normalized) ||
      SENSITIVE_WEBHOOK_FIELDS.some((f) => normalized.includes(f))
    ) {
      out[key] = "[redacted]";
    } else {
      out[key] = redactWebhookValue(value);
    }
  }
  return out;
}

export function logWebhook(entry: Omit<WebhookLog, "timestamp">): void {
  emit("info", "webhook", {
    timestamp: new Date().toISOString(),
    ...entry,
    data: redactWebhookData(entry.data),
  });
}

export function logInfo(message: string, meta?: Record<string, unknown>): void {
  emit("info", "info", {
    timestamp: new Date().toISOString(),
    message,
    ...redactWebhookData(meta ?? {}),
  });
}

export function logWarn(message: string, meta?: Record<string, unknown>): void {
  emit("warn", "warn", {
    timestamp: new Date().toISOString(),
    message,
    ...redactWebhookData(meta ?? {}),
  });
}

export function logError(message: string, error?: unknown, meta?: Record<string, unknown>): void {
  const errMeta = error === undefined ? {} : redactedThrownDiagnostics(error);
  emit("error", "error", {
    timestamp: new Date().toISOString(),
    message,
    ...errMeta,
    ...redactWebhookData(meta ?? {}),
  });
}
