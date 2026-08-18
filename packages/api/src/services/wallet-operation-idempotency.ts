import { createHash, timingSafeEqual } from "node:crypto";
import { getDb, walletOperationIdempotency } from "@stwd/db";
import { and, eq } from "drizzle-orm";

export type WalletOperationStatus = "processing" | "submission_unknown" | "completed";

export type WalletOperationReplay = {
  status: WalletOperationStatus;
  txId: string;
  txHash: string | null;
  responseStatus: number | null;
  responseBody: Record<string, unknown> | null;
};

export type WalletOperationClaim =
  | { kind: "claimed"; txId: string }
  | { kind: "conflict" }
  | { kind: "replay"; entry: WalletOperationReplay };

const IDEMPOTENCY_KEY_RE = /^[\x21-\x7e]{8,255}$/;

export function normalizeWalletIdempotencyKey(value: string): string {
  const normalized = value.trim().normalize("NFC");
  if (!IDEMPOTENCY_KEY_RE.test(normalized)) {
    throw new Error("Invalid Idempotency-Key header");
  }
  return normalized;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new Error("Idempotency payload contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  throw new Error("Idempotency payload contains an unsupported value");
}

export function walletOperationRequestDigest(value: unknown): string {
  return sha256(canonicalJson(value));
}

function equalDigest(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  const encoder = new TextEncoder();
  return timingSafeEqual(encoder.encode(left), encoder.encode(right));
}

export async function claimWalletOperation(input: {
  tenantId: string;
  agentId: string;
  operation: string;
  idempotencyKey: string;
  request: unknown;
  txId: string;
}): Promise<WalletOperationClaim> {
  const db = getDb();
  const key = normalizeWalletIdempotencyKey(input.idempotencyKey);
  const idempotencyKeyHash = sha256(key);
  const requestDigest = walletOperationRequestDigest(input.request);
  const inserted = await db
    .insert(walletOperationIdempotency)
    .values({
      tenantId: input.tenantId,
      agentId: input.agentId,
      operation: input.operation,
      idempotencyKeyHash,
      requestDigest,
      txId: input.txId,
      status: "processing",
    })
    .onConflictDoNothing()
    .returning({ txId: walletOperationIdempotency.txId });
  if (inserted.length === 1) return { kind: "claimed", txId: input.txId };

  const [existing] = await db
    .select()
    .from(walletOperationIdempotency)
    .where(
      and(
        eq(walletOperationIdempotency.tenantId, input.tenantId),
        eq(walletOperationIdempotency.agentId, input.agentId),
        eq(walletOperationIdempotency.operation, input.operation),
        eq(walletOperationIdempotency.idempotencyKeyHash, idempotencyKeyHash),
      ),
    );
  if (!existing) throw new Error("Wallet idempotency claim disappeared");
  if (!equalDigest(existing.requestDigest, requestDigest)) return { kind: "conflict" };
  return {
    kind: "replay",
    entry: {
      status: existing.status as WalletOperationStatus,
      txId: existing.txId,
      txHash: existing.txHash,
      responseStatus: existing.responseStatus,
      responseBody: existing.responseBody,
    },
  };
}

export async function markWalletOperationSubmissionUnknown(input: {
  tenantId: string;
  agentId: string;
  operation: string;
  txId: string;
}): Promise<void> {
  const db = getDb();
  const updated = await db
    .update(walletOperationIdempotency)
    .set({ status: "submission_unknown", updatedAt: new Date() })
    .where(
      and(
        eq(walletOperationIdempotency.tenantId, input.tenantId),
        eq(walletOperationIdempotency.agentId, input.agentId),
        eq(walletOperationIdempotency.operation, input.operation),
        eq(walletOperationIdempotency.txId, input.txId),
        eq(walletOperationIdempotency.status, "processing"),
      ),
    )
    .returning({ txId: walletOperationIdempotency.txId });
  if (updated.length !== 1) throw new Error("Wallet idempotency claim is not active");
}

/** Release is permitted only while submission has definitely not started. */
export async function releaseWalletOperationClaim(input: {
  tenantId: string;
  agentId: string;
  operation: string;
  txId: string;
}): Promise<void> {
  const db = getDb();
  await db
    .delete(walletOperationIdempotency)
    .where(
      and(
        eq(walletOperationIdempotency.tenantId, input.tenantId),
        eq(walletOperationIdempotency.agentId, input.agentId),
        eq(walletOperationIdempotency.operation, input.operation),
        eq(walletOperationIdempotency.txId, input.txId),
        eq(walletOperationIdempotency.status, "processing"),
      ),
    );
}

export async function completeWalletOperation(input: {
  tenantId: string;
  agentId: string;
  operation: string;
  txId: string;
  txHash?: string;
  responseStatus: number;
  responseBody: Record<string, unknown>;
}): Promise<void> {
  const db = getDb();
  const updated = await db
    .update(walletOperationIdempotency)
    .set({
      status: "completed",
      txHash: input.txHash,
      responseStatus: input.responseStatus,
      responseBody: input.responseBody,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(walletOperationIdempotency.tenantId, input.tenantId),
        eq(walletOperationIdempotency.agentId, input.agentId),
        eq(walletOperationIdempotency.operation, input.operation),
        eq(walletOperationIdempotency.txId, input.txId),
      ),
    )
    .returning({ txId: walletOperationIdempotency.txId });
  if (updated.length !== 1) throw new Error("Wallet idempotency claim is missing");
}
