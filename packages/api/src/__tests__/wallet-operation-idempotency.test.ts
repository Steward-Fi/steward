import { afterAll, beforeAll, describe, expect, test } from "bun:test";

process.env.STEWARD_PGLITE_MEMORY = "true";

import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  claimWalletOperation,
  completeWalletOperation,
  markWalletOperationSubmissionUnknown,
  releaseWalletOperationClaim,
  walletOperationRequestDigest,
} from "../services/wallet-operation-idempotency";

const tenantId = `wallet-idem-tenant-${Date.now()}`;
const agentId = `wallet-idem-agent-${Date.now()}`;
const operation = "vault.sign.broadcast";

describe("durable wallet operation idempotency", () => {
  beforeAll(async () => {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({
      id: tenantId,
      name: "Wallet idempotency test",
      apiKeyHash: "wallet-idem-hash",
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Wallet idempotency agent",
      walletAddress: "0x1111111111111111111111111111111111111111",
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("canonical digest ignores object key order but not values", () => {
    expect(walletOperationRequestDigest({ value: "1", to: "0x1" })).toBe(
      walletOperationRequestDigest({ to: "0x1", value: "1" }),
    );
    expect(walletOperationRequestDigest({ value: "1" })).not.toBe(
      walletOperationRequestDigest({ value: "2" }),
    );
  });

  test("an atomic concurrent claim has exactly one winner across callers", async () => {
    const key = "concurrent-wallet-key";
    const claims = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        claimWalletOperation({
          tenantId,
          agentId,
          operation,
          idempotencyKey: key,
          request: { to: "0x2222222222222222222222222222222222222222", value: "1" },
          txId: `wallet-concurrent-${index}`,
        }),
      ),
    );
    expect(claims.filter((claim) => claim.kind === "claimed")).toHaveLength(1);
    expect(claims.filter((claim) => claim.kind === "replay")).toHaveLength(7);
    const txIds = new Set(
      claims.map((claim) => (claim.kind === "claimed" ? claim.txId : claim.entry.txId)),
    );
    expect(txIds.size).toBe(1);
  });

  test("same key with a different canonical body conflicts", async () => {
    const base = {
      tenantId,
      agentId,
      operation,
      idempotencyKey: "different-body-key",
    };
    expect(
      await claimWalletOperation({ ...base, request: { value: "1" }, txId: "wallet-body-a" }),
    ).toEqual({ kind: "claimed", txId: "wallet-body-a" });
    expect(
      await claimWalletOperation({ ...base, request: { value: "2" }, txId: "wallet-body-b" }),
    ).toEqual({ kind: "conflict" });
  });

  test("a definitely pre-submission claim can be released and reclaimed", async () => {
    const base = {
      tenantId,
      agentId,
      operation,
      idempotencyKey: "released-before-submit",
      request: { value: "4" },
    };
    expect(await claimWalletOperation({ ...base, txId: "wallet-release-a" })).toEqual({
      kind: "claimed",
      txId: "wallet-release-a",
    });
    await releaseWalletOperationClaim({
      tenantId,
      agentId,
      operation,
      txId: "wallet-release-a",
    });
    expect(await claimWalletOperation({ ...base, txId: "wallet-release-b" })).toEqual({
      kind: "claimed",
      txId: "wallet-release-b",
    });
  });

  test("submission-unknown and completed outcomes replay without reopening", async () => {
    const base = {
      tenantId,
      agentId,
      operation,
      idempotencyKey: "unknown-then-complete-key",
      request: { value: "3" },
      txId: "wallet-unknown",
    };
    expect(await claimWalletOperation(base)).toEqual({
      kind: "claimed",
      txId: "wallet-unknown",
    });
    await markWalletOperationSubmissionUnknown({
      tenantId,
      agentId,
      operation,
      txId: base.txId,
    });
    const unknownReplay = await claimWalletOperation({ ...base, txId: "ignored-unknown" });
    expect(unknownReplay.kind).toBe("replay");
    if (unknownReplay.kind === "replay") {
      expect(unknownReplay.entry.status).toBe("submission_unknown");
      expect(unknownReplay.entry.txId).toBe(base.txId);
    }

    const responseBody = {
      ok: true,
      data: { txId: base.txId, txHash: `0x${"ab".repeat(32)}` },
    };
    await completeWalletOperation({
      tenantId,
      agentId,
      operation,
      txId: base.txId,
      txHash: `0x${"ab".repeat(32)}`,
      responseStatus: 200,
      responseBody,
    });
    const completedReplay = await claimWalletOperation({ ...base, txId: "ignored-completed" });
    expect(completedReplay).toEqual({
      kind: "replay",
      entry: {
        status: "completed",
        txId: base.txId,
        txHash: `0x${"ab".repeat(32)}`,
        responseStatus: 200,
        responseBody,
      },
    });
  });
});
