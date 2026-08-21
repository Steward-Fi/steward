import { afterAll, beforeAll, beforeEach, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditEvents,
  closeDb,
  getDb,
  policies,
  tenantConfigs,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  ExternalBroadcastOutcomeUnknownError,
  SolanaBroadcastNotSubmittedError,
  Vault,
} from "@stwd/vault";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { idempotencyMiddleware, MemoryIdempotencyStore } from "../middleware/idempotency";
import type { AppVariables } from "../services/context";

const TENANT_ID = `solana-recovery-tenant-${Date.now()}`;
const AGENT_ID = `solana-recovery-agent-${Date.now()}`;
const FROM = "7v54NWdBtkjuAFJrLGsS2SXnuk8nKam81mZJeeYxVFi9";
const RECIPIENT = "6TcyBfPdBt1kjsvDZLzmBFnuMaLWiTaAt4RjUr9VA5YD";
const SIGNATURE =
  "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
const RECENT_BLOCKHASH = "11111111111111111111111111111111";
const ARTIFACT_EVIDENCE = {
  artifactSignature: SIGNATURE,
  signer: "11111111111111111111111111111111",
  recentBlockhash: RECENT_BLOCKHASH,
  blockhashKind: "recent" as const,
  lastValidBlockHeight: 1_000,
  rawIntentDigest: "a".repeat(64),
};
const WITHIN_CAP_V0_TRANSFER =
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQACBGa+fjMsekUzMr2dCn99sFX1xe8aBq2mbZizn7aBDEc6URw0oaLLUh3xa7JGuN6OeZfOI1x+drIqPXUDokgZ3YoDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcDAgAFAkANAwACAAkD6AMAAAAAAAADAgABDAIAAAB7AAAAAAAAAAA=";

function withRecentBlockhash(transaction: string, blockhash: string): string {
  const bytes = Buffer.from(transaction, "base64");
  const readShortVec = (offset: number): [number, number] => {
    let value = 0;
    let shift = 0;
    let cursor = offset;
    while (true) {
      const byte = bytes[cursor++];
      value |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return [value, cursor];
      shift += 7;
    }
  };
  const [signatureCount, messageOffset] = readShortVec(0);
  let cursor = messageOffset + signatureCount * 64;
  if ((bytes[cursor] & 0x80) !== 0) cursor += 1;
  cursor += 3;
  const [accountCount, accountsOffset] = readShortVec(cursor);
  cursor = accountsOffset + accountCount * 32;
  const replacement = Buffer.alloc(32);
  Buffer.from(blockhash).copy(replacement, 0, 0, 32);
  replacement.copy(bytes, cursor);
  return bytes.toString("base64");
}

function withComputeUnitLimit(transaction: string, units: number): string {
  const bytes = Buffer.from(transaction, "base64");
  const marker = Buffer.from([2, 0x40, 0x0d, 0x03, 0]);
  const offset = bytes.indexOf(marker);
  if (offset < 0) throw new Error("compute-unit-limit instruction not found");
  bytes.writeUInt32LE(units, offset + 1);
  return bytes.toString("base64");
}

setDefaultTimeout(30_000);

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", "solana-recovery-admin");
    if (c.req.header("x-test-recent-mfa") === "true") {
      c.set("sessionMfaVerifiedAt", Date.now());
    }
    c.set("requestId", crypto.randomUUID());
    await next();
  });
  app.use("*", idempotencyMiddleware({ store: new MemoryIdempotencyStore(), ttlMs: 60_000 }));
  app.route("/vault", vaultRoutes);
  return app;
}

async function onlyRecoveryRow() {
  const rows = await getDb().select().from(transactions).where(eq(transactions.agentId, AGENT_ID));
  expect(rows).toHaveLength(1);
  return rows[0];
}

describe("Solana durable recovery anchors", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "solana-recovery-anchor-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "solana-recovery-anchor-audit-hmac-key-with-more-than-32-bytes";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Solana Recovery Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Solana Recovery Agent",
      walletAddress: FROM,
    });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: { mfa: { requireFor: { vaultSigning: false } } },
      });
    await getDb()
      .insert(policies)
      .values([
        {
          id: `${AGENT_ID}-approved-recipient`,
          agentId: AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [RECIPIENT], mode: "whitelist" },
        },
        {
          id: `${AGENT_ID}-auto-approve-threshold`,
          agentId: AGENT_ID,
          type: "auto-approve-threshold",
          enabled: true,
          config: { threshold: "999" },
        },
      ]);
    app = await makeApp();
  });

  beforeEach(async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "solana-recovery-anchor-audit-hmac-key-with-more-than-32-bytes";
    __resetAuditHmacKeyCacheForTests();
    delete process.env.STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING;
    delete process.env.REDIS_URL;
    await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    delete process.env.STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING;
    delete process.env.REDIS_URL;
    __resetAuditHmacKeyCacheForTests();
  });

  it("keeps the parsed-route anchor and submitted signature when final bookkeeping fails", async () => {
    const originalSign = Vault.prototype.signSolanaTransaction;
    Vault.prototype.signSolanaTransaction = async (request) => {
      const staged = await onlyRecoveryRow();
      expect(staged.status).toBe("approved");
      expect(staged.data).toBe(WITHIN_CAP_V0_TRANSFER);
      expect(staged.txHash).toBeNull();

      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      const checkpoint = await onlyRecoveryRow();
      expect(checkpoint.status).toBe("outcome_unknown");
      expect(checkpoint.txHash).toBe(SIGNATURE);
      expect(checkpoint.actionPayload).toMatchObject({
        artifactSignature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      return {
        signature: SIGNATURE,
        broadcast: true,
        chainId: request.chainId ?? 101,
        ...ARTIFACT_EVIDENCE,
        caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      };
    };

    await getDb().execute(
      sql.raw(`
      ALTER TABLE transactions
      ADD CONSTRAINT test_reject_solana_finalization
      CHECK (status <> 'broadcast' OR action_type <> 'solana_transaction')
    `),
    );
    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "solana-recovery-final-write-failure",
        },
        body: JSON.stringify({ transaction: WITHIN_CAP_V0_TRANSFER, broadcast: true }),
      });

      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        ok: true,
        data: { signature: SIGNATURE, broadcast: true },
      });
      const surviving = await onlyRecoveryRow();
      expect(surviving.status).toBe("outcome_unknown");
      expect(surviving.txHash).toBe(SIGNATURE);
      expect(surviving.data).toBe(WITHIN_CAP_V0_TRANSFER);
    } finally {
      Vault.prototype.signSolanaTransaction = originalSign;
      await getDb().execute(
        sql.raw("ALTER TABLE transactions DROP CONSTRAINT test_reject_solana_finalization"),
      );
    }
  });

  it("keeps the blind-route broadcast row and success response when final audit fails", async () => {
    process.env.STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING = "true";
    const originalSign = Vault.prototype.signSolanaTransaction;
    Vault.prototype.signSolanaTransaction = async (request) => {
      const staged = await onlyRecoveryRow();
      expect(staged.status).toBe("approved");
      expect(staged.data).toBe("not-a-solana-transaction");
      expect(staged.actionPayload).toMatchObject({ blindSigned: true, recoveryAnchor: true });

      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      const checkpoint = await onlyRecoveryRow();
      expect(checkpoint.status).toBe("outcome_unknown");
      expect(checkpoint.txHash).toBe(SIGNATURE);
      expect(checkpoint.actionPayload).toMatchObject({
        artifactSignature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });

      process.env.STEWARD_AUDIT_HMAC_KEY = "too-weak";
      __resetAuditHmacKeyCacheForTests();
      return {
        signature: SIGNATURE,
        broadcast: true,
        chainId: request.chainId ?? 101,
        ...ARTIFACT_EVIDENCE,
      };
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "solana-recovery-audit-failure",
        },
        body: JSON.stringify({
          transaction: "not-a-solana-transaction",
          broadcast: true,
          to: RECIPIENT,
          value: "123",
        }),
      });

      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        ok: true,
        data: { txId: expect.any(String), signature: SIGNATURE, broadcast: true },
      });
      const surviving = await onlyRecoveryRow();
      expect(surviving.status).toBe("broadcast");
      expect(surviving.txHash).toBe(SIGNATURE);
      expect(surviving.data).toBe("not-a-solana-transaction");
      expect(readPayload(surviving.actionPayload).recoveryEffectsState).toBe("pending");
    } finally {
      Vault.prototype.signSolanaTransaction = originalSign;
      process.env.STEWARD_AUDIT_HMAC_KEY =
        "solana-recovery-anchor-audit-hmac-key-with-more-than-32-bytes";
      __resetAuditHmacKeyCacheForTests();
    }
  });

  it("keeps recovery effects pending while a configured Redis backend is unavailable", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:1";
    const originalSign = Vault.prototype.signSolanaTransaction;
    Vault.prototype.signSolanaTransaction = async (request) => {
      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      return {
        signature: SIGNATURE,
        broadcast: true,
        chainId: request.chainId ?? 101,
        ...ARTIFACT_EVIDENCE,
      };
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "solana-recovery-redis-unavailable",
        },
        body: JSON.stringify({ transaction: WITHIN_CAP_V0_TRANSFER, broadcast: true }),
      });

      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        ok: true,
        data: { txId: expect.any(String), signature: SIGNATURE, broadcast: true },
      });
      const surviving = await onlyRecoveryRow();
      expect(surviving.status).toBe("broadcast");
      expect(surviving.txHash).toBe(SIGNATURE);
      expect(readPayload(surviving.actionPayload).recoveryEffectsState).toBe("pending");
    } finally {
      Vault.prototype.signSolanaTransaction = originalSign;
      delete process.env.REDIS_URL;
    }
  });

  it("returns a non-retryable 202 with the durable hash when confirmation is ambiguous", async () => {
    const originalSign = Vault.prototype.signSolanaTransaction;
    Vault.prototype.signSolanaTransaction = async (request) => {
      expect((await onlyRecoveryRow()).status).toBe("approved");
      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      throw new ExternalBroadcastOutcomeUnknownError(SIGNATURE, {
        cause: new Error("injected confirmation timeout"),
      });
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "solana-recovery-confirmation-unknown",
        },
        body: JSON.stringify({ transaction: WITHIN_CAP_V0_TRANSFER, broadcast: true }),
      });

      expect(response.status).toBe(202);
      expect(await response.json()).toMatchObject({
        ok: false,
        data: {
          code: "external_broadcast_outcome_unknown",
          txHash: SIGNATURE,
          reconciliationRequired: true,
        },
      });
      const surviving = await onlyRecoveryRow();
      expect(surviving.status).toBe("outcome_unknown");
      expect(surviving.txHash).toBe(SIGNATURE);
      expect(readPayload(surviving.actionPayload).recoveryEffectsState).toBe("accounted_unknown");
      expect(
        await getDb()
          .select()
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.resourceId, surviving.id),
              eq(auditEvents.action, "vault.sign.solana.effects_completed"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      Vault.prototype.signSolanaTransaction = originalSign;
    }
  });

  it("serializes ambiguous accounting against a failed reconciliation without success evidence", async () => {
    const routes = await import("../routes/vault");
    const originalSign = Vault.prototype.signSolanaTransaction;
    const originalReconcile = Vault.prototype.reconcileSolanaBroadcast;
    let releaseClaim!: () => void;
    const claimRelease = new Promise<void>((resolve) => {
      releaseClaim = resolve;
    });
    let reportClaim!: () => void;
    const claimEntered = new Promise<void>((resolve) => {
      reportClaim = resolve;
    });
    const restoreClaimHook = routes.__setSolanaRecoveryEffectsClaimHookForTests(async (input) => {
      if (input.status !== "outcome_unknown") return;
      reportClaim();
      await claimRelease;
    });
    Vault.prototype.signSolanaTransaction = async (request) => {
      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
      });
      throw new ExternalBroadcastOutcomeUnknownError(SIGNATURE);
    };
    Vault.prototype.reconcileSolanaBroadcast = async () => "failed";

    try {
      const first = app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "solana-recovery-effects-reconcile-race",
        },
        body: JSON.stringify({ transaction: WITHIN_CAP_V0_TRANSFER, broadcast: true }),
      });
      await claimEntered;
      const staged = await onlyRecoveryRow();
      expect(readPayload(staged.actionPayload).recoveryEffectsState).toBe("processing");

      const blocked = await app.request(
        `/vault/${AGENT_ID}/transactions/${staged.id}/reconcile-solana`,
        { method: "POST" },
      );
      expect(blocked.status).toBe(409);
      expect((await onlyRecoveryRow()).status).toBe("outcome_unknown");

      releaseClaim();
      expect((await first).status).toBe(202);
      expect(readPayload((await onlyRecoveryRow()).actionPayload).recoveryEffectsState).toBe(
        "accounted_unknown",
      );

      const reconciled = await app.request(
        `/vault/${AGENT_ID}/transactions/${staged.id}/reconcile-solana`,
        { method: "POST" },
      );
      expect(reconciled.status).toBe(200);
      const final = await onlyRecoveryRow();
      expect(final.status).toBe("failed");
      expect(readPayload(final.actionPayload).recoveryEffectsState).toBe("accounted_unknown");
      expect(
        await getDb()
          .select()
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.resourceId, staged.id),
              eq(auditEvents.action, "vault.sign.solana.effects_completed"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      releaseClaim();
      restoreClaimHook();
      Vault.prototype.signSolanaTransaction = originalSign;
      Vault.prototype.reconcileSolanaBroadcast = originalReconcile;
    }
  });

  it("replays the confirmed winner when definite-preflight cleanup loses its signature CAS", async () => {
    const originalSign = Vault.prototype.signSolanaTransaction;
    Vault.prototype.signSolanaTransaction = async (request) => {
      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      const checkpoint = await onlyRecoveryRow();
      await getDb()
        .update(transactions)
        .set({ status: "confirmed", confirmedAt: new Date() })
        .where(eq(transactions.id, checkpoint.id));
      throw new SolanaBroadcastNotSubmittedError(SIGNATURE);
    };
    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "solana-preflight-cas-winner",
        },
        body: JSON.stringify({ transaction: WITHIN_CAP_V0_TRANSFER, broadcast: true }),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        ok: true,
        data: { signature: SIGNATURE, broadcast: true },
      });
      const row = await onlyRecoveryRow();
      expect(row.status).toBe("confirmed");
      const notSubmittedAudits = await getDb()
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.resourceId, row.id),
            eq(auditEvents.action, "vault.sign.solana.not_submitted"),
          ),
        );
      expect(notSubmittedAudits).toHaveLength(0);
    } finally {
      Vault.prototype.signSolanaTransaction = originalSign;
    }
  });

  it("durably replays across both cache-unsafe and cache-safe session auth", async () => {
    const context = await import("../services/context");
    const originalSign = Vault.prototype.signSolanaTransaction;
    let signCalls = 0;
    let releaseAttempt!: () => void;
    const attemptBarrier = new Promise<void>((resolve) => {
      releaseAttempt = resolve;
    });
    let signalAttemptStarted!: () => void;
    const attemptStarted = new Promise<void>((resolve) => {
      signalAttemptStarted = resolve;
    });
    Vault.prototype.signSolanaTransaction = async (request) => {
      signCalls += 1;
      signalAttemptStarted();
      await attemptBarrier;
      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      return {
        signature: SIGNATURE,
        broadcast: true,
        chainId: request.chainId ?? 101,
        ...ARTIFACT_EVIDENCE,
        caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      };
    };
    const request = (recentMfa = false, transaction = WITHIN_CAP_V0_TRANSFER) =>
      app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "session-admin-durable-solana-replay",
          ...(recentMfa ? { "x-test-recent-mfa": "true" } : {}),
        },
        body: JSON.stringify({ transaction, broadcast: true }),
      });

    try {
      const firstPromise = request();
      await attemptStarted;
      const concurrent = await request(true);
      expect(concurrent.status).toBe(409);
      expect(await concurrent.json()).toMatchObject({
        ok: false,
        data: { status: "processing" },
      });
      expect(signCalls).toBe(1);

      releaseAttempt();
      const first = await firstPromise;
      const changedComputeBudget = await request(
        true,
        withComputeUnitLimit(WITHIN_CAP_V0_TRANSFER, 210_000),
      );
      expect(changedComputeBudget.status).toBe(409);
      expect(await changedComputeBudget.json()).toMatchObject({
        ok: false,
        error: "Idempotency-Key was already used for a different Solana transaction",
      });
      const replay = await request(true, withRecentBlockhash(WITHIN_CAP_V0_TRANSFER, RECIPIENT));
      expect(first.status).toBe(200);
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBeNull();
      expect(await replay.json()).toEqual(await first.json());
      expect(signCalls).toBe(1);
      const row = await onlyRecoveryRow();
      expect(row.status).toBe("broadcast");
      expect(readPayload(row.actionPayload).recentBlockhash).toBe(RECENT_BLOCKHASH);
      expect(readPayload(row.actionPayload).recoveryEffectsState).toBe("complete");
      const completionAudits = await getDb()
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.resourceId, row.id),
            eq(auditEvents.action, "vault.sign.solana.effects_completed"),
          ),
        );
      expect(completionAudits).toHaveLength(1);
      expect(readPayload(row.actionPayload).artifactSignature).toBe(SIGNATURE);
      expect(readPayload(row.actionPayload).blockhashKind).toBe("recent");
      expect((await context.getTransactionStats(AGENT_ID, 101)).recentTxCount24h).toBe(1);

      const mismatch = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "session-admin-durable-solana-replay",
        },
        body: JSON.stringify({
          transaction: WITHIN_CAP_V0_TRANSFER,
          broadcast: true,
          chainId: 102,
        }),
      });
      expect(mismatch.status).toBe(409);
      expect(signCalls).toBe(1);
    } finally {
      Vault.prototype.signSolanaTransaction = originalSign;
    }
  });

  it("never takes over an expired lease after its parsed claim entered raw custody", async () => {
    const context = await import("../services/context");
    const originalSign = Vault.prototype.signSolanaTransaction;
    let signCalls = 0;
    let submittedCalls = 0;
    let releaseStale!: () => void;
    const staleBarrier = new Promise<void>((resolve) => {
      releaseStale = resolve;
    });
    let signalStaleStarted!: () => void;
    const staleStarted = new Promise<void>((resolve) => {
      signalStaleStarted = resolve;
    });
    Vault.prototype.signSolanaTransaction = async (request) => {
      signCalls += 1;
      signalStaleStarted();
      await staleBarrier;
      await request.onBroadcastPrepared?.({
        signature: SIGNATURE,
        recentBlockhash: RECENT_BLOCKHASH,
        blockhashKind: "recent",
      });
      submittedCalls += 1;
      return {
        signature: SIGNATURE,
        broadcast: true,
        chainId: request.chainId ?? 101,
        ...ARTIFACT_EVIDENCE,
        caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      };
    };
    const request = () =>
      app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "expired-solana-attempt-takeover",
        },
        body: JSON.stringify({ transaction: WITHIN_CAP_V0_TRANSFER, broadcast: true }),
      });

    try {
      const staleResponse = request();
      await staleStarted;
      const staged = await onlyRecoveryRow();
      await getDb()
        .update(transactions)
        .set({
          actionPayload: {
            ...readPayload(staged.actionPayload),
            attemptLeaseUntil: new Date(Date.now() - 1_000).toISOString(),
          },
        })
        .where(eq(transactions.id, staged.id));

      const takeoverResponse = await request();
      expect(takeoverResponse.status).toBe(409);
      expect(await takeoverResponse.json()).toMatchObject({
        ok: false,
        data: { status: "processing" },
      });
      expect(signCalls).toBe(1);
      expect(submittedCalls).toBe(0);

      releaseStale();
      expect((await staleResponse).status).toBe(200);
      expect(submittedCalls).toBe(1);
      expect((await onlyRecoveryRow()).status).toBe("broadcast");
    } finally {
      releaseStale();
      Vault.prototype.signSolanaTransaction = originalSign;
    }
  });

  it("reconciles only the stored signature and blockhash through guarded transitions", async () => {
    const originalReconcile = Vault.prototype.reconcileSolanaBroadcast;
    const cases = [
      { outcome: "confirmed" as const, status: 200 },
      { outcome: "broadcast" as const, status: 200 },
      { outcome: "failed" as const, status: 200 },
      { outcome: "outcome_unknown" as const, status: 202 },
    ];
    try {
      for (const [index, testCase] of cases.entries()) {
        await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
        const txId = `solana-reconcile-${index}`;
        await getDb()
          .insert(transactions)
          .values({
            id: txId,
            agentId: AGENT_ID,
            status: "outcome_unknown",
            toAddress: RECIPIENT,
            value: "123",
            chainId: 101,
            txHash: SIGNATURE,
            actionType: "solana_transaction",
            actionPayload: {
              type: "solana_transaction",
              recoveryAnchor: true,
              recentBlockhash: RECENT_BLOCKHASH,
              ...(index === 0
                ? {
                    recoveryEffectsState: "processing",
                    recoveryEffectsToken: "crashed-effects-owner",
                    recoveryEffectsLeaseUntil: new Date(Date.now() - 1_000).toISOString(),
                  }
                : {}),
            },
          });
        Vault.prototype.reconcileSolanaBroadcast = async (input) => {
          expect(input).toEqual({
            signature: SIGNATURE,
            recentBlockhash: RECENT_BLOCKHASH,
            chainId: 101,
          });
          return testCase.outcome;
        };
        const response = await app.request(
          `/vault/${AGENT_ID}/transactions/${txId}/reconcile-solana`,
          { method: "POST" },
        );
        expect(response.status).toBe(testCase.status);
        const [row] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
        expect(row?.status).toBe(testCase.outcome);
        if (testCase.outcome === "confirmed" || testCase.outcome === "broadcast") {
          expect(readPayload(row?.actionPayload).recoveryEffectsState).toBe("complete");
          const completionAudits = await getDb()
            .select()
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.resourceId, txId),
                eq(auditEvents.action, "vault.sign.solana.effects_completed"),
              ),
            );
          expect(completionAudits).toHaveLength(1);
        }
      }
    } finally {
      Vault.prototype.reconcileSolanaBroadcast = originalReconcile;
    }
  });

  it("retries durable effects without re-querying Solana after reconciliation committed", async () => {
    const originalReconcile = Vault.prototype.reconcileSolanaBroadcast;
    let reconcileCalls = 0;
    Vault.prototype.reconcileSolanaBroadcast = async () => {
      reconcileCalls++;
      return "broadcast";
    };
    const txId = "solana-reconcile-effects-retry";
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "outcome_unknown",
        toAddress: RECIPIENT,
        value: "123",
        chainId: 101,
        txHash: SIGNATURE,
        actionType: "solana_transaction",
        actionPayload: {
          type: "solana_transaction",
          recoveryAnchor: true,
          recentBlockhash: RECENT_BLOCKHASH,
          recoveryEffectsState: "pending",
        },
      });
    try {
      // Force the effects phase to fail only after the authoritative RPC result
      // has already transitioned the row to broadcast.
      process.env.REDIS_URL = "redis://127.0.0.1:1";
      const first = await app.request(`/vault/${AGENT_ID}/transactions/${txId}/reconcile-solana`, {
        method: "POST",
      });
      expect(first.status).toBe(500);
      const [committed] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, txId));
      expect(committed.status).toBe("broadcast");
      expect(readPayload(committed.actionPayload).recoveryEffectsState).toBe("pending");

      delete process.env.REDIS_URL;
      Vault.prototype.reconcileSolanaBroadcast = async () => {
        throw new Error("a committed reconciliation must not be queried again");
      };
      const response = await app.request(
        `/vault/${AGENT_ID}/transactions/${txId}/reconcile-solana`,
        { method: "POST" },
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        ok: true,
        data: { txId, signature: SIGNATURE, status: "broadcast" },
      });
      const [row] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
      expect(readPayload(row.actionPayload).recoveryEffectsState).toBe("complete");
      expect(reconcileCalls).toBe(1);
    } finally {
      delete process.env.REDIS_URL;
      Vault.prototype.reconcileSolanaBroadcast = originalReconcile;
    }
  });
});

function readPayload(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}
