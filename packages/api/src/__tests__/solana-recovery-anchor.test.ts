import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  closeDb,
  getDb,
  policies,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { ExternalBroadcastOutcomeUnknownError } from "@stwd/vault";
import { eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `solana-recovery-tenant-${Date.now()}`;
const AGENT_ID = `solana-recovery-agent-${Date.now()}`;
const FROM = "7v54NWdBtkjuAFJrLGsS2SXnuk8nKam81mZJeeYxVFi9";
const RECIPIENT = "6TcyBfPdBt1kjsvDZLzmBFnuMaLWiTaAt4RjUr9VA5YD";
const SIGNATURE =
  "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
const WITHIN_CAP_V0_TRANSFER =
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQACBGa+fjMsekUzMr2dCn99sFX1xe8aBq2mbZizn7aBDEc6URw0oaLLUh3xa7JGuN6OeZfOI1x+drIqPXUDokgZ3YoDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcDAgAFAkANAwACAAkD6AMAAAAAAAADAgABDAIAAAB7AAAAAAAAAAA=";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", "solana-recovery-admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("requestId", crypto.randomUUID());
    await next();
  });
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
    await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    delete process.env.STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING;
    __resetAuditHmacKeyCacheForTests();
  });

  it("keeps the parsed-route anchor and submitted signature when final bookkeeping fails", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signSolanaTransaction.bind(context.vault);
    context.vault.signSolanaTransaction = async (request) => {
      const staged = await onlyRecoveryRow();
      expect(staged.status).toBe("approved");
      expect(staged.data).toBe(WITHIN_CAP_V0_TRANSFER);
      expect(staged.txHash).toBeNull();

      await request.onBroadcastPrepared?.(SIGNATURE);
      const checkpoint = await onlyRecoveryRow();
      expect(checkpoint.status).toBe("outcome_unknown");
      expect(checkpoint.txHash).toBe(SIGNATURE);
      return { signature: SIGNATURE, broadcast: true, chainId: request.chainId ?? 101 };
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
      context.vault.signSolanaTransaction = originalSign;
      await getDb().execute(
        sql.raw("ALTER TABLE transactions DROP CONSTRAINT test_reject_solana_finalization"),
      );
    }
  });

  it("keeps the blind-route broadcast row and success response when final audit fails", async () => {
    process.env.STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING = "true";
    const context = await import("../services/context");
    const originalSign = context.vault.signSolanaTransaction.bind(context.vault);
    context.vault.signSolanaTransaction = async (request) => {
      const staged = await onlyRecoveryRow();
      expect(staged.status).toBe("approved");
      expect(staged.data).toBe("not-a-solana-transaction");
      expect(staged.actionPayload).toMatchObject({ blindSigned: true, recoveryAnchor: true });

      await request.onBroadcastPrepared?.(SIGNATURE);
      const checkpoint = await onlyRecoveryRow();
      expect(checkpoint.status).toBe("outcome_unknown");
      expect(checkpoint.txHash).toBe(SIGNATURE);

      process.env.STEWARD_AUDIT_HMAC_KEY = "too-weak";
      __resetAuditHmacKeyCacheForTests();
      return { signature: SIGNATURE, broadcast: true, chainId: request.chainId ?? 101 };
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
        data: { signature: SIGNATURE, broadcast: true },
      });
      const surviving = await onlyRecoveryRow();
      expect(surviving.status).toBe("broadcast");
      expect(surviving.txHash).toBe(SIGNATURE);
      expect(surviving.data).toBe("not-a-solana-transaction");
    } finally {
      context.vault.signSolanaTransaction = originalSign;
      process.env.STEWARD_AUDIT_HMAC_KEY =
        "solana-recovery-anchor-audit-hmac-key-with-more-than-32-bytes";
      __resetAuditHmacKeyCacheForTests();
    }
  });

  it("returns a non-retryable 202 with the durable hash when confirmation is ambiguous", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signSolanaTransaction.bind(context.vault);
    context.vault.signSolanaTransaction = async (request) => {
      expect((await onlyRecoveryRow()).status).toBe("approved");
      await request.onBroadcastPrepared?.(SIGNATURE);
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
    } finally {
      context.vault.signSolanaTransaction = originalSign;
    }
  });
});
