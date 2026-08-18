import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import {
  agents,
  closeDb,
  executionAuthorizationNonces,
  getDb,
  policies,
  tenants,
  walletOperationIdempotency,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { ExternalBroadcastOutcomeUnknownError, Vault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { TransactionReceipt } from "viem";
import * as auditService from "../services/audit";
import type { AppVariables } from "../services/context";
import * as walletIdempotencyService from "../services/wallet-operation-idempotency";

const tenantId = `broadcast-idem-tenant-${Date.now()}`;
const agentId = `broadcast-idem-agent-${Date.now()}`;
const recipient = "0x1111111111111111111111111111111111111111";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "broadcast-idem-owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

function post(app: Awaited<ReturnType<typeof makeApp>>, path: string, key: string, body: unknown) {
  return app.request(`/vault/${agentId}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify(body),
  });
}

describe("wallet broadcast idempotency route fence", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_DB_MODE = "pglite";
    process.env.STEWARD_MASTER_PASSWORD = "broadcast-idem-master-password";
    process.env.STEWARD_JWT_SECRET = "broadcast-idem-jwt-secret-with-enough-entropy-0123456789";
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "e".repeat(64);
    process.env.STEWARD_AUDIT_HMAC_KEY = "d".repeat(64);
    process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING = "true";
    delete process.env.REDIS_URL;
    delete process.env.REDIS_REQUIRED;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({
      id: tenantId,
      name: "Broadcast idempotency",
      apiKeyHash: "broadcast-idem-hash",
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Broadcast idempotency agent",
      walletAddress: "0x2222222222222222222222222222222222222222",
    });
    await getDb()
      .insert(policies)
      .values([
        {
          id: `${agentId}-addresses`,
          agentId,
          type: "approved-addresses",
          enabled: true,
          config: { mode: "whitelist", addresses: [recipient] },
        },
        {
          id: `${agentId}-threshold`,
          agentId,
          type: "auto-approve-threshold",
          enabled: true,
          config: { threshold: "100" },
        },
      ]);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    delete process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING;
  });

  test("malformed broadcast keys fail as 400 before signing", async () => {
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("not-used");
    try {
      const app = await makeApp();
      const response = await post(app, "/sign", "short", {
        to: recipient,
        value: "1",
        data: "0x12345678",
        chainId: 8453,
        broadcast: true,
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        ok: false,
        error: "Invalid Idempotency-Key header",
      });
      expect(signSpy).not.toHaveBeenCalled();
    } finally {
      signSpy.mockRestore();
    }
  });

  test("known sign broadcast replays even when its success audit fails", async () => {
    const hash = `0x${"ab".repeat(32)}`;
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue(hash);
    const originalAudit = auditService.writeAuditEvent;
    const auditSpy = spyOn(auditService, "writeAuditEvent").mockImplementation(async (event) => {
      if (event.action === "vault.sign") throw new Error("audit unavailable after broadcast");
      return originalAudit(event);
    });
    try {
      const app = await makeApp();
      const request = { to: recipient, value: "1", chainId: 8453, broadcast: true };
      const first = await post(app, "/sign", "known-sign-broadcast", request);
      const firstBody = (await first.json()) as {
        ok: boolean;
        data: { txId: string; txHash: string };
      };
      expect(first.status).toBe(200);
      expect(firstBody.ok).toBe(true);
      expect(firstBody.data.txHash).toBe(hash);
      const authorizationsAfterFirst = await getDb().select().from(executionAuthorizationNonces);

      const replay = await post(app, "/sign", "known-sign-broadcast", request);
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(await replay.json()).toEqual(firstBody);
      expect(signSpy).toHaveBeenCalledTimes(1);
      expect(await getDb().select().from(executionAuthorizationNonces)).toHaveLength(
        authorizationsAfterFirst.length,
      );
    } finally {
      auditSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  test("an ambiguous sign failure becomes terminal submission_unknown", async () => {
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockRejectedValue(
      new Error("connection closed after submission"),
    );
    try {
      const app = await makeApp();
      const request = { to: recipient, value: "2", chainId: 8453, broadcast: true };
      const first = await post(app, "/sign", "unknown-sign-broadcast", request);
      expect(first.status).toBe(202);
      expect(await first.json()).toMatchObject({
        ok: false,
        data: { status: "submission_unknown" },
      });
      const replay = await post(app, "/sign", "unknown-sign-broadcast", request);
      expect(replay.status).toBe(202);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(signSpy).toHaveBeenCalledTimes(1);

      const rows = await getDb()
        .select({ status: walletOperationIdempotency.status })
        .from(walletOperationIdempotency)
        .where(eq(walletOperationIdempotency.operation, "vault.sign.broadcast"));
      expect(rows.map((row) => row.status)).toContain("submission_unknown");
    } finally {
      signSpy.mockRestore();
    }
  });

  test("receipt reconciliation makes an outcome_unknown idempotent replay current", async () => {
    const hash = `0x${"bc".repeat(32)}` as const;
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockRejectedValue(
      new ExternalBroadcastOutcomeUnknownError(hash),
    );
    try {
      const app = await makeApp();
      const request = { to: recipient, value: "3", chainId: 8453, broadcast: true };
      const first = await post(app, "/sign", "receipt-reconciled-sign", request);
      expect(first.status).toBe(202);
      expect(await first.json()).toMatchObject({
        ok: false,
        data: { txHash: hash, reconciliationRequired: true },
      });

      const receipt: TransactionReceipt = {
        blockHash: `0x${"01".repeat(32)}`,
        blockNumber: 100n,
        contractAddress: null,
        cumulativeGasUsed: 21_000n,
        effectiveGasPrice: 1n,
        from: "0x2222222222222222222222222222222222222222",
        gasUsed: 21_000n,
        logs: [],
        logsBloom: `0x${"00".repeat(256)}`,
        status: "success",
        to: recipient,
        transactionHash: hash,
        transactionIndex: 0,
        type: "legacy",
      };
      const { pollBroadcastTransactionReceipts } = await import(
        "../services/transaction-receipt-poller"
      );
      const summary = await pollBroadcastTransactionReceipts({
        clientFactory: () => ({
          getTransactionReceipt: async () => receipt,
          getBlockNumber: async () => 100n,
        }),
      });
      expect(summary.confirmed).toBe(1);

      const replay = await post(app, "/sign", "receipt-reconciled-sign", request);
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(await replay.json()).toEqual({
        ok: true,
        data: { txId: expect.any(String), txHash: hash, status: "confirmed" },
      });
      expect(signSpy).toHaveBeenCalledTimes(1);
    } finally {
      signSpy.mockRestore();
    }
  });

  test("known hash with failed ledger completion returns reconciliation-required 202", async () => {
    const hash = `0x${"ef".repeat(32)}`;
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue(hash);
    const completionSpy = spyOn(
      walletIdempotencyService,
      "completeWalletOperation",
    ).mockRejectedValue(new Error("ledger completion unavailable"));
    try {
      const app = await makeApp();
      const request = { to: recipient, value: "4", chainId: 8453, broadcast: true };
      const response = await post(app, "/sign", "reconcile-sign-broadcast", request);
      expect(response.status).toBe(202);
      expect(await response.json()).toEqual({
        ok: true,
        data: {
          txId: expect.any(String),
          txHash: hash,
          status: "accepted_reconciliation_required",
        },
      });
      expect(signSpy).toHaveBeenCalledTimes(1);

      const replay = await post(app, "/sign", "reconcile-sign-broadcast", request);
      expect(replay.status).toBe(200);
      expect(await replay.json()).toMatchObject({
        ok: true,
        data: { txHash: hash, status: "broadcast" },
      });
      expect(signSpy).toHaveBeenCalledTimes(1);
    } finally {
      completionSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  test("known transfer broadcast survives post-broadcast audit failure and replays", async () => {
    const hash = `0x${"cd".repeat(32)}`;
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    });
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue(hash);
    const originalAudit = auditService.writeAuditEvent;
    const auditSpy = spyOn(auditService, "writeAuditEvent").mockImplementation(async (event) => {
      if (event.action === "wallet_action.transfer.succeeded") {
        throw new Error("audit unavailable after transfer broadcast");
      }
      return originalAudit(event);
    });
    try {
      const app = await makeApp();
      const request = { to: recipient, value: "3", chainId: 8453, broadcast: true };
      const first = await post(app, "/actions/transfer", "known-transfer-broadcast", request);
      const firstBody = (await first.json()) as {
        ok: boolean;
        data: { id: string; txHash: string };
      };
      expect(first.status).toBe(200);
      expect(firstBody.ok).toBe(true);
      expect(firstBody.data.txHash).toBe(hash);

      const replay = await post(app, "/actions/transfer", "known-transfer-broadcast", request);
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(await replay.json()).toEqual(firstBody);
      expect(signSpy).toHaveBeenCalledTimes(1);
    } finally {
      auditSpy.mockRestore();
      signSpy.mockRestore();
      rpcSpy.mockRestore();
    }
  });
});
