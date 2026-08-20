import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { ExternalBroadcastOutcomeUnknownError } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `wallet-actions-tenant-${Date.now()}`;
const OTHER_TENANT_ID = `wallet-actions-other-tenant-${Date.now()}`;
const AGENT_ID = `wallet-actions-agent-${Date.now()}`;
const AGENT_WITHOUT_ALLOWLIST_ID = `wallet-actions-no-allowlist-${Date.now()}`;
const SOLANA_AGENT_ID = `wallet-actions-solana-agent-${Date.now()}`;
const SOLANA_AGENT_WITHOUT_MINT_ID = `wallet-actions-solana-no-mint-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const BLOCKED = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN = "0x4200000000000000000000000000000000000006";
const ALLOWED_SOLANA = "7J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg";
const BLOCKED_SOLANA = "8J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg";
const SOLANA_MINT = "So11111111111111111111111111111111111111112";
const ORIGINAL_REDIS_URL = process.env.REDIS_URL;
const ORIGINAL_REDIS_REQUIRED = process.env.REDIS_REQUIRED;
const SERIALIZED_SPL_TRANSFER =
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAIF6UPMZDHYTBaZ84s4PYnN/eY1HN26Qb0JbdXSFq+/tZZh2lmTgEh2HN5KGa6apfFlq4jJQUkI4Gb/A5au2FTWSwR4o/Pr5Ke0sw7ZpMZJP/G4jcxjJ16HXZc5252A2hpABpuIV/6rgYT7aH9jRhjANdrEOdwa6ztVmKDwAAAAAAEG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jPWFfv8AqQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQEAgMBAAoMewAAAAAAAAAJ";

function expectedErc20TransferCalldata(recipient: string, amount: string) {
  return `0xa9059cbb${recipient.toLowerCase().replace(/^0x/, "").padStart(64, "0")}${BigInt(amount).toString(16).padStart(64, "0")}`;
}

async function makeApp(tenantId = TENANT_ID) {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", "wallet-actions-admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("wallet transfer actions", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    delete process.env.REDIS_URL;
    delete process.env.REDIS_REQUIRED;
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "wallet-actions-master-password";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Wallet Actions Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb()
      .insert(tenants)
      .values({
        id: OTHER_TENANT_ID,
        name: "Other Wallet Actions Tenant",
        apiKeyHash: `hash-${OTHER_TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(agents).values({
      id: AGENT_WITHOUT_ALLOWLIST_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Agent Without Allowlist",
      walletAddress: "0x0000000000000000000000000000000000000002",
    });
    await getDb().insert(agents).values({
      id: SOLANA_AGENT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Solana Agent",
      walletAddress: "9J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
    });
    await getDb().insert(agents).values({
      id: SOLANA_AGENT_WITHOUT_MINT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Solana Agent Without Mint Allowlist",
      walletAddress: "Aj9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
    });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-recipients",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED, TOKEN], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-token-transfer-selector",
        agentId: AGENT_ID,
        type: "contract-allowlist",
        enabled: true,
        config: {
          contracts: [
            {
              address: TOKEN,
              selectors: ["0xa9059cbb"],
              constraints: {
                "0xa9059cbb": {
                  recipientAllowlist: [ALLOWED],
                  maxAmount: "99",
                },
              },
            },
          ],
        },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "manual-approval-threshold",
        agentId: AGENT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-solana-recipient",
        agentId: SOLANA_AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED_SOLANA, SOLANA_MINT], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "solana-auto-approve-threshold",
        agentId: SOLANA_AGENT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-solana-recipient-without-mint",
        agentId: SOLANA_AGENT_WITHOUT_MINT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED_SOLANA], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "solana-without-mint-auto-approve-threshold",
        agentId: SOLANA_AGENT_WITHOUT_MINT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIGINAL_REDIS_URL;
    if (ORIGINAL_REDIS_REQUIRED === undefined) delete process.env.REDIS_REQUIRED;
    else process.env.REDIS_REQUIRED = ORIGINAL_REDIS_REQUIRED;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIGINAL_REDIS_URL;
  });

  it("quotes native transfers and records rejected transfer actions for status polling", async () => {
    const quoteResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer/quote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1000", chainId: 8453, broadcast: false }),
    });
    expect(quoteResponse.status).toBe(200);
    const quoteBody = (await quoteResponse.json()) as {
      ok: boolean;
      data: { type: string; token: string; request: { broadcast: boolean } };
    };
    expect(quoteBody.ok).toBe(true);
    expect(quoteBody.data.type).toBe("transfer");
    expect(quoteBody.data.token).toBe("native");
    expect(quoteBody.data.request.broadcast).toBe(false);

    const createResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: BLOCKED, amountWei: "1000", chainId: 8453, broadcast: false }),
    });
    expect(createResponse.status).toBe(403);
    const createBody = (await createResponse.json()) as {
      ok: boolean;
      data: { id: string; type: string; status: string; to: string };
    };
    expect(createBody.ok).toBe(false);
    expect(createBody.data.type).toBe("transfer");
    expect(createBody.data.status).toBe("rejected");
    expect(createBody.data.to).toBe(BLOCKED);

    const [tx] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, createBody.data.id));
    expect(tx.id).toBe(createBody.data.id);
    expect(tx.status).toBe("rejected");
    expect(tx.actionType).toBe("transfer");

    const statusResponse = await app.request(`/vault/${AGENT_ID}/actions/${createBody.data.id}`);
    expect(statusResponse.status).toBe(200);
    const statusBody = (await statusResponse.json()) as {
      ok: boolean;
      data: { id: string; status: string };
    };
    expect(statusBody.ok).toBe(true);
    expect(statusBody.data.id).toBe(createBody.data.id);
    expect(statusBody.data.status).toBe("rejected");

    const otherTenantApp = await makeApp(OTHER_TENANT_ID);
    const otherTenantStatusResponse = await otherTenantApp.request(
      `/vault/${AGENT_ID}/actions/${createBody.data.id}`,
    );
    expect(otherTenantStatusResponse.status).toBe(404);

    await getDb().insert(transactions).values({
      id: "legacy-sign-tx",
      agentId: AGENT_ID,
      status: "signed",
      toAddress: ALLOWED,
      value: "1000",
      chainId: 8453,
    });
    const legacyStatusResponse = await app.request(`/vault/${AGENT_ID}/actions/legacy-sign-tx`);
    expect(legacyStatusResponse.status).toBe(404);

    const pendingResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1000", chainId: 8453, broadcast: false }),
    });
    expect(pendingResponse.status).toBe(202);
    const pendingBody = (await pendingResponse.json()) as {
      ok: boolean;
      data: { id: string; status: string };
    };
    expect(pendingBody.ok).toBe(true);
    expect(pendingBody.data.status).toBe("pending_approval");

    const pendingStatusResponse = await app.request(
      `/vault/${AGENT_ID}/actions/${pendingBody.data.id}`,
    );
    expect(pendingStatusResponse.status).toBe(200);
    const pendingStatusBody = (await pendingStatusResponse.json()) as {
      ok: boolean;
      data: { status: string };
    };
    expect(pendingStatusBody.data.status).toBe("pending_approval");

    const signedActionId = "legacy-signed-transfer-action";
    await getDb()
      .insert(transactions)
      .values({
        id: signedActionId,
        agentId: AGENT_ID,
        status: "signed",
        toAddress: ALLOWED,
        value: "1000",
        chainId: 8453,
        actionType: "transfer",
        actionPayload: {
          type: "transfer",
          token: "native",
          broadcast: false,
          signedTx: "0xsigned-bearer-transaction",
        },
      });
    const signedStatusResponse = await app.request(`/vault/${AGENT_ID}/actions/${signedActionId}`);
    expect(signedStatusResponse.status).toBe(200);
    const signedStatusBody = (await signedStatusResponse.json()) as {
      ok: boolean;
      data: { status: string; signedTx?: string };
    };
    expect(signedStatusBody.ok).toBe(true);
    expect(signedStatusBody.data.status).toBe("signed");
    expect(signedStatusBody.data.signedTx).toBeUndefined();

    const confirmedActionId = "legacy-confirmed-transfer-action";
    const confirmedAt = new Date();
    await getDb()
      .insert(transactions)
      .values({
        id: confirmedActionId,
        agentId: AGENT_ID,
        status: "confirmed",
        toAddress: ALLOWED,
        value: "1000",
        chainId: 8453,
        actionType: "transfer",
        txHash: "0xconfirmed-transfer",
        confirmedAt,
        actionPayload: {
          type: "transfer",
          token: "native",
          recipient: ALLOWED,
          amount: "1000",
          broadcast: true,
        },
      });
    const confirmedStatusResponse = await app.request(
      `/vault/${AGENT_ID}/actions/${confirmedActionId}`,
    );
    expect(confirmedStatusResponse.status).toBe(200);
    const confirmedStatusBody = (await confirmedStatusResponse.json()) as {
      ok: boolean;
      data: { status: string; txHash?: string; confirmedAt?: string };
    };
    expect(confirmedStatusBody.ok).toBe(true);
    expect(confirmedStatusBody.data.status).toBe("confirmed");
    expect(confirmedStatusBody.data.txHash).toBe("0xconfirmed-transfer");
    expect(confirmedStatusBody.data.confirmedAt).toBe(confirmedAt.toISOString());
  });

  it("signs ERC20 transfer actions through selector-gated token contracts", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    const calldata = expectedErc20TransferCalldata(ALLOWED, "42");
    let signCalls = 0;

    context.vault.signTransaction = async (request, metadata) => {
      signCalls += 1;
      expect(request.agentId).toBe(AGENT_ID);
      expect(request.to).toBe(TOKEN);
      expect(request.value).toBe("0");
      expect(request.data).toBe(calldata);
      expect(request.chainId).toBe(8453);
      expect(request.gasLimit).toBe("65000");
      expect(request.broadcast).toBe(false);
      expect(metadata.status).toBe("signed");
      await getDb().insert(transactions).values({
        id: metadata.txId,
        agentId: request.agentId,
        status: "signed",
        toAddress: request.to,
        value: request.value,
        data: request.data,
        chainId: request.chainId,
      });
      return "0xsigned-erc20";
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED,
          token: TOKEN,
          value: "42",
          chainId: 8453,
          broadcast: false,
          referenceId: "erc20-transfer-success",
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: {
          id: string;
          token: string;
          to: string;
          value: string;
          status: string;
          signedTx?: string;
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("signed");
      expect(body.data.token).toBe(TOKEN);
      expect(body.data.to).toBe(ALLOWED);
      expect(body.data.value).toBe("42");
      expect(body.data.signedTx).toBe("0xsigned-erc20");

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(tx.status).toBe("signed");
      expect(tx.toAddress).toBe(TOKEN);
      expect(tx.value).toBe("0");
      expect(tx.data).toBe(calldata);
      const actionPayload = tx.actionPayload as {
        type: string;
        token: string;
        recipient: string;
        amount: string;
        broadcast: boolean;
        referenceId?: string;
        requestDigest?: string;
      };
      expect(actionPayload).toMatchObject({
        type: "transfer",
        token: TOKEN,
        recipient: ALLOWED,
        amount: "42",
        broadcast: false,
        referenceId: "erc20-transfer-success",
        requestDigest: expect.any(String),
      });

      for (const changed of [
        { value: "43" },
        { to: BLOCKED },
        { token: "native" },
        { chainId: 1 },
      ]) {
        const conflict = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            to: ALLOWED,
            token: TOKEN,
            value: "42",
            chainId: 8453,
            broadcast: false,
            referenceId: "erc20-transfer-success",
            ...changed,
          }),
        });
        expect(conflict.status).toBe(409);
      }
      expect(signCalls).toBe(1);

      const statusResponse = await app.request(`/vault/${AGENT_ID}/actions/${body.data.id}`);
      expect(statusResponse.status).toBe(200);
      const statusBody = (await statusResponse.json()) as {
        ok: boolean;
        data: { status: string; token: string; to: string; value: string; signedTx?: string };
      };
      expect(statusBody.ok).toBe(true);
      expect(statusBody.data.status).toBe("signed");
      expect(statusBody.data.token).toBe(TOKEN);
      expect(statusBody.data.to).toBe(ALLOWED);
      expect(statusBody.data.value).toBe("42");
      expect(statusBody.data.signedTx).toBeUndefined();
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("rejects ERC20 transfer actions without a constrained selector allowlist", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    context.vault.signTransaction = async () => {
      throw new Error("ERC20 rejection should not reach signing");
    };

    const response = await app.request(`/vault/${AGENT_WITHOUT_ALLOWLIST_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: ALLOWED,
        token: TOKEN,
        value: "1",
        chainId: 8453,
        broadcast: false,
      }),
    });
    try {
      expect(response.status).toBe(403);
      const body = (await response.json()) as {
        ok: boolean;
        error?: string;
        data?: { id: string; status: string; token: string; policyResults?: Array<unknown> };
      };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Transfer rejected by policy");
      expect(body.data?.status).toBe("rejected");
      expect(body.data?.token).toBe(TOKEN);
      expect(body.data?.policyResults).toEqual([
        expect.objectContaining({
          policyId: "erc20-transfer-contract-allowlist-required",
          passed: false,
        }),
      ]);

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data?.id ?? ""));
      expect(tx.status).toBe("rejected");
      expect(tx.toAddress).toBe(TOKEN);
      expect(tx.value).toBe("0");
      expect(tx.data).toBe(expectedErc20TransferCalldata(ALLOWED, "1"));
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("recovers a broadcast transfer by idempotency key before changed policy gates", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    const txHash = `0x${"ab".repeat(32)}`;
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      return txHash;
    };
    const key = `transfer-accounting-${crypto.randomUUID()}`;
    const request = (value = "42") =>
      new Request(`http://localhost/vault/${AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({
          to: ALLOWED,
          token: TOKEN,
          value,
          chainId: 8453,
          broadcast: true,
        }),
      });
    process.env.REDIS_URL = "redis://127.0.0.1:1";
    try {
      const first = await app.request(request());
      expect(first.status).toBe(503);
      const firstBody = (await first.json()) as {
        data: { txId: string; status: string; accounting: string };
      };
      expect(firstBody.data).toMatchObject({ status: "broadcast", accounting: "pending" });
      const [pending] = await getDb()
        .select({ actionPayload: transactions.actionPayload })
        .from(transactions)
        .where(eq(transactions.id, firstBody.data.txId));
      const occurredAt = (pending?.actionPayload as Record<string, unknown>)
        .recoveryEffectsOccurredAt;

      await getDb()
        .update(policies)
        .set({ config: { addresses: [], mode: "whitelist" } })
        .where(eq(policies.id, "approved-recipients"));
      const mismatch = await app.request(request("43"));
      expect(mismatch.status).toBe(409);
      expect(signCalls).toBe(1);

      delete process.env.REDIS_URL;
      const replay = await app.request(request());
      expect(replay.status).toBe(200);
      expect(await replay.json()).toMatchObject({
        ok: true,
        data: { id: firstBody.data.txId, txHash, status: "broadcast" },
      });
      expect(signCalls).toBe(1);
      const [complete] = await getDb()
        .select({ actionPayload: transactions.actionPayload })
        .from(transactions)
        .where(eq(transactions.id, firstBody.data.txId));
      expect(complete?.actionPayload).toMatchObject({ recoveryEffectsState: "complete" });
      expect((complete?.actionPayload as Record<string, unknown>).recoveryEffectsOccurredAt).toBe(
        occurredAt,
      );
    } finally {
      await getDb()
        .update(policies)
        .set({ config: { addresses: [ALLOWED, TOKEN], mode: "whitelist" } })
        .where(eq(policies.id, "approved-recipients"));
      context.vault.signTransaction = originalSignTransaction;
      if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
      else process.env.REDIS_URL = ORIGINAL_REDIS_URL;
    }
  });

  it("rejects ERC20 transfer actions above selector maxAmount", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: ALLOWED,
        token: TOKEN,
        value: "1000",
        chainId: 8453,
        broadcast: false,
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { status: string; token: string; policyResults?: Array<unknown> };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Transfer rejected by policy");
    expect(body.data?.status).toBe("rejected");
    expect(body.data?.token).toBe(TOKEN);
    expect(body.data?.policyResults).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "contract-allowlist",
          passed: false,
          reason: "Token amount 1000 exceeds selector maxAmount 99",
        }),
      ]),
    );
  });

  it("signs native Solana transfer actions through the existing Solana signing primitive", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);

    context.vault.signTransaction = async (request, metadata) => {
      expect(request.agentId).toBe(SOLANA_AGENT_ID);
      expect(request.to).toBe(ALLOWED_SOLANA);
      expect(request.value).toBe("123");
      expect(request.data).toBeUndefined();
      expect(request.chainId).toBe(101);
      expect(request.broadcast).toBe(false);
      expect(metadata.status).toBe("signed");
      await getDb().insert(transactions).values({
        id: metadata.txId,
        agentId: request.agentId,
        status: "signed",
        toAddress: request.to,
        value: request.value,
        data: request.data,
        chainId: request.chainId,
      });
      return "base64-signed-solana-transaction";
    };

    try {
      const response = await app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          value: "123",
          chainId: 101,
          broadcast: false,
          referenceId: "native-solana-transfer-success",
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: {
          id: string;
          chainId: number;
          token: string;
          to: string;
          value: string;
          status: string;
          signedTx?: string;
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("signed");
      expect(body.data.chainId).toBe(101);
      expect(body.data.token).toBe("native");
      expect(body.data.to).toBe(ALLOWED_SOLANA);
      expect(body.data.value).toBe("123");
      expect(body.data.signedTx).toBe("base64-signed-solana-transaction");

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(tx.status).toBe("signed");
      expect(tx.toAddress).toBe(ALLOWED_SOLANA);
      expect(tx.value).toBe("123");
      expect(tx.data).toBeNull();
      expect(tx.chainId).toBe(101);
      expect(tx.actionPayload).toMatchObject({
        type: "transfer",
        token: "native",
        recipient: ALLOWED_SOLANA,
        amount: "123",
        broadcast: false,
        referenceId: "native-solana-transfer-success",
        requestDigest: expect.any(String),
      });
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("rejects Solana transfer actions outside the recipient allowlist", async () => {
    const context = await import("../services/context");
    const originalSignTransaction = context.vault.signTransaction.bind(context.vault);
    context.vault.signTransaction = async () => {
      throw new Error("Solana rejection should not reach signing");
    };

    try {
      const response = await app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: BLOCKED_SOLANA,
          value: "123",
          chainId: 101,
          broadcast: false,
        }),
      });
      expect(response.status).toBe(403);
      const body = (await response.json()) as {
        ok: boolean;
        error?: string;
        data?: { status: string; token: string; policyResults?: Array<unknown> };
      };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Transfer rejected by policy");
      expect(body.data?.status).toBe("rejected");
      expect(body.data?.token).toBe("native");
      expect(body.data?.policyResults).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            policyId: "approved-solana-recipient",
            passed: false,
          }),
        ]),
      );
    } finally {
      context.vault.signTransaction = originalSignTransaction;
    }
  });

  it("signs SPL token transfer actions with recipient and mint allowlisted", async () => {
    const context = await import("../services/context");
    const originalBuildSplTransfer = context.vault.buildSolanaSplTransferTransaction.bind(
      context.vault,
    );
    const originalSignSolanaTransaction = context.vault.signSolanaTransaction.bind(context.vault);

    context.vault.buildSolanaSplTransferTransaction = async (request) => {
      expect(request.agentId).toBe(SOLANA_AGENT_ID);
      expect(request.tenantId).toBe(TENANT_ID);
      expect(request.to).toBe(ALLOWED_SOLANA);
      expect(request.token).toBe(SOLANA_MINT);
      expect(request.value).toBe("123");
      expect(request.chainId).toBe(101);
      return {
        transaction: SERIALIZED_SPL_TRANSFER,
        sourceTokenAccount: "source-token-account",
        destinationTokenAccount: "destination-token-account",
        mint: SOLANA_MINT,
        tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        decimals: 9,
      };
    };
    context.vault.signSolanaTransaction = async (request) => {
      expect(request.agentId).toBe(SOLANA_AGENT_ID);
      expect(request.tenantId).toBe(TENANT_ID);
      expect(request.transaction).toBe(SERIALIZED_SPL_TRANSFER);
      expect(request.chainId).toBe(101);
      expect(request.broadcast).toBe(false);
      expect(request.expectedTo).toBeUndefined();
      expect(request.expectedValue).toBeUndefined();
      return {
        signature: "base64-signed-spl-transfer-transaction",
        broadcast: false,
        chainId: request.chainId,
      };
    };

    try {
      const response = await app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          token: SOLANA_MINT,
          value: "123",
          chainId: 101,
          broadcast: false,
          referenceId: "spl-transfer-success",
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: {
          id: string;
          chainId: number;
          token: string;
          to: string;
          value: string;
          status: string;
          signedTx?: string;
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("signed");
      expect(body.data.chainId).toBe(101);
      expect(body.data.token).toBe(SOLANA_MINT);
      expect(body.data.to).toBe(ALLOWED_SOLANA);
      expect(body.data.value).toBe("123");
      expect(body.data.signedTx).toBe("base64-signed-spl-transfer-transaction");

      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(tx.status).toBe("signed");
      expect(tx.toAddress).toBe(ALLOWED_SOLANA);
      expect(tx.value).toBe("123");
      expect(tx.data).toBe(SERIALIZED_SPL_TRANSFER);
      expect(tx.chainId).toBe(101);
      expect(tx.actionPayload).toMatchObject({
        type: "transfer",
        token: SOLANA_MINT,
        recipient: ALLOWED_SOLANA,
        amount: "123",
        broadcast: false,
        referenceId: "spl-transfer-success",
        requestDigest: expect.any(String),
      });
    } finally {
      context.vault.buildSolanaSplTransferTransaction = originalBuildSplTransfer;
      context.vault.signSolanaTransaction = originalSignSolanaTransaction;
    }
  });

  it("anchors and durably replays an ambiguous SPL broadcast without resending", async () => {
    const context = await import("../services/context");
    const originalBuild = context.vault.buildSolanaSplTransferTransaction.bind(context.vault);
    const originalSign = context.vault.signSolanaTransaction.bind(context.vault);
    const signature =
      "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
    let signCalls = 0;
    let buildCalls = 0;
    let signalBuildStarted!: () => void;
    let releaseBuild!: () => void;
    const buildStarted = new Promise<void>((resolve) => {
      signalBuildStarted = resolve;
    });
    const buildRelease = new Promise<void>((resolve) => {
      releaseBuild = resolve;
    });
    context.vault.buildSolanaSplTransferTransaction = async () => {
      buildCalls += 1;
      signalBuildStarted();
      await buildRelease;
      return {
        transaction: SERIALIZED_SPL_TRANSFER,
        sourceTokenAccount: "source-token-account",
        destinationTokenAccount: "destination-token-account",
        mint: SOLANA_MINT,
        tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        decimals: 9,
      };
    };
    context.vault.signSolanaTransaction = async (request) => {
      signCalls += 1;
      await request.onBroadcastPrepared?.({
        signature,
        recentBlockhash: "11111111111111111111111111111111",
        blockhashKind: "recent",
      });
      throw new ExternalBroadcastOutcomeUnknownError(signature);
    };
    const request = (value = "123", referenceId?: string, sponsor = false) =>
      app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": "durable-spl" },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          token: SOLANA_MINT,
          value,
          chainId: 101,
          broadcast: true,
          referenceId,
          sponsor,
        }),
      });

    try {
      const firstPromise = request();
      await buildStarted;
      const concurrentReplayPromise = request();
      await Bun.sleep(25);
      expect(buildCalls).toBe(1);
      releaseBuild();
      const [first, concurrentReplay] = await Promise.all([firstPromise, concurrentReplayPromise]);
      const firstBody = await first.json();
      expect(first.status, JSON.stringify(firstBody)).toBe(202);
      expect(concurrentReplay.status).toBe(202);
      expect(firstBody).toMatchObject({
        ok: false,
        data: { txHash: signature, reconciliationRequired: true },
      });
      await getDb()
        .update(policies)
        .set({ enabled: false })
        .where(eq(policies.agentId, SOLANA_AGENT_ID));
      const replay = await request();
      expect(replay.status).toBe(202);
      expect(signCalls).toBe(1);
      expect(buildCalls).toBe(1);
      const mismatch = await request("124");
      expect(mismatch.status).toBe(409);
      const referenceMismatch = await request("123", "durable-spl-other-reference");
      expect(referenceMismatch.status).toBe(409);
      const sponsorshipMismatch = await request("123", undefined, true);
      expect(sponsorshipMismatch.status).toBe(409);
      expect(signCalls).toBe(1);
      expect(buildCalls).toBe(1);

      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.txHash, signature));
      expect(row.status).toBe("outcome_unknown");
      expect(row.actionType).toBe("transfer");
      expect(row.actionPayload).toMatchObject({
        type: "transfer",
        recoveryType: "solana_transaction",
        recoveryActionType: "transfer",
        token: SOLANA_MINT,
        recentBlockhash: "11111111111111111111111111111111",
      });
    } finally {
      await getDb()
        .update(policies)
        .set({ enabled: true })
        .where(eq(policies.agentId, SOLANA_AGENT_ID));
      context.vault.buildSolanaSplTransferTransaction = originalBuild;
      context.vault.signSolanaTransaction = originalSign;
    }
  });

  it("replays pending and rejected Solana transfers before mutable gates", async () => {
    const context = await import("../services/context");
    const originalBuild = context.vault.buildSolanaSplTransferTransaction.bind(context.vault);
    const originalSign = context.vault.signSolanaTransaction.bind(context.vault);
    let buildCalls = 0;
    context.vault.buildSolanaSplTransferTransaction = async () => {
      buildCalls += 1;
      return {
        transaction: SERIALIZED_SPL_TRANSFER,
        sourceTokenAccount: "source-token-account",
        destinationTokenAccount: "destination-token-account",
        mint: SOLANA_MINT,
        tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        decimals: 9,
      };
    };
    context.vault.signSolanaTransaction = async () => {
      throw new Error("pending/rejected Solana transfer must not reach signing");
    };
    const request = (agentId: string, key: string, value = "123") =>
      app.request(`/vault/${agentId}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          token: SOLANA_MINT,
          value,
          chainId: 101,
          broadcast: true,
        }),
      });

    try {
      await getDb()
        .update(policies)
        .set({ config: { threshold: "1" } })
        .where(eq(policies.id, "solana-auto-approve-threshold"));
      expect((await request(SOLANA_AGENT_ID, "pending-solana-transfer")).status).toBe(202);
      await getDb()
        .update(policies)
        .set({ enabled: false })
        .where(eq(policies.agentId, SOLANA_AGENT_ID));
      expect((await request(SOLANA_AGENT_ID, "pending-solana-transfer")).status).toBe(202);
      expect((await request(SOLANA_AGENT_ID, "pending-solana-transfer", "124")).status).toBe(409);

      expect((await request(SOLANA_AGENT_WITHOUT_MINT_ID, "rejected-solana-transfer")).status).toBe(
        403,
      );
      await getDb()
        .update(policies)
        .set({ enabled: false })
        .where(eq(policies.agentId, SOLANA_AGENT_WITHOUT_MINT_ID));
      expect((await request(SOLANA_AGENT_WITHOUT_MINT_ID, "rejected-solana-transfer")).status).toBe(
        403,
      );
      expect(
        (await request(SOLANA_AGENT_WITHOUT_MINT_ID, "rejected-solana-transfer", "124")).status,
      ).toBe(409);
      expect(buildCalls).toBe(2);
    } finally {
      await getDb()
        .update(policies)
        .set({ enabled: true })
        .where(eq(policies.agentId, SOLANA_AGENT_ID));
      await getDb()
        .update(policies)
        .set({ config: { threshold: "999" } })
        .where(eq(policies.id, "solana-auto-approve-threshold"));
      await getDb()
        .update(policies)
        .set({ enabled: true })
        .where(eq(policies.agentId, SOLANA_AGENT_WITHOUT_MINT_ID));
      context.vault.buildSolanaSplTransferTransaction = originalBuild;
      context.vault.signSolanaTransaction = originalSign;
    }
  });

  it("checkpoints native SOL before its lower-level broadcast and preserves the route payload", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    const signature =
      "5oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
    let signCalls = 0;
    context.vault.signTransaction = async (_request, metadata) => {
      signCalls += 1;
      await metadata.onSolanaBroadcastPrepared?.({
        signature,
        recentBlockhash: "11111111111111111111111111111111",
        blockhashKind: "recent",
      });
      throw new ExternalBroadcastOutcomeUnknownError(signature);
    };
    const request = () =>
      app.request(`/vault/${SOLANA_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": "durable-native-sol" },
        body: JSON.stringify({
          to: ALLOWED_SOLANA,
          value: "321",
          chainId: 101,
          broadcast: true,
        }),
      });

    try {
      expect((await request()).status).toBe(202);
      expect((await request()).status).toBe(202);
      expect(signCalls).toBe(1);
      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.txHash, signature));
      expect(row).toMatchObject({ status: "outcome_unknown", actionType: "transfer" });
      expect(row.actionPayload).toMatchObject({
        type: "transfer",
        token: "native",
        amount: "321",
        recoveryActionType: "transfer",
        recentBlockhash: "11111111111111111111111111111111",
      });
    } finally {
      context.vault.signTransaction = originalSign;
    }
  });

  it("rejects SPL token transfer actions when the mint is not allowlisted", async () => {
    const context = await import("../services/context");
    const originalBuildSplTransfer = context.vault.buildSolanaSplTransferTransaction.bind(
      context.vault,
    );
    const originalSignSolanaTransaction = context.vault.signSolanaTransaction.bind(context.vault);

    context.vault.buildSolanaSplTransferTransaction = async () => ({
      transaction: SERIALIZED_SPL_TRANSFER,
      sourceTokenAccount: "source-token-account",
      destinationTokenAccount: "destination-token-account",
      mint: SOLANA_MINT,
      tokenProgram: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      decimals: 9,
    });
    context.vault.signSolanaTransaction = async () => {
      throw new Error("SPL mint policy rejection should not reach signing");
    };

    try {
      const response = await app.request(
        `/vault/${SOLANA_AGENT_WITHOUT_MINT_ID}/actions/transfer`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            to: ALLOWED_SOLANA,
            token: SOLANA_MINT,
            value: "123",
            chainId: 101,
            broadcast: false,
          }),
        },
      );
      expect(response.status).toBe(403);
      const body = (await response.json()) as {
        ok: boolean;
        error?: string;
        data?: { status: string; token: string; policyResults?: Array<unknown> };
      };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Transfer rejected by policy");
      expect(body.data?.status).toBe("rejected");
      expect(body.data?.token).toBe(SOLANA_MINT);
      expect(body.data?.policyResults).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            policyId: "spl-transfer-mint-recipient-allowlist-required",
            passed: false,
          }),
        ]),
      );
    } finally {
      context.vault.buildSolanaSplTransferTransaction = originalBuildSplTransfer;
      context.vault.signSolanaTransaction = originalSignSolanaTransaction;
    }
  });
});
