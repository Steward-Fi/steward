import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { agents, approvalQueue, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const TENANT_ID = `userop-tenant-${Date.now()}`;
const AGENT_ID = `userop-agent-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const BLOCKED = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_PRIVATE_KEY = `0x${"1".repeat(64)}`;
const TEST_WALLET_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";

const baseUserOperation = {
  sender: ALLOWED,
  nonce: "0",
  callData: "0x",
  verificationGasLimit: "100000",
  callGasLimit: "100000",
  preVerificationGas: "21000",
  maxPriorityFeePerGas: "1000000",
  maxFeePerGas: "2000000",
};

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault user operation signing", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-user-operation-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "vault-user-operation-audit-hmac-key-with-enough-entropy";
    process.env.STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING = "true";
    process.env.STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "User Operation Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "User Operation Agent",
      walletAddress: ALLOWED,
    });
    await getDb()
      .insert(policies)
      .values({
        id: "userop-approved-recipients",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED], mode: "whitelist" },
      });
    await new Vault({ masterPassword: process.env.STEWARD_MASTER_PASSWORD ?? "" }).importKey(
      TENANT_ID,
      AGENT_ID,
      TEST_PRIVATE_KEY,
      "evm",
    );
    app = await makeApp();
  }, 120_000);

  beforeEach(() => {
    dispatchWebhookMock.mockClear();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING;
    delete process.env.STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING;
  });

  it("fails closed for user operation signing even when the unsafe flag is enabled", async () => {
    const missingPolicyMetadata = await app.request(`/vault/${AGENT_ID}/sign-user-operation`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        userOperation: baseUserOperation,
        chainId: 8453,
      }),
    });
    expect(missingPolicyMetadata.status).toBe(403);
    const missingPolicyBody = (await missingPolicyMetadata.json()) as {
      ok: boolean;
      error?: string;
    };
    expect(missingPolicyBody.ok).toBe(false);
    expect(missingPolicyBody.error).toContain("User operation signing is disabled");
    expect(missingPolicyBody.error).toContain("callData decoding");

    const invalidUserOperation = await app.request(`/vault/${AGENT_ID}/sign-user-operation`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        userOperation: { ...baseUserOperation, callData: "not-hex" },
        chainId: 8453,
        to: ALLOWED,
        value: "0",
      }),
    });
    expect(invalidUserOperation.status).toBe(403);
    const invalidUserOperationBody = (await invalidUserOperation.json()) as {
      ok: boolean;
      error?: string;
    };
    expect(invalidUserOperationBody.ok).toBe(false);
    expect(invalidUserOperationBody.error).toContain("User operation signing is disabled");
  });

  it("does not let top-level user operation policy metadata approve different calldata", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-user-operation`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        userOperation: { ...baseUserOperation, callData: "0xdeadbeef" },
        chainId: 8453,
        to: ALLOWED,
        value: "0",
      }),
    });

    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
    };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("User operation signing is disabled");
  });

  it("fails closed for EIP-7702 authorizations even when the unsafe flag is enabled", async () => {
    const invalidResponse = await app.request(`/vault/${AGENT_ID}/sign-authorization`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contractAddress: "not-an-address",
        chainId: 8453,
        nonce: 0,
      }),
    });
    expect(invalidResponse.status).toBe(403);
    const invalidBody = (await invalidResponse.json()) as { ok: boolean; error?: string };
    expect(invalidBody.ok).toBe(false);
    expect(invalidBody.error).toContain("EIP-7702 authorization signing is disabled");

    const rejectedResponse = await app.request(`/vault/${AGENT_ID}/sign-authorization`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contractAddress: ALLOWED,
        chainId: 8453,
        nonce: 0,
      }),
    });
    expect(rejectedResponse.status).toBe(403);
    const rejectedBody = (await rejectedResponse.json()) as {
      ok: boolean;
      error?: string;
    };
    expect(rejectedBody.ok).toBe(false);
    expect(rejectedBody.error).toContain("EIP-7702 authorization signing is disabled");
  });

  it("lists and gets first-class transaction records with filters", async () => {
    const txId = `tx-list-${Date.now()}`;
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "broadcast",
        toAddress: ALLOWED,
        value: "42",
        data: "0x",
        chainId: 8453,
        txHash: "0xfeedface",
        actionType: "test_action",
        actionPayload: { type: "test_action", externalId: "external-1" },
        policyResults: [],
        signedAt: new Date(),
      });

    const listResponse = await app.request(
      `/vault/${AGENT_ID}/transactions?status=broadcast&actionType=test_action&limit=5`,
    );
    expect(listResponse.status).toBe(200);
    const listBody = (await listResponse.json()) as {
      ok: boolean;
      data: {
        transactions: Array<{
          id: string;
          actionType: string | null;
          actionPayload: Record<string, unknown> | null;
        }>;
        limit: number;
        offset: number;
      };
    };
    expect(listBody.ok).toBe(true);
    expect(listBody.data.limit).toBe(5);
    expect(listBody.data.transactions.some((tx) => tx.id === txId)).toBe(true);
    const listed = listBody.data.transactions.find((tx) => tx.id === txId);
    expect(listed?.actionType).toBe("test_action");
    expect(listed?.actionPayload).toMatchObject({ externalId: "external-1" });

    const getResponse = await app.request(`/vault/${AGENT_ID}/transactions/${txId}`);
    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as {
      ok: boolean;
      data: { id: string; txHash?: string; request: { value: string } };
    };
    expect(getBody.ok).toBe(true);
    expect(getBody.data.id).toBe(txId);
    expect(getBody.data.txHash).toBe("0xfeedface");
    expect(getBody.data.request.value).toBe("42");

    const invalidFilterResponse = await app.request(
      `/vault/${AGENT_ID}/transactions?status=unknown`,
    );
    expect(invalidFilterResponse.status).toBe(400);
  });

  it("updates transaction lifecycle state and dispatches catalog webhooks", async () => {
    const txId = `lifecycle-${Date.now()}`;
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "broadcast",
        toAddress: ALLOWED,
        value: "0",
        data: "0x",
        chainId: 8453,
        txHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        actionPayload: { referenceId: "customer-ref-1" },
        policyResults: [],
      });

    const confirmedResponse = await app.request(
      `/vault/${AGENT_ID}/transactions/${txId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          type: "transaction.confirmed",
          txHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
          blockNumber: 123,
          confirmations: 2,
        }),
      },
    );
    expect(confirmedResponse.status).toBe(200);
    const confirmedBody = (await confirmedResponse.json()) as {
      data: { id: string; status: string; txHash: string; confirmedAt?: string };
    };
    expect(confirmedBody.data.status).toBe("confirmed");
    expect(confirmedBody.data.confirmedAt).toBeTruthy();
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "transaction.confirmed",
      expect.objectContaining({
        txId,
        wallet_id: AGENT_ID,
        transaction_id: txId,
        txHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        transaction_hash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        chainId: 8453,
        caip2: "eip155:8453",
        status: "confirmed",
        blockNumber: 123,
        confirmations: 2,
        reference_id: "customer-ref-1",
      }),
    );

    dispatchWebhookMock.mockClear();
    const replacementTxId = `${txId}-replacement`;
    await getDb()
      .insert(transactions)
      .values({
        id: replacementTxId,
        agentId: AGENT_ID,
        status: "broadcast",
        toAddress: ALLOWED,
        value: "0",
        data: "0x",
        chainId: 8453,
        txHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        actionPayload: { referenceId: "customer-ref-replace" },
        policyResults: [],
      });
    const replacedResponse = await app.request(
      `/vault/${AGENT_ID}/transactions/${replacementTxId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          type: "transaction.replaced",
          replacementTxHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
          reason: "repriced",
        }),
      },
    );
    expect(replacedResponse.status).toBe(200);
    const replacedBody = (await replacedResponse.json()) as {
      data: { status: string; txHash: string };
    };
    expect(replacedBody.data.status).toBe("broadcast");
    expect(replacedBody.data.txHash).toBe(
      "0x2222222222222222222222222222222222222222222222222222222222222222",
    );
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "transaction.replaced",
      expect.objectContaining({
        txId: replacementTxId,
        previousTxHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        replacementTxHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        transaction_hash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        caip2: "eip155:8453",
        status: "broadcast",
        reason: "repriced",
        reference_id: "customer-ref-replace",
      }),
    );

    dispatchWebhookMock.mockClear();
    const pendingResponse = await app.request(`/vault/${AGENT_ID}/transactions/${txId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "transaction.still_pending", reason: "slow-confirmation" }),
    });
    expect(pendingResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "transaction.still_pending",
      expect.objectContaining({
        txId,
        transaction_id: txId,
        wallet_id: AGENT_ID,
        caip2: "eip155:8453",
        transaction_request: expect.objectContaining({
          to: ALLOWED,
          value: "0",
          data: "0x",
          chainId: 8453,
        }),
      }),
    );

    dispatchWebhookMock.mockClear();
    const fundsTxId = `${txId}-funds`;
    await getDb()
      .insert(transactions)
      .values({
        id: fundsTxId,
        agentId: AGENT_ID,
        status: "broadcast",
        toAddress: ALLOWED,
        value: "1000000000000000000",
        data: "0x",
        chainId: 8453,
        txHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        actionPayload: { referenceId: "customer-ref-funds" },
        policyResults: [],
      });
    const depositResponse = await app.request(
      `/vault/${AGENT_ID}/transactions/${fundsTxId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          type: "wallet.funds_deposited",
          txHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
          amount: "1000000000000000000",
          sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          blockNumber: 456,
          confirmations: 3,
          mnemonic:
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
          privateKey: TEST_PRIVATE_KEY,
        }),
      },
    );
    expect(depositResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "wallet.funds_deposited",
      expect.objectContaining({
        wallet_id: AGENT_ID,
        transaction_id: fundsTxId,
        transaction_hash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        caip2: "eip155:8453",
        asset: { type: "native-token", address: null },
        amount: "1000000000000000000",
        sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        recipient: TEST_WALLET_ADDRESS,
        block: { number: 456 },
        confirmations: 3,
        reference_id: "customer-ref-funds",
      }),
    );
    const depositDispatchPayloads = JSON.stringify(dispatchWebhookMock.mock.calls);
    expect(depositDispatchPayloads).not.toContain(TEST_PRIVATE_KEY);
    expect(depositDispatchPayloads).not.toContain("abandon abandon");

    dispatchWebhookMock.mockClear();
    const withdrawResponse = await app.request(
      `/vault/${AGENT_ID}/transactions/${fundsTxId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          type: "wallet.funds_withdrawn",
          txHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
          recipient: "0xcccccccccccccccccccccccccccccccccccccccc",
          secret: "should-not-dispatch",
        }),
      },
    );
    expect(withdrawResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "wallet.funds_withdrawn",
      expect.objectContaining({
        wallet_id: AGENT_ID,
        transaction_id: fundsTxId,
        transaction_hash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        caip2: "eip155:8453",
        amount: "1000000000000000000",
        sender: TEST_WALLET_ADDRESS,
        recipient: "0xcccccccccccccccccccccccccccccccccccccccc",
        reference_id: "customer-ref-funds",
      }),
    );
    const fundsDispatchPayloads = JSON.stringify(dispatchWebhookMock.mock.calls);
    expect(fundsDispatchPayloads).not.toContain("should-not-dispatch");
    expect(fundsDispatchPayloads).not.toContain(TEST_PRIVATE_KEY);
    expect(fundsDispatchPayloads).not.toContain("abandon abandon");

    const badResponse = await app.request(
      `/vault/${AGENT_ID}/transactions/${replacementTxId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: "transaction.replaced" }),
      },
    );
    expect(badResponse.status).toBe(400);
  });

  it("dispatches user operation lifecycle webhooks from transaction lifecycle updates", async () => {
    const txId = `userop-lifecycle-${Date.now()}`;
    const userOperationHash = `0x${"3".repeat(64)}`;
    const txHash = `0x${"4".repeat(64)}`;
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "broadcast",
        toAddress: ALLOWED,
        value: "0",
        data: "0x",
        chainId: 8453,
        txHash,
        actionType: "user_operation",
        actionPayload: {
          type: "user_operation",
          entryPoint: "0x0000000071727de22e5e9d8baf0edac6f37da032",
          sender: ALLOWED,
          userOperationHash,
        },
        policyResults: [],
      });

    const confirmedResponse = await app.request(
      `/vault/${AGENT_ID}/transactions/${txId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          type: "transaction.confirmed",
          txHash,
          blockNumber: 456,
          confirmations: 3,
        }),
      },
    );
    expect(confirmedResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "user_operation.completed",
      expect.objectContaining({
        wallet_id: AGENT_ID,
        transaction_id: txId,
        transaction_hash: txHash,
        user_operation_hash: userOperationHash,
        caip2: "eip155:8453",
        status: "completed",
        entry_point: "0x0000000071727de22e5e9d8baf0edac6f37da032",
        sender: ALLOWED,
        blockNumber: 456,
        confirmations: 3,
      }),
    );

    dispatchWebhookMock.mockClear();
    const failedResponse = await app.request(`/vault/${AGENT_ID}/transactions/${txId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        type: "transaction.provider_error",
        txHash,
        error: "bundler rejected receipt",
      }),
    });
    expect(failedResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "user_operation.failed",
      expect.objectContaining({
        wallet_id: AGENT_ID,
        transaction_id: txId,
        transaction_hash: txHash,
        user_operation_hash: userOperationHash,
        caip2: "eip155:8453",
        status: "failed",
        error: "bundler rejected receipt",
      }),
    );
  });

  it("validates and policy-checks wallet_sendCalls-style batch actions", async () => {
    const invalidResponse = await app.request(`/vault/${AGENT_ID}/actions/send-calls`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ calls: [], chainId: 8453 }),
    });
    expect(invalidResponse.status).toBe(400);
    const invalidBody = (await invalidResponse.json()) as { ok: boolean; error?: string };
    expect(invalidBody.ok).toBe(false);
    expect(invalidBody.error).toContain("calls must be a non-empty array");

    const rejectedResponse = await app.request(`/vault/${AGENT_ID}/actions/send-calls`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chainId: 8453,
        broadcast: false,
        calls: [
          { to: ALLOWED, value: "1000" },
          { to: BLOCKED, value: "2000" },
        ],
      }),
    });
    expect(rejectedResponse.status).toBe(403);
    const rejectedBody = (await rejectedResponse.json()) as {
      ok: boolean;
      data: {
        id: string;
        type: string;
        status: string;
        totalValue: string;
        policyResults: Array<{ callIndex?: number; passed: boolean }>;
      };
      error?: string;
    };
    expect(rejectedBody.ok).toBe(false);
    expect(rejectedBody.error).toContain("Batch calls rejected by policy");
    expect(rejectedBody.data.type).toBe("send_calls");
    expect(rejectedBody.data.status).toBe("rejected");
    expect(rejectedBody.data.totalValue).toBe("3000");
    expect(rejectedBody.data.policyResults.some((result) => result.callIndex === 1)).toBe(true);

    const [tx] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, rejectedBody.data.id));
    expect(tx.status).toBe("rejected");
    expect(tx.actionType).toBe("send_calls");
    expect(tx.actionPayload).toMatchObject({
      type: "send_calls",
      totalValue: "3000",
      broadcast: false,
    });
  });

  it("dispatches intent.created when wallet_sendCalls requires manual approval", async () => {
    const thresholdPolicyId = `intent-threshold-${Date.now()}`;
    await getDb()
      .insert(policies)
      .values({
        id: thresholdPolicyId,
        agentId: AGENT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "1" },
      });
    try {
      const response = await app.request(`/vault/${AGENT_ID}/actions/send-calls`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chainId: 8453,
          broadcast: false,
          referenceId: "manual-send-calls-ref",
          calls: [{ to: ALLOWED, value: "2" }],
        }),
      });
      expect(response.status).toBe(202);
      const body = (await response.json()) as {
        data: { id: string; status: string };
      };
      expect(body.data.status).toBe("pending_approval");
      expect(dispatchWebhookMock).toHaveBeenCalledWith(
        TENANT_ID,
        AGENT_ID,
        "intent.created",
        expect.objectContaining({
          intent_id: body.data.id,
          transaction_id: body.data.id,
          wallet_id: AGENT_ID,
          action_type: "wallet_action.send_calls",
          status: "pending",
          reference_id: "manual-send-calls-ref",
        }),
      );
    } finally {
      await getDb().delete(policies).where(eq(policies.id, thresholdPolicyId));
      dispatchWebhookMock.mockClear();
    }
  });

  it("does not replay pending send-calls approvals as normal transactions", async () => {
    const succeededTxId = `send-calls-succeeded-${Date.now()}`;
    await getDb()
      .insert(transactions)
      .values({
        id: succeededTxId,
        agentId: AGENT_ID,
        status: "pending",
        toAddress: ALLOWED,
        value: "0",
        data: "0x",
        chainId: 8453,
        actionType: "send_calls",
        actionPayload: {
          type: "send_calls",
          calls: [{ to: ALLOWED, value: "0" }],
          totalValue: "0",
          broadcast: false,
          referenceId: "approve-send-calls-ref",
        },
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `approval-${succeededTxId}`,
        txId: succeededTxId,
        agentId: AGENT_ID,
        status: "pending",
      });

    const approveSuccessResponse = await app.request(
      `/vault/${AGENT_ID}/approve/${succeededTxId}`,
      { method: "POST" },
    );
    const approveSuccessBody = (await approveSuccessResponse.json()) as {
      ok: boolean;
      error?: string;
    };
    expect(approveSuccessResponse.status).toBe(403);
    expect(approveSuccessBody.ok).toBe(false);
    expect(approveSuccessBody.error).toContain("batch call actions is disabled");

    dispatchWebhookMock.mockClear();
    const rejectedTxId = `send-calls-rejected-${Date.now()}`;
    await getDb()
      .insert(transactions)
      .values({
        id: rejectedTxId,
        agentId: AGENT_ID,
        status: "pending",
        toAddress: ALLOWED,
        value: "0",
        data: "0x",
        chainId: 8453,
        actionType: "send_calls",
        actionPayload: {
          type: "send_calls",
          calls: [{ to: ALLOWED, value: "0" }],
          totalValue: "0",
          broadcast: false,
        },
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `approval-${rejectedTxId}`,
        txId: rejectedTxId,
        agentId: AGENT_ID,
        status: "pending",
      });

    const rejectResponse = await app.request(`/vault/${AGENT_ID}/reject/${rejectedTxId}`, {
      method: "POST",
    });
    expect(rejectResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "wallet_action.send_calls.rejected",
      { actionId: rejectedTxId },
    );
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "intent.rejected",
      expect.objectContaining({
        intent_id: rejectedTxId,
        action_type: "wallet_action.send_calls",
        status: "rejected",
      }),
    );
  });

  it("dispatches transfer-specific rejection webhooks", async () => {
    dispatchWebhookMock.mockClear();
    const rejectedTxId = `transfer-rejected-${Date.now()}`;
    await getDb()
      .insert(transactions)
      .values({
        id: rejectedTxId,
        agentId: AGENT_ID,
        status: "pending",
        toAddress: ALLOWED,
        value: "0",
        data: "0x",
        chainId: 8453,
        actionType: "transfer",
        actionPayload: {
          type: "transfer",
          token: "native",
          recipient: ALLOWED,
          amount: "0",
          broadcast: false,
        },
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `approval-${rejectedTxId}`,
        txId: rejectedTxId,
        agentId: AGENT_ID,
        status: "pending",
      });

    const rejectResponse = await app.request(`/vault/${AGENT_ID}/reject/${rejectedTxId}`, {
      method: "POST",
    });
    expect(rejectResponse.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "wallet_action.transfer.rejected",
      { actionId: rejectedTxId },
    );
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "intent.rejected",
      expect.objectContaining({
        intent_id: rejectedTxId,
        action_type: "wallet_action.transfer",
        status: "rejected",
      }),
    );
  });
});
