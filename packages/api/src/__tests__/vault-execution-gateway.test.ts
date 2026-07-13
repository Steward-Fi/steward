import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import {
  agents,
  agentWallets,
  approvalQueue,
  auditEvents,
  closeDb,
  executionAuthorizationNonces,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import { executionPayloadDigestForEvmSign } from "../services/execution-authorization";

const TENANT_ID = `gateway-tenant-${Date.now()}`;
const AGENT_ID = `gateway-agent-${Date.now()}`;
const USER_ID = "00000000-0000-4000-8000-000000000123";
const ORIGINAL_REDIS_URL = process.env.REDIS_URL;
const ORIGINAL_REDIS_REQUIRED = process.env.REDIS_REQUIRED;

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", USER_ID);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault EVM execution gateway", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_DB_MODE = "pglite";
    process.env.STEWARD_MASTER_PASSWORD = "gateway-test-master-password";
    process.env.STEWARD_JWT_SECRET = "gateway-test-jwt-secret-with-enough-entropy-0123456789";
    process.env.STEWARD_AUDIT_HMAC_KEY = "b".repeat(64);
    process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING = "true";
    delete process.env.REDIS_URL;
    delete process.env.REDIS_REQUIRED;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Gateway Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(users).values({
      id: USER_ID,
      email: "gateway-owner@example.test",
    });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: TENANT_ID,
      role: "owner",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Gateway Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb()
      .insert(policies)
      .values({
        id: `${AGENT_ID}-approved-addresses`,
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: {
          mode: "whitelist",
          addresses: ["0x1111111111111111111111111111111111111111"],
        },
      });
  });

  afterAll(async () => {
    delete process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING;
    if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIGINAL_REDIS_URL;
    if (ORIGINAL_REDIS_REQUIRED === undefined) delete process.env.REDIS_REQUIRED;
    else process.env.REDIS_REQUIRED = ORIGINAL_REDIS_REQUIRED;
    await closeDb();
  });

  it("mints and consumes an execution authorization before primary EVM signing", async () => {
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      return "0xsigned";
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          data: "0x12345678",
          chainId: 8453,
          broadcast: false,
        }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);

      const nonceRows = await getDb()
        .select({ status: executionAuthorizationNonces.status })
        .from(executionAuthorizationNonces);
      expect(nonceRows).toEqual([{ status: "consumed" }]);

      const audits = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID));
      expect(audits.map((row) => row.action)).toContain("vault.execution_authorization.minted");
      expect(audits.map((row) => row.action)).toContain("vault.execution_authorization.consumed");
    } finally {
      signSpy.mockRestore();
    }
  });

  it("preserves the legacy Solana sign path without minting an EVM authorization", async () => {
    const beforeRows = await getDb().select().from(executionAuthorizationNonces);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      return "solana-signed";
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          data: "0x12345678",
          chainId: 101,
          broadcast: false,
        }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);

      const afterRows = await getDb().select().from(executionAuthorizationNonces);
      expect(afterRows).toHaveLength(beforeRows.length);
    } finally {
      signSpy.mockRestore();
    }
  });

  it("mints and consumes an execution authorization for primary EVM approval replay", async () => {
    const txId = "tx-gateway-approval-replay";
    const replayRequest = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      to: "0x1111111111111111111111111111111111111111",
      value: "1",
      data: "0x12345678",
      chainId: 8453,
      nonce: 7,
      gasLimit: "45000",
      broadcast: false,
      walletAddress: "0x0000000000000000000000000000000000000001",
    };
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "pending",
        toAddress: replayRequest.to,
        value: replayRequest.value,
        data: replayRequest.data,
        chainId: replayRequest.chainId,
        actionPayload: {
          type: "transaction",
          broadcast: false,
          nonce: replayRequest.nonce,
          gasLimit: replayRequest.gasLimit,
          walletAddress: replayRequest.walletAddress,
        },
        executionPayloadDigest: executionPayloadDigestForEvmSign(replayRequest),
        executionPolicyRevisionHash: "queued-policy-revision",
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `aq-${txId}`,
        txId,
        agentId: AGENT_ID,
        status: "pending",
        requestedByType: "agent",
        requestedById: AGENT_ID,
      });

    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      return "0xsigned";
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);

      const nonceRows = await getDb()
        .select({ status: executionAuthorizationNonces.status })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.requestId, txId));
      expect(nonceRows).toEqual([{ status: "consumed" }]);
    } finally {
      signSpy.mockRestore();
    }
  });

  // ── Fail-closed negative cases (BLOCKER 1 regression coverage) ──────────────
  // Every case proves the raw Vault.signTransaction signer is NEVER called for a
  // legacy/malformed primary-EVM approval row, and the request is rejected.

  const REPLAY_BASE = {
    tenantId: TENANT_ID,
    agentId: AGENT_ID,
    to: "0x1111111111111111111111111111111111111111",
    value: "1",
    data: "0x12345678",
    chainId: 8453,
    nonce: 7,
    gasLimit: "45000",
    broadcast: false,
    walletAddress: "0x0000000000000000000000000000000000000001",
  };

  async function seedPendingEvmApproval(
    txId: string,
    overrides: {
      actionPayload?: Record<string, unknown> | null;
      executionPayloadDigest?: string | null;
      executionPolicyRevisionHash?: string | null;
    },
  ) {
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "pending",
        toAddress: REPLAY_BASE.to,
        value: REPLAY_BASE.value,
        data: REPLAY_BASE.data,
        chainId: REPLAY_BASE.chainId,
        actionPayload:
          overrides.actionPayload === undefined
            ? {
                type: "transaction",
                broadcast: false,
                nonce: REPLAY_BASE.nonce,
                gasLimit: REPLAY_BASE.gasLimit,
                walletAddress: REPLAY_BASE.walletAddress,
              }
            : (overrides.actionPayload ?? undefined),
        executionPayloadDigest:
          overrides.executionPayloadDigest === undefined
            ? executionPayloadDigestForEvmSign(REPLAY_BASE)
            : (overrides.executionPayloadDigest ?? null),
        executionPolicyRevisionHash:
          overrides.executionPolicyRevisionHash === undefined
            ? "queued-policy-revision"
            : (overrides.executionPolicyRevisionHash ?? null),
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `aq-${txId}`,
        txId,
        agentId: AGENT_ID,
        status: "pending",
        requestedByType: "agent",
        requestedById: AGENT_ID,
      });
  }

  async function expectFailClosed(txId: string, expectedReason?: string) {
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      throw new Error("raw signer must not be called for fail-closed approval");
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await res.json();
      expect(res.status).toBe(409);
      expect(body.ok).toBe(false);
      // Raw signer NEVER reached.
      expect(signSpy).toHaveBeenCalledTimes(0);
      // No authorization nonce was minted for this fail-closed row.
      const nonceRows = await getDb()
        .select({ id: executionAuthorizationNonces.id })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.requestId, txId));
      expect(nonceRows).toHaveLength(0);
      // The pending approval remains pending (not silently approved).
      const [approval] = await getDb()
        .select({ status: approvalQueue.status })
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(approval?.status).toBe("pending");
      // A specific rejection audit was written with the expected reason. This
      // proves the audit contract holds (not just that signing was prevented).
      const rejectionAudits = await getDb()
        .select({ action: auditEvents.action, metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, txId));
      const rejection = rejectionAudits.find(
        (row) => row.action === "vault.execution_authorization.rejected",
      );
      expect(rejection, `a rejection audit must exist for ${txId}`).toBeDefined();
      if (expectedReason) {
        expect((rejection?.metadata as Record<string, unknown> | undefined)?.reason).toBe(
          expectedReason,
        );
      }
    } finally {
      signSpy.mockRestore();
    }
  }

  it("fails closed when the stored execution payload digest is null (legacy row)", async () => {
    const txId = "tx-fail-null-digest";
    await seedPendingEvmApproval(txId, { executionPayloadDigest: null });
    await expectFailClosed(txId, "missing_stored_execution_payload_digest");
  });

  it("fails closed when the stored policy revision hash is null (legacy row)", async () => {
    const txId = "tx-fail-null-policy-revision";
    await seedPendingEvmApproval(txId, { executionPolicyRevisionHash: null });
    await expectFailClosed(txId, "missing_stored_execution_policy_revision_hash");
  });

  it("fails closed when the transaction action payload is missing/malformed", async () => {
    const txId = "tx-fail-malformed-action-payload";
    // action_type null + non-transaction payload => getTransactionActionPayload
    // returns null => previously flipped isPrimaryEvmApproval=false and raw-signed.
    await seedPendingEvmApproval(txId, {
      actionPayload: { type: "not-a-transaction", broadcast: false },
    });
    await expectFailClosed(txId, "missing_or_malformed_transaction_action_payload");
  });

  it("fails closed when the stored digest mismatches the replay (payload mutation)", async () => {
    const txId = "tx-fail-digest-mutation";
    // Stored digest reflects nonce=7; mutate the queued action payload nonce to 99
    // so the recomputed replay digest no longer matches the immutable snapshot.
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: 99,
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
      // stored digest still bound to nonce=7
      executionPayloadDigest: executionPayloadDigestForEvmSign(REPLAY_BASE),
    });
    await expectFailClosed(txId, "stored_digest_mismatch");
  });

  // ── FINDING 1: strict transaction-action-payload validation ────────────────
  // Each stored payload is a well-typed `transaction` action with exactly ONE
  // malformed present field. Previously these were silently coerced/dropped
  // (mutating the approved intent) or threw deep in the shared normalizer with
  // no specific rejection audit. Now every one fails closed with the
  // malformed_transaction_action_payload reason, no nonce row, and zero raw
  // signer calls.

  it("fails closed on a string nonce in the action payload", async () => {
    const txId = "tx-fail-string-nonce";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: "7", // wrong type: string, not a number
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on an unsafe-integer nonce in the action payload", async () => {
    const txId = "tx-fail-unsafe-nonce";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: Number.MAX_SAFE_INTEGER + 1, // passes Number.isInteger, fails isSafeInteger
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a negative nonce in the action payload", async () => {
    const txId = "tx-fail-negative-nonce";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: -1,
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a wrong-type (non-boolean) broadcast in the action payload", async () => {
    const txId = "tx-fail-wrong-broadcast";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: "false", // wrong type: string, previously coerced to true
        nonce: REPLAY_BASE.nonce,
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a present-null broadcast in the action payload", async () => {
    const txId = "tx-fail-null-broadcast";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: null, // present null is not a boolean -> must fail closed
        nonce: REPLAY_BASE.nonce,
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a wrong-type gasLimit in the action payload", async () => {
    const txId = "tx-fail-wrong-gaslimit";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: REPLAY_BASE.nonce,
        gasLimit: 45000, // wrong type: number, must be a decimal uint string
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a wrong-type venue in the action payload", async () => {
    const txId = "tx-fail-wrong-venue";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: REPLAY_BASE.nonce,
        gasLimit: REPLAY_BASE.gasLimit,
        venue: { hostile: true }, // wrong type: object, must be a string
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a wrong-type walletAddress in the action payload", async () => {
    const txId = "tx-fail-wrong-wallet";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: REPLAY_BASE.nonce,
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: 12345, // wrong type: number, must be a string
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  // ── ROUND 3 / ITEM 1: present-null must fail closed (not be normalized away) ─
  // A PRESENT null for nonce/gasLimit/venue/walletAddress is distinct from an
  // absent key. The old validator used `x !== undefined && x !== null`, which
  // treated a present null as "absent" and silently dropped it, mutating the
  // digested intent without a rejection. The validator now distinguishes
  // absence from present-null via Object.hasOwn, so each of these fails closed:
  // 409 + malformed_transaction_action_payload audit + zero nonce rows + zero
  // raw signer calls (all asserted by expectFailClosed). Legitimately-minted
  // payloads never serialize explicit nulls for these fields (the
  // transactionActionPayload builder omits undefined/null keys and jsonb never
  // injects nulls), so these payloads can only be malformed/adversarial.

  it("fails closed on a present-null nonce in the action payload", async () => {
    const txId = "tx-fail-null-nonce";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: null, // present null must be rejected, not normalized to omitted
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a present-null gasLimit in the action payload", async () => {
    const txId = "tx-fail-null-gaslimit";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: REPLAY_BASE.nonce,
        gasLimit: null, // present null must be rejected, not normalized to omitted
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a present-null venue in the action payload", async () => {
    const txId = "tx-fail-null-venue";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: REPLAY_BASE.nonce,
        gasLimit: REPLAY_BASE.gasLimit,
        venue: null, // present null must be rejected, not normalized to omitted
        walletAddress: REPLAY_BASE.walletAddress,
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  it("fails closed on a present-null walletAddress in the action payload", async () => {
    const txId = "tx-fail-null-wallet";
    await seedPendingEvmApproval(txId, {
      actionPayload: {
        type: "transaction",
        broadcast: false,
        nonce: REPLAY_BASE.nonce,
        gasLimit: REPLAY_BASE.gasLimit,
        walletAddress: null, // present null must be rejected, not normalized to omitted
      },
    });
    await expectFailClosed(txId, "malformed_transaction_action_payload");
  });

  // ── FINDING 4: third-party-custody backend is not gateway-supported ────────────
  // The execution authorization is cryptographically bound to backend
  // "local-vault". An agent whose EVM wallet resolves to EXTERNAL custody (an
  // agent_wallets row with custody:"third-party" metadata and NO local chain key)
  // must be rejected BEFORE minting/consuming and BEFORE the third-party custody
  // provider is ever reached. Otherwise a local-vault-bound authorization could
  // authorize an third-party-custody execution.

  const EXTERNAL_AGENT_ID = `gateway-ext-agent-${Date.now()}`;

  async function seedExternalCustodyAgent() {
    await getDb().insert(agents).values({
      id: EXTERNAL_AGENT_ID,
      tenantId: TENANT_ID,
      name: "External Custody Agent",
      walletAddress: "0x00000000000000000000000000000000000000ff",
    });
    // Non-local-custody EVM wallet, NO encrypted_chain_keys row => the resolver
    // returns a non-local-vault backend. The custody discriminator "external" and
    // its metadata key "third-partyKey" matches the vault package,
    // aligning with isExternalKeyWalletMetadata string literals exactly.
    const custodyMetadata: Record<string, unknown> = {
      custody: "external",
      externalKey: {
        providerId: "test-kms",
        keyId: "key-ext-1",
        registeredAt: new Date().toISOString(),
        exportablePrivateKey: false,
        signingAvailability: "provider-signing",
      },
    };
    await getDb().insert(agentWallets).values({
      agentId: EXTERNAL_AGENT_ID,
      chainFamily: "evm",
      address: "0x00000000000000000000000000000000000000ff",
      metadata: custodyMetadata,
    });
    await getDb()
      .insert(policies)
      .values({
        id: `${EXTERNAL_AGENT_ID}-approved-addresses`,
        agentId: EXTERNAL_AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: {
          mode: "whitelist",
          addresses: ["0x1111111111111111111111111111111111111111"],
        },
      });
  }

  it("fails closed (third-party custody) on the direct /sign path before the provider is reached", async () => {
    await seedExternalCustodyAgent();
    // Spy on the raw signer; the third-party custody provider is only ever reached
    // THROUGH Vault.signTransaction, so proving signTransaction is never called
    // proves the provider is never reached.
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      throw new Error(
        "raw signer / third-party provider must not be reached for third-party custody",
      );
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${EXTERNAL_AGENT_ID}/sign`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "ext-custody-sign-1",
        },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          broadcast: true,
        }),
      });
      const body = await res.json();
      expect(res.status).toBe(409);
      expect(body.ok).toBe(false);
      expect(signSpy).toHaveBeenCalledTimes(0);
      // The direct /sign path uses a fresh random txId, so assert on the audit
      // reason keyed by the agent instead.
      const audits = await getDb()
        .select({ action: auditEvents.action, metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, EXTERNAL_AGENT_ID));
      const rejection = audits.find(
        (row) => row.action === "vault.execution_authorization.rejected",
      );
      expect(rejection, "third-party-custody rejection audit must exist").toBeDefined();
      expect((rejection?.metadata as Record<string, unknown> | undefined)?.reason).toBe(
        "third-party_custody_not_gateway_supported",
      );
    } finally {
      signSpy.mockRestore();
    }
  });

  it("fails closed (third-party custody) on the approval replay path before the provider is reached", async () => {
    const txId = "tx-ext-custody-approval";
    // Seed a well-formed primary EVM approval row for the EXTERNAL custody agent.
    const extCustodyReplay = { ...REPLAY_BASE, agentId: EXTERNAL_AGENT_ID };
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: EXTERNAL_AGENT_ID,
        status: "pending",
        toAddress: extCustodyReplay.to,
        value: extCustodyReplay.value,
        data: extCustodyReplay.data,
        chainId: extCustodyReplay.chainId,
        actionPayload: {
          type: "transaction",
          broadcast: false,
          nonce: extCustodyReplay.nonce,
          gasLimit: extCustodyReplay.gasLimit,
          walletAddress: extCustodyReplay.walletAddress,
        },
        executionPayloadDigest: executionPayloadDigestForEvmSign(extCustodyReplay),
        executionPolicyRevisionHash: "queued-policy-revision",
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `aq-${txId}`,
        txId,
        agentId: EXTERNAL_AGENT_ID,
        status: "pending",
        requestedByType: "agent",
        requestedById: EXTERNAL_AGENT_ID,
      });

    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      throw new Error(
        "raw signer / third-party provider must not be reached for third-party custody",
      );
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${EXTERNAL_AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await res.json();
      expect(res.status).toBe(409);
      expect(body.ok).toBe(false);
      expect(signSpy).toHaveBeenCalledTimes(0);
      const nonceRows = await getDb()
        .select({ id: executionAuthorizationNonces.id })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.requestId, txId));
      expect(nonceRows).toHaveLength(0);
      const audits = await getDb()
        .select({ action: auditEvents.action, metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, txId));
      const rejection = audits.find(
        (row) => row.action === "vault.execution_authorization.rejected",
      );
      expect(rejection, "third-party-custody approval rejection audit must exist").toBeDefined();
      expect((rejection?.metadata as Record<string, unknown> | undefined)?.reason).toBe(
        "third-party_custody_not_gateway_supported",
      );
      const [approval] = await getDb()
        .select({ status: approvalQueue.status })
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(approval?.status).toBe("pending");
    } finally {
      signSpy.mockRestore();
    }
  });
});
