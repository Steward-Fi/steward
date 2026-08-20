import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout, spyOn } from "bun:test";
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
import type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
  ExternalKeySignTransactionRequest,
  ExternalKeySignTransactionResult,
} from "@stwd/vault";
import {
  BackendBindingMismatchError,
  ExternalBroadcastOutcomeUnknownError,
  externalCustodyIdentityDigest,
  Vault,
} from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import { executionPayloadDigestForEvmSign } from "../services/execution-authorization";
import { getConfiguredVault } from "../services/vault-factory";

const TENANT_ID = `gateway-tenant-${Date.now()}`;
const AGENT_ID = `gateway-agent-${Date.now()}`;
const USER_ID = "00000000-0000-4000-8000-000000000123";
const SOLANA_RECIPIENT = "11111111111111111111111111111111";
const ORIGINAL_REDIS_URL = process.env.REDIS_URL;
const ORIGINAL_REDIS_REQUIRED = process.env.REDIS_REQUIRED;
const ORIGINAL_EXECUTION_AUTH_SECRET = process.env.STEWARD_EXECUTION_AUTH_SECRET;
setDefaultTimeout(30_000);

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
    process.env.STEWARD_EXECUTION_AUTH_SECRET = `gateway-test:${"e".repeat(48)}`;
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
          addresses: ["0x1111111111111111111111111111111111111111", SOLANA_RECIPIENT],
        },
      });
  });

  afterAll(async () => {
    delete process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING;
    if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = ORIGINAL_REDIS_URL;
    if (ORIGINAL_REDIS_REQUIRED === undefined) delete process.env.REDIS_REQUIRED;
    else process.env.REDIS_REQUIRED = ORIGINAL_REDIS_REQUIRED;
    if (ORIGINAL_EXECUTION_AUTH_SECRET === undefined) {
      delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    } else {
      process.env.STEWARD_EXECUTION_AUTH_SECRET = ORIGINAL_EXECUTION_AUTH_SECRET;
    }
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
          to: SOLANA_RECIPIENT,
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
        executionBackend: "local-vault",
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
    await getDb()
      .insert(agents)
      .values({
        id: EXTERNAL_AGENT_ID,
        tenantId: TENANT_ID,
        name: "External Custody Agent",
        walletAddress: "0x00000000000000000000000000000000000000ff",
      })
      .onConflictDoNothing();
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
    await getDb()
      .insert(agentWallets)
      .values({
        agentId: EXTERNAL_AGENT_ID,
        chainFamily: "evm",
        address: "0x00000000000000000000000000000000000000ff",
        metadata: custodyMetadata,
      })
      .onConflictDoNothing();
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
      })
      .onConflictDoNothing();
  }

  it("mints and consumes an identity-bound external-custody authorization on direct /sign", async () => {
    await seedExternalCustodyAgent();
    const expectedIdentity = externalCustodyIdentityDigest({
      providerId: "test-kms",
      keyId: "key-ext-1",
      address: "0x00000000000000000000000000000000000000ff",
    });
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(
      async (_request, options) => {
        expect(options.expectedBackend).toBe("external-custody");
        expect(options.expectedBackendIdentityDigest).toBe(expectedIdentity);
        return "0xexternally-signed";
      },
    );
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
          broadcast: false,
        }),
      });
      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);
      const [authorization] = await getDb()
        .select({
          backend: executionAuthorizationNonces.backend,
          identity: executionAuthorizationNonces.backendIdentityDigest,
          status: executionAuthorizationNonces.status,
        })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.agentId, EXTERNAL_AGENT_ID));
      expect(authorization).toEqual({
        backend: "external-custody",
        identity: expectedIdentity,
        status: "consumed",
      });
    } finally {
      signSpy.mockRestore();
    }
  });

  it("falls back to the pre-staged direct intent after an ambiguous broadcast write failure", async () => {
    await seedExternalCustodyAgent();
    const txHash = `0x${"cd".repeat(32)}`;
    const provider: ExternalKeyCustodyProvider & { signCalls: number } = {
      id: "direct-outcome-provider",
      contractVersion: 1,
      signCalls: 0,
      async registerKeyHandle(): Promise<ExternalKeyHandleRegistration> {
        throw new Error("registerKeyHandle is not used by this test");
      },
      async signTransaction(): Promise<ExternalKeySignTransactionResult> {
        this.signCalls += 1;
        throw new ExternalBroadcastOutcomeUnknownError(txHash, {
          cause: new Error("https://rpc.example.test/SUPER_SECRET_API_KEY timed out"),
        });
      },
    };
    const routeVault = getConfiguredVault({
      fallbackPassword: process.env.STEWARD_MASTER_PASSWORD,
    }) as unknown as {
      externalKeyCustodyProvider?: ExternalKeyCustodyProvider;
      recordSignedTransaction: (...args: unknown[]) => Promise<void>;
    };
    const priorProvider = routeVault.externalKeyCustodyProvider;
    const originalRecord = routeVault.recordSignedTransaction;
    routeVault.externalKeyCustodyProvider = provider;
    routeVault.recordSignedTransaction = async () => {
      throw new Error("injected direct outcome write failure");
    };
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${EXTERNAL_AGENT_ID}/sign`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "ext-custody-outcome-unknown-direct",
        },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          broadcast: true,
        }),
      });
      const text = await res.text();
      const body = JSON.parse(text);
      expect(res.status).toBe(202);
      expect(body).toEqual({
        ok: false,
        error: "Broadcast outcome is unknown; reconcile the transaction hash before retrying",
        data: {
          code: "external_broadcast_outcome_unknown",
          txId: expect.any(String),
          txHash,
          reconciliationRequired: true,
        },
      });
      expect(text).not.toContain("SUPER_SECRET_API_KEY");
      expect(text).not.toContain("rpc.example.test");
      expect(provider.signCalls).toBe(1);
      const audits = await getDb()
        .select({ action: auditEvents.action, resourceId: auditEvents.resourceId })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, body.data.txId));
      expect(audits).toContainEqual({
        action: "vault.broadcast.outcome_unknown",
        resourceId: body.data.txId,
      });
      const [transaction] = await getDb()
        .select({ status: transactions.status, txHash: transactions.txHash })
        .from(transactions)
        .where(eq(transactions.id, body.data.txId));
      expect(transaction).toEqual({ status: "outcome_unknown", txHash });

      // A persistence failure inside Vault still surfaces the same typed error.
      // Replaying the caller's idempotency key is rejected by the consumed
      // authorization and cannot enter the signer a second time.
      const retry = await app.request(`/vault/${EXTERNAL_AGENT_ID}/sign`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "ext-custody-outcome-unknown-direct",
        },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          broadcast: true,
        }),
      });
      expect(retry.status).not.toBe(200);
      expect(provider.signCalls).toBe(1);
    } finally {
      routeVault.externalKeyCustodyProvider = priorProvider;
      routeVault.recordSignedTransaction = originalRecord;
    }
  });

  it("does not expose credential-bearing provider text through the generic HTTP error path", async () => {
    const canary = "SUPER_SECRET_PROVIDER_TOKEN";
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      throw new Error(
        `KMS key arn:aws:kms:us-east-1:123456789012:key/example not found at https://kms.example.test/${canary}`,
      );
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "provider-error-redaction-canary",
        },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          broadcast: true,
        }),
      });
      const text = await res.text();
      expect(res.status).toBe(500);
      expect(JSON.parse(text)).toEqual({ ok: false, error: "Internal server error" });
      expect(text).not.toContain(canary);
      expect(text).not.toContain("arn:aws:kms");
      expect(text).not.toContain("kms.example.test");
      expect(signSpy).toHaveBeenCalledTimes(1);
    } finally {
      signSpy.mockRestore();
    }
  });

  it("reports outcome_unknown truthfully through the transfer action API", async () => {
    const txId = "tx-transfer-outcome-unknown";
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "outcome_unknown",
        toAddress: "0x1111111111111111111111111111111111111111",
        value: "1",
        chainId: 8453,
        txHash: `0x${"ab".repeat(32)}`,
        actionType: "transfer",
        actionPayload: {
          type: "transfer",
          token: "native",
          recipient: "0x1111111111111111111111111111111111111111",
          amount: "1",
          broadcast: true,
        },
      });

    const app = await makeApp();
    const res = await app.request(`/vault/${AGENT_ID}/actions/${txId}`);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.data).toMatchObject({ id: txId, status: "outcome_unknown" });
  });

  it("replays an approval only through the queued external provider/key/address identity", async () => {
    const txId = "tx-ext-custody-approval";
    // Seed a well-formed primary EVM approval row for the EXTERNAL custody agent.
    const extCustodyReplay = { ...REPLAY_BASE, agentId: EXTERNAL_AGENT_ID };
    const expectedIdentity = externalCustodyIdentityDigest({
      providerId: "test-kms",
      keyId: "key-ext-1",
      address: "0x00000000000000000000000000000000000000ff",
    });
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
        executionBackend: "external-custody",
        executionBackendIdentityDigest: expectedIdentity,
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

    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(
      async (_request, options) => {
        expect(options.expectedBackend).toBe("external-custody");
        expect(options.expectedBackendIdentityDigest).toBe(expectedIdentity);
        return "0xexternally-approved";
      },
    );
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${EXTERNAL_AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);
      const nonceRows = await getDb()
        .select({
          backend: executionAuthorizationNonces.backend,
          identity: executionAuthorizationNonces.backendIdentityDigest,
          status: executionAuthorizationNonces.status,
        })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.requestId, txId));
      expect(nonceRows).toEqual([
        { backend: "external-custody", identity: expectedIdentity, status: "consumed" },
      ]);
      const [approval] = await getDb()
        .select({ status: approvalQueue.status })
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(approval?.status).toBe("approved");
    } finally {
      signSpy.mockRestore();
    }
  });

  it("keeps a successful external broadcast terminal when final bookkeeping fails and never reopens approval", async () => {
    await seedExternalCustodyAgent();
    const txId = "tx-ext-custody-outcome-unknown";
    const txHash = `0x${"ef".repeat(32)}`;
    const walletAddress = "0x00000000000000000000000000000000000000ff";
    const replay = {
      ...REPLAY_BASE,
      agentId: EXTERNAL_AGENT_ID,
      walletAddress,
      broadcast: true,
    };
    const identity = externalCustodyIdentityDigest({
      providerId: "test-kms",
      keyId: "key-ext-1",
      address: walletAddress,
    });
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: EXTERNAL_AGENT_ID,
        status: "pending",
        toAddress: replay.to,
        value: replay.value,
        data: replay.data,
        chainId: replay.chainId,
        actionPayload: {
          type: "transaction",
          broadcast: true,
          nonce: replay.nonce,
          gasLimit: replay.gasLimit,
          walletAddress,
        },
        executionPayloadDigest: executionPayloadDigestForEvmSign(replay),
        executionPolicyRevisionHash: "queued-policy-revision",
        executionBackend: "external-custody",
        executionBackendIdentityDigest: identity,
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

    const provider: ExternalKeyCustodyProvider & { signCalls: number } = {
      id: "approval-outcome-provider",
      contractVersion: 1,
      signCalls: 0,
      async registerKeyHandle(): Promise<ExternalKeyHandleRegistration> {
        throw new Error("registerKeyHandle is not used by this test");
      },
      async signTransaction(request): Promise<ExternalKeySignTransactionResult> {
        this.signCalls += 1;
        await request.onPreparedBroadcast?.(txHash);
        return { result: txHash, broadcast: true };
      },
    };
    const routeVault = getConfiguredVault({
      fallbackPassword: process.env.STEWARD_MASTER_PASSWORD,
    }) as unknown as {
      externalKeyCustodyProvider?: ExternalKeyCustodyProvider;
      recordSignedTransaction: (...args: unknown[]) => Promise<void>;
    };
    const priorProvider = routeVault.externalKeyCustodyProvider;
    const originalRecord = routeVault.recordSignedTransaction;
    let writes = 0;
    routeVault.externalKeyCustodyProvider = provider;
    routeVault.recordSignedTransaction = async (...args) => {
      writes += 1;
      if (writes === 2) throw new Error("injected final approval write failure");
      await originalRecord.apply(routeVault, args);
    };
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${EXTERNAL_AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await res.json();
      expect(res.status).toBe(202);
      expect(body.data).toMatchObject({
        code: "external_broadcast_outcome_unknown",
        txHash,
        reconciliationRequired: true,
      });
      const [approval] = await getDb()
        .select({ status: approvalQueue.status })
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(approval?.status).toBe("approved");
      const [transaction] = await getDb()
        .select({ status: transactions.status, txHash: transactions.txHash })
        .from(transactions)
        .where(eq(transactions.id, txId));
      expect(transaction).toEqual({ status: "outcome_unknown", txHash });

      const retry = await app.request(`/vault/${EXTERNAL_AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(retry.status).toBe(404);
      expect(provider.signCalls).toBe(1);
      expect(writes).toBe(2);
    } finally {
      routeVault.externalKeyCustodyProvider = priorProvider;
      routeVault.recordSignedTransaction = originalRecord;
    }
  });

  it("rejects approval replay when the external provider/key/address identity changed", async () => {
    const txId = "tx-ext-custody-identity-changed";
    const replay = { ...REPLAY_BASE, agentId: EXTERNAL_AGENT_ID };
    const queuedIdentity = externalCustodyIdentityDigest({
      providerId: "test-kms",
      keyId: "key-ext-1",
      address: "0x00000000000000000000000000000000000000ff",
    });
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: EXTERNAL_AGENT_ID,
        status: "pending",
        toAddress: replay.to,
        value: replay.value,
        data: replay.data,
        chainId: replay.chainId,
        actionPayload: {
          type: "transaction",
          broadcast: false,
          nonce: replay.nonce,
          gasLimit: replay.gasLimit,
          walletAddress: replay.walletAddress,
        },
        executionPayloadDigest: executionPayloadDigestForEvmSign(replay),
        executionPolicyRevisionHash: "queued-policy-revision",
        executionBackend: "external-custody",
        executionBackendIdentityDigest: queuedIdentity,
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
    await getDb()
      .update(agentWallets)
      .set({
        metadata: {
          custody: "external",
          externalKey: {
            providerId: "test-kms",
            keyId: "key-ext-2",
            registeredAt: new Date().toISOString(),
            exportablePrivateKey: false,
            signingAvailability: "provider-signing",
          },
        },
      })
      .where(eq(agentWallets.agentId, EXTERNAL_AGENT_ID));
    const signSpy = spyOn(Vault.prototype, "signTransaction");
    try {
      const res = await (await makeApp()).request(`/vault/${EXTERNAL_AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status).toBe(409);
      expect(signSpy).toHaveBeenCalledTimes(0);
      const audits = await getDb()
        .select({ metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, txId));
      expect((audits.at(-1)?.metadata as Record<string, unknown> | undefined)?.reason).toBe(
        "custody_identity_changed_since_approval_request",
      );
    } finally {
      signSpy.mockRestore();
      await getDb()
        .update(agentWallets)
        .set({
          metadata: {
            custody: "external",
            externalKey: {
              providerId: "test-kms",
              keyId: "key-ext-1",
              registeredAt: new Date().toISOString(),
              exportablePrivateKey: false,
              signingAvailability: "provider-signing",
            },
          },
        })
        .where(eq(agentWallets.agentId, EXTERNAL_AGENT_ID));
    }
  });

  // ── ROUND 3 / ITEM 3 (PART B): backend-binding TOCTOU — API-level transition —
  //
  // The FINDING 4 tests above reject when the wallet ALREADY resolves to a
  // non-local backend at the gateway precheck (resolveExecutionBackend returns
  // the non-local backend), so no authorization is ever minted. This test
  // exercises the harder TOCTOU: the wallet resolves as `local-vault` at MINT
  // time (precheck passes, an authorization IS minted+consumed and bound to
  // "local-vault"), then the custody FLIPS to the provider-backed backend
  // BEFORE the raw signing boundary. The raw Vault.signTransaction re-resolves
  // the backend from its OWN fresh wallet lookup (independent of the gateway's
  // resolveExecutionBackend precheck) and, because the authorization is bound to
  // "local-vault", MUST fail closed with BackendBindingMismatchError BEFORE the
  // provider is reached.
  //
  // We model the flip by making the wallet provider-custody in the DB (the
  // post-flip state the raw signer sees) while stubbing resolveExecutionBackend
  // to return "local-vault" (the pre-flip value the gateway precheck read). The
  // real signTransaction runs (NOT mocked) so the re-resolution + fail-closed
  // guard actually execute. We register a REAL provider spy on the route's Vault
  // instance and assert it is NEVER called — proving the guard fires before any
  // provider routing.
  //
  // Required assertions (round-3 PART B):
  //  (1) the real provider spy is NEVER called,
  //  (2) the specific BackendBindingMismatchError / backend_binding_mismatch
  //      code surfaces (HTTP 409 with data.code), and
  //  (3) the specific PART-A rejection audit
  //      (vault.execution_authorization.rejected, reason backend_binding_mismatch)
  //      is written at the API level.

  const TRANSITION_AGENT_ID = `gateway-transition-agent-${Date.now()}`;

  class ProviderSpy implements ExternalKeyCustodyProvider {
    id = "transition-provider-spy";
    readonly contractVersion = 1 as const;
    registerCalls: ExternalKeyHandleImportRequest[] = [];
    signCalls: ExternalKeySignTransactionRequest[] = [];
    async registerKeyHandle(
      request: ExternalKeyHandleImportRequest,
    ): Promise<ExternalKeyHandleRegistration> {
      this.registerCalls.push(request);
      throw new Error("provider registerKeyHandle must not be reached in the transition test");
    }
    async signTransaction(
      request: ExternalKeySignTransactionRequest,
    ): Promise<ExternalKeySignTransactionResult> {
      // If this ever runs, the TOCTOU guard failed: a local-vault-bound
      // authorization reached the provider.
      this.signCalls.push(request);
      throw new Error(
        "provider signTransaction must not be reached for a backend-binding mismatch",
      );
    }
  }

  it("fails closed (backend binding mismatch) on the direct /sign path when a local-vault-bound authorization re-resolves to the provider backend before the provider", async () => {
    // Seed a wallet that is provider-custody in the DB (the post-flip state the
    // raw signer's re-resolution will observe), mirroring seedExternalCustodyAgent.
    await getDb().insert(agents).values({
      id: TRANSITION_AGENT_ID,
      tenantId: TENANT_ID,
      name: "Transition Custody Agent",
      walletAddress: "0x00000000000000000000000000000000000000ee",
    });
    const custodyMetadata: Record<string, unknown> = {
      custody: "external",
      externalKey: {
        providerId: "test-kms",
        keyId: "key-transition-1",
        registeredAt: new Date().toISOString(),
        exportablePrivateKey: false,
        signingAvailability: "provider-signing",
      },
    };
    await getDb().insert(agentWallets).values({
      agentId: TRANSITION_AGENT_ID,
      chainFamily: "evm",
      address: "0x00000000000000000000000000000000000000ee",
      metadata: custodyMetadata,
    });
    await getDb()
      .insert(policies)
      .values({
        id: `${TRANSITION_AGENT_ID}-approved-addresses`,
        agentId: TRANSITION_AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: {
          mode: "whitelist",
          addresses: ["0x1111111111111111111111111111111111111111"],
        },
      });

    // Register a REAL provider spy on the route's Vault instance so we can
    // assert it is NEVER reached. The route resolves its Vault via
    // getConfiguredVault (the same instance the `vault` proxy in services/context
    // delegates to), so setting the provider on that instance is what the raw
    // signer would use if it ever routed to the provider backend.
    const routeVault = getConfiguredVault({
      fallbackPassword: process.env.STEWARD_MASTER_PASSWORD,
    });
    const providerSpy = new ProviderSpy();
    const vaultWithProvider = routeVault as unknown as {
      externalKeyCustodyProvider?: ExternalKeyCustodyProvider;
    };
    const priorProvider = vaultWithProvider.externalKeyCustodyProvider;
    vaultWithProvider.externalKeyCustodyProvider = providerSpy;

    // Stub resolveExecutionBackend to return the PRE-flip value "local-vault"
    // so the gateway precheck passes and mints+consumes an authorization bound
    // to local-vault. The raw signTransaction below is NOT mocked, so its own
    // fresh wallet lookup still observes the provider-custody DB wallet and
    // fails closed at the signing boundary.
    const resolveSpy = spyOn(Vault.prototype, "resolveExecutionTarget").mockResolvedValue({
      backend: "local-vault",
    });

    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${TRANSITION_AGENT_ID}/sign`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": "transition-binding-mismatch-1",
        },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          broadcast: false,
        }),
      });
      const body = await res.json();

      // (2) the specific backend_binding_mismatch surfaces as the fail-closed 409.
      expect(res.status).toBe(409);
      expect(body.ok).toBe(false);
      expect(body.data?.code).toBe("backend_binding_mismatch");

      // (1) the real provider spy was NEVER called.
      expect(providerSpy.signCalls).toHaveLength(0);
      expect(providerSpy.registerCalls).toHaveLength(0);

      // Prove the guard genuinely engaged: the mint-time precheck resolver was
      // consulted, and the mismatch error type is the vault-layer one.
      expect(resolveSpy).toHaveBeenCalled();

      // (3) the PART-A rejection audit is written with reason backend_binding_mismatch.
      const audits = await getDb()
        .select({ action: auditEvents.action, metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, TRANSITION_AGENT_ID));
      const rejection = audits.find(
        (row) => row.action === "vault.execution_authorization.rejected",
      );
      expect(rejection, "backend-binding-mismatch rejection audit must exist").toBeDefined();
      const rejectionMeta = rejection?.metadata as Record<string, unknown> | undefined;
      expect(rejectionMeta?.reason).toBe("backend_binding_mismatch");
      expect(rejectionMeta?.expectedBackend).toBe("local-vault");
      expect(rejectionMeta?.resolvedBackend).toBe("external-custody");

      // Sanity: the vault-layer error class is exported and matches the code the
      // API surfaced, keeping the API contract and the vault guard in lockstep.
      expect(new BackendBindingMismatchError("local-vault", "external-custody").code).toBe(
        "backend_binding_mismatch",
      );
    } finally {
      resolveSpy.mockRestore();
      vaultWithProvider.externalKeyCustodyProvider = priorProvider;
    }
  });
});
