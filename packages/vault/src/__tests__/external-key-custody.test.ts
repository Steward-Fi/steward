import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { agentWallets, encryptedChainKeys, eq, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and } from "drizzle-orm";
import type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
  ExternalKeySigningAvailability,
  ExternalKeySignTransactionRequest,
  ExternalKeySignTransactionResult,
} from "../external-key-custody";
import { ExternalBroadcastOutcomeUnknownError } from "../external-key-custody";
import { BackendBindingMismatchError, Vault } from "../vault";

const MASTER_PASSWORD = "test-vault-external-key-custody";
const TENANT_ID = "tenant-external-key-custody";

setDefaultTimeout(120000);

const openClients: Array<{ close: () => Promise<void> }> = [];

class TestExternalKeyProvider implements ExternalKeyCustodyProvider {
  id = "test-external-key-provider";
  readonly contractVersion = 1 as const;
  registerCalls: ExternalKeyHandleImportRequest[] = [];
  signCalls: ExternalKeySignTransactionRequest[] = [];

  constructor(
    private readonly signingAvailability: ExternalKeySigningAvailability = "not-supported",
    private readonly signer?: (
      request: ExternalKeySignTransactionRequest,
    ) => Promise<ExternalKeySignTransactionResult>,
  ) {}

  async registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration> {
    this.registerCalls.push(request);
    return {
      custody: "external",
      tenantId: request.tenantId,
      agentId: request.agentId,
      chainFamily: request.chainFamily,
      address: request.address,
      handle: request.handle,
      venue: request.venue ?? null,
      purpose: request.purpose ?? null,
      metadata: request.metadata ?? {},
      registeredAt: new Date("2026-06-05T00:00:00.000Z"),
      exportablePrivateKey: false,
      signingAvailability: this.signingAvailability,
    };
  }

  async signTransaction(
    request: ExternalKeySignTransactionRequest,
  ): Promise<ExternalKeySignTransactionResult> {
    this.signCalls.push(request);
    if (!this.signer) {
      throw new Error("test signer not installed");
    }
    return this.signer(request);
  }
}

async function freshVault(provider?: ExternalKeyCustodyProvider): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "External Key Custody Test Tenant",
    apiKeyHash: "test-hash",
  });

  return new Vault({
    masterPassword: MASTER_PASSWORD,
    externalKeyCustodyProvider: provider,
  });
}

function externalHandleRequest(
  overrides: Partial<ExternalKeyHandleImportRequest> = {},
): ExternalKeyHandleImportRequest {
  return {
    tenantId: TENANT_ID,
    agentId: "agent-external",
    chainFamily: "evm",
    address: "0x1111111111111111111111111111111111111111",
    handle: { providerId: "test-hsm", keyId: "key-1", version: "1", region: "us-east-1" },
    venue: "hsm-primary",
    purpose: "hsm",
    metadata: { label: "primary-hsm-handle" },
    ...overrides,
  };
}

describe("external key custody seam", () => {
  let vault: Vault;

  beforeEach(async () => {
    vault = await freshVault();
  });

  afterAll(async () => {
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
  });

  test("fails closed when no external key provider is configured", async () => {
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");

    await expect(vault.importExternalKeyHandle(externalHandleRequest())).rejects.toThrow(
      "External key custody provider is not configured",
    );
  });

  test("rejects nested private key material before calling the provider", async () => {
    const provider = new TestExternalKeyProvider();
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");

    await expect(
      vault.importExternalKeyHandle(
        externalHandleRequest({
          handle: {
            providerId: "test-hsm",
            keyId: "key-1",
            metadata: { privateKey: "0xnot-allowed" },
          },
        }),
      ),
    ).rejects.toThrow("must not contain private key material");
    expect(provider.registerCalls).toHaveLength(0);
  });

  test("registers only public external handle metadata and no encrypted key row", async () => {
    const provider = new TestExternalKeyProvider();
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");

    const registration = await vault.importExternalKeyHandle(externalHandleRequest());

    expect(registration.exportablePrivateKey).toBe(false);
    expect(registration.signingAvailability).toBe("not-supported");

    const wallets = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, "agent-external"));
    const externalWallet = wallets.find((wallet) => wallet.venue === "hsm-primary");
    expect(externalWallet?.address).toBe("0x1111111111111111111111111111111111111111");
    expect(externalWallet?.metadata).toMatchObject({
      custody: "external",
      externalKey: {
        providerId: "test-hsm",
        keyId: "key-1",
        exportablePrivateKey: false,
        signingAvailability: "not-supported",
      },
    });
    const serializedMetadata = JSON.stringify(externalWallet?.metadata).toLowerCase();
    expect(serializedMetadata).not.toContain("ciphertext");
    expect(serializedMetadata).not.toContain("mnemonic");
    expect(serializedMetadata).not.toContain("seed");

    const chainKeys = await getDb()
      .select()
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, "agent-external"));
    expect(chainKeys.some((key) => key.venue === "hsm-primary")).toBe(false);

    const fetched = await vault.getWallet({ agentId: "agent-external", venue: "hsm-primary" });
    expect(fetched.address).toBe("0x1111111111111111111111111111111111111111");
    expect(fetched.metadata).toMatchObject({ custody: "external" });
  });

  test("rejects default-scope external registration over a legacy server-managed key", async () => {
    const provider = new TestExternalKeyProvider();
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    // Reproduce a pre-multiwallet agent: the legacy encrypted_keys row remains,
    // while the newer scoped key/wallet rows do not exist.
    await getDb()
      .delete(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, "agent-external"));
    await getDb().delete(agentWallets).where(eq(agentWallets.agentId, "agent-external"));

    await expect(
      vault.importExternalKeyHandle(externalHandleRequest({ venue: undefined })),
    ).rejects.toThrow("legacy server-managed key");
    expect(provider.registerCalls).toHaveLength(0);
  });

  test("all unsupported default-scope signers fail closed on external custody before legacy fallback", async () => {
    const provider = new TestExternalKeyProvider("provider-signing", async () => ({
      result: "0xunused",
      broadcast: false,
    }));
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await getDb()
      .delete(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, "agent-external"),
          eq(encryptedChainKeys.chainFamily, "evm"),
        ),
      );
    await getDb()
      .update(agentWallets)
      .set({
        metadata: {
          custody: "external",
          externalKey: {
            providerId: "test-hsm",
            keyId: "key-1",
            version: "1",
            region: "us-east-1",
            exportablePrivateKey: false,
            signingAvailability: "provider-signing",
          },
        },
      })
      .where(and(eq(agentWallets.agentId, "agent-external"), eq(agentWallets.chainFamily, "evm")));

    const unsupported =
      "This wallet uses external custody; this signing operation is not supported for external keys";
    await expect(vault.signMessage(TENANT_ID, "agent-external", "message")).rejects.toThrow(
      unsupported,
    );
    await expect(
      vault.signRawHash(TENANT_ID, "agent-external", `0x${"11".repeat(32)}` as `0x${string}`),
    ).rejects.toThrow(unsupported);
    await expect(
      vault.signRawDigest(TENANT_ID, "agent-external", "secp256k1", `0x${"22".repeat(32)}`),
    ).rejects.toThrow(unsupported);
    await expect(
      vault.signAuthorization(TENANT_ID, "agent-external", {
        contractAddress: "0x2222222222222222222222222222222222222222",
        chainId: 8453,
        nonce: 0,
      }),
    ).rejects.toThrow(unsupported);
    await expect(
      vault.signTypedData({
        tenantId: TENANT_ID,
        agentId: "agent-external",
        domain: { name: "test", chainId: 8453 },
        types: { Message: [{ name: "value", type: "uint256" }] },
        primaryType: "Message",
        value: { value: 1 },
      }),
    ).rejects.toThrow(unsupported);
    await expect(
      vault.signUserOperation({
        tenantId: TENANT_ID,
        agentId: "agent-external",
        chainId: 8453,
        userOperation: {} as never,
      }),
    ).rejects.toThrow(unsupported);
    expect(provider.signCalls).toHaveLength(0);
  });

  test("external-only wallets refuse signing when provider signing is unavailable", async () => {
    const provider = {
      id: "unsupported-signing-provider",
      contractVersion: 1 as const,
      async registerKeyHandle(
        request: ExternalKeyHandleImportRequest,
      ): Promise<ExternalKeyHandleRegistration> {
        return {
          custody: "external",
          tenantId: request.tenantId,
          agentId: request.agentId,
          chainFamily: request.chainFamily,
          address: request.address,
          handle: request.handle,
          venue: request.venue ?? null,
          purpose: request.purpose ?? null,
          metadata: request.metadata ?? {},
          registeredAt: new Date("2026-06-05T00:00:00.000Z"),
          exportablePrivateKey: false,
          signingAvailability: "provider-signing",
        };
      },
    } satisfies ExternalKeyCustodyProvider & { registerCalls?: ExternalKeyHandleImportRequest[] };
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());

    const target = await vault.resolveExecutionTarget({
      tenantId: TENANT_ID,
      agentId: "agent-external",
      chainId: 8453,
      venue: "hsm-primary",
    });
    await expect(
      vault.signTransaction(
        {
          tenantId: TENANT_ID,
          agentId: "agent-external",
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1",
          venue: "hsm-primary",
          broadcast: false,
        },
        {
          expectedBackend: target.backend,
          expectedBackendIdentityDigest: target.backendIdentityDigest,
        },
      ),
    ).rejects.toThrow("External key custody signing provider is not configured for this wallet");
  });

  test("external-only wallets refuse signing when a handle is not provider-signing enabled", async () => {
    const provider = new TestExternalKeyProvider();
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());

    const target = await vault.resolveExecutionTarget({
      tenantId: TENANT_ID,
      agentId: "agent-external",
      chainId: 8453,
      venue: "hsm-primary",
    });
    await expect(
      vault.signTransaction(
        {
          tenantId: TENANT_ID,
          agentId: "agent-external",
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1",
          venue: "hsm-primary",
          broadcast: false,
        },
        {
          expectedBackend: target.backend,
          expectedBackendIdentityDigest: target.backendIdentityDigest,
        },
      ),
    ).rejects.toThrow("External key custody signing provider is not configured for this wallet");
  });

  test("delegates transaction signing to a provider without private key material", async () => {
    const provider = new TestExternalKeyProvider("provider-signing", async (request) => {
      expect(request.handle).toEqual({
        providerId: "test-hsm",
        keyId: "key-1",
        version: "1",
        region: "us-east-1",
      });
      expect(request.address).toBe("0x1111111111111111111111111111111111111111");
      expect(JSON.stringify(request).toLowerCase()).not.toContain("privatekey");
      return { result: "0xsigned-by-external-provider", broadcast: false };
    });
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());
    const target = await vault.resolveExecutionTarget({
      tenantId: TENANT_ID,
      agentId: "agent-external",
      chainId: 8453,
      venue: "hsm-primary",
    });

    const signed = await vault.signTransaction(
      {
        tenantId: TENANT_ID,
        agentId: "agent-external",
        chainId: 8453,
        to: "0x2222222222222222222222222222222222222222",
        value: "1",
        data: "0x",
        venue: "hsm-primary",
        broadcast: false,
      },
      {
        txId: "external-tx-1",
        expectedBackend: target.backend,
        expectedBackendIdentityDigest: target.backendIdentityDigest,
      },
    );

    expect(signed).toBe("0xsigned-by-external-provider");
    expect(provider.signCalls).toHaveLength(1);

    const [tx] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, "external-tx-1"));
    expect(tx?.agentId).toBe("agent-external");
    expect(tx?.status).toBe("signed");
    expect(tx?.txHash).toBeNull();
  });

  test("persists deterministic outcome_unknown before surfacing an ambiguous provider broadcast", async () => {
    const txHash = `0x${"ab".repeat(32)}`;
    let checkpointObserved = false;
    const provider = new TestExternalKeyProvider("provider-signing", async (request) => {
      expect(request.onPreparedBroadcast).toBeFunction();
      await request.onPreparedBroadcast?.(txHash);
      const [checkpoint] = await getDb()
        .select({ status: transactions.status, txHash: transactions.txHash })
        .from(transactions)
        .where(eq(transactions.id, "external-outcome-unknown"));
      expect(checkpoint).toEqual({ status: "outcome_unknown", txHash });
      checkpointObserved = true;
      throw new ExternalBroadcastOutcomeUnknownError(txHash);
    });
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());
    const target = await vault.resolveExecutionTarget({
      tenantId: TENANT_ID,
      agentId: "agent-external",
      chainId: 8453,
      venue: "hsm-primary",
    });

    await expect(
      vault.signTransaction(
        {
          tenantId: TENANT_ID,
          agentId: "agent-external",
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1",
          venue: "hsm-primary",
          broadcast: true,
        },
        {
          txId: "external-outcome-unknown",
          expectedBackend: target.backend,
          expectedBackendIdentityDigest: target.backendIdentityDigest,
        },
      ),
    ).rejects.toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);

    const [tx] = await getDb()
      .select({
        status: transactions.status,
        txHash: transactions.txHash,
        backend: transactions.executionBackend,
        identity: transactions.executionBackendIdentityDigest,
      })
      .from(transactions)
      .where(eq(transactions.id, "external-outcome-unknown"));
    expect(tx).toEqual({
      status: "outcome_unknown",
      txHash,
      backend: "external-custody",
      identity: target.backendIdentityDigest,
    });
    expect(provider.signCalls).toHaveLength(1);
    expect(checkpointObserved).toBe(true);
  });

  test("preserves typed outcome_unknown when its first durable write fails", async () => {
    const txHash = `0x${"bc".repeat(32)}`;
    const provider = new TestExternalKeyProvider("provider-signing", async () => {
      throw new ExternalBroadcastOutcomeUnknownError(txHash);
    });
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());
    const target = await vault.resolveExecutionTarget({
      tenantId: TENANT_ID,
      agentId: "agent-external",
      chainId: 8453,
      venue: "hsm-primary",
    });
    const writableVault = vault as unknown as {
      recordSignedTransaction: (...args: unknown[]) => Promise<void>;
    };
    writableVault.recordSignedTransaction = async () => {
      throw new Error("injected transaction write failure");
    };

    let thrown: unknown;
    try {
      await vault.signTransaction(
        {
          tenantId: TENANT_ID,
          agentId: "agent-external",
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1",
          venue: "hsm-primary",
          broadcast: true,
        },
        {
          txId: "external-outcome-write-failure",
          expectedBackend: target.backend,
          expectedBackendIdentityDigest: target.backendIdentityDigest,
        },
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
    expect((thrown as ExternalBroadcastOutcomeUnknownError).transactionHash).toBe(txHash);
    expect(provider.signCalls).toHaveLength(1);
  });

  // ── ROUND 3 / ITEM 3: backend-resolution TOCTOU (fail closed at sign) ────
  // resolveExecutionBackend is a separate, stale-able DB read. Between the
  // gateway's precheck (which may see "local-vault") and the raw sign, the
  // wallet's backend can FLIP to external custody (local key removed, external
  // key inserted). The raw signer re-resolves the backend from the SAME fresh
  // wallet lookup it will sign with; when the caller's authorization is bound to
  // "local-vault" (options.expectedBackend), a request that re-resolves to the
  // external branch must fail closed with BackendBindingMismatchError BEFORE the
  // external custody provider is ever reached.

  test("fails closed (backend binding mismatch) before the provider when a local-vault-bound sign re-resolves to external custody", async () => {
    const provider = new TestExternalKeyProvider("provider-signing", async () => {
      // If this ever runs, the TOCTOU guard failed: a local-vault-bound
      // authorization reached the external custody provider.
      throw new Error("provider must not be reached for a backend-binding mismatch");
    });
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    // Wallet resolves to external custody (provider-signing). This models the
    // post-flip state at signing time.
    await vault.importExternalKeyHandle(externalHandleRequest());

    // Sanity: without a bound backend, this SAME wallet WOULD reach the
    // provider (which throws its own guard). We assert the mismatch path is
    // distinct from the normal provider path.
    let error: unknown;
    try {
      await vault.signTransaction(
        {
          tenantId: TENANT_ID,
          agentId: "agent-external",
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1",
          data: "0x",
          venue: "hsm-primary",
          broadcast: false,
        },
        { txId: "toctou-mismatch-1", expectedBackend: "local-vault" },
      );
    } catch (err) {
      error = err;
    }

    expect(error).toBeInstanceOf(BackendBindingMismatchError);
    expect((error as BackendBindingMismatchError).code).toBe("backend_binding_mismatch");
    expect((error as BackendBindingMismatchError).expectedBackend).toBe("local-vault");
    // The provider signer was NEVER invoked.
    expect(provider.signCalls).toHaveLength(0);

    // No transaction row was written for the failed sign.
    const rows = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, "toctou-mismatch-1"));
    expect(rows).toHaveLength(0);
  });

  test("blocks external custody before the provider when the caller has no backend binding", async () => {
    const provider = new TestExternalKeyProvider("provider-signing", async () => ({
      result: "0xsigned-by-external-provider",
      broadcast: false,
    }));
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());

    await expect(
      vault.signTransaction(
        {
          tenantId: TENANT_ID,
          agentId: "agent-external",
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1",
          data: "0x",
          venue: "hsm-primary",
          broadcast: false,
        },
        { txId: "toctou-unbound-1" },
      ),
    ).rejects.toThrow("Execution backend binding mismatch");
    expect(provider.signCalls).toHaveLength(0);
  });

  test("break-glass private key export refuses agents with external custody wallets", async () => {
    const provider = new TestExternalKeyProvider();
    vault = await freshVault(provider);
    await vault.createAgent(TENANT_ID, "agent-external", "External Agent");
    await vault.importExternalKeyHandle(externalHandleRequest());

    await expect(
      vault.exportPrivateKey(TENANT_ID, "agent-external", {
        breakGlass: true,
        actorId: "operator",
        reason: "test",
      }),
    ).rejects.toThrow("External key custody private keys are not exportable");
  });
});
