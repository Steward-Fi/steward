/**
 * DB-backed Monero wallet lifecycle: createWallet must encrypt the canonical
 * key payload WITH its keystore context (AAD) so every read path (balance,
 * transfer, break-glass export, master-password rotation) can decrypt it — the
 * exact class of bug the venue-wallet AAD regression test guards for other
 * chains. Also exercises fail-closed behavior (no backend configured), the
 * dual-derivation address cross-check, signing-freeze on transfer paths, and
 * that no private key material ever lands in agent_wallets.metadata.
 */
import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agentWallets,
  and,
  encryptedChainKeys,
  eq,
  getDb,
  tenants,
  vaultSigningFreezes,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { KeyStore } from "../keystore";
import { backendFromKeyStore } from "../keystore-backend";
import {
  decodeMoneroAddress,
  type MoneroBalanceResult,
  type MoneroKeyPayloadV1,
  MoneroNotConfiguredError,
  type MoneroTransferDestination,
  type MoneroWalletBackend,
  type MoneroWalletBackendContext,
  type PreparedMoneroTransfer,
  parseMoneroKeyPayload,
} from "../monero";
import { isVaultSigningFrozenError } from "../signing-freeze";
import { Vault } from "../vault";

const MASTER_PASSWORD = "test-monero-lifecycle";
const TENANT_ID = "test-tenant";
const AGENT_ID = "agent-monero";
const SCOPE = "monero:mainnet:0";

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

/** In-memory MoneroWalletBackend: records calls, never touches a network. */
class FakeMoneroBackend implements MoneroWalletBackend {
  readonly network = "mainnet" as const;
  calls: string[] = [];
  verifiedPayloads: MoneroKeyPayloadV1[] = [];
  daemonHeight = 3_400_000;
  relayedMetadata: string[] = [];
  discarded = 0;

  async getDaemonHeight(): Promise<number> {
    this.calls.push("getDaemonHeight");
    return this.daemonHeight;
  }

  async verifyWalletKeys(payload: MoneroKeyPayloadV1): Promise<void> {
    this.calls.push("verifyWalletKeys");
    this.verifiedPayloads.push(payload);
  }

  async getBalance(
    payload: MoneroKeyPayloadV1,
    _context: MoneroWalletBackendContext,
  ): Promise<MoneroBalanceResult> {
    this.calls.push("getBalance");
    if (!/^[0-9a-f]{64}$/.test(payload.spendKey)) throw new Error("bad payload reached backend");
    return {
      balancePiconero: 5_000_000_000_000n,
      unlockedPiconero: 4_000_000_000_000n,
      blocksToUnlock: 2,
      syncedHeight: this.daemonHeight + 5,
    };
  }

  async prepareTransfer(
    _payload: MoneroKeyPayloadV1,
    _context: MoneroWalletBackendContext,
    request: { destinations: MoneroTransferDestination[]; priority?: number },
  ): Promise<PreparedMoneroTransfer> {
    this.calls.push("prepareTransfer");
    const amount = request.destinations.reduce(
      (total, destination) => total + destination.amountPiconero,
      0n,
    );
    return {
      txMetadata: "fake-tx-metadata",
      txHash: "ab".repeat(32),
      feePiconero: 31_000_000n,
      amountPiconero: amount,
    };
  }

  async relayTransfer(
    payload: MoneroKeyPayloadV1,
    _context: MoneroWalletBackendContext,
    txMetadata: string,
  ): Promise<{ txHash: string }> {
    this.calls.push("relayTransfer");
    if (!/^[0-9a-f]{64}$/.test(payload.spendKey)) throw new Error("bad payload reached backend");
    this.relayedMetadata.push(txMetadata);
    return { txHash: "cd".repeat(32) };
  }

  async discardPreparedTransfer(): Promise<void> {
    this.calls.push("discardPreparedTransfer");
    this.discarded += 1;
  }
}

async function freshVault(options: { backend?: MoneroWalletBackend | null } = {}): Promise<{
  vault: Vault;
  keyStore: KeyStore;
  backend: FakeMoneroBackend;
}> {
  delete process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK;
  delete process.env.STEWARD_MONERO_WALLET_RPC_URL;

  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Test Tenant", apiKeyHash: "test-hash" });

  const keyStore = new KeyStore(MASTER_PASSWORD);
  const backend = new FakeMoneroBackend();
  const vault = new Vault({
    masterPassword: MASTER_PASSWORD,
    keystoreBackend: backendFromKeyStore(keyStore),
    moneroBackend: options.backend === null ? undefined : (options.backend ?? backend),
  });
  await vault.createAgent(TENANT_ID, AGENT_ID, "Monero Agent");
  return { vault, keyStore, backend };
}

describe("Monero wallet lifecycle (DB-backed)", () => {
  afterAll(async () => {
    for (const client of openClients) await client.close().catch(() => {});
    openClients.length = 0;
  });

  test("createWallet stores an AAD-bound canonical payload and public-only metadata", async () => {
    const { vault, keyStore, backend } = await freshVault();

    const wallet = await vault.createWallet({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      chainType: "monero",
    });
    expect(wallet.venue).toBe(SCOPE);
    expect(wallet.address.startsWith("4")).toBe(true);
    expect(backend.calls).toContain("getDaemonHeight");
    expect(backend.calls).toContain("verifyWalletKeys");

    // wallet2 cross-check received the exact payload that was persisted
    expect(backend.verifiedPayloads[0]?.address).toBe(wallet.address);
    expect(backend.verifiedPayloads[0]?.restoreHeight).toBe(backend.daemonHeight);

    const [keyRow] = await getDb()
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, AGENT_ID),
          eq(encryptedChainKeys.chainFamily, "monero"),
          eq(encryptedChainKeys.venue, SCOPE),
        ),
      );
    expect(keyRow).toBeDefined();

    // Decrypts ONLY with the exact createWallet-time AAD context.
    const serialized = await keyStore.decrypt(
      { ciphertext: keyRow.ciphertext, iv: keyRow.iv, tag: keyRow.tag, salt: keyRow.salt },
      { tenantId: TENANT_ID, agentId: AGENT_ID, chainFamily: "monero", venue: SCOPE },
    );
    const payload = parseMoneroKeyPayload(serialized);
    expect(payload.address).toBe(wallet.address);
    expect(payload.network).toBe("mainnet");
    expect(decodeMoneroAddress(payload.address).publicSpendKey).toBeDefined();

    expect(() =>
      keyStore.decrypt(
        { ciphertext: keyRow.ciphertext, iv: keyRow.iv, tag: keyRow.tag, salt: keyRow.salt },
        { tenantId: TENANT_ID, agentId: AGENT_ID, chainFamily: "monero", venue: null },
      ),
    ).toThrow();

    // Public wallet row: monero metadata present, no secret key material.
    const [walletRow] = await getDb()
      .select()
      .from(agentWallets)
      .where(and(eq(agentWallets.agentId, AGENT_ID), eq(agentWallets.chainFamily, "monero")));
    const metadataJson = JSON.stringify(walletRow.metadata);
    expect(metadataJson).toContain("publicSpendKey");
    expect(metadataJson).not.toContain(payload.spendKey);
    expect(metadataJson).not.toContain(payload.viewKey);
  });

  test("createWallet fails closed without a configured backend", async () => {
    const { vault } = await freshVault({ backend: null });
    await expect(
      vault.createWallet({ tenantId: TENANT_ID, agentId: AGENT_ID, chainType: "monero" }),
    ).rejects.toThrow(MoneroNotConfiguredError);
    const rows = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    expect(rows.filter((row) => row.chainFamily === "monero").length).toBe(0);
  });

  test("createWallet rejects network mismatch and non-zero accounts", async () => {
    const { vault } = await freshVault();
    await expect(
      vault.createWallet({
        agentId: AGENT_ID,
        tenantId: TENANT_ID,
        chainType: "monero",
        monero: { network: "stagenet" },
      }),
    ).rejects.toThrow(/operates on mainnet/);
    await expect(
      vault.createWallet({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        chainType: "monero",
        monero: { account: 1 },
      }),
    ).rejects.toThrow(/account 0/);
  });

  test("getMoneroBalance round-trips through the backend with the decrypted payload", async () => {
    const { vault } = await freshVault();
    await vault.createWallet({ tenantId: TENANT_ID, agentId: AGENT_ID, chainType: "monero" });

    const balance = await vault.getMoneroBalance({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      walletScope: SCOPE,
    });
    expect(balance.balancePiconero).toBe(5_000_000_000_000n);
    expect(balance.unlockedPiconero).toBe(4_000_000_000_000n);
    expect(balance.network).toBe("mainnet");
    expect(balance.walletAddress.startsWith("4")).toBe(true);

    await expect(
      vault.getMoneroBalance({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        walletScope: "monero:mainnet:1",
      }),
    ).rejects.toThrow(/No signing key found/);
    await expect(
      vault.getMoneroBalance({ tenantId: "other-tenant", agentId: AGENT_ID, walletScope: SCOPE }),
    ).rejects.toThrow(/not found/);
  });

  test("prepareMoneroTransfer validates amounts/destinations and relays only prepared metadata", async () => {
    const { vault, backend } = await freshVault();
    await vault.createWallet({ tenantId: TENANT_ID, agentId: AGENT_ID, chainType: "monero" });
    // Any valid mainnet address works as a destination.
    const destinationAddress =
      "45AmZ2FRjuqZts5NGzb7ZXSNRuwS9MUqEeakpyEeSHsB5mywLwBzzq2cTsbJzTVUuLSHxtbfgKyZJVBqPffpP8fm79sjAcK";

    const prepared = await vault.prepareMoneroTransfer({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      walletScope: SCOPE,
      destinations: [{ address: destinationAddress, amountPiconero: "2500000000000" }],
      priority: 1,
    });
    expect(prepared.feePiconero).toBe(31_000_000n);
    expect(prepared.amountPiconero).toBe(2_500_000_000_000n);
    expect(prepared.txMetadata).toBe("fake-tx-metadata");

    await expect(
      vault.prepareMoneroTransfer({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        walletScope: SCOPE,
        destinations: [{ address: destinationAddress, amountPiconero: "0" }],
      }),
    ).rejects.toThrow(/greater than zero/);
    await expect(
      vault.prepareMoneroTransfer({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        walletScope: SCOPE,
        destinations: [],
      }),
    ).rejects.toThrow(/at least one destination/);

    const relayed = await vault.relayMoneroTransfer({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      walletScope: SCOPE,
      txMetadata: prepared.txMetadata,
    });
    expect(relayed.txHash).toBe("cd".repeat(32));
    expect(backend.relayedMetadata).toEqual(["fake-tx-metadata"]);

    await vault.discardMoneroTransfer({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      walletScope: SCOPE,
    });
    expect(backend.discarded).toBe(1);
  });

  test("signing freeze blocks prepare and relay (but not balance reads)", async () => {
    const { vault } = await freshVault();
    await vault.createWallet({ tenantId: TENANT_ID, agentId: AGENT_ID, chainType: "monero" });
    await getDb().insert(vaultSigningFreezes).values({
      tenantId: TENANT_ID,
      scopeType: "agent",
      agentId: AGENT_ID,
      reason: "test freeze",
      createdByType: "user",
      createdById: "test",
    });

    const destinationAddress =
      "45AmZ2FRjuqZts5NGzb7ZXSNRuwS9MUqEeakpyEeSHsB5mywLwBzzq2cTsbJzTVUuLSHxtbfgKyZJVBqPffpP8fm79sjAcK";
    try {
      await vault.prepareMoneroTransfer({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        walletScope: SCOPE,
        destinations: [{ address: destinationAddress, amountPiconero: "1" }],
      });
      throw new Error("expected prepare to be frozen");
    } catch (error) {
      expect(isVaultSigningFrozenError(error)).toBe(true);
    }
    try {
      await vault.relayMoneroTransfer({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        walletScope: SCOPE,
        txMetadata: "fake-tx-metadata",
      });
      throw new Error("expected relay to be frozen");
    } catch (error) {
      expect(isVaultSigningFrozenError(error)).toBe(true);
    }

    // Read-only balance still works while frozen.
    const balance = await vault.getMoneroBalance({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      walletScope: SCOPE,
    });
    expect(balance.balancePiconero).toBe(5_000_000_000_000n);
  });

  test("break-glass export returns spend/view keys and restore height", async () => {
    const { vault } = await freshVault();
    const wallet = await vault.createWallet({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      chainType: "monero",
    });

    await expect(vault.exportPrivateKey(TENANT_ID, AGENT_ID)).rejects.toThrow(/break-glass/);

    const exported = await vault.exportPrivateKey(TENANT_ID, AGENT_ID, {
      breakGlass: true,
      actorId: "test-admin",
      reason: "lifecycle test",
    });
    expect(exported.monero).toHaveLength(1);
    const entry = exported.monero?.[0];
    expect(entry?.address).toBe(wallet.address);
    expect(entry?.spendKey).toMatch(/^[0-9a-f]{64}$/);
    expect(entry?.viewKey).toMatch(/^[0-9a-f]{64}$/);
    expect(entry?.venue).toBe(SCOPE);
    expect(entry?.restoreHeight).toBeGreaterThan(0);
  });
});
