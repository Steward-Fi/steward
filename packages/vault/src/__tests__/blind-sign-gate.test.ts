import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "../vault";

/**
 * SEC-163 regression: the vault layer must fail closed on UNCONDITIONED
 * signing. Solana requests without the expectedTo/expectedValue policy
 * envelope and ALL Bitcoin PSBT requests (no envelope mechanism exists there)
 * require an explicit `allowBlindSign: true` caller attestation that edge
 * policy approved the payload.
 */

const MASTER_PASSWORD = "test-vault-blind-sign-gate";
const TENANT_ID = "vault-blind-sign-gate-tenant";
const AGENT_ID = "vault-blind-sign-gate-agent";
const RECENT_BLOCKHASH = new PublicKey(new Uint8Array(32).fill(7)).toBase58();

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

function toBase64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));
}

async function freshVault(): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Vault Blind Sign Gate Tenant",
    apiKeyHash: "test-hash",
  });

  return new Vault({ masterPassword: MASTER_PASSWORD });
}

async function createSolanaAgent(vault: Vault): Promise<PublicKey> {
  const identity = await vault.createAgent(TENANT_ID, AGENT_ID, "Blind Sign Gate Agent");
  const solanaAddress = identity.walletAddresses?.solana;
  if (!solanaAddress) throw new Error("test agent did not receive a Solana wallet");
  return new PublicKey(solanaAddress);
}

function nativeTransfer(feePayer: PublicKey, to: PublicKey, lamports: number): string {
  const tx = new Transaction({ feePayer, recentBlockhash: RECENT_BLOCKHASH }).add(
    SystemProgram.transfer({ fromPubkey: feePayer, toPubkey: to, lamports }),
  );
  return toBase64(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
}

describe("Vault blind-sign gate (SEC-163)", () => {
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

  test("signSolanaTransaction rejects an envelope-less request without allowBlindSign", async () => {
    const feePayer = await createSolanaAgent(vault);
    const tx = nativeTransfer(feePayer, PublicKey.unique(), 1_000);

    await expect(
      vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: tx,
        broadcast: false,
      }),
    ).rejects.toThrow(/governed execution grant/);
  });

  test("signSolanaTransaction rejects a caller-forged parsed execution object", async () => {
    const feePayer = await createSolanaAgent(vault);
    const tx = nativeTransfer(feePayer, PublicKey.unique(), 1_000);
    const forged = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      transaction: tx,
      broadcast: false,
      governedParsedSign: {
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        chainId: 101,
        broadcast: false,
        messageDigest: "attacker-controlled",
        executionPayloadDigest: "attacker-controlled",
      },
    } as unknown as Parameters<Vault["signSolanaTransaction"]>[0];

    await expect(vault.signSolanaTransaction(forged)).rejects.toThrow(/governed execution grant/);
  });

  test("signSolanaTransaction signs an envelope-less request with allowBlindSign: true", async () => {
    const feePayer = await createSolanaAgent(vault);
    const tx = nativeTransfer(feePayer, PublicKey.unique(), 1_000);

    const result = await vault.signSolanaTransaction({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      transaction: tx,
      broadcast: false,
      allowBlindSign: true,
    });

    expect(result.broadcast).toBe(false);
    expect(result.signature.length).toBeGreaterThan(0);
  });

  test("signSolanaTransaction still honors the envelope without the flag", async () => {
    const feePayer = await createSolanaAgent(vault);
    const recipient = PublicKey.unique();
    const tx = nativeTransfer(feePayer, recipient, 1_000);

    // Matching envelope: signs without allowBlindSign.
    const result = await vault.signSolanaTransaction({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      transaction: tx,
      broadcast: false,
      expectedTo: recipient.toBase58(),
      expectedValue: "1000",
    });
    expect(result.broadcast).toBe(false);

    // Mismatched envelope: the byte-level assertion still rejects.
    await expect(
      vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: tx,
        broadcast: false,
        expectedTo: PublicKey.unique().toBase58(),
        expectedValue: "1000",
      }),
    ).rejects.toThrow(/recipient does not match/i);
  });

  test("signBitcoinPsbt rejects without allowBlindSign before touching key material", async () => {
    await vault.createAgent(TENANT_ID, AGENT_ID, "Blind Sign Gate Agent");

    await expect(
      vault.signBitcoinPsbt({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        walletScope: "bitcoin:mainnet:0-0-0",
        psbtBase64: toBase64(new Uint8Array([1, 2, 3])),
      }),
    ).rejects.toThrow(/allowBlindSign/);
  });
});
