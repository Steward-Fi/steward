import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { p2tr, p2wpkh, TEST_NETWORK, Transaction } from "@scure/btc-signer";
import { pubECDSA, pubSchnorr } from "@scure/btc-signer/utils.js";
import { auditEvents, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `bitcoin-psbt-tenant-${Date.now()}`;
const AGENT_ID = `bitcoin-psbt-agent-${Date.now()}`;
const DENIED_AGENT_ID = `bitcoin-psbt-denied-agent-${Date.now()}`;
const SPEND_LIMIT_AGENT_ID = `bitcoin-psbt-spend-agent-${Date.now()}`;
const TAPROOT_AGENT_ID = `bitcoin-psbt-taproot-agent-${Date.now()}`;
const ALLOWED_RECIPIENT = p2wpkh(pubECDSA(new Uint8Array(32).fill(7)), TEST_NETWORK).address!;
const DENIED_RECIPIENT = p2wpkh(pubECDSA(new Uint8Array(32).fill(8)), TEST_NETWORK).address!;
const TAPROOT_RECIPIENT = p2tr(pubSchnorr(new Uint8Array(32).fill(12)), undefined, TEST_NETWORK)
  .address!;

function decodeHex(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function buildSpendableP2wpkhPsbt(publicKey: string, recipient = ALLOWED_RECIPIENT): string {
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(9),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2wpkh(decodeHex(publicKey)).script,
    },
  });
  tx.addOutputAddress(recipient, 40_000n, TEST_NETWORK);
  return encodeBase64(tx.toPSBT());
}

function buildSpendableP2wpkhPsbtWithChange(publicKey: string, changeAddress: string): string {
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(13),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2wpkh(decodeHex(publicKey)).script,
    },
  });
  tx.addOutputAddress(ALLOWED_RECIPIENT, 30_000n, TEST_NETWORK);
  tx.addOutputAddress(changeAddress, 15_000n, TEST_NETWORK);
  return encodeBase64(tx.toPSBT());
}

function buildSpendableP2trPsbt(xOnlyPublicKey: string, recipient = TAPROOT_RECIPIENT): string {
  const internalKey = decodeHex(xOnlyPublicKey);
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(12),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2tr(internalKey, undefined, TEST_NETWORK).script,
    },
    tapInternalKey: internalKey,
  });
  tx.addOutputAddress(recipient, 40_000n, TEST_NETWORK);
  return encodeBase64(tx.toPSBT());
}

function buildHighFeeP2wpkhPsbt(publicKey: string): string {
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(11),
    index: 0,
    witnessUtxo: {
      amount: 200_000n,
      script: p2wpkh(decodeHex(publicKey)).script,
    },
  });
  tx.addOutputAddress(ALLOWED_RECIPIENT, 40_000n, TEST_NETWORK);
  return encodeBase64(tx.toPSBT());
}

function buildPartiallySpendableP2wpkhPsbt(publicKey: string): string {
  const otherPublicKey = pubECDSA(new Uint8Array(32).fill(10));
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(9),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2wpkh(decodeHex(publicKey)).script,
    },
  });
  tx.addInput({
    txid: new Uint8Array(32).fill(10),
    index: 0,
    witnessUtxo: {
      amount: 30_000n,
      script: p2wpkh(otherPublicKey).script,
    },
  });
  tx.addOutputAddress(ALLOWED_RECIPIENT, 70_000n, TEST_NETWORK);
  return encodeBase64(tx.toPSBT());
}

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("userId", "bitcoin-psbt-admin");
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault Bitcoin PSBT signing", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let walletScope = "";
  let walletPublicKey = "";
  let changeWalletAddress = "";
  let spendLimitWalletScope = "";
  let spendLimitWalletPublicKey = "";
  let taprootWalletScope = "";
  let taprootWalletXOnlyPublicKey = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-bitcoin-psbt-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Bitcoin PSBT Tenant",
      apiKeyHash: "hash",
    });
    const vault = new Vault({ masterPassword: process.env.STEWARD_MASTER_PASSWORD });
    await vault.createAgent(TENANT_ID, AGENT_ID, "Bitcoin PSBT Agent");
    await vault.createAgent(TENANT_ID, DENIED_AGENT_ID, "Bitcoin PSBT Denied Agent");
    await vault.createAgent(TENANT_ID, SPEND_LIMIT_AGENT_ID, "Bitcoin PSBT Spend Agent");
    await vault.createAgent(TENANT_ID, TAPROOT_AGENT_ID, "Bitcoin PSBT Taproot Agent");
    const wallet = await vault.createWallet({
      agentId: AGENT_ID,
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2wpkh" },
    });
    const changeWallet = await vault.createWallet({
      agentId: AGENT_ID,
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2wpkh", index: 1 },
    });
    await vault.createWallet({
      agentId: DENIED_AGENT_ID,
      scope: wallet.venue ?? undefined,
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2wpkh" },
    });
    const spendLimitWallet = await vault.createWallet({
      agentId: SPEND_LIMIT_AGENT_ID,
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2wpkh" },
    });
    const taprootWallet = await vault.createWallet({
      agentId: TAPROOT_AGENT_ID,
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2tr" },
    });
    walletScope = wallet.venue ?? "";
    walletPublicKey = (wallet.metadata.bitcoin as { publicKey: string }).publicKey;
    changeWalletAddress = changeWallet.address;
    spendLimitWalletScope = spendLimitWallet.venue ?? "";
    spendLimitWalletPublicKey = (spendLimitWallet.metadata.bitcoin as { publicKey: string })
      .publicKey;
    taprootWalletScope = taprootWallet.venue ?? "";
    taprootWalletXOnlyPublicKey = (taprootWallet.metadata.bitcoin as { xOnlyPublicKey: string })
      .xOnlyPublicKey;
    await getDb()
      .insert(policies)
      .values([
        {
          id: `${AGENT_ID}-bitcoin-raw-signing`,
          agentId: AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["bitcoin"], allowedCurves: ["secp256k1"] },
        },
        {
          id: `${AGENT_ID}-bitcoin-addresses`,
          agentId: AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [ALLOWED_RECIPIENT], mode: "whitelist" },
        },
        {
          id: `${DENIED_AGENT_ID}-bitcoin-raw-signing`,
          agentId: DENIED_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["sui"], allowedCurves: ["ed25519"] },
        },
        {
          id: `${SPEND_LIMIT_AGENT_ID}-bitcoin-raw-signing`,
          agentId: SPEND_LIMIT_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["bitcoin"], allowedCurves: ["secp256k1"] },
        },
        {
          id: `${SPEND_LIMIT_AGENT_ID}-bitcoin-addresses`,
          agentId: SPEND_LIMIT_AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [ALLOWED_RECIPIENT], mode: "whitelist" },
        },
        {
          id: `${TAPROOT_AGENT_ID}-bitcoin-raw-signing`,
          agentId: TAPROOT_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["bitcoin"], allowedCurves: ["secp256k1"] },
        },
        {
          id: `${TAPROOT_AGENT_ID}-bitcoin-addresses`,
          agentId: TAPROOT_AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [TAPROOT_RECIPIENT], mode: "whitelist" },
        },
      ]);
    app = await makeApp();
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("signs a scoped Bitcoin P2WPKH PSBT through the guarded API route", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(walletPublicKey),
        referenceId: "btc-psbt-1",
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        signedPsbtBase64: string;
        signedInputs: number;
        addressType: string;
        network: string;
        walletScope: string;
        walletAddress: string;
        transactionId: string;
      };
    };

    expect(body.ok).toBe(true);
    expect(body.data.signedInputs).toBe(1);
    expect(body.data.addressType).toBe("p2wpkh");
    expect(body.data.network).toBe("testnet");
    expect(body.data.walletScope).toBe(walletScope);
    expect(body.data.transactionId).toBeTruthy();
    const [stored] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.transactionId));
    expect(stored).toMatchObject({
      agentId: AGENT_ID,
      status: "signed",
      value: "50000",
      chainId: 202,
      actionType: "bitcoin_psbt",
    });

    const signed = Transaction.fromPSBT(decodeBase64(body.data.signedPsbtBase64));
    signed.finalize();
    expect(signed.hex).toContain("0001");
  });

  it("optionally finalizes a scoped Bitcoin PSBT without broadcasting it", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(walletPublicKey),
        finalize: true,
        referenceId: "btc-psbt-finalize-1",
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        signedPsbtBase64: string;
        signedInputs: number;
        finalizedTxHex?: string;
        txId?: string;
        vsize?: number;
        feeSats?: string;
      };
    };

    expect(body.ok).toBe(true);
    expect(body.data.signedInputs).toBe(1);
    const finalizedTxHex = body.data.finalizedTxHex;
    expect(finalizedTxHex).toMatch(/^[0-9a-f]+$/);
    if (!finalizedTxHex) throw new Error("missing finalizedTxHex");
    expect(body.data.txId).toMatch(/^[0-9a-f]{64}$/);
    expect(body.data.vsize).toBeGreaterThan(0);
    expect(body.data.feeSats).toBe("10000");
    expect(Transaction.fromRaw(decodeHex(`0x${finalizedTxHex}`)).id).toBe(body.data.txId);
  });

  it("treats same-agent same-network Bitcoin wallet outputs as change", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildSpendableP2wpkhPsbtWithChange(walletPublicKey, changeWalletAddress),
        referenceId: "btc-psbt-change-1",
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { transactionId: string };
    };
    expect(body.ok).toBe(true);
    const [stored] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.transactionId));
    expect(stored).toMatchObject({
      agentId: AGENT_ID,
      status: "signed",
      value: "35000",
      chainId: 202,
      actionType: "bitcoin_psbt",
    });
    expect(stored.actionPayload).toMatchObject({
      destinationTotalSats: "30000",
      feeSats: "5000",
      spendSats: "35000",
      changeOutputCount: 1,
    });
  });

  it("signs and finalizes a scoped Bitcoin P2TR PSBT through the guarded API route", async () => {
    const response = await app.request(`/vault/${TAPROOT_AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope: taprootWalletScope,
        psbtBase64: buildSpendableP2trPsbt(taprootWalletXOnlyPublicKey),
        finalize: true,
        referenceId: "btc-psbt-taproot-1",
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        signedInputs: number;
        addressType: string;
        finalizedTxHex?: string;
        txId?: string;
        feeSats?: string;
        transactionId: string;
      };
    };

    expect(body.ok).toBe(true);
    expect(body.data.signedInputs).toBe(1);
    expect(body.data.addressType).toBe("p2tr");
    expect(body.data.finalizedTxHex).toMatch(/^[0-9a-f]+$/);
    expect(body.data.txId).toMatch(/^[0-9a-f]{64}$/);
    expect(body.data.feeSats).toBe("10000");
    const [stored] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.transactionId));
    expect(stored).toMatchObject({
      agentId: TAPROOT_AGENT_ID,
      status: "signed",
      value: "50000",
      chainId: 202,
      txHash: body.data.txId,
      actionType: "bitcoin_psbt",
    });
  });

  it("returns 400 without raw transaction data when finalizing a partially spendable PSBT fails", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildPartiallySpendableP2wpkhPsbt(walletPublicKey),
        finalize: true,
        referenceId: "btc-psbt-finalize-partial",
      }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: unknown;
    };

    expect(body.ok).toBe(false);
    expect(body.error).toContain("Bitcoin PSBT finalization failed");
    expect("data" in body).toBe(false);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain("finalizedTxHex");
    expect(serialized).not.toContain("signedPsbtBase64");
    const [failedAudit] = await getDb()
      .select({ metadata: auditEvents.metadata })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.action, "vault.bitcoin_psbt.sign.failed"),
        ),
      );
    expect(failedAudit?.metadata).toMatchObject({
      walletScope,
      finalize: true,
      referenceId: "btc-psbt-finalize-partial",
      error: "Bitcoin PSBT finalization failed",
      failureKind: "finalization",
    });
    const auditSerialized = JSON.stringify(failedAudit?.metadata);
    expect(auditSerialized).not.toContain("finalizedTxHex");
    expect(auditSerialized).not.toContain("signedPsbtBase64");
  });

  it("rejects PSBTs whose decoded destination output is outside the address policy", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(walletPublicKey, DENIED_RECIPIENT),
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: {
        output?: { address?: string; amountSats?: string };
        policyResults?: Array<{ type: string; passed: boolean; reason?: string }>;
      };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Bitcoin PSBT signing rejected by policy");
    expect(body.data?.output).toMatchObject({
      address: DENIED_RECIPIENT,
      amountSats: "40000",
    });
    expect(
      body.data?.policyResults?.find((result) => result.type === "approved-addresses"),
    ).toMatchObject({
      passed: false,
    });
  });

  it("rejects PSBTs that burn excessive value as Bitcoin miner fee", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildHighFeeP2wpkhPsbt(walletPublicKey),
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { feeSats?: string; maxFeeSats?: string };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Bitcoin PSBT fee exceeds configured maximum");
    expect(body.data).toEqual({ feeSats: "160000", maxFeeSats: "100000" });
  });

  it("rejects Bitcoin PSBT signing when scoped policy does not allow bitcoin", async () => {
    const response = await app.request(`/vault/${DENIED_AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(walletPublicKey),
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { policyResults?: Array<{ type: string; passed: boolean }> };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Bitcoin PSBT signing rejected by policy");
    expect(body.data?.policyResults?.some((result) => result.type === "raw-signing-chain")).toBe(
      true,
    );
  });

  it("rejects oversized or non-base64 PSBT bodies before vault signing", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ walletScope, psbtBase64: "not a psbt" }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("psbtBase64");
  });

  it("returns a client-safe 400 for base64-valid malformed PSBT payloads", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ walletScope, psbtBase64: "AAAA" }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Malformed Bitcoin PSBT");
  });

  it("rejects non-boolean finalize flags before vault signing", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(walletPublicKey),
        finalize: "yes",
      }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("finalize must be a boolean");
  });

  it("counts signed Bitcoin PSBT spend against later spending-limit evaluations", async () => {
    const policyId = `${SPEND_LIMIT_AGENT_ID}-bitcoin-spend-limit`;
    await getDb()
      .insert(policies)
      .values({
        id: policyId,
        agentId: SPEND_LIMIT_AGENT_ID,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "60000", maxPerDay: "60000", maxPerWeek: "60000" },
      });

    const first = await app.request(`/vault/${SPEND_LIMIT_AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope: spendLimitWalletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(spendLimitWalletPublicKey),
        referenceId: "btc-spend-counter-1",
      }),
    });
    expect(first.status).toBe(200);

    const second = await app.request(`/vault/${SPEND_LIMIT_AGENT_ID}/sign-bitcoin-psbt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        walletScope: spendLimitWalletScope,
        psbtBase64: buildSpendableP2wpkhPsbt(spendLimitWalletPublicKey),
        referenceId: "btc-spend-counter-2",
      }),
    });
    expect(second.status).toBe(403);
    const body = (await second.json()) as {
      ok: boolean;
      data?: {
        output?: { address?: string; amountSats?: string };
        aggregate?: { destinationTotalSats?: string; feeSats?: string; spendSats?: string };
        policyResults?: Array<{ type: string; passed: boolean; reason?: string; aggregate?: true }>;
      };
    };
    expect(body.ok).toBe(false);
    expect(body.data?.output).toMatchObject({
      address: ALLOWED_RECIPIENT,
      amountSats: "40000",
    });
    expect(
      body.data?.policyResults?.find(
        (result) => result.type === "spending-limit" && result.passed === false,
      ),
    ).toMatchObject({ passed: false });
  });
});
