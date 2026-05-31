import { describe, expect, test } from "bun:test";
import { MockCustodialWalletAdapter } from "../adapters/custodial.js";
import { MockKycAdapter } from "../adapters/kyc.js";
import { MockTosAdapter } from "../adapters/tos.js";
import { AdapterUnavailableError, AdapterValidationError } from "../types.js";

// ─── KYC: privacy-preserving (never persists raw document bytes) ───────────────

describe("MockKycAdapter privacy", () => {
  test("startVerification begins pending", async () => {
    const kyc = new MockKycAdapter();
    const v = await kyc.startVerification({ userId: "user_1", level: "standard" });
    expect(v.status).toBe("pending");
    expect(v.documents).toHaveLength(0);
  });

  test("submitDocument stores ONLY a hash + descriptor, never raw content", async () => {
    const kyc = new MockKycAdapter();
    const started = await kyc.startVerification({ userId: "user_1", level: "basic" });

    const secret = "TOP-SECRET-PASSPORT-NUMBER-X9999";
    const content = new TextEncoder().encode(secret);
    const updated = await kyc.submitDocument({
      verificationId: started.id,
      documentType: "passport",
      content,
    });

    expect(updated.status).toBe("verified");
    expect(updated.documents).toHaveLength(1);
    const doc = updated.documents[0];
    // Only a 64-hex-char SHA-256 hash + byte length is retained.
    expect(doc.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.byteLength).toBe(content.byteLength);

    // The raw secret must NOT appear anywhere in the serialized record.
    const serialized = JSON.stringify(updated);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain("PASSPORT-NUMBER");
    // No `content`/`raw`/`bytes` field leaked.
    expect((doc as Record<string, unknown>).content).toBeUndefined();
  });

  test("hash is stable for identical bytes and differs for different bytes", async () => {
    const kyc = new MockKycAdapter();
    const v1 = await kyc.startVerification({ userId: "u", level: "basic" });
    const d1 = await kyc.submitDocument({
      verificationId: v1.id,
      documentType: "id",
      content: new TextEncoder().encode("abc"),
    });
    const v2 = await kyc.startVerification({ userId: "u", level: "basic" });
    const d2 = await kyc.submitDocument({
      verificationId: v2.id,
      documentType: "id",
      content: new TextEncoder().encode("abc"),
    });
    const v3 = await kyc.startVerification({ userId: "u", level: "basic" });
    const d3 = await kyc.submitDocument({
      verificationId: v3.id,
      documentType: "id",
      content: new TextEncoder().encode("xyz"),
    });
    expect(d1.documents[0].contentHash).toBe(d2.documents[0].contentHash);
    expect(d1.documents[0].contentHash).not.toBe(d3.documents[0].contentHash);
  });

  test("rejects empty document bytes", async () => {
    const kyc = new MockKycAdapter();
    const v = await kyc.startVerification({ userId: "u", level: "basic" });
    await expect(
      kyc.submitDocument({ verificationId: v.id, documentType: "id", content: new Uint8Array(0) }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects an invalid level", async () => {
    const kyc = new MockKycAdapter();
    await expect(
      // @ts-expect-error deliberately invalid level
      kyc.startVerification({ userId: "u", level: "platinum" }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects submitting to an unknown verification", async () => {
    const kyc = new MockKycAdapter();
    await expect(
      kyc.submitDocument({
        verificationId: "kyc_missing",
        documentType: "id",
        content: new TextEncoder().encode("a"),
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("getStatus returns null for unknown id", async () => {
    const kyc = new MockKycAdapter();
    expect(await kyc.getStatus("kyc_nope")).toBeNull();
  });
});

// ─── TOS ───────────────────────────────────────────────────────────────────────

describe("MockTosAdapter", () => {
  test("records and reads back an acceptance", async () => {
    const tos = new MockTosAdapter();
    const rec = await tos.recordAcceptance({ userId: "u1", documentId: "tos", version: "1.0" });
    expect(rec.version).toBe("1.0");
    const got = await tos.getAcceptance("u1", "tos");
    expect(got?.version).toBe("1.0");
  });

  test("isCurrentVersionAccepted reflects the latest accepted version", async () => {
    const tos = new MockTosAdapter();
    await tos.recordAcceptance({ userId: "u1", documentId: "tos", version: "1.0" });
    expect(await tos.isCurrentVersionAccepted("u1", "tos", "1.0")).toBe(true);
    expect(await tos.isCurrentVersionAccepted("u1", "tos", "2.0")).toBe(false);

    // Re-accept a newer version; the latest wins.
    await tos.recordAcceptance({ userId: "u1", documentId: "tos", version: "2.0" });
    expect(await tos.isCurrentVersionAccepted("u1", "tos", "2.0")).toBe(true);
    expect(await tos.isCurrentVersionAccepted("u1", "tos", "1.0")).toBe(false);
  });

  test("unaccepted document reads as null / not current", async () => {
    const tos = new MockTosAdapter();
    expect(await tos.getAcceptance("u1", "unseen")).toBeNull();
    expect(await tos.isCurrentVersionAccepted("u1", "unseen", "1.0")).toBe(false);
  });

  test("rejects an over-long ip", async () => {
    const tos = new MockTosAdapter();
    await expect(
      tos.recordAcceptance({ userId: "u1", documentId: "tos", version: "1.0", ip: "x".repeat(65) }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });
});

// ─── Custodial: NEVER fabricates a signature ───────────────────────────────────

describe("MockCustodialWalletAdapter fail-closed signing", () => {
  test("createCustodialWallet returns a placeholder address and never a key", async () => {
    const cust = new MockCustodialWalletAdapter();
    const wallet = await cust.createCustodialWallet({ userId: "u1", chain: "evm" });
    expect(wallet.custodied).toBe(true);
    expect(wallet.address).toBe("0x000000000000000000000000000000000000c0de");
    // No private key material is ever exposed on the wallet object.
    const serialized = JSON.stringify(wallet);
    expect(serialized.toLowerCase()).not.toContain("privatekey");
    expect(serialized.toLowerCase()).not.toContain("secret");
  });

  test("requestSignature ALWAYS fails closed — never returns a signature", async () => {
    const cust = new MockCustodialWalletAdapter();
    const wallet = await cust.createCustodialWallet({ userId: "u1", chain: "evm" });
    const result = await cust.requestSignature({
      walletId: wallet.id,
      payload: "0xdeadbeef",
      scheme: "evm-personal",
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("mock must never sign");
    expect(result.available).toBe(false);
    expect((result as Record<string, unknown>).signature).toBeUndefined();
    expect(result.reason).toContain("never");
  });

  test("requireSignature helper always throws AdapterUnavailableError", async () => {
    const cust = new MockCustodialWalletAdapter();
    const wallet = await cust.createCustodialWallet({ userId: "u1", chain: "evm" });
    await expect(
      cust.requireSignature({ walletId: wallet.id, payload: "0xab", scheme: "evm-tx" }),
    ).rejects.toBeInstanceOf(AdapterUnavailableError);
  });

  test("validates a malformed payload before refusing (clean 400-class error)", async () => {
    const cust = new MockCustodialWalletAdapter();
    const wallet = await cust.createCustodialWallet({ userId: "u1", chain: "evm" });
    await expect(
      cust.requestSignature({ walletId: wallet.id, payload: "not-hex", scheme: "evm-tx" }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects an unknown walletId", async () => {
    const cust = new MockCustodialWalletAdapter();
    await expect(
      cust.requestSignature({ walletId: "custodial_missing", payload: "0xab", scheme: "evm-tx" }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects an unsupported chain", async () => {
    const cust = new MockCustodialWalletAdapter();
    await expect(
      // @ts-expect-error deliberately invalid chain
      cust.createCustodialWallet({ userId: "u1", chain: "bitcoin" }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });
});
