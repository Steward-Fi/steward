import { describe, expect, test } from "bun:test";
import { p2tr, p2wpkh, TEST_NETWORK, Transaction } from "@scure/btc-signer";
import { pubECDSA, pubSchnorr } from "@scure/btc-signer/utils.js";

import {
  extractBitcoinPsbtOutputs,
  inspectBitcoinPsbt,
  parseBitcoinPsbtSigningMetadata,
  signBitcoinPsbt,
} from "../bitcoin-psbt";

const PRIVATE_KEY = `0x${"01".repeat(32)}`;
const OTHER_PRIVATE_KEY = `0x${"02".repeat(32)}`;

function decodeHex0x(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function encodeHex0x(bytes: Uint8Array): `0x${string}` {
  let out = "0x";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out as `0x${string}`;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function buildSpendableP2wpkhPsbt(privateKey = PRIVATE_KEY): string {
  const key = decodeHex0x(privateKey);
  const pubKey = pubECDSA(key);
  const recipient = p2wpkh(pubECDSA(decodeHex0x(OTHER_PRIVATE_KEY)), TEST_NETWORK);
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(1),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2wpkh(pubKey).script,
    },
  });
  tx.addOutput({ amount: 40_000n, script: recipient.script });
  return encodeBase64(tx.toPSBT());
}

function buildSpendableP2trPsbt(privateKey = PRIVATE_KEY): string {
  const key = decodeHex0x(privateKey);
  const xOnlyPublicKey = pubSchnorr(key);
  const wallet = p2tr(xOnlyPublicKey, undefined, TEST_NETWORK);
  const recipient = p2tr(pubSchnorr(decodeHex0x(OTHER_PRIVATE_KEY)), undefined, TEST_NETWORK);
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(3),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: wallet.script,
    },
    tapInternalKey: xOnlyPublicKey,
  });
  tx.addOutput({ amount: 40_000n, script: recipient.script });
  return encodeBase64(tx.toPSBT());
}

function buildPartiallySpendableP2wpkhPsbt(): string {
  const walletPubKey = pubECDSA(decodeHex0x(PRIVATE_KEY));
  const otherPubKey = pubECDSA(decodeHex0x(OTHER_PRIVATE_KEY));
  const recipient = p2wpkh(otherPubKey, TEST_NETWORK);
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(1),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2wpkh(walletPubKey).script,
    },
  });
  tx.addInput({
    txid: new Uint8Array(32).fill(2),
    index: 0,
    witnessUtxo: {
      amount: 30_000n,
      script: p2wpkh(otherPubKey).script,
    },
  });
  tx.addOutput({ amount: 70_000n, script: recipient.script });
  return encodeBase64(tx.toPSBT());
}

function buildNonStandardOutputP2wpkhPsbt(): string {
  const key = decodeHex0x(PRIVATE_KEY);
  const pubKey = pubECDSA(key);
  const tx = new Transaction({ version: 2 });
  tx.addInput({
    txid: new Uint8Array(32).fill(4),
    index: 0,
    witnessUtxo: {
      amount: 50_000n,
      script: p2wpkh(pubKey).script,
    },
  });
  tx.addOutput({ amount: 40_000n, script: new Uint8Array([0x6a, 0x01, 0x00]) });
  return encodeBase64(tx.toPSBT());
}

function signingMetadata(privateKey = PRIVATE_KEY) {
  const key = decodeHex0x(privateKey);
  return {
    bitcoin: {
      network: "testnet" as const,
      addressType: "p2wpkh" as const,
      publicKey: encodeHex0x(pubECDSA(key)),
      xOnlyPublicKey: encodeHex0x(pubSchnorr(key)),
    },
  };
}

function taprootSigningMetadata(privateKey = PRIVATE_KEY) {
  const key = decodeHex0x(privateKey);
  return {
    bitcoin: {
      network: "testnet" as const,
      addressType: "p2tr" as const,
      publicKey: encodeHex0x(pubECDSA(key)),
      xOnlyPublicKey: encodeHex0x(pubSchnorr(key)),
    },
  };
}

describe("Bitcoin PSBT signing", () => {
  test("signs a P2WPKH PSBT and leaves it finalizable by the caller", () => {
    const result = signBitcoinPsbt({
      psbtBase64: buildSpendableP2wpkhPsbt(),
      privateKey: PRIVATE_KEY,
      walletMetadata: signingMetadata(),
    });

    expect(result.signedInputs).toBe(1);
    expect(result.addressType).toBe("p2wpkh");
    expect(result.network).toBe("testnet");

    const signed = Transaction.fromPSBT(
      Uint8Array.from(atob(result.signedPsbtBase64), (char) => char.charCodeAt(0)),
    );
    signed.finalize();
    expect(signed.hex).toContain("0001");
  });

  test("signs and finalizes a key-path P2TR PSBT", () => {
    const result = signBitcoinPsbt({
      psbtBase64: buildSpendableP2trPsbt(),
      privateKey: PRIVATE_KEY,
      walletMetadata: taprootSigningMetadata(),
      finalize: true,
    });

    expect(result.signedInputs).toBe(1);
    expect(result.addressType).toBe("p2tr");
    expect(result.finalizedTxHex).toMatch(/^[0-9a-f]+$/);
    expect(result.txId).toMatch(/^[0-9a-f]{64}$/);
    expect(result.feeSats).toBe("10000");
  });

  test("optionally finalizes a signed PSBT and returns broadcast-ready transaction metadata", () => {
    const result = signBitcoinPsbt({
      psbtBase64: buildSpendableP2wpkhPsbt(),
      privateKey: PRIVATE_KEY,
      walletMetadata: signingMetadata(),
      finalize: true,
    });

    expect(result.signedInputs).toBe(1);
    expect(result.finalizedTxHex).toMatch(/^[0-9a-f]+$/);
    expect(result.finalizedTxHex).toContain("0001");
    expect(result.txId).toMatch(/^[0-9a-f]{64}$/);
    expect(result.vsize).toBeGreaterThan(0);
    expect(result.feeSats).toBe("10000");

    const finalized = Transaction.fromRaw(decodeHex0x(`0x${result.finalizedTxHex}`));
    expect(finalized.id).toBe(result.txId);
  });

  test("fails finalization when only part of a PSBT is spendable by the wallet", () => {
    expect(() =>
      signBitcoinPsbt({
        psbtBase64: buildPartiallySpendableP2wpkhPsbt(),
        privateKey: PRIVATE_KEY,
        walletMetadata: signingMetadata(),
        finalize: true,
      }),
    ).toThrow(/^Bitcoin PSBT finalization failed/);
  });

  test("rejects malformed PSBT input", () => {
    expect(() =>
      signBitcoinPsbt({
        psbtBase64: "not base64",
        privateKey: PRIVATE_KEY,
        walletMetadata: signingMetadata(),
      }),
    ).toThrow(/Malformed Bitcoin PSBT|PSBT base64 decoding failed/);
  });

  test("extracts standard destination outputs for policy evaluation", () => {
    const outputs = extractBitcoinPsbtOutputs(buildSpendableP2wpkhPsbt(), signingMetadata());

    expect(outputs).toEqual([
      {
        index: 0,
        address: p2wpkh(pubECDSA(decodeHex0x(OTHER_PRIVATE_KEY)), TEST_NETWORK).address,
        amountSats: "40000",
      },
    ]);
  });

  test("rejects non-address outputs before policy extraction can undercount spend", () => {
    expect(() => inspectBitcoinPsbt(buildNonStandardOutputP2wpkhPsbt(), signingMetadata())).toThrow(
      /unknown output script type|does not contain a standard address|Malformed Bitcoin PSBT/,
    );
  });

  test("rejects missing or unsupported Bitcoin metadata", () => {
    expect(() => parseBitcoinPsbtSigningMetadata({})).toThrow(/metadata is required/);
    expect(() =>
      parseBitcoinPsbtSigningMetadata({
        bitcoin: {
          network: "signet" as "testnet",
          addressType: "p2wpkh",
          publicKey: signingMetadata().bitcoin.publicKey,
        },
      }),
    ).toThrow(/Unsupported Bitcoin wallet network/);
  });

  test("rejects private keys that do not match wallet metadata", () => {
    expect(() =>
      signBitcoinPsbt({
        psbtBase64: buildSpendableP2wpkhPsbt(),
        privateKey: OTHER_PRIVATE_KEY,
        walletMetadata: signingMetadata(),
      }),
    ).toThrow(/does not match wallet metadata publicKey/);
  });

  test("rejects Taproot metadata with a mismatched x-only public key", () => {
    expect(() =>
      signBitcoinPsbt({
        psbtBase64: buildSpendableP2trPsbt(),
        privateKey: PRIVATE_KEY,
        walletMetadata: {
          bitcoin: {
            ...taprootSigningMetadata().bitcoin,
            xOnlyPublicKey: encodeHex0x(pubSchnorr(decodeHex0x(OTHER_PRIVATE_KEY))),
          },
        },
      }),
    ).toThrow(/does not match wallet metadata xOnlyPublicKey/);
  });

  test("rejects PSBTs without inputs spendable by the wallet", () => {
    expect(() =>
      signBitcoinPsbt({
        psbtBase64: buildSpendableP2wpkhPsbt(OTHER_PRIVATE_KEY),
        privateKey: PRIVATE_KEY,
        walletMetadata: signingMetadata(),
      }),
    ).toThrow(/does not contain inputs spendable by this wallet/);
  });
});
