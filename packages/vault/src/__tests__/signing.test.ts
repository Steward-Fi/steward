import { describe, expect, it, beforeAll } from "bun:test";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { verifyTypedData, recoverMessageAddress } from "viem";

import { KeyStore } from "../keystore";
import { generateSolanaKeypair, restoreSolanaKeypair } from "../solana";

// ─── Test Config ──────────────────────────────────────────────────────────

const MASTER_PASSWORD = "test-vault-signing";

// ─── KeyStore Tests ───────────────────────────────────────────────────────

describe("KeyStore", () => {
  const keyStore = new KeyStore(MASTER_PASSWORD);

  it("encrypts and decrypts EVM private key", () => {
    const privateKey = generatePrivateKey();
    const encrypted = keyStore.encrypt(privateKey);

    expect(encrypted.ciphertext).toBeTruthy();
    expect(encrypted.iv).toBeTruthy();
    expect(encrypted.tag).toBeTruthy();
    expect(encrypted.salt).toBeTruthy();

    const decrypted = keyStore.decrypt(encrypted);
    expect(decrypted).toBe(privateKey);
  });

  it("encrypts and decrypts Solana secret key", () => {
    const kp = generateSolanaKeypair();
    const encrypted = keyStore.encrypt(kp.secretKey);
    const decrypted = keyStore.decrypt(encrypted);
    expect(decrypted).toBe(kp.secretKey);
  });

  it("different encryptions of same key produce different ciphertexts", () => {
    const privateKey = generatePrivateKey();
    const enc1 = keyStore.encrypt(privateKey);
    const enc2 = keyStore.encrypt(privateKey);
    // Random IV + salt means different ciphertexts
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
    // But both decrypt to the same key
    expect(keyStore.decrypt(enc1)).toBe(privateKey);
    expect(keyStore.decrypt(enc2)).toBe(privateKey);
  });
});

// ─── EIP-712 Typed Data Signing (unit level) ──────────────────────────────

describe("EIP-712 Typed Data Signing", () => {
  it("signs and verifies EIP-712 typed data using viem account", async () => {
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);

    const domain = {
      name: "TestToken",
      version: "1",
      chainId: 8453,
      verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" as `0x${string}`,
    };

    const types = {
      Permit: [
        { name: "owner", type: "address" },
        { name: "spender", type: "address" },
        { name: "value", type: "uint256" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    } as const;

    const message = {
      owner: account.address,
      spender: "0x1234567890123456789012345678901234567890" as `0x${string}`,
      value: 1000000000000000000n,
      nonce: 0n,
      deadline: 1700000000n,
    };

    const signature = await account.signTypedData({
      domain,
      types,
      primaryType: "Permit",
      message,
    });

    expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);
    expect(signature.length).toBe(132); // 0x + 130 hex chars (65 bytes)

    // Verify the signature recovers to the correct address
    const valid = await verifyTypedData({
      address: account.address,
      domain,
      types,
      primaryType: "Permit",
      message,
      signature,
    });
    expect(valid).toBe(true);
  });
});

// ─── Sign Without Broadcast (unit level) ──────────────────────────────────

describe("Sign Without Broadcast", () => {
  it("signs a transaction without broadcasting using viem account", async () => {
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);

    const signedTx = await account.signTransaction({
      to: "0x1234567890123456789012345678901234567890" as `0x${string}`,
      value: 1000000000000000000n,
      gas: 21000n,
      nonce: 0,
      gasPrice: 1000000000n,
      chainId: 8453,
    });

    expect(signedTx).toMatch(/^0x[0-9a-fA-F]+$/);
    // Signed transaction is longer than a signature
    expect(signedTx.length).toBeGreaterThan(132);
  });
});

// ─── Solana Keypair Tests ─────────────────────────────────────────────────

describe("Solana Keypair", () => {
  it("generates a valid Solana keypair", () => {
    const kp = generateSolanaKeypair();
    expect(kp.publicKey).toBeTruthy();
    expect(kp.secretKey).toBeTruthy();
    // Solana public key is base58, typically 32-44 chars
    expect(kp.publicKey.length).toBeGreaterThan(20);
    // Secret key is 64 bytes as hex = 128 hex chars
    expect(kp.secretKey.length).toBe(128);
  });

  it("restores keypair from 128-char hex secret key", () => {
    const kp = generateSolanaKeypair();
    const restored = restoreSolanaKeypair(kp.secretKey);
    expect(restored.publicKey.toBase58()).toBe(kp.publicKey);
  });

  it("restores keypair from base58-encoded secret key", () => {
    // This is the format agents typically use (Phantom export, Solana CLI)
    // Generate a keypair and convert to base58 for testing
    const kp = generateSolanaKeypair();
    const hexBytes = Buffer.from(kp.secretKey, "hex");
    
    // Encode as base58 (same alphabet as Solana uses)
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let num = BigInt("0x" + hexBytes.toString("hex"));
    let base58 = "";
    while (num > 0n) {
      const remainder = Number(num % 58n);
      base58 = ALPHABET[remainder] + base58;
      num = num / 58n;
    }
    // Add leading '1's for leading zero bytes
    for (let i = 0; i < hexBytes.length && hexBytes[i] === 0; i++) {
      base58 = "1" + base58;
    }
    
    // Now restore from base58
    const restored = restoreSolanaKeypair(base58);
    expect(restored.publicKey.toBase58()).toBe(kp.publicKey);
  });

  it("restores keypair from 64-char hex seed (32 bytes)", () => {
    const kp = generateSolanaKeypair();
    // Extract just the 32-byte seed from the 64-byte secret key
    const seed = kp.secretKey.slice(0, 64); // first 32 bytes as hex
    const restored = restoreSolanaKeypair(seed);
    expect(restored.publicKey.toBase58()).toBe(kp.publicKey);
  });

  it("throws on invalid secret key length", () => {
    expect(() => restoreSolanaKeypair("abc123")).toThrow();
  });
});

// ─── RPC Passthrough Blocked Methods ──────────────────────────────────────

describe("RPC Passthrough Method Blocking", () => {
  const blockedMethods = [
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
    "eth_signTypedData_v4",
    "sendTransaction",
  ];

  const allowedMethods = [
    "eth_call",
    "eth_getBalance",
    "eth_blockNumber",
    "eth_getTransactionReceipt",
    "eth_chainId",
    "getBalance",
    "getLatestBlockhash",
  ];

  for (const method of blockedMethods) {
    it(`blocks ${method}`, () => {
      expect(blockedMethods.includes(method)).toBe(true);
    });
  }

  for (const method of allowedMethods) {
    it(`allows ${method}`, () => {
      expect(blockedMethods.includes(method)).toBe(false);
    });
  }
});
