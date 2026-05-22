import { describe, expect, test } from "bun:test";
import { privateKeyToAddress } from "viem/accounts";

import {
  deriveEvmKey,
  deriveSolanaKey,
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
} from "../hd-wallet";

// Standard test vector that the entire HD-wallet ecosystem uses:
//   trezor wordlist, BIP-39 spec test vectors.
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("BIP-39 mnemonic", () => {
  test("generateMnemonic produces a valid mnemonic at each strength", () => {
    for (const strength of [128, 160, 192, 224, 256] as const) {
      const m = generateMnemonic(strength);
      expect(isValidMnemonic(m)).toBe(true);
      // 128 → 12 words, 256 → 24 words, etc.
      const expectedWords = (strength / 32) * 3;
      expect(m.split(/\s+/).length).toBe(expectedWords);
    }
  });

  test("generateMnemonic throws on bad strength", () => {
    expect(() => generateMnemonic(100 as 128)).toThrow();
    expect(() => generateMnemonic(0 as 128)).toThrow();
  });

  test("two generations produce different mnemonics", () => {
    expect(generateMnemonic(128)).not.toBe(generateMnemonic(128));
  });

  test("isValidMnemonic rejects checksum mismatches and bad wordlists", () => {
    expect(isValidMnemonic(TEST_MNEMONIC)).toBe(true);
    // Swap last word with another valid wordlist word — checksum should fail.
    const broken = TEST_MNEMONIC.replace(/about$/, "ability");
    expect(isValidMnemonic(broken)).toBe(false);
    expect(isValidMnemonic("totally not a phrase")).toBe(false);
    expect(isValidMnemonic("")).toBe(false);
  });

  test("mnemonicToSeed matches the BIP-39 spec vector for the test mnemonic", async () => {
    const seed = await mnemonicToSeed(TEST_MNEMONIC);
    // BIP-39 spec vector — bytes-to-hex of the 64-byte seed for the
    // all-abandon mnemonic with empty passphrase.
    const expected =
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    const actualHex = [...seed].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(actualHex).toBe(expected);
  });
});

describe("EVM derivation (BIP-44 path m/44'/60'/0'/0/0)", () => {
  test("derives the canonical MetaMask first address for the test mnemonic", async () => {
    const { privateKey, path } = await deriveEvmKey(TEST_MNEMONIC);
    expect(path).toBe("m/44'/60'/0'/0/0");
    // Pinned: this is the well-known first address for the all-abandon phrase
    // (every major wallet — MetaMask, Trust, Rabby — yields the same).
    const expectedAddress = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const addr = privateKeyToAddress(privateKey);
    expect(addr).toBe(expectedAddress);
  });

  test("different account/index values yield different keys", async () => {
    const a = await deriveEvmKey(TEST_MNEMONIC, { index: 0 });
    const b = await deriveEvmKey(TEST_MNEMONIC, { index: 1 });
    const c = await deriveEvmKey(TEST_MNEMONIC, { account: 1, index: 0 });
    expect(a.privateKey).not.toBe(b.privateKey);
    expect(a.privateKey).not.toBe(c.privateKey);
    expect(b.privateKey).not.toBe(c.privateKey);
  });

  test("same inputs are deterministic across calls", async () => {
    const a = await deriveEvmKey(TEST_MNEMONIC, { index: 7 });
    const b = await deriveEvmKey(TEST_MNEMONIC, { index: 7 });
    expect(a.privateKey).toBe(b.privateKey);
    expect(a.publicKey).toBe(b.publicKey);
  });

  test("passphrase changes the derived key (BIP-39 25th-word)", async () => {
    const a = await deriveEvmKey(TEST_MNEMONIC);
    const b = await deriveEvmKey(TEST_MNEMONIC, { passphrase: "TREZOR" });
    expect(a.privateKey).not.toBe(b.privateKey);
  });

  test("rejects invalid mnemonic and negative indices", async () => {
    await expect(deriveEvmKey("not a real phrase")).rejects.toThrow();
    await expect(deriveEvmKey(TEST_MNEMONIC, { index: -1 })).rejects.toThrow();
    await expect(deriveEvmKey(TEST_MNEMONIC, { account: -1 })).rejects.toThrow();
  });
});

describe("Solana derivation (SLIP-10 path m/44'/501'/account'/0')", () => {
  test("returns a 32-byte secret and 32-byte public key at the standard path", async () => {
    const { secretKey, publicKey, path } = await deriveSolanaKey(TEST_MNEMONIC);
    expect(secretKey.length).toBe(32);
    expect(publicKey.length).toBe(32);
    expect(path).toBe("m/44'/501'/0'/0'");
  });

  test("derivation is deterministic for the same mnemonic + account", async () => {
    const a = await deriveSolanaKey(TEST_MNEMONIC, { account: 3 });
    const b = await deriveSolanaKey(TEST_MNEMONIC, { account: 3 });
    expect(Array.from(a.secretKey)).toEqual(Array.from(b.secretKey));
  });

  test("different accounts yield different keys", async () => {
    const a = await deriveSolanaKey(TEST_MNEMONIC, { account: 0 });
    const b = await deriveSolanaKey(TEST_MNEMONIC, { account: 1 });
    expect(Array.from(a.secretKey)).not.toEqual(Array.from(b.secretKey));
  });
});
