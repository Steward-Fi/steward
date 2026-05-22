/**
 * HD wallet derivation — BIP-39 mnemonic + BIP-32 child-key derivation +
 * BIP-44 path conventions for EVM and Solana.
 *
 * This is the "12/24-word recovery phrase" UX consumer wallets ship. A user
 * generates a mnemonic once; every chain-specific keypair the wallet ever
 * uses is deterministically derived from it. The mnemonic is the entire
 * backup — write it down and you can re-create every key on every chain.
 *
 * Paths used here:
 *   EVM:    m/44'/60'/account'/0/index   (BIP-44 + Ethereum)
 *   Solana: m/44'/501'/account'/0'       (Phantom / Solflare convention)
 *
 * The EVM path is the canonical one used by every major wallet. The Solana
 * path matches Phantom's default; some wallets (Solflare deep paths) use
 * m/44'/501'/account'/0'/index' but Phantom's shape is far more widely
 * deployed and what users will recognize when they import a phrase.
 *
 * Mnemonic generation uses 128 bits of entropy for 12 words; 256 bits for
 * 24 words. Both are spec strengths. 24 words is recommended for any
 * material-value vault; 12 words is fine for ephemeral or low-value keys.
 *
 * Library: @scure/bip39 and @scure/bip32 — audited, no native deps.
 */

import { HDKey } from "@scure/bip32";
import * as bip39 from "@scure/bip39";
import { wordlist as englishWordlist } from "@scure/bip39/wordlists/english";

const EVM_PATH_PREFIX = "m/44'/60'";
const SOLANA_PATH_PREFIX = "m/44'/501'";

export type MnemonicStrength = 128 | 160 | 192 | 224 | 256;

/**
 * Generate a fresh BIP-39 mnemonic with the requested entropy.
 *   128 → 12 words   192 → 18 words   256 → 24 words
 * Defaults to 256 bits / 24 words.
 */
export function generateMnemonic(strength: MnemonicStrength = 256): string {
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw new Error("strength must be one of 128, 160, 192, 224, 256");
  }
  return bip39.generateMnemonic(englishWordlist, strength);
}

/** True if `mnemonic` is a valid BIP-39 phrase (checksum + wordlist verified). */
export function isValidMnemonic(mnemonic: string): boolean {
  if (typeof mnemonic !== "string") return false;
  return bip39.validateMnemonic(mnemonic.trim(), englishWordlist);
}

/** Derive the 64-byte BIP-39 seed (PBKDF2 with optional passphrase). */
export async function mnemonicToSeed(mnemonic: string, passphrase = ""): Promise<Uint8Array> {
  if (!isValidMnemonic(mnemonic)) {
    throw new Error("invalid mnemonic — checksum or wordlist mismatch");
  }
  return bip39.mnemonicToSeed(mnemonic.trim(), passphrase);
}

export interface DerivedEvmKey {
  /** 0x-prefixed 32-byte hex. */
  privateKey: `0x${string}`;
  /** Uncompressed public key, 65 bytes hex (0x04 || X || Y). */
  publicKey: `0x${string}`;
  path: string;
}

/**
 * Derive an EVM account at index `account/0/index` (BIP-44 / Ethereum spec).
 *
 * Default path m/44'/60'/0'/0/0 — what MetaMask and every reference wallet
 * use for the first account. Importing the same mnemonic into MetaMask
 * yields the same address.
 */
export async function deriveEvmKey(
  mnemonic: string,
  options: { account?: number; index?: number; passphrase?: string } = {},
): Promise<DerivedEvmKey> {
  const account = options.account ?? 0;
  const index = options.index ?? 0;
  if (!Number.isInteger(account) || account < 0) {
    throw new Error("account must be a non-negative integer");
  }
  if (!Number.isInteger(index) || index < 0) {
    throw new Error("index must be a non-negative integer");
  }
  const seed = await mnemonicToSeed(mnemonic, options.passphrase);
  const root = HDKey.fromMasterSeed(seed);
  const path = `${EVM_PATH_PREFIX}/${account}'/0/${index}`;
  const child = root.derive(path);
  if (!child.privateKey || !child.publicKey) {
    throw new Error("derivation failed (no key material)");
  }
  return {
    privateKey: bytesToHex0x(child.privateKey),
    publicKey: bytesToHex0x(uncompressSecp256k1(child.publicKey)),
    path,
  };
}

export interface DerivedSolanaKey {
  /** 32-byte Ed25519 seed (the canonical "private key" form for Solana). */
  secretKey: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  path: string;
}

/**
 * Derive a Solana keypair at Phantom's path m/44'/501'/account'/0'.
 *
 * Ed25519 derivation is SLIP-10 (hardened-only). The implementation here is
 * intentionally self-contained — it follows the SLIP-10 spec exactly so we
 * do not add another transitive dependency for one well-defined function.
 */
export async function deriveSolanaKey(
  mnemonic: string,
  options: { account?: number; passphrase?: string } = {},
): Promise<DerivedSolanaKey> {
  const account = options.account ?? 0;
  if (!Number.isInteger(account) || account < 0) {
    throw new Error("account must be a non-negative integer");
  }
  const seed = await mnemonicToSeed(mnemonic, options.passphrase);
  const path = `${SOLANA_PATH_PREFIX}/${account}'/0'`;

  // SLIP-10 Ed25519: each step uses HMAC-SHA-512 with the chain code as key.
  // The first step seeds from "ed25519 seed".
  const initial = await hmacSha512(new TextEncoder().encode("ed25519 seed"), seed);
  let key = initial.slice(0, 32);
  let chain = initial.slice(32, 64);

  const indices = [44 | 0x80000000, 501 | 0x80000000, account | 0x80000000, 0 | 0x80000000];
  for (const idx of indices) {
    const data = new Uint8Array(37);
    data[0] = 0x00;
    data.set(key, 1);
    data[33] = (idx >>> 24) & 0xff;
    data[34] = (idx >>> 16) & 0xff;
    data[35] = (idx >>> 8) & 0xff;
    data[36] = idx & 0xff;
    const I = await hmacSha512(chain, data);
    key = I.slice(0, 32);
    chain = I.slice(32, 64);
  }

  // Convert the 32-byte Ed25519 seed to the public key via the noble curves
  // wrapper that @scure/bip32 already brings in.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const publicKey = ed25519.getPublicKey(key);
  return { secretKey: key, publicKey, path };
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function bytesToHex0x(bytes: Uint8Array): `0x${string}` {
  let out = "0x";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out as `0x${string}`;
}

/**
 * Uncompress a 33-byte secp256k1 SEC1 public key to its 65-byte form. Used
 * because viem and most EVM tooling expect the uncompressed form for things
 * like `keccak256(pubkey).slice(-20) → address`.
 */
function uncompressSecp256k1(compressed: Uint8Array): Uint8Array {
  if (compressed.length === 65 && compressed[0] === 0x04) return compressed;
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new Error("expected compressed secp256k1 public key (33 bytes, 0x02/0x03 prefix)");
  }
  // Defer to noble — @scure/bip32 depends on it, so it's already installed.
  const { secp256k1 } =
    require("@noble/curves/secp256k1") as typeof import("@noble/curves/secp256k1");
  const point = secp256k1.ProjectivePoint.fromHex(compressed);
  return point.toRawBytes(false);
}

async function hmacSha512(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    message.buffer.slice(
      message.byteOffset,
      message.byteOffset + message.byteLength,
    ) as ArrayBuffer,
  );
  return new Uint8Array(sig);
}
