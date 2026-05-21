/**
 * Wallet signing helpers for Playwright e2e tests.
 *
 * Wallet popups (MetaMask, Phantom) can't be driven from headless Playwright
 * without bespoke extension fixtures. We instead exercise the real backend
 * SIWE / SIWS contract directly: build the exact message the SDK would, sign
 * it with a locally-generated keypair, and POST to /auth/verify[/solana].
 *
 * The signatures are cryptographically real — siwe / ed25519 verification
 * runs on the server, hits the live nonce store, mints a JWT, and writes a
 * row to the users table. The only piece we skip is the wallet-extension
 * UX bridge, which is out of scope for headless browsers.
 */

import { sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import bs58 from "bs58";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

export function buildSiweMessage(opts: {
  domain: string;
  address: `0x${string}`;
  uri: string;
  nonce: string;
  chainId?: number;
  statement?: string;
}): string {
  const issuedAt = new Date().toISOString();
  return [
    `${opts.domain} wants you to sign in with your Ethereum account:`,
    opts.address,
    "",
    opts.statement ?? "Sign in to Steward",
    "",
    `URI: ${opts.uri}`,
    "Version: 1",
    `Chain ID: ${opts.chainId ?? 1}`,
    `Nonce: ${opts.nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

export function buildSiwsMessage(opts: {
  domain: string;
  publicKey: string;
  uri: string;
  nonce: string;
  chainId?: string;
  statement?: string;
}): string {
  const issuedAt = new Date().toISOString();
  return [
    `${opts.domain} wants you to sign in with your Solana account:`,
    opts.publicKey,
    "",
    opts.statement ?? "Sign in to Steward",
    "",
    `URI: ${opts.uri}`,
    "Version: 1",
    `Chain ID: ${opts.chainId ?? "mainnet"}`,
    `Nonce: ${opts.nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

export async function makeEvmSigner() {
  const pk = generatePrivateKey();
  const account = privateKeyToAccount(pk);
  return {
    address: account.address,
    sign: (message: string) => account.signMessage({ message }),
  };
}

export function makeSolanaSigner() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  // ed25519 raw public key is the last 32 bytes of the DER SPKI export.
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.subarray(spki.length - 32);
  const address = bs58.encode(rawPub);

  function sign(message: string): string {
    const sig = cryptoSign(null, Buffer.from(message, "utf8"), privateKey);
    return bs58.encode(sig);
  }

  return { address, sign };
}
