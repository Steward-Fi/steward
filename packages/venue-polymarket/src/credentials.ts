import { z } from "zod";

// ---------------------------------------------------------------------------
// Credential-injection model
// ---------------------------------------------------------------------------
//
// In matchr, Polymarket creds lived as inline DB columns (polymarket_api_*).
// In steward they come from the VAULT. This package is a PURE adapter: it takes
// RESOLVED credentials as inputs and NEVER reads a DB or hardcodes a key.
//
//   - L2 CLOB creds  { key, secret, passphrase }  — the HMAC keypair that
//     authenticates ongoing REST trading calls. Derive once from L1, store in
//     vault, hand to the adapter at order time.
//   - funder Safe address (signatureType 2)       — the wallet that holds USDC
//     + outcome tokens. signer !== funder.
//   - a SIGNER abstraction                         — the L1 delegate. The
//     clob-client signs EIP-712 orders + derives L2 creds with this signer.
//     Mirrors how venue-hyperliquid takes a VaultClient signer rather than a
//     raw key read from a DB.
//
// The raw private key (if any) is provided BY THE CALLER (resolved from vault),
// never read here. Prefer the EthersSignerLike seam so an third-party/remote signer
// (e.g. a vault-backed signer) can be plugged without ever materializing a key.

export const clobApiCredentialsSchema = z.object({
  key: z.string().min(1),
  secret: z.string().min(1),
  passphrase: z.string().min(1),
});
export type ClobApiCredentials = z.infer<typeof clobApiCredentialsSchema>;

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/, "must be a 0x-address");

/**
 * Minimal ethers-v5/v6 signer surface the clob-client needs. Callers can pass:
 *   - an ethers.Wallet built from a vault-resolved private key, OR
 *   - any object exposing { address / getAddress, signMessage, _signTypedData/signTypedData }.
 * The package never constructs a signer from a stored key itself.
 */
export interface EthersSignerLike {
  getAddress?(): Promise<string>;
  address?: string;
  signMessage?(message: string | Uint8Array): Promise<string>;
  // ethers v5 uses _signTypedData; v6 uses signTypedData. Either is accepted.
  _signTypedData?(...args: unknown[]): Promise<string>;
  signTypedData?(...args: unknown[]): Promise<string>;
}

/**
 * Resolved Polymarket account config — all injected by the caller (from vault),
 * none read from a DB inside this package.
 */
export interface PolymarketAccount {
  /** L2 CLOB creds. Required for any authed trading call. */
  apiCredentials: ClobApiCredentials;
  /** The funder Safe address (signatureType 2). Holds USDC + tokens. */
  funderAddress: string;
  /**
   * The delegate signer (L1). Used by the clob-client to sign orders and to
   * derive/refresh L2 creds. Provided by the caller; never built from a stored
   * key in this package.
   */
  signer: EthersSignerLike;
  /** signatureType. Defaults to 2 (Gnosis Safe funder) — the agent-custody model. */
  signatureType?: number;
}

/**
 * Bridge an injected signer to the surface `@polymarket/clob-client` /
 * `@polymarket/order-utils` actually call at runtime, so the signer shapes this
 * package accepts genuinely work:
 *
 *  1. EIP-712 signing: order-utils calls the ethers v5 method `_signTypedData`.
 *     ethers v6 wallets expose `signTypedData` instead. A bare cast satisfies TS
 *     but a v6 signer would throw (`_signTypedData is not a function`). We add a
 *     `_signTypedData` that delegates to v6's `signTypedData` when only the v6
 *     method is present.
 *  2. Address: order-utils calls `signer.getAddress()` UNCONDITIONALLY. A custom
 *     /remote signer that exposes only `.address` (which assertPolymarketAccount
 *     accepts) would otherwise throw. We synthesize `getAddress()` from
 *     `.address` when it's missing.
 *
 * Returns a Proxy (no mutation of the caller's object). A signer that already
 * exposes both `_signTypedData` and `getAddress` passes through unchanged.
 */
export function toClobCompatibleSigner<T extends EthersSignerLike>(signer: T): T {
  const needsSignTypedData =
    typeof signer._signTypedData !== "function" && typeof signer.signTypedData === "function";
  const needsGetAddress = typeof signer.getAddress !== "function" && !!signer.address;
  if (!needsSignTypedData && !needsGetAddress) return signer;

  const v6SignTypedData =
    typeof signer.signTypedData === "function" ? signer.signTypedData.bind(signer) : undefined;
  const address = signer.address;

  return new Proxy(signer, {
    get(target, prop, receiver) {
      // _signTypedData(domain, types, value) maps 1:1 to v6 signTypedData.
      if (prop === "_signTypedData" && needsSignTypedData && v6SignTypedData) {
        return (...args: unknown[]) => v6SignTypedData(...args);
      }
      // order-utils calls getAddress() unconditionally; synthesize from .address.
      if (prop === "getAddress" && needsGetAddress) {
        return async () => address;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

export function assertPolymarketAccount(account: PolymarketAccount): PolymarketAccount {
  clobApiCredentialsSchema.parse(account.apiCredentials);
  addressSchema.parse(account.funderAddress);
  if (!account.signer) {
    throw new Error("PolymarketAccount.signer is required");
  }
  // Must be able to report an address: order-utils calls getAddress() (which
  // toClobCompatibleSigner can synthesize from .address).
  if (typeof account.signer.getAddress !== "function" && !account.signer.address) {
    throw new Error("PolymarketAccount.signer must expose getAddress() or .address");
  }
  // Must be able to sign typed data: order-utils calls _signTypedData (v5) or we
  // bridge from signTypedData (v6). Without either, order submission would throw
  // a TypeError at runtime — fail fast here instead.
  if (
    typeof account.signer._signTypedData !== "function" &&
    typeof account.signer.signTypedData !== "function"
  ) {
    throw new Error(
      "PolymarketAccount.signer must expose _signTypedData (ethers v5) or signTypedData (ethers v6)",
    );
  }
  return account;
}

export async function resolveSignerAddress(signer: EthersSignerLike): Promise<string> {
  if (typeof signer.getAddress === "function") return signer.getAddress();
  if (signer.address) return signer.address;
  throw new Error("signer exposes neither getAddress() nor .address");
}

/**
 * Detect a likely-401 (invalid/expired L2 creds) from a clob-client error so the
 * caller can trigger a re-derive from L1. We never clear creds here (no DB).
 */
export function isPolymarketUnauthorized(error: unknown): boolean {
  const e = error as { status?: number; response?: { status?: number } } | null;
  return e?.status === 401 || e?.response?.status === 401;
}
