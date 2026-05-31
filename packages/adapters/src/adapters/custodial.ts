/**
 * CustodialWalletAdapter — external-custodian seam.
 *
 * SECURITY POSTURE (critical): the mock NEVER holds private keys and NEVER
 * fabricates signatures. `createCustodialWallet`/`getWallet` model registration
 * metadata in memory, but `requestSignature` ALWAYS fails closed with a clear
 * "not available in mock / requires a real custodian" result. A real custodian
 * integration would call out to the provider's signing API here; a mock that
 * returned a fake signature would be a catastrophic money-path footgun, so it
 * refuses instead.
 */

import { AdapterUnavailableError, AdapterValidationError, type BaseAdapter } from "../types.js";
import { assertId } from "../validation.js";

export type ChainFamily = "evm" | "solana";

export interface CreateCustodialWalletRequest {
  userId: string;
  chain: ChainFamily;
}

export interface CustodialWallet {
  readonly id: string;
  readonly provider: string;
  readonly userId: string;
  readonly chain: ChainFamily;
  /**
   * Address as reported by the custodian. The mock has no real custodian, so it
   * exposes a clearly-marked placeholder and the key is NOT held anywhere.
   */
  readonly address: string;
  readonly custodied: true;
  readonly createdAt: number;
}

export interface RequestSignatureRequest {
  walletId: string;
  /** Payload to sign (hex for EVM tx/message). Opaque to the adapter. */
  payload: string;
  /** Signing scheme requested. */
  scheme: "evm-personal" | "evm-typed-data" | "evm-tx" | "solana-tx";
}

/**
 * Result of a signature request. The mock can only ever return the `unavailable`
 * variant — it has no key material and refuses to invent one.
 */
export type SignatureResult =
  | { readonly ok: true; readonly signature: string; readonly provider: string }
  | {
      readonly ok: false;
      readonly available: false;
      readonly provider: string;
      readonly reason: string;
    };

export interface CustodialWalletAdapter extends BaseAdapter {
  readonly category: "custodial";
  createCustodialWallet(request: CreateCustodialWalletRequest): Promise<CustodialWallet>;
  getWallet(id: string): Promise<CustodialWallet | null>;
  /**
   * Request a signature from the custodian. The mock ALWAYS returns the
   * fail-closed `{ ok: false, available: false }` result and NEVER a signature.
   */
  requestSignature(request: RequestSignatureRequest): Promise<SignatureResult>;
}

const VALID_CHAINS: ReadonlySet<ChainFamily> = new Set(["evm", "solana"]);
const HEX_RE = /^0x[0-9a-fA-F]*$/;

export class MockCustodialWalletAdapter implements CustodialWalletAdapter {
  readonly category = "custodial" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private wallets = new Map<string, CustodialWallet>();
  private now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async createCustodialWallet(request: CreateCustodialWalletRequest): Promise<CustodialWallet> {
    const userId = assertId(request.userId, "userId", 128);
    if (!VALID_CHAINS.has(request.chain)) {
      throw new AdapterValidationError("chain must be evm or solana");
    }
    const id = `custodial_${crypto.randomUUID()}`;
    // Clearly-marked placeholder address. No private key is generated or stored.
    const address =
      request.chain === "evm"
        ? "0x000000000000000000000000000000000000c0de"
        : "MockCustodialWalletNoKeyHeld11111111111111";
    const wallet: CustodialWallet = {
      id,
      provider: this.provider,
      userId,
      chain: request.chain,
      address,
      custodied: true,
      createdAt: this.now(),
    };
    this.wallets.set(id, wallet);
    return wallet;
  }

  async getWallet(id: string): Promise<CustodialWallet | null> {
    const walletId = assertId(id, "walletId", 128);
    return this.wallets.get(walletId) ?? null;
  }

  async requestSignature(request: RequestSignatureRequest): Promise<SignatureResult> {
    // Validate inputs so a malformed call is a 400, not a silent refusal — but
    // even a perfectly-formed request can NEVER yield a signature from the mock.
    const walletId = assertId(request.walletId, "walletId", 128);
    if (typeof request.payload !== "string" || !HEX_RE.test(request.payload)) {
      throw new AdapterValidationError("payload must be a 0x-prefixed hex string");
    }
    if (
      request.scheme !== "evm-personal" &&
      request.scheme !== "evm-typed-data" &&
      request.scheme !== "evm-tx" &&
      request.scheme !== "solana-tx"
    ) {
      throw new AdapterValidationError("unsupported signing scheme");
    }
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      throw new AdapterValidationError("unknown walletId");
    }

    // Fail closed. The mock has no key material and will not fabricate one.
    return {
      ok: false,
      available: false,
      provider: this.provider,
      reason:
        "Custodial signing is not available in the mock adapter. A real custodian provider must be configured; the mock never holds keys or fabricates signatures.",
    };
  }

  /**
   * Convenience helper for routes that prefer an exception to a result object.
   * Always throws — the mock cannot sign.
   */
  async requireSignature(request: RequestSignatureRequest): Promise<never> {
    const result = await this.requestSignature(request);
    if (result.ok) {
      // Unreachable for the mock, but keeps the type honest for real providers.
      throw new Error("unexpected: mock returned a signature");
    }
    throw new AdapterUnavailableError("custodial", result.reason);
  }
}
