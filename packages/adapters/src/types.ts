/**
 * Shared adapter types.
 *
 * All financial-service adapters in this package speak a common vocabulary for
 * money primitives, unsigned transactions/intents, and fail-closed errors.
 *
 * SECURITY POSTURE (money-path):
 *   - Adapters NEVER sign anything. The richest artifact an adapter may produce
 *     is an {@link UnsignedTxIntent}: a description of a transaction that the
 *     EXISTING signing + policy path (vault / trade route) can consume. Returning
 *     a signed/broadcastable artifact from an adapter is forbidden by contract.
 *   - Adapters treat all inputs as untrusted. Amount/identifier validation lives
 *     in the mock implementations and in the route layer; nothing downstream may
 *     assume a quote or session is well-formed without re-checking.
 *   - Adapters NEVER hold private keys and NEVER fabricate signatures.
 */

/** Categories of pluggable financial-service adapters. */
export type AdapterCategory =
  | "swap"
  | "earn"
  | "onramp"
  | "offramp"
  | "kyc"
  | "tos"
  | "custodial"
  | "push"
  | "bridge"
  | "exchange";

/**
 * An unsigned transaction intent. This is the ONLY fund-moving artifact an
 * adapter may emit. It is deliberately NOT signed and NOT broadcastable; it must
 * be routed through the existing vault/policy signing path before any value
 * moves. `kind` discriminates how the consumer should treat it.
 */
export interface UnsignedTxIntent {
  /** Always literally false. Re-affirms that no signing happened in the adapter. */
  readonly signed: false;
  /** Discriminator describing the intent's semantic shape. */
  readonly kind: "evm-tx" | "evm-typed-data" | "abstract-intent";
  /** Target chain id (EVM). */
  readonly chainId: number;
  /** Destination address (contract or EOA), 0x-prefixed for EVM. */
  readonly to: string;
  /** Native value in wei as a decimal string ("0" for token-only calls). */
  readonly value: string;
  /** Optional calldata (0x-prefixed hex). Undefined / "0x" means a plain transfer. */
  readonly data?: string;
  /**
   * The address that will own/originate the resulting transaction once signed.
   * Echoed so the policy/signing layer can bind the intent to a wallet.
   */
  readonly owner: string;
  /** Adapter category that produced this intent (for audit/routing). */
  readonly category: AdapterCategory;
  /** Provider identifier that produced this intent (e.g. "mock"). */
  readonly provider: string;
  /** Free-form, NON-SECRET metadata describing the operation for audit. */
  readonly metadata?: Record<string, unknown>;
}

/** A token reference used by swap/earn quoting. */
export interface TokenRef {
  /** Token contract address, or a well-known symbol for native assets. */
  readonly address: string;
  /** Optional symbol for display/logging (never used for routing decisions). */
  readonly symbol?: string;
  /** ERC-20 decimals; defaults to 18 when omitted. */
  readonly decimals?: number;
}

/** Base shape every adapter exposes so the registry can introspect/disable it. */
export interface BaseAdapter {
  /** Adapter category. */
  readonly category: AdapterCategory;
  /** Provider identifier (e.g. "mock", or a real provider slug later). */
  readonly provider: string;
  /**
   * Whether this adapter is operational. The registry returns adapters whose
   * `enabled` is false in production when no real provider is configured, so any
   * fund-moving call fails closed instead of silently using a mock.
   */
  readonly enabled: boolean;
}

/**
 * Thrown when an adapter operation is invoked but the adapter is not configured
 * for the current environment (fail-closed). Routes map this to a 503.
 */
export class AdapterNotConfiguredError extends Error {
  readonly category: AdapterCategory;
  constructor(category: AdapterCategory, detail?: string) {
    super(
      `No ${category} adapter is configured for this environment.${
        detail ? ` ${detail}` : ""
      } Configure a real provider (STEWARD_${category.toUpperCase()}_ADAPTER) before using this in production.`,
    );
    this.name = "AdapterNotConfiguredError";
    this.category = category;
  }
}

/**
 * Thrown for invalid/untrusted input to an adapter (bad amount, unknown token,
 * expired quote, slippage out of bounds). Routes map this to a 400.
 */
export class AdapterValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdapterValidationError";
  }
}

/**
 * Thrown when an operation is structurally valid but cannot be honored by a mock
 * because it would require a real provider relationship (e.g. custodial signing).
 * This is a fail-closed signal — NEVER a fabricated success. Routes map this to 501.
 */
export class AdapterUnavailableError extends Error {
  readonly category: AdapterCategory;
  constructor(category: AdapterCategory, message: string) {
    super(message);
    this.name = "AdapterUnavailableError";
    this.category = category;
  }
}
