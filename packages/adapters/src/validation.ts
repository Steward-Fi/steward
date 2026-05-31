/**
 * Untrusted-input validation helpers shared by mock adapters.
 *
 * Every adapter treats its arguments as untrusted. These helpers throw
 * {@link AdapterValidationError} on bad input so the route layer can return a
 * 400 without leaking internals.
 */

import { AdapterValidationError } from "./types.js";

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const UINT256_DECIMAL_RE = /^\d+$/;
const MAX_UINT256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935n;

/** Assert a positive, finite number (used for fiat amounts / human-scale values). */
export function assertPositiveAmount(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AdapterValidationError(`${field} must be a finite number`);
  }
  if (value <= 0) {
    throw new AdapterValidationError(`${field} must be greater than zero`);
  }
  return value;
}

/**
 * Assert a uint256 decimal string ("amount in base units / wei"). Rejects
 * negatives, non-numeric, zero (when `allowZero` is false), and overflow.
 */
export function assertUint256(value: unknown, field: string, allowZero = false): string {
  if (typeof value !== "string" || !UINT256_DECIMAL_RE.test(value)) {
    throw new AdapterValidationError(`${field} must be a base-unit decimal string`);
  }
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new AdapterValidationError(`${field} must be a valid integer string`);
  }
  if (parsed < 0n) {
    throw new AdapterValidationError(`${field} must not be negative`);
  }
  if (!allowZero && parsed === 0n) {
    throw new AdapterValidationError(`${field} must be greater than zero`);
  }
  if (parsed > MAX_UINT256) {
    throw new AdapterValidationError(`${field} exceeds uint256 range`);
  }
  return value;
}

/** Assert an EVM address. */
export function assertEvmAddress(value: unknown, field: string): string {
  if (typeof value !== "string" || !EVM_ADDRESS_RE.test(value)) {
    throw new AdapterValidationError(`${field} must be a 0x EVM address`);
  }
  return value;
}

/** Assert a positive-integer chain id. */
export function assertChainId(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new AdapterValidationError("chainId must be a positive integer");
  }
  return value;
}

/** Assert basis-points slippage in [0, 10000]. */
export function assertSlippageBps(value: unknown): number {
  if (value === undefined) return 50; // default 0.5%
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new AdapterValidationError("slippageBps must be an integer");
  }
  if (value < 0 || value > 10_000) {
    throw new AdapterValidationError("slippageBps must be between 0 and 10000");
  }
  return value;
}

/** Assert a non-empty, length-bounded string identifier. */
export function assertId(value: unknown, field: string, maxLength = 128): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new AdapterValidationError(`${field} is required`);
  }
  const trimmed = value.trim();
  if (trimmed.length > maxLength) {
    throw new AdapterValidationError(`${field} must be ${maxLength} characters or fewer`);
  }
  return trimmed;
}

/** Assert a 3-letter-ish fiat currency code (ISO-4217 style). */
export function assertFiatCurrency(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z]{3}$/.test(value)) {
    throw new AdapterValidationError("fiatCurrency must be a 3-letter currency code");
  }
  return value.toUpperCase();
}
