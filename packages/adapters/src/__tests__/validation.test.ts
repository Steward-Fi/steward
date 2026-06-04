import { describe, expect, test } from "bun:test";
import { AdapterValidationError } from "../types.js";
import {
  assertChainId,
  assertEvmAddress,
  assertFiatCurrency,
  assertId,
  assertPositiveAmount,
  assertSlippageBps,
  assertUint256,
} from "../validation.js";

describe("assertUint256", () => {
  test("accepts a positive base-unit string", () => {
    expect(assertUint256("1000", "amount")).toBe("1000");
  });
  test("rejects zero by default but allows it when allowZero=true", () => {
    expect(() => assertUint256("0", "amount")).toThrow(AdapterValidationError);
    expect(assertUint256("0", "amount", true)).toBe("0");
  });
  test("rejects negatives, decimals, and non-numeric", () => {
    expect(() => assertUint256("-1", "amount")).toThrow(AdapterValidationError);
    expect(() => assertUint256("1.5", "amount")).toThrow(AdapterValidationError);
    expect(() => assertUint256("0xff", "amount")).toThrow(AdapterValidationError);
  });
  test("rejects uint256 overflow", () => {
    const over = (2n ** 256n).toString();
    expect(() => assertUint256(over, "amount")).toThrow(AdapterValidationError);
  });
});

describe("assertEvmAddress / assertChainId", () => {
  test("accepts a valid 0x address", () => {
    expect(assertEvmAddress("0x1111111111111111111111111111111111111111", "a")).toBeTruthy();
  });
  test("rejects malformed addresses", () => {
    expect(() => assertEvmAddress("0x123", "a")).toThrow(AdapterValidationError);
    expect(() => assertEvmAddress("nope", "a")).toThrow(AdapterValidationError);
  });
  test("chainId must be a positive integer", () => {
    expect(assertChainId(8453)).toBe(8453);
    expect(() => assertChainId(0)).toThrow(AdapterValidationError);
    expect(() => assertChainId(-1)).toThrow(AdapterValidationError);
    expect(() => assertChainId(1.5)).toThrow(AdapterValidationError);
  });
});

describe("assertSlippageBps", () => {
  test("defaults to 50 when undefined", () => {
    expect(assertSlippageBps(undefined)).toBe(50);
  });
  test("enforces the [0,10000] bound", () => {
    expect(assertSlippageBps(0)).toBe(0);
    expect(assertSlippageBps(10_000)).toBe(10_000);
    expect(() => assertSlippageBps(10_001)).toThrow(AdapterValidationError);
    expect(() => assertSlippageBps(-1)).toThrow(AdapterValidationError);
  });
});

describe("assertId / assertFiatCurrency / assertPositiveAmount", () => {
  test("assertId trims and bounds length", () => {
    expect(assertId("  abc  ", "id")).toBe("abc");
    expect(() => assertId("", "id")).toThrow(AdapterValidationError);
    expect(() => assertId("x".repeat(200), "id", 128)).toThrow(AdapterValidationError);
  });
  test("assertFiatCurrency normalizes to uppercase", () => {
    expect(assertFiatCurrency("usd")).toBe("USD");
    expect(() => assertFiatCurrency("dollars")).toThrow(AdapterValidationError);
  });
  test("assertPositiveAmount rejects non-positive / non-finite", () => {
    expect(assertPositiveAmount(1.23, "amt")).toBe(1.23);
    expect(() => assertPositiveAmount(0, "amt")).toThrow(AdapterValidationError);
    expect(() => assertPositiveAmount(Number.NaN, "amt")).toThrow(AdapterValidationError);
  });
});
