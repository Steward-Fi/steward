/**
 * SEC-115 / SEC-193 regression tests for execution-payload helpers.
 */

import { describe, expect, it } from "bun:test";
import { canonicalJsonStringify, isEvmChainId } from "../execution-payload";

describe("canonicalJsonStringify", () => {
  it("sorts keys and stringifies bigints", () => {
    expect(canonicalJsonStringify({ b: 1n, a: "x" })).toBe('{"a":"x","b":"1"}');
  });

  it("does not drop own __proto__ keys (SEC-115)", () => {
    // JSON.parse creates an OWN `__proto__` member; building the canonical
    // output via plain `{}` assignment would silently drop it, making two
    // snapshots that differ only in that member digest identically.
    const withProto = JSON.parse('{"__proto__":{"polluted":true},"a":1}') as Record<
      string,
      unknown
    >;
    const withoutProto = { a: 1 };
    const canonical = canonicalJsonStringify(withProto);
    expect(canonical).toContain('"__proto__"');
    expect(canonical).not.toBe(canonicalJsonStringify(withoutProto));
  });
});

describe("isEvmChainId (SEC-193)", () => {
  it("returns true for registered EVM chains", () => {
    expect(isEvmChainId(1)).toBe(true);
    expect(isEvmChainId(8453)).toBe(true);
    expect(isEvmChainId(137)).toBe(true);
  });

  it("returns false for non-EVM families and unknown ids (fail closed)", () => {
    expect(isEvmChainId(101)).toBe(false); // Solana
    expect(isEvmChainId(102)).toBe(false); // Solana devnet
    expect(isEvmChainId(201)).toBe(false); // Bitcoin
    expect(isEvmChainId(202)).toBe(false); // Bitcoin testnet
    expect(isEvmChainId(301)).toBe(false); // Monero
    expect(isEvmChainId(302)).toBe(false); // Monero stagenet
    expect(isEvmChainId(999_999)).toBe(false); // unknown
  });
});
