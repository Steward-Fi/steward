import { describe, expect, it } from "bun:test";
import { CHAINS, fromCaip2, SUPPORTED_CHAINS, toCaip2 } from "../types";

describe("SDK chain registry", () => {
  it("supports Gnosis by numeric id and CAIP-2 id", () => {
    expect(SUPPORTED_CHAINS.gnosis).toBe(100);
    expect(CHAINS["eip155:100"]).toMatchObject({
      numericId: 100,
      family: "evm",
      name: "Gnosis",
      symbol: "xDAI",
      testnet: false,
    });
    expect(toCaip2(100)).toBe("eip155:100");
    expect(fromCaip2("eip155:100")).toBe(100);
  });
});
