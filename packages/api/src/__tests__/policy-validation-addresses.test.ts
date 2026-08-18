import { describe, expect, it } from "bun:test";
import { getPolicyRuleValidationError } from "../services/policy-validation";

function addressRule(addresses: unknown[]) {
  return {
    id: "addresses",
    type: "approved-addresses",
    enabled: true,
    config: { addresses, mode: "whitelist" },
  };
}

describe("approved-addresses write validation", () => {
  it("accepts exact supported address-family syntax, including mixed-chain lists", () => {
    expect(
      getPolicyRuleValidationError(
        addressRule([
          "0x1234567890123456789012345678901234567890",
          "7J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
          "tb1q50rtrmj2f8vl9tem8qpfw36ylw5jg9j20l03x8",
          "49wsWmQA1WyM4gNpPkx1cRUCAamWaSBbMMmiGWNWGfWZRiXUH9DdMMi5ZJUM98K2xk62AEX3C6pCDMp1iXt2PLqX54LVKjA",
        ]),
      ),
    ).toBeNull();
  });

  it("rejects malformed, checksum-invalid, mixed-case, and unsupported addresses", () => {
    for (const address of [
      "0x1234",
      "1111111111111111111111111111111",
      "tb1Q50rtrmj2f8vl9tem8qpfw36ylw5jg9j20l03x8",
      "tb1q50rtrmj2f8vl9tem8qpfw36ylw5jg9j20l03x9",
      "4".repeat(94),
      "not-an-address",
    ]) {
      expect(getPolicyRuleValidationError(addressRule([address]))).toContain(
        "valid EVM, Solana, Bitcoin, or Monero addresses",
      );
    }
  });
});
