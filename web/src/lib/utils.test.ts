import { describe, expect, it } from "bun:test";

import { formatWei } from "./utils";

describe("formatWei", () => {
  it("formats whole and fractional ETH values", () => {
    expect(formatWei("1000000000000000000")).toBe("1.0000");
    expect(formatWei("1500000000000000000", "ETH")).toBe("1.5000 ETH");
  });

  it("formats small nonzero values without floating point conversion", () => {
    expect(formatWei("99999999999999")).toBe("<0.0001");
  });

  it("preserves large wei precision", () => {
    expect(formatWei("123456789012345678901234567890")).toBe(
      "123456789012.3456",
    );
  });

  it("returns zero for malformed input", () => {
    expect(formatWei("abc", "ETH")).toBe("0 ETH");
  });
});
