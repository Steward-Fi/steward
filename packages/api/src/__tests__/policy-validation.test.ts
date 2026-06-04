import { describe, expect, it } from "bun:test";
import { getPolicyRulesValidationError } from "../services/policy-validation";

describe("policy rule validation", () => {
  it("rejects fail-open rate-limit and auto-approve configs", () => {
    expect(
      getPolicyRulesValidationError([
        { id: "rate", type: "rate-limit", enabled: true, config: {} },
      ]),
    ).toContain("rate-limit");

    expect(
      getPolicyRulesValidationError([
        { id: "auto", type: "auto-approve-threshold", enabled: true, config: {} },
      ]),
    ).toContain("auto-approve-threshold");
  });

  it("accepts valid persisted policy configs", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "spend",
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "1000", maxPerDay: "5000" },
        },
        {
          id: "rate",
          type: "rate-limit",
          enabled: true,
          config: { maxTxPerHour: 5, maxTxPerDay: 20 },
        },
      ]),
    ).toBeNull();
  });

  it("rejects duplicate enabled auto-approve thresholds", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "auto-permissive",
          type: "auto-approve-threshold",
          enabled: true,
          config: { threshold: "2000000000000000000" },
        },
        {
          id: "auto-strict",
          type: "auto-approve-threshold",
          enabled: true,
          config: { threshold: "500000000000000000" },
        },
      ]),
    ).toBe('Duplicate policy type "auto-approve-threshold"');
  });

  it("allows disabled historical auto-approve threshold variants", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "auto-active",
          type: "auto-approve-threshold",
          enabled: true,
          config: { threshold: "2000000000000000000" },
        },
        {
          id: "auto-disabled",
          type: "auto-approve-threshold",
          enabled: false,
          config: { threshold: "500000000000000000" },
        },
      ]),
    ).toBeNull();
  });

  it("accepts valid contract-allowlist configs", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0x1111111111111111111111111111111111111111",
                selectors: ["0xa9059cbb", "0x095ea7b3"],
                constraints: {
                  "0xa9059cbb": {
                    recipientAllowlist: ["0x3333333333333333333333333333333333333333"],
                    maxAmount: "1000",
                  },
                  "0x095ea7b3": {
                    spenderBlocklist: ["0x4444444444444444444444444444444444444444"],
                    maxAmount: "10",
                  },
                },
              },
              {
                address: "0x2222222222222222222222222222222222222222",
                selectors: ["0x23b872dd"],
              },
            ],
          },
        },
      ]),
    ).toBeNull();
  });

  it("rejects malformed contract-allowlist entries and selectors", () => {
    const expectedError =
      "contract-allowlist.contracts must be non-empty entries with EVM address, 4-byte selectors, and valid selector constraints";

    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: { contracts: "not-an-array" },
        },
      ]),
    ).toBe(expectedError);

    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0xnot-an-address",
                selectors: ["0xa9059cbb"],
              },
            ],
          },
        },
      ]),
    ).toBe(expectedError);

    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0x1111111111111111111111111111111111111111",
                selectors: [],
              },
            ],
          },
        },
      ]),
    ).toBe(expectedError);

    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0x1111111111111111111111111111111111111111",
                selectors: ["0x1234", "0xa9059cbb"],
              },
            ],
          },
        },
      ]),
    ).toBe(expectedError);

    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0x1111111111111111111111111111111111111111",
                selectors: ["0xa9059cbb"],
                constraints: {
                  "0x095ea7b3": {
                    recipientAllowlist: ["0x2222222222222222222222222222222222222222"],
                  },
                },
              },
            ],
          },
        },
      ]),
    ).toBe(expectedError);

    expect(
      getPolicyRulesValidationError([
        {
          id: "contracts",
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0x1111111111111111111111111111111111111111",
                selectors: ["0xa9059cbb"],
                constraints: {
                  "0xa9059cbb": {
                    recipientAllowlist: ["0xnot-an-address"],
                  },
                },
              },
            ],
          },
        },
      ]),
    ).toBe(expectedError);
  });

  it("rejects unsupported persisted policy types before assignment", () => {
    expect(
      getPolicyRulesValidationError([
        { id: "bad", type: "not-a-policy", enabled: true, config: {} },
      ]),
    ).toContain("Unknown policy type");
  });

  it("rejects wei strings outside uint256 bounds before BigInt parsing paths", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "huge-spend",
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "9".repeat(79) },
        },
      ]),
    ).toContain("wei string");

    expect(
      getPolicyRulesValidationError([
        {
          id: "huge-reputation",
          type: "reputation-scaling",
          enabled: true,
          config: {
            baseMaxPerTx: "1",
            maxMaxPerTx:
              "115792089237316195423570985008687907853269984665640564039457584007913129639936",
            curve: "linear",
          },
        },
      ]),
    ).toContain("wei strings");
  });

  it("rejects oversized policy lists before deep validation", () => {
    expect(
      getPolicyRulesValidationError(
        Array.from({ length: 51 }, (_, index) => ({
          id: `policy-${index}`,
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "1000", maxPerDay: "5000" },
        })),
      ),
    ).toContain("more than 50");

    expect(
      getPolicyRulesValidationError([
        {
          id: "large",
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "1000", maxPerDay: "5000", note: "x".repeat(70_000) },
        },
      ]),
    ).toContain("65536 bytes");
  });
});
