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
        {
          id: "raw-signing",
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["sui", "tron"], allowedCurves: ["ed25519", "secp256k1"] },
        },
      ]),
    ).toBeNull();
  });

  it("rejects malformed raw-signing-chain configs", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "raw-signing",
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["sui", 123] },
        },
      ]),
    ).toBe("raw-signing-chain.allowedChains must be a string array");

    expect(
      getPolicyRulesValidationError([
        {
          id: "raw-signing",
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["sui"], requireSupported: "yes" },
        },
      ]),
    ).toBe("raw-signing-chain.requireSupported must be a boolean");
  });

  it("rejects malformed condition-set references before database lookup", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "condition-set",
          type: "condition-set",
          enabled: true,
          config: {
            conditionSetId: "not-a-uuid",
            operator: "not_in_condition_set",
          },
        },
      ]),
    ).toBe("condition-set.conditionSetId must be a UUID");
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

  it("accepts a valid typed-data policy (regression: previously rejected as unknown type)", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "td",
          type: "typed-data",
          enabled: true,
          config: {
            verifyingContractAllowlist: ["0xE7C3D8C9a439feDe00D2600032D5dB0Be71C3c29"],
            allowedChainIds: [80002],
            allowedDomainNames: ["JPY Coin"],
            allowedPrimaryTypes: ["ReceiveWithAuthorization"],
            messageConditions: [
              {
                field: "to",
                operator: "address_in",
                values: ["0x752B7AaD0089286EB7b553d84D05233d80c9FCB4"],
              },
              { field: "value", operator: "uint_max", value: "3000000000000000000" },
            ],
          },
        },
      ]),
    ).toBeNull();

    // An empty config is a valid (vacuously-passing) typed-data policy; its real
    // value is that its existence enables typed-data signing at all.
    expect(
      getPolicyRulesValidationError([
        { id: "td-empty", type: "typed-data", enabled: true, config: {} },
      ]),
    ).toBeNull();
  });

  it("accepts every typed-data message operator with evaluator-parity shapes", () => {
    const address = "0x752B7AaD0089286EB7b553d84D05233d80c9FCB4";
    expect(
      getPolicyRulesValidationError([
        {
          id: "td-operators",
          type: "typed-data",
          enabled: true,
          config: {
            messageConditions: [
              { field: "details.to", operator: "address_in", values: [address, address] },
              { field: "from", operator: "address_not_in", values: [address] },
              { field: "memo", operator: "eq", value: "" },
              { field: "nonce", operator: "in", values: ["1", "01"] },
              { field: "state", operator: "not_in", values: ["cancelled"] },
              {
                field: "amount",
                operator: "uint_max",
                value: ` 0x${"0".repeat(80)}ffff `,
              },
            ],
          },
        },
      ]),
    ).toBeNull();
  });

  it("rejects typed-data values whose evaluator meaning would be absent or ambiguous", () => {
    const invalidConfigs: unknown[] = [
      { verifyingContractAllowlist: [] },
      { verifyingContractBlocklist: [] },
      { allowedChainIds: [] },
      { allowedChainIds: [0] },
      { allowedChainIds: [-1] },
      { allowedChainIds: [1.5] },
      { allowedChainIds: [Number.MAX_SAFE_INTEGER + 1] },
      { allowedChainIds: ["8453"] },
      { allowedDomainNames: [] },
      { allowedDomainNames: [""] },
      { allowedDomainNames: ["   "] },
      { allowedDomainNames: [" Permit2 "] },
      { allowedPrimaryTypes: [] },
      { allowedPrimaryTypes: [""] },
      { allowedPrimaryTypes: ["Permit Type"] },
      { messageConditions: [] },
      { messageConditions: [{ field: "to", operator: "address_in", values: [] }] },
      { messageConditions: [{ field: "to", operator: "address_not_in", values: [] }] },
      { messageConditions: [{ field: "state", operator: "in", values: [] }] },
      { messageConditions: [{ field: "state", operator: "not_in", values: [] }] },
      { messageConditions: [{ field: "amount", operator: "uint_max", value: "-1" }] },
      { messageConditions: [{ field: "amount", operator: "uint_max", value: "1.5" }] },
      {
        messageConditions: [
          {
            field: "amount",
            operator: "uint_max",
            value: "115792089237316195423570985008687907853269984665640564039457584007913129639936",
          },
        ],
      },
    ];

    for (const config of invalidConfigs) {
      expect(
        getPolicyRulesValidationError([
          { id: "td-invalid", type: "typed-data", enabled: true, config },
        ]),
      ).toContain("typed-data");
    }
  });

  it("rejects unknown keys, wrong operator shapes, unsafe paths, and malformed addresses", () => {
    const address = "0x752B7AaD0089286EB7b553d84D05233d80c9FCB4";
    const invalidConfigs: unknown[] = [
      { allowedChainId: [8453] },
      { verifyingContractAllowlist: ["not-an-address"] },
      { verifyingContractAllowlist: [`${address}00`] },
      { messageConditions: [{ field: "to", operator: "unknown", value: "x" }] },
      { messageConditions: [{ field: "to", operator: "address_in", value: address }] },
      {
        messageConditions: [
          { field: "to", operator: "address_in", values: [address], value: address },
        ],
      },
      { messageConditions: [{ field: "memo", operator: "eq", values: ["x"] }] },
      { messageConditions: [{ field: "memo", operator: "eq", value: "x", ignored: true }] },
      { messageConditions: [{ field: "", operator: "eq", value: "x" }] },
      { messageConditions: [{ field: "details..to", operator: "eq", value: "x" }] },
      { messageConditions: [{ field: "__proto__.admin", operator: "eq", value: "true" }] },
      { messageConditions: [{ field: "constructor.prototype", operator: "eq", value: "x" }] },
    ];

    for (const config of invalidConfigs) {
      expect(
        getPolicyRulesValidationError([
          { id: "td-invalid", type: "typed-data", enabled: true, config },
        ]),
      ).toContain("typed-data");
    }
  });

  it("rejects oversized typed-data strings at the policy-list boundary", () => {
    expect(
      getPolicyRulesValidationError([
        {
          id: "td-large",
          type: "typed-data",
          enabled: true,
          config: { allowedDomainNames: ["x".repeat(70_000)] },
        },
      ]),
    ).toContain("65536 bytes");
  });
});
