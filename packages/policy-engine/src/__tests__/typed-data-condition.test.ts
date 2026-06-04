/**
 * EIP-712 typed-data conditions + ERC721/ERC1155 calldata decoding.
 *
 * Two complementary surfaces of Task #3 (Privy parity for
 * `eth_signTypedData_v4` domain/message conditions and ABI-decoded NFT
 * calldata conditions):
 *
 *  1. TYPED-DATA — drives the real `typed-data` evaluator over decoded EIP-712
 *     payloads. Proves the evaluator FAILS CLOSED against spoofed domains
 *     (wrong verifyingContract / chainId / name), disallowed primaryTypes
 *     (e.g. a Seaport order when only a Permit is authorized), and message
 *     fields that violate address allow/blocklists or uint caps — while
 *     remaining "not applicable" (pass) for ordinary transaction signs.
 *
 *  2. NFT CALLDATA — drives the `contract-allowlist` evaluator over ERC721 /
 *     ERC1155 transfer + approval selectors, proving recipient/operator
 *     allowlists, tokenId allow/blocklists, per-token amount caps, and the
 *     dynamic-array decode used by `safeBatchTransferFrom` all enforce
 *     (and fail closed when a constrained field cannot be decoded).
 */
import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { type EvaluatorContext, evaluatePolicy } from "../evaluators";

// ─── helpers ────────────────────────────────────────────────────────────────

function makeContext(overrides: Partial<EvaluatorContext> = {}): EvaluatorContext {
  const defaultRequest: SignRequest = {
    agentId: "test-agent",
    tenantId: "test-tenant",
    to: "0x1234567890123456789012345678901234567890",
    value: "0",
    chainId: 8453,
  };
  return {
    request: defaultRequest,
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    ...overrides,
  };
}

function makeTypedDataRule(config: Record<string, unknown>, id = "typed-data-1"): PolicyRule {
  return { id, type: "typed-data", enabled: true, config };
}

function makeContractAllowlistRule(
  config: Record<string, unknown>,
  id = "contract-allowlist-1",
): PolicyRule {
  return { id, type: "contract-allowlist", enabled: true, config };
}

function abiAddress(address: string): string {
  return address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

function abiUint(value: bigint | number | string): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const TOKEN = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SPENDER_OK = "0x1111111111111111111111111111111111111111";
const SPENDER_EVIL = "0x2222222222222222222222222222222222222222";

function permitTypedData(overrides: {
  verifyingContract?: string;
  chainId?: number;
  name?: string;
  primaryType?: string;
  spender?: string;
  amount?: string;
}): NonNullable<EvaluatorContext["typedData"]> {
  return {
    domain: {
      name: overrides.name ?? "Permit2",
      chainId: overrides.chainId ?? 8453,
      verifyingContract: overrides.verifyingContract ?? PERMIT2,
    },
    types: {
      PermitSingle: [
        { name: "token", type: "address" },
        { name: "spender", type: "address" },
        { name: "amount", type: "uint256" },
      ],
    },
    primaryType: overrides.primaryType ?? "PermitSingle",
    value: {
      token: TOKEN,
      spender: overrides.spender ?? SPENDER_OK,
      amount: overrides.amount ?? "1000",
    },
  };
}

// ─── 1. typed-data evaluator ─────────────────────────────────────────────────

describe("typed-data condition", () => {
  it("is not applicable (passes) for an ordinary transaction sign", async () => {
    const rule = makeTypedDataRule({ verifyingContractAllowlist: [PERMIT2] });
    const result = await evaluatePolicy(rule, makeContext()); // no ctx.typedData
    expect(result.passed).toBe(true);
  });

  it("approves typed data whose domain + message satisfy every constraint", async () => {
    const rule = makeTypedDataRule({
      verifyingContractAllowlist: [PERMIT2],
      allowedChainIds: [8453],
      allowedDomainNames: ["Permit2"],
      allowedPrimaryTypes: ["PermitSingle"],
      messageConditions: [
        { field: "spender", operator: "address_in", values: [SPENDER_OK] },
        { field: "amount", operator: "uint_max", value: "1000" },
      ],
    });
    const result = await evaluatePolicy(rule, makeContext({ typedData: permitTypedData({}) }));
    expect(result.passed).toBe(true);
  });

  it("DENIES a spoofed verifyingContract (domain spoof resistance)", async () => {
    const rule = makeTypedDataRule({ verifyingContractAllowlist: [PERMIT2] });
    const result = await evaluatePolicy(
      rule,
      makeContext({
        typedData: permitTypedData({
          verifyingContract: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        }),
      }),
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("verifyingContract");
  });

  it("DENIES (fails closed) when the allowlist is set but the domain has no verifyingContract", async () => {
    const rule = makeTypedDataRule({ verifyingContractAllowlist: [PERMIT2] });
    const td = permitTypedData({});
    td.domain.verifyingContract = undefined;
    const result = await evaluatePolicy(rule, makeContext({ typedData: td }));
    expect(result.passed).toBe(false);
  });

  it("DENIES a mismatched domain chainId", async () => {
    const rule = makeTypedDataRule({ allowedChainIds: [8453] });
    const result = await evaluatePolicy(
      rule,
      makeContext({ typedData: permitTypedData({ chainId: 1 }) }),
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("chainId");
  });

  it("DENIES a disallowed primaryType (e.g. a Seaport order when only Permit is allowed)", async () => {
    const rule = makeTypedDataRule({ allowedPrimaryTypes: ["PermitSingle"] });
    const result = await evaluatePolicy(
      rule,
      makeContext({ typedData: permitTypedData({ primaryType: "OrderComponents" }) }),
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("primaryType");
  });

  it("DENIES a spoofed domain name", async () => {
    const rule = makeTypedDataRule({ allowedDomainNames: ["Permit2"] });
    const result = await evaluatePolicy(
      rule,
      makeContext({ typedData: permitTypedData({ name: "EvilPermit" }) }),
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("name");
  });

  it("DENIES a message field spender outside the allowlist", async () => {
    const rule = makeTypedDataRule({
      messageConditions: [{ field: "spender", operator: "address_in", values: [SPENDER_OK] }],
    });
    const result = await evaluatePolicy(
      rule,
      makeContext({ typedData: permitTypedData({ spender: SPENDER_EVIL }) }),
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("spender");
  });

  it("DENIES a message field address present in a not_in blocklist", async () => {
    const rule = makeTypedDataRule({
      messageConditions: [{ field: "spender", operator: "address_not_in", values: [SPENDER_EVIL] }],
    });
    const result = await evaluatePolicy(
      rule,
      makeContext({ typedData: permitTypedData({ spender: SPENDER_EVIL }) }),
    );
    expect(result.passed).toBe(false);
  });

  it("DENIES a uint message field that exceeds its uint_max cap", async () => {
    const rule = makeTypedDataRule({
      messageConditions: [{ field: "amount", operator: "uint_max", value: "1000" }],
    });
    const result = await evaluatePolicy(
      rule,
      makeContext({ typedData: permitTypedData({ amount: "1001" }) }),
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("amount");
  });

  it("DENIES (fails closed) when a constrained message field is missing", async () => {
    const rule = makeTypedDataRule({
      messageConditions: [{ field: "nonexistent", operator: "address_in", values: [SPENDER_OK] }],
    });
    const result = await evaluatePolicy(rule, makeContext({ typedData: permitTypedData({}) }));
    expect(result.passed).toBe(false);
  });

  it("supports dot-path message fields and 0x-hex uint values", async () => {
    const rule = makeTypedDataRule({
      messageConditions: [
        { field: "details.token", operator: "address_in", values: [TOKEN] },
        { field: "details.amount", operator: "uint_max", value: "100" },
      ],
    });
    const td = permitTypedData({});
    td.value = { details: { token: TOKEN, amount: "0x64" } }; // 0x64 == 100
    const ok = await evaluatePolicy(rule, makeContext({ typedData: td }));
    expect(ok.passed).toBe(true);

    const td2 = permitTypedData({});
    td2.value = { details: { token: TOKEN, amount: "0x65" } }; // 101 > 100
    const tooBig = await evaluatePolicy(rule, makeContext({ typedData: td2 }));
    expect(tooBig.passed).toBe(false);
  });
});

// ─── 2. ERC721 / ERC1155 calldata decoding ───────────────────────────────────

describe("NFT calldata conditions (contract-allowlist)", () => {
  const nft = "0x1234567890123456789012345678901234567890";
  const owner = "0x1111111111111111111111111111111111111111";
  const recipientOk = "0x3333333333333333333333333333333333333333";
  const recipientEvil = "0x4444444444444444444444444444444444444444";

  // ERC721 safeTransferFrom(address,address,uint256)
  const ERC721_SAFE_TRANSFER = "0x42842e0e";
  // ERC721 safeTransferFrom(address,address,uint256,bytes)
  const ERC721_SAFE_TRANSFER_DATA = "0xb88d4fde";
  // setApprovalForAll(address,bool)
  const SET_APPROVAL_FOR_ALL = "0xa22cb465";
  // ERC1155 safeTransferFrom(address,address,uint256,uint256,bytes)
  const ERC1155_SAFE_TRANSFER = "0xf242432a";
  // ERC1155 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
  const ERC1155_BATCH = "0x2eb2c2d6";

  function ctxWithData(data: string): EvaluatorContext {
    return makeContext({
      request: { ...makeContext().request, to: nft, data },
    });
  }

  it("enforces ERC721 safeTransferFrom recipient + tokenId allowlists", async () => {
    const rule = makeContractAllowlistRule({
      contracts: [
        {
          address: nft,
          selectors: [ERC721_SAFE_TRANSFER],
          constraints: {
            [ERC721_SAFE_TRANSFER]: {
              recipientAllowlist: [recipientOk],
              tokenIdAllowlist: ["7"],
            },
          },
        },
      ],
    });

    const allowed = await evaluatePolicy(
      rule,
      ctxWithData(
        `${ERC721_SAFE_TRANSFER}${abiAddress(owner)}${abiAddress(recipientOk)}${abiUint(7)}`,
      ),
    );
    expect(allowed.passed).toBe(true);

    const badRecipient = await evaluatePolicy(
      rule,
      ctxWithData(
        `${ERC721_SAFE_TRANSFER}${abiAddress(owner)}${abiAddress(recipientEvil)}${abiUint(7)}`,
      ),
    );
    expect(badRecipient.passed).toBe(false);
    expect(badRecipient.reason).toContain("recipient");

    const badTokenId = await evaluatePolicy(
      rule,
      ctxWithData(
        `${ERC721_SAFE_TRANSFER}${abiAddress(owner)}${abiAddress(recipientOk)}${abiUint(8)}`,
      ),
    );
    expect(badTokenId.passed).toBe(false);
    expect(badTokenId.reason).toContain("Token id");
  });

  it("decodes the ERC721 safeTransferFrom overload that carries trailing bytes", async () => {
    const rule = makeContractAllowlistRule({
      contracts: [
        {
          address: nft,
          selectors: [ERC721_SAFE_TRANSFER_DATA],
          constraints: { [ERC721_SAFE_TRANSFER_DATA]: { recipientAllowlist: [recipientOk] } },
        },
      ],
    });
    const blocked = await evaluatePolicy(
      rule,
      ctxWithData(
        `${ERC721_SAFE_TRANSFER_DATA}${abiAddress(owner)}${abiAddress(recipientEvil)}${abiUint(1)}${abiUint(128)}${abiUint(0)}`,
      ),
    );
    expect(blocked.passed).toBe(false);
    expect(blocked.reason).toContain("recipient");
  });

  it("blocks granting setApprovalForAll to a non-allowlisted operator but allows revocation", async () => {
    const rule = makeContractAllowlistRule({
      contracts: [
        {
          address: nft,
          selectors: [SET_APPROVAL_FOR_ALL],
          constraints: { [SET_APPROVAL_FOR_ALL]: { spenderAllowlist: [recipientOk] } },
        },
      ],
    });

    const grantEvil = await evaluatePolicy(
      rule,
      ctxWithData(`${SET_APPROVAL_FOR_ALL}${abiAddress(recipientEvil)}${abiUint(1)}`),
    );
    expect(grantEvil.passed).toBe(false);
    expect(grantEvil.reason).toContain("operator");

    const grantOk = await evaluatePolicy(
      rule,
      ctxWithData(`${SET_APPROVAL_FOR_ALL}${abiAddress(recipientOk)}${abiUint(1)}`),
    );
    expect(grantOk.passed).toBe(true);

    // Revoking (approved == false) is always allowed, even for a non-allowlisted operator.
    const revokeEvil = await evaluatePolicy(
      rule,
      ctxWithData(`${SET_APPROVAL_FOR_ALL}${abiAddress(recipientEvil)}${abiUint(0)}`),
    );
    expect(revokeEvil.passed).toBe(true);
  });

  it("enforces ERC1155 safeTransferFrom recipient, tokenId and amount caps", async () => {
    const rule = makeContractAllowlistRule({
      contracts: [
        {
          address: nft,
          selectors: [ERC1155_SAFE_TRANSFER],
          constraints: {
            [ERC1155_SAFE_TRANSFER]: {
              recipientAllowlist: [recipientOk],
              tokenIdAllowlist: ["5"],
              maxAmount: "100",
            },
          },
        },
      ],
    });

    const ok = await evaluatePolicy(
      rule,
      ctxWithData(
        `${ERC1155_SAFE_TRANSFER}${abiAddress(owner)}${abiAddress(recipientOk)}${abiUint(5)}${abiUint(100)}${abiUint(160)}${abiUint(0)}`,
      ),
    );
    expect(ok.passed).toBe(true);

    const overAmount = await evaluatePolicy(
      rule,
      ctxWithData(
        `${ERC1155_SAFE_TRANSFER}${abiAddress(owner)}${abiAddress(recipientOk)}${abiUint(5)}${abiUint(101)}${abiUint(160)}${abiUint(0)}`,
      ),
    );
    expect(overAmount.passed).toBe(false);
    expect(overAmount.reason).toContain("exceeds selector maxAmount");
  });

  it("decodes ERC1155 safeBatchTransferFrom dynamic arrays and enforces caps element-wise", async () => {
    // Layout: from, to, idsOff(0xa0=160), amountsOff(0x100=256), dataOff(0x160=352),
    // ids=[1,2], amounts=[10,20], data=[] (len 0).
    function batch(ids: number[], amounts: number[]): string {
      const head = [
        abiAddress(owner),
        abiAddress(recipientOk),
        abiUint(160),
        abiUint(160 + 32 * (1 + ids.length)),
        abiUint(160 + 32 * (1 + ids.length) + 32 * (1 + amounts.length)),
      ];
      const idsEnc = [abiUint(ids.length), ...ids.map((v) => abiUint(v))];
      const amountsEnc = [abiUint(amounts.length), ...amounts.map((v) => abiUint(v))];
      const dataEnc = [abiUint(0)];
      return `${ERC1155_BATCH}${[...head, ...idsEnc, ...amountsEnc, ...dataEnc].join("")}`;
    }

    const rule = makeContractAllowlistRule({
      contracts: [
        {
          address: nft,
          selectors: [ERC1155_BATCH],
          constraints: {
            [ERC1155_BATCH]: {
              recipientAllowlist: [recipientOk],
              tokenIdAllowlist: ["1", "2"],
              maxAmount: "100",
            },
          },
        },
      ],
    });

    const ok = await evaluatePolicy(rule, ctxWithData(batch([1, 2], [10, 20])));
    expect(ok.passed).toBe(true);

    const overAmount = await evaluatePolicy(rule, ctxWithData(batch([1, 2], [10, 200])));
    expect(overAmount.passed).toBe(false);
    expect(overAmount.reason).toContain("exceeds selector maxAmount");

    const badTokenId = await evaluatePolicy(rule, ctxWithData(batch([1, 9], [10, 20])));
    expect(badTokenId.passed).toBe(false);
    expect(badTokenId.reason).toContain("Token id");
  });
});
