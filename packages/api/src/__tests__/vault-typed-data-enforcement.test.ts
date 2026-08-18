/**
 * EIP-712 typed-data policy enforcement on the vault sign-typed-data path.
 *
 * Drives the real {@link PolicyEngine} over a `typed-data`
 *     policy through the exact `typedData` evaluation context the route passes,
 *     proving a spoofed domain / over-cap permit is DENIED while a conforming
 *     one is APPROVED, and that the policy is "not applicable" (does not block)
 *     for an ordinary transaction sign.
 */
import { describe, expect, it } from "bun:test";
import { PolicyEngine } from "@stwd/policy-engine";
import type { PolicyRule, SignRequest } from "@stwd/shared";

// ─── behavioral helpers ───────────────────────────────────────────────────────

const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const SPENDER_OK = "0x1111111111111111111111111111111111111111";
const SPENDER_EVIL = "0x2222222222222222222222222222222222222222";

/** A Permit2-scoped typed-data policy: only this domain + spender, capped amount. */
function permitPolicySet(): PolicyRule[] {
  return [
    {
      id: "td-permit",
      type: "typed-data",
      enabled: true,
      config: {
        verifyingContractAllowlist: [PERMIT2],
        allowedChainIds: [8453],
        allowedPrimaryTypes: ["PermitSingle"],
        messageConditions: [
          { field: "spender", operator: "address_in", values: [SPENDER_OK] },
          { field: "amount", operator: "uint_max", value: "1000" },
        ],
      },
    } as unknown as PolicyRule,
  ];
}

function signReq(): SignRequest {
  // The route uses domain.verifyingContract as `to` and value "0".
  return {
    agentId: "agent-td",
    tenantId: "tenant-td",
    to: PERMIT2,
    value: "0",
    chainId: 8453,
  };
}

function typedData(overrides: {
  verifyingContract?: string;
  spender?: string;
  amount?: string;
  primaryType?: string;
}) {
  return {
    domain: {
      name: "Permit2",
      chainId: 8453,
      verifyingContract: overrides.verifyingContract ?? PERMIT2,
    },
    types: {
      PermitSingle: [
        { name: "spender", type: "address" },
        { name: "amount", type: "uint256" },
      ],
    },
    primaryType: overrides.primaryType ?? "PermitSingle",
    value: { spender: overrides.spender ?? SPENDER_OK, amount: overrides.amount ?? "1000" },
  };
}

// ─── 1. behavioral: the enforcement contract ───────────────────────────────────

describe("typed-data policy enforcement (behavioral)", () => {
  const engine = new PolicyEngine();
  const policySet = permitPolicySet();

  it("APPROVES a conforming permit (right domain, spender, amount)", async () => {
    const evaluation = await engine.evaluate(policySet, {
      request: signReq(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      typedData: typedData({}),
    });
    expect(evaluation.approved).toBe(true);
  });

  it("DENIES a spoofed verifyingContract", async () => {
    const evaluation = await engine.evaluate(policySet, {
      request: signReq(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      typedData: typedData({ verifyingContract: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }),
    });
    expect(evaluation.approved).toBe(false);
  });

  it("DENIES a permit whose spender is not allowlisted", async () => {
    const evaluation = await engine.evaluate(policySet, {
      request: signReq(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      typedData: typedData({ spender: SPENDER_EVIL }),
    });
    expect(evaluation.approved).toBe(false);
  });

  it("DENIES a permit amount over the cap", async () => {
    const evaluation = await engine.evaluate(policySet, {
      request: signReq(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      typedData: typedData({ amount: "1001" }),
    });
    expect(evaluation.approved).toBe(false);
  });

  it("does not block an ordinary transaction sign (typedData absent → not applicable)", async () => {
    const evaluation = await engine.evaluate(policySet, {
      request: { ...signReq(), value: "5" },
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
    });
    expect(evaluation.approved).toBe(true);
  });
});
