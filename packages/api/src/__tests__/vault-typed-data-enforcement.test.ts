/**
 * EIP-712 typed-data policy enforcement on the vault sign-typed-data path.
 *
 * Two complementary layers (mirrors vault-aggregation-enforcement.test.ts):
 *
 *  1. BEHAVIORAL — drives the real {@link PolicyEngine} over a `typed-data`
 *     policy through the exact `typedData` evaluation context the route passes,
 *     proving a spoofed domain / over-cap permit is DENIED while a conforming
 *     one is APPROVED, and that the policy is "not applicable" (does not block)
 *     for an ordinary transaction sign.
 *
 *  2. WIRING — reads routes/vault.ts and asserts the `POST /:agentId/sign-typed-data`
 *     handler (a) no longer hard-disables typed-data signing, (b) applies the
 *     fail-closed gate (a `typed-data` policy OR the audited env opt-in) AFTER
 *     the agent-access auth check, and (c) builds the decoded `typedData` and
 *     feeds it into the policy evaluation. Guards the money/authorization path
 *     from silently drifting away from the behavior proven in layer 1.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
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

// ─── 2. wiring: vault.ts composes the contract on the typed-data path ──────────

describe("typed-data policy enforcement (vault.ts wiring)", () => {
  const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");

  it("no longer hard-disables typed-data signing", () => {
    expect(vaultSource).not.toContain("function typedDataSigningDisabled");
    expect(vaultSource).not.toContain("EIP-712 typed data signing is disabled");
  });

  it("applies the auth gate first, then a fail-closed typed-data-policy / env gate", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-typed-data"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-user-operation"');
    expect(routeEnd).toBeGreaterThan(routeStart);
    const route = vaultSource.slice(routeStart, routeEnd);

    const auth = route.indexOf("requireAgentAccess(c)");
    const policyLoad = route.indexOf("getScopedPolicySet(tenantId, agentId");
    const gate = route.indexOf('p.type === "typed-data"');
    const envOptIn = route.indexOf(
      "allowUnsafeTypedDataSigning() && allowVaultUnsafeTypedDataSigning()",
    );
    const deny = route.indexOf("!hasTypedDataPolicy && !typedDataEnvOptIn");

    expect(auth).toBeGreaterThanOrEqual(0);
    // policy-derived gate comes after auth …
    expect(policyLoad).toBeGreaterThan(auth);
    expect(gate).toBeGreaterThan(policyLoad);
    // … the env opt-in is the only escape hatch …
    expect(envOptIn).toBeGreaterThan(policyLoad);
    // … and the route refuses unless one of them holds (fail closed).
    expect(deny).toBeGreaterThan(gate);
  });

  it("builds the decoded typedData and feeds it into the policy evaluation", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-typed-data"');
    const routeEnd = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-user-operation"');
    const route = vaultSource.slice(routeStart, routeEnd);

    const build = route.indexOf("const typedData = {");
    const evaluate = route.indexOf("await policyEngine.evaluate(policySet");
    const ctxField = route.indexOf("typedData,", evaluate);

    expect(build).toBeGreaterThanOrEqual(0);
    // typedData built before evaluation …
    expect(evaluate).toBeGreaterThan(build);
    // … and passed into the evaluation context.
    expect(ctxField).toBeGreaterThan(evaluate);
    // verifyingContract is used as the request `to` so destination policies apply.
    expect(route).toContain("verifyingContractTo");
  });
});
