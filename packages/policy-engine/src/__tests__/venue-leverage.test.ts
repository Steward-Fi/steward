// Sprint 4 Phase 1 Day 3 tests: venue-allowlist + leverage-cap evaluators.

import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { PolicyEngine } from "../engine";
import { evaluateLeverageCap } from "../evaluators/leverage-cap";
import { evaluateVenueAllowlist } from "../evaluators/venue-allowlist";

function venueRule(allowedVenues: string[]): PolicyRule {
  return {
    id: "venue-1",
    type: "venue-allowlist",
    enabled: true,
    config: { allowedVenues },
  };
}

function leverageRule(maxLeverage: number): PolicyRule {
  return {
    id: "lev-1",
    type: "leverage-cap",
    enabled: true,
    config: { maxLeverage },
  };
}

describe("venue-allowlist evaluator", () => {
  it("ALLOWs when the requested venue is in the allowlist", () => {
    const result = evaluateVenueAllowlist(venueRule(["hyperliquid"]), { venue: "hyperliquid" });
    expect(result.passed).toBe(true);
    expect(result.reason).toContain("hyperliquid");
  });

  it("NACKs when the requested venue is NOT in the allowlist", () => {
    const result = evaluateVenueAllowlist(venueRule(["hyperliquid"]), { venue: "polymarket" });
    expect(result.passed).toBe(false);
    expect(result.reason).toBe("venue-not-allowlisted: polymarket");
  });

  it("NACKs when the eval context omits the venue (trade-sessions must set it)", () => {
    const result = evaluateVenueAllowlist(venueRule(["hyperliquid"]), {});
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("missing venue");
  });

  it("NACKs and surfaces misconfig when the allowlist is empty", () => {
    const result = evaluateVenueAllowlist(venueRule([]), { venue: "hyperliquid" });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("misconfigured");
  });

  it("ALLOWs when multiple venues are in the allowlist", () => {
    const result = evaluateVenueAllowlist(venueRule(["hyperliquid", "polymarket"]), {
      venue: "polymarket",
    });
    expect(result.passed).toBe(true);
  });

  it("returns passed=true when the policy itself is disabled (per evaluator contract)", async () => {
    const { evaluatePolicy } = await import("../evaluators");
    const rule: PolicyRule = {
      id: "v",
      type: "venue-allowlist",
      enabled: false,
      config: { allowedVenues: [] },
    };
    const ctx = makeEvaluatorCtx({ venue: "nope" });
    const r = await evaluatePolicy(rule, ctx);
    expect(r.passed).toBe(true);
  });
});

describe("leverage-cap evaluator", () => {
  it("ALLOWs when leverage is below the cap", () => {
    const r = evaluateLeverageCap(leverageRule(2), { leverage: 1.5 });
    expect(r.passed).toBe(true);
  });

  it("ALLOWs when leverage equals the cap (inclusive)", () => {
    const r = evaluateLeverageCap(leverageRule(2), { leverage: 2 });
    expect(r.passed).toBe(true);
  });

  it("NACKs when leverage exceeds the cap", () => {
    const r = evaluateLeverageCap(leverageRule(2), { leverage: 3 });
    expect(r.passed).toBe(false);
    expect(r.reason).toBe("leverage-exceeds-cap: 3 > 2");
  });

  it("ALLOWs when leverage is undefined (non-leveraged trade)", () => {
    const r = evaluateLeverageCap(leverageRule(2), {});
    expect(r.passed).toBe(true);
    expect(r.reason).toContain("non-leveraged");
  });

  it("ALLOWs when leverage is null (typed-edge case)", () => {
    const r = evaluateLeverageCap(leverageRule(2), { leverage: undefined });
    expect(r.passed).toBe(true);
  });

  it("NACKs when maxLeverage is not a finite number (misconfig)", () => {
    const r = evaluateLeverageCap(
      { ...leverageRule(2), config: { maxLeverage: NaN } as any },
      {
        leverage: 1,
      },
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("finite number");
  });

  it("NACKs when maxLeverage is less than 1 (misconfig)", () => {
    const r = evaluateLeverageCap(leverageRule(0), { leverage: 0.5 });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("must be >= 1");
  });

  it("NACKs when leverage is not a finite number (malformed payload)", () => {
    const r = evaluateLeverageCap(leverageRule(2), { leverage: Number.POSITIVE_INFINITY });
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("not a finite number");
  });
});

describe("PolicyEngine.evaluate (venue + leverage end-to-end)", () => {
  it("ALLOWs when both evaluators pass", async () => {
    const engine = new PolicyEngine();
    const result = await engine.evaluate([venueRule(["hyperliquid"]), leverageRule(2)], {
      request: makeSignRequest(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      venue: "hyperliquid",
      leverage: 2,
    });
    expect(result.approved).toBe(true);
    expect(result.requiresManualApproval).toBe(false);
    expect(result.results.every((r) => r.passed)).toBe(true);
  });

  it("rejects when venue-allowlist fails (hard policy)", async () => {
    const engine = new PolicyEngine();
    const result = await engine.evaluate([venueRule(["hyperliquid"]), leverageRule(2)], {
      request: makeSignRequest(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      venue: "polymarket",
      leverage: 1,
    });
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
    const venueResult = result.results.find((r) => r.type === "venue-allowlist");
    expect(venueResult?.passed).toBe(false);
  });

  it("rejects when leverage-cap fails (hard policy)", async () => {
    const engine = new PolicyEngine();
    const result = await engine.evaluate([venueRule(["hyperliquid"]), leverageRule(2)], {
      request: makeSignRequest(),
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      venue: "hyperliquid",
      leverage: 5,
    });
    expect(result.approved).toBe(false);
    const leverageResult = result.results.find((r) => r.type === "leverage-cap");
    expect(leverageResult?.passed).toBe(false);
    expect(leverageResult?.reason).toContain("5 > 2");
  });
});

function makeSignRequest(): SignRequest {
  return {
    agentId: "sol",
    tenantId: "test-tenant",
    to: "0x0000000000000000000000000000000000000000",
    value: "0",
    chainId: 42161,
  };
}

function makeEvaluatorCtx(overrides: { venue?: string; leverage?: number } = {}) {
  return {
    request: makeSignRequest(),
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    ...overrides,
  };
}
