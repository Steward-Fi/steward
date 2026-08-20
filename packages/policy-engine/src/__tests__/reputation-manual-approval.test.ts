/**
 * Behavioral coverage for reputation-threshold's `action` semantics as routed
 * by the REAL engine (`PolicyEngine.evaluate`), not just the evaluator.
 *
 * Regression target: a reputation score below `minScore` used to always return
 * `passed: false`, which the engine treats as a hard deny for this "hard"
 * (non-`auto-approve-threshold`) policy — so a tenant configuring
 * `require-approval` got a silent hard reject instead of human review.
 *
 * Contract under test:
 *   - block            → hard deny   (approved:false, requiresManualApproval:false)
 *   - require-approval → manual queue (approved:false, requiresManualApproval:true)
 *   - approve          → approved     (approved:true,  requiresManualApproval:false)
 *   - missing/unknown  → hard deny   (fail closed)
 * The same mapping applies to `fallbackAction` when no score is available.
 */

import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import type { PolicyEvaluatedEvent, PolicyEvaluationContext } from "../engine";
import { PolicyEngine } from "../engine";
import { resultRequiresManualApproval } from "../manual-approval";

// ─── Fixtures ───────────────────────────────────────────────────────────────

/**
 * Build a schema-valid reputation-threshold rule by default. Individual
 * malformed-config tests delete or replace fields explicitly; this keeps the
 * behavior tests aligned with the write-time and runtime policy contract.
 */
function makeReputationRule(
  partial: {
    minScore: number;
    action?: string;
    fallbackAction?: string;
    source?: string;
  },
  id = "rep-1",
): PolicyRule {
  const config: Record<string, unknown> = {
    minScore: partial.minScore,
    source: partial.source ?? "internal",
    action: partial.action ?? "block",
    fallbackAction: partial.fallbackAction ?? "block",
  };
  return { id, type: "reputation-threshold", enabled: true, config };
}

function makePolicyContext(
  overrides: Partial<PolicyEvaluationContext> = {},
): PolicyEvaluationContext {
  const request: SignRequest = {
    agentId: "test-agent",
    tenantId: "test-tenant",
    to: "0x1234567890123456789012345678901234567890",
    value: "1000000000000000000", // 1 ETH
    chainId: 8453,
  };
  return {
    request,
    recentTxCount24h: 0,
    recentTxCount1h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    ...overrides,
  };
}

describe("PolicyEngine — reputation-threshold action routing (score below minScore)", () => {
  it("block → hard deny (default-deny preserved)", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, action: "block" });
    const res = await engine.evaluate([rule], makePolicyContext({ reputationScore: 10 }));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
    expect(res.results[0]?.passed).toBe(false);
  });

  it("require-approval → routed to manual approval (NOT a hard deny)", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, action: "require-approval" });
    const res = await engine.evaluate([rule], makePolicyContext({ reputationScore: 10 }));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(true);
    expect(res.results[0]?.passed).toBe(false);
    // The per-policy result carries the explicit opt-in signal.
    expect(resultRequiresManualApproval(res.results[0] as never)).toBe(true);
  });

  it("approve → approved (the policy does not block this tx)", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, action: "approve" });
    const res = await engine.evaluate([rule], makePolicyContext({ reputationScore: 10 }));

    expect(res.approved).toBe(true);
    expect(res.requiresManualApproval).toBe(false);
    expect(res.results[0]?.passed).toBe(true);
  });

  it("missing action → hard deny (fail closed)", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50 });
    // Deliberately corrupt a persisted row after constructing a valid fixture.
    delete (rule.config as Record<string, unknown>).action;
    const res = await engine.evaluate([rule], makePolicyContext({ reputationScore: 10 }));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
    expect(res.results[0]?.passed).toBe(false);
  });

  it("unknown action → hard deny (fail closed)", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, action: "escalate-to-ceo" });
    const res = await engine.evaluate([rule], makePolicyContext({ reputationScore: 10 }));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
    expect(res.results[0]?.passed).toBe(false);
  });

  it("score meeting minScore is approved regardless of action", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, action: "require-approval" });
    const res = await engine.evaluate([rule], makePolicyContext({ reputationScore: 80 }));

    expect(res.approved).toBe(true);
    expect(res.requiresManualApproval).toBe(false);
    expect(res.results[0]?.passed).toBe(true);
  });
});

describe("PolicyEngine — reputation-threshold fallbackAction (no score available)", () => {
  it("fallbackAction block → hard deny", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, fallbackAction: "block" });
    const res = await engine.evaluate([rule], makePolicyContext({}));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
  });

  it("fallbackAction require-approval → routed to manual approval", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, fallbackAction: "require-approval" });
    const res = await engine.evaluate([rule], makePolicyContext({}));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(true);
  });

  it("fallbackAction approve with no score wired → hard deny (fail closed, SEC-040)", async () => {
    const engine = new PolicyEngine();
    const rule = makeReputationRule({ minScore: 50, fallbackAction: "approve" });
    const res = await engine.evaluate([rule], makePolicyContext({}));

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
  });
});

describe("PolicyEngine — require-approval interaction with other policies", () => {
  it("a hard-DENY from another policy overrides require-approval (still rejected)", async () => {
    const engine = new PolicyEngine();
    const repRule = makeReputationRule({ minScore: 50, action: "require-approval" });
    // approved-addresses whitelist that excludes the request target → hard deny.
    const addressRule = {
      id: "addr-1",
      type: "approved-addresses" as const,
      enabled: true,
      config: {
        mode: "whitelist",
        addresses: ["0x000000000000000000000000000000000000dead"],
      },
    };
    const res = await engine.evaluate(
      [repRule, addressRule],
      makePolicyContext({ reputationScore: 10 }),
    );

    // The plain hard failure must win: no manual-approval upgrade.
    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(false);
  });

  it("require-approval alongside passing hard policies routes to manual approval", async () => {
    const engine = new PolicyEngine();
    const repRule = makeReputationRule({ minScore: 50, action: "require-approval" });
    const addressRule = {
      id: "addr-1",
      type: "approved-addresses" as const,
      enabled: true,
      config: {
        // blacklist that does NOT contain the target → passes.
        mode: "blacklist",
        addresses: ["0x000000000000000000000000000000000000dead"],
      },
    };
    const res = await engine.evaluate(
      [repRule, addressRule],
      makePolicyContext({ reputationScore: 10 }),
    );

    expect(res.approved).toBe(false);
    expect(res.requiresManualApproval).toBe(true);
  });
});

describe("PolicyEngine — audit verdict reflects manual-approval routing", () => {
  it("emits NEEDS_MANUAL for require-approval, NACK for block", async () => {
    const events: PolicyEvaluatedEvent[] = [];
    const engine = new PolicyEngine({ auditHook: (e) => void events.push(e) });

    await engine.evaluate(
      [makeReputationRule({ minScore: 50, action: "require-approval" })],
      makePolicyContext({ reputationScore: 10 }),
    );
    await engine.evaluate(
      [makeReputationRule({ minScore: 50, action: "block" })],
      makePolicyContext({ reputationScore: 10 }),
    );

    expect(events[0]?.verdict).toBe("NEEDS_MANUAL");
    expect(events[1]?.verdict).toBe("NACK");
  });
});
