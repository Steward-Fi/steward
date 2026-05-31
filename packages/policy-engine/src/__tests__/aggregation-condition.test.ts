import { describe, expect, test } from "bun:test";
import type { PolicyRule, PriceOracle, SignRequest } from "@stwd/shared";
import { evaluatePolicy } from "../evaluators";
import {
  type AggregationLookup,
  type AggregationQuery,
  type AggregationSnapshot,
  aggregationLookupFromMap,
  aggregationQueriesForPolicies,
  aggregationQueryKey,
  evaluateAggregation,
  NAMED_WINDOW_SECONDS,
  resolveScopeKey,
  resolveWindowSeconds,
} from "../evaluators/aggregation";

// ─── helpers ────────────────────────────────────────────────────────────────

function req(overrides: Partial<SignRequest> = {}): SignRequest {
  return {
    agentId: "agent-1",
    tenantId: "tenant-1",
    to: "0x1111111111111111111111111111111111111111",
    value: "0",
    chainId: 8453,
    ...overrides,
  };
}

function rule(config: Record<string, unknown>, overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: "agg-policy",
    type: "aggregation",
    enabled: true,
    config,
    ...overrides,
  };
}

/** A lookup that always returns the same snapshot value regardless of query. */
function fixedLookup(value: bigint): AggregationLookup {
  return () => ({ value });
}

/** A lookup that captures the query it was called with, for spoof tests. */
function capturingLookup(value: bigint): {
  lookup: AggregationLookup;
  calls: AggregationQuery[];
} {
  const calls: AggregationQuery[] = [];
  const lookup: AggregationLookup = (query) => {
    calls.push(query);
    return { value };
  };
  return { lookup, calls };
}

// ─── metric coverage ──────────────────────────────────────────────────────────

describe("aggregation metrics", () => {
  test("value_sum: denies when projected sum crosses gte threshold", async () => {
    // existing aggregate 900, this tx adds 100 → 1000 >= 1000 → deny
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "1000",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "100" }),
      aggregations: fixedLookup(900n),
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("value_sum");
  });

  test("value_sum: allows when projected sum stays below gte threshold", async () => {
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "1000",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "99" }),
      aggregations: fixedLookup(900n),
    });
    expect(result.passed).toBe(true);
  });

  test("tx_count: counts recorded aggregate, ignores request value", async () => {
    const r = rule({
      metric: "tx_count",
      window: { named: "1h" },
      comparator: "gte",
      threshold: "5",
    });
    // 5 already recorded; tx_count does not add the in-flight request (provider
    // records it on commit), so aggregate is 5 >= 5 → deny.
    const deny = await evaluateAggregation(r, {
      request: req({ value: "999999999" }),
      aggregations: fixedLookup(5n),
    });
    expect(deny.passed).toBe(false);

    const allow = await evaluateAggregation(r, {
      request: req(),
      aggregations: fixedLookup(4n),
    });
    expect(allow.passed).toBe(true);
  });

  test("unique_recipients: denies at/above gt threshold", async () => {
    const r = rule({
      metric: "unique_recipients",
      window: { named: "7d" },
      comparator: "gt",
      threshold: "10",
    });
    const deny = await evaluateAggregation(r, {
      request: req(),
      aggregations: fixedLookup(11n),
    });
    expect(deny.passed).toBe(false);

    const allow = await evaluateAggregation(r, {
      request: req(),
      aggregations: fixedLookup(10n),
    });
    expect(allow.passed).toBe(true);
  });
});

// ─── comparator coverage at / above / below threshold ──────────────────────────

describe("comparators at exact threshold (gt vs gte confusion)", () => {
  const base = {
    metric: "tx_count" as const,
    window: { named: "1h" as const },
    threshold: "100",
  };

  test("gt: aggregate exactly at threshold does NOT trip (allows)", async () => {
    const result = await evaluateAggregation(rule({ ...base, comparator: "gt" }), {
      request: req(),
      aggregations: fixedLookup(100n),
    });
    expect(result.passed).toBe(true);
  });

  test("gte: aggregate exactly at threshold trips (denies)", async () => {
    const result = await evaluateAggregation(rule({ ...base, comparator: "gte" }), {
      request: req(),
      aggregations: fixedLookup(100n),
    });
    expect(result.passed).toBe(false);
  });

  test("lt: aggregate exactly at threshold does NOT trip", async () => {
    const result = await evaluateAggregation(rule({ ...base, comparator: "lt" }), {
      request: req(),
      aggregations: fixedLookup(100n),
    });
    expect(result.passed).toBe(true);
  });

  test("lte: aggregate exactly at threshold trips", async () => {
    const result = await evaluateAggregation(rule({ ...base, comparator: "lte" }), {
      request: req(),
      aggregations: fixedLookup(100n),
    });
    expect(result.passed).toBe(false);
  });

  test("eq: trips only at exact threshold", async () => {
    const atThreshold = await evaluateAggregation(rule({ ...base, comparator: "eq" }), {
      request: req(),
      aggregations: fixedLookup(100n),
    });
    expect(atThreshold.passed).toBe(false);
    const offThreshold = await evaluateAggregation(rule({ ...base, comparator: "eq" }), {
      request: req(),
      aggregations: fixedLookup(99n),
    });
    expect(offThreshold.passed).toBe(true);
  });

  test("gt: one above threshold trips, one below does not", async () => {
    const above = await evaluateAggregation(rule({ ...base, comparator: "gt" }), {
      request: req(),
      aggregations: fixedLookup(101n),
    });
    expect(above.passed).toBe(false);
    const below = await evaluateAggregation(rule({ ...base, comparator: "gt" }), {
      request: req(),
      aggregations: fixedLookup(99n),
    });
    expect(below.passed).toBe(true);
  });
});

// ─── window resolution + boundary ──────────────────────────────────────────────

describe("window resolution and boundary", () => {
  test("named windows resolve to documented seconds", () => {
    expect(NAMED_WINDOW_SECONDS["1h"]).toBe(3600);
    expect(NAMED_WINDOW_SECONDS["24h"]).toBe(86400);
    expect(NAMED_WINDOW_SECONDS["7d"]).toBe(604800);
    expect(NAMED_WINDOW_SECONDS["30d"]).toBe(2592000);
  });

  test("explicit seconds override named and resolve", () => {
    expect(
      resolveWindowSeconds({
        metric: "tx_count",
        window: { named: "1h", seconds: 42 },
        comparator: "gt",
        threshold: "1",
      }),
    ).toBe(42);
  });

  test("the resolved windowSeconds is passed to the provider so off-by-one cannot occur", async () => {
    // A condition that would only pass if the window were mis-resolved. The
    // evaluator must hand the provider the exact resolved window; we assert the
    // query the lookup receives matches the named window's seconds.
    const { lookup, calls } = capturingLookup(3n);
    await evaluateAggregation(
      rule({ metric: "tx_count", window: { named: "24h" }, comparator: "gte", threshold: "5" }),
      { request: req(), aggregations: lookup },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0].windowSeconds).toBe(86400);
  });

  test("zero-window denies (fail closed)", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: { seconds: 0 }, comparator: "gt", threshold: "1" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("window");
  });

  test("negative-window denies (fail closed)", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: { seconds: -3600 }, comparator: "gt", threshold: "1" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });

  test("empty/missing window denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: {}, comparator: "gt", threshold: "1" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });

  test("non-integer / unsafe window denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: { seconds: 1.5 }, comparator: "gt", threshold: "1" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });
});

// ─── scope coverage ─────────────────────────────────────────────────────────────

describe("scope grouping", () => {
  test("per_recipient: scopeKey is the lowercased recipient", async () => {
    const { lookup, calls } = capturingLookup(0n);
    await evaluateAggregation(
      rule({
        metric: "value_sum",
        window: { named: "24h" },
        scope: "per_recipient",
        comparator: "gte",
        threshold: "1000",
      }),
      {
        request: req({ to: "0xABCDEF0000000000000000000000000000000001", value: "10" }),
        aggregations: lookup,
      },
    );
    expect(calls[0].scope).toBe("per_recipient");
    expect(calls[0].scopeKey).toBe("0xabcdef0000000000000000000000000000000001");
  });

  test("per_chain: scopeKey is the decimal chainId", async () => {
    const { lookup, calls } = capturingLookup(0n);
    await evaluateAggregation(
      rule({
        metric: "tx_count",
        window: { named: "1h" },
        scope: "per_chain",
        comparator: "gte",
        threshold: "3",
      }),
      { request: req({ chainId: 42161 }), aggregations: lookup },
    );
    expect(calls[0].scope).toBe("per_chain");
    expect(calls[0].scopeKey).toBe("42161");
  });

  test("agent scope uses empty scopeKey", async () => {
    const { lookup, calls } = capturingLookup(0n);
    await evaluateAggregation(
      rule({ metric: "tx_count", window: { named: "1h" }, comparator: "gte", threshold: "3" }),
      { request: req(), aggregations: lookup },
    );
    expect(calls[0].scope).toBe("agent");
    expect(calls[0].scopeKey).toBe("");
  });

  test("per_recipient with missing recipient denies", async () => {
    const result = await evaluateAggregation(
      rule({
        metric: "value_sum",
        window: { named: "24h" },
        scope: "per_recipient",
        comparator: "gte",
        threshold: "1000",
      }),
      { request: req({ to: "" }), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });

  test("per_chain with invalid chainId denies", async () => {
    expect(resolveScopeKey("per_chain", req({ chainId: 0 }))).toBeNull();
    const result = await evaluateAggregation(
      rule({
        metric: "tx_count",
        window: { named: "1h" },
        scope: "per_chain",
        comparator: "gte",
        threshold: "1",
      }),
      { request: req({ chainId: -1 }), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });
});

// ─── bigint precision (no float drift) ──────────────────────────────────────────

describe("bigint precision", () => {
  test("huge wei sums compare exactly with no float drift", async () => {
    // 18 decimals: existing 5 ETH, threshold 10 ETH, add 5 ETH → exactly 10 ETH.
    const fiveEth = 5n * 10n ** 18n;
    const tenEth = (10n * 10n ** 18n).toString();
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: tenEth,
    });
    const deny = await evaluateAggregation(r, {
      request: req({ value: fiveEth.toString() }),
      aggregations: fixedLookup(fiveEth),
    });
    expect(deny.passed).toBe(false);

    // One wei under → allow. A float impl would round this away.
    const allow = await evaluateAggregation(r, {
      request: req({ value: (fiveEth - 1n).toString() }),
      aggregations: fixedLookup(fiveEth),
    });
    expect(allow.passed).toBe(true);
  });

  test("threshold at uint256 max is accepted; aggregate below it allows", async () => {
    const maxUint =
      "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const r = rule({
      metric: "value_sum",
      window: { named: "30d" },
      comparator: "gte",
      threshold: maxUint,
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "1" }),
      aggregations: fixedLookup(10n),
    });
    expect(result.passed).toBe(true);
  });
});

// ─── USD denomination (with oracle + fail-closed) ───────────────────────────────

function oracleReturning(usd: number | null): PriceOracle {
  return {
    getNativeUsdPrice: async () => null,
    getTokenUsdPrice: async () => null,
    weiToUsd: async () => usd,
    usdToWei: async () => null,
  };
}

describe("usd denomination", () => {
  test("usd value_sum with oracle: denies when projected cents cross threshold", async () => {
    // threshold = 5000 cents = $50. Oracle reports projected sum is worth $60.
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "5000",
      denomination: "usd",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "1" }),
      aggregations: fixedLookup(10n),
      priceOracle: oracleReturning(60), // $60 → 6000 cents >= 5000 → deny
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("¢");
  });

  test("usd value_sum with oracle: allows when projected cents below threshold", async () => {
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "5000",
      denomination: "usd",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "1" }),
      aggregations: fixedLookup(10n),
      priceOracle: oracleReturning(49.5), // $49.50 → 4950 cents < 5000 → allow
    });
    expect(result.passed).toBe(true);
  });

  test("usd denomination WITHOUT oracle fails closed (deny)", async () => {
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "5000",
      denomination: "usd",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "1" }),
      aggregations: fixedLookup(10n),
      // no priceOracle
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("price oracle");
  });

  test("usd denomination with oracle returning null fails closed (deny)", async () => {
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "5000",
      denomination: "usd",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "1" }),
      aggregations: fixedLookup(10n),
      priceOracle: oracleReturning(null),
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("priced");
  });

  test("usd denomination on a non-value metric is rejected (deny)", async () => {
    const r = rule({
      metric: "tx_count",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "5",
      denomination: "usd",
    });
    const result = await evaluateAggregation(r, {
      request: req(),
      aggregations: fixedLookup(0n),
      priceOracle: oracleReturning(100),
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("usd denomination is only valid for value_sum");
  });
});

// ─── provider unavailable → deny ────────────────────────────────────────────────

describe("provider availability (fail closed)", () => {
  test("no aggregations lookup on context denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: { named: "1h" }, comparator: "gte", threshold: "1" }),
      { request: req() },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("no aggregate provider");
  });

  test("lookup returns undefined (no snapshot) denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: { named: "1h" }, comparator: "gte", threshold: "1" }),
      { request: req(), aggregations: () => undefined },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("authoritative aggregate unavailable");
  });

  test("lookup returns negative snapshot denies (corrupt provider)", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "value_sum", window: { named: "1h" }, comparator: "gte", threshold: "1" }),
      { request: req(), aggregations: () => ({ value: -1n }) as AggregationSnapshot },
    );
    expect(result.passed).toBe(false);
  });
});

// ─── malformed config → deny ────────────────────────────────────────────────────

describe("malformed config (fail closed)", () => {
  test("negative threshold denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "value_sum", window: { named: "1h" }, comparator: "gte", threshold: "-5" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("threshold");
  });

  test("non-numeric threshold denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "value_sum", window: { named: "1h" }, comparator: "gte", threshold: "0xFF" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });

  test("float threshold denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "value_sum", window: { named: "1h" }, comparator: "gte", threshold: "1.5" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
  });

  test("threshold above uint256 max (overflow) denies", async () => {
    // uint256 max + 1
    const overMax =
      "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    const result = await evaluateAggregation(
      rule({
        metric: "value_sum",
        window: { named: "1h" },
        comparator: "gte",
        threshold: overMax,
      }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("threshold");
  });

  test("unknown metric denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "lol_sum", window: { named: "1h" }, comparator: "gte", threshold: "1" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("unknown metric");
  });

  test("unknown comparator denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "tx_count", window: { named: "1h" }, comparator: "approx", threshold: "1" }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("unknown comparator");
  });

  test("unknown scope denies", async () => {
    const result = await evaluateAggregation(
      rule({
        metric: "tx_count",
        window: { named: "1h" },
        scope: "per_galaxy",
        comparator: "gte",
        threshold: "1",
      }),
      { request: req(), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("unknown scope");
  });

  test("value_sum with unparseable request value denies", async () => {
    const result = await evaluateAggregation(
      rule({ metric: "value_sum", window: { named: "1h" }, comparator: "gte", threshold: "1000" }),
      { request: req({ value: "not-a-number" }), aggregations: fixedLookup(0n) },
    );
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("uint256");
  });
});

// ─── RED TEAM ───────────────────────────────────────────────────────────────────

describe("red team: caller cannot spoof the aggregate", () => {
  test("request carries a bogus low 'spentToday'/'aggregate' field — evaluation ignores it", async () => {
    // The SignRequest type has no aggregate field, but an attacker may stuff
    // arbitrary keys. Prove the evaluator only consults the provider lookup and
    // never reads request-supplied aggregate-ish fields.
    const spoofed = {
      ...req({ value: "1" }),
      // attacker-injected fields:
      spentToday: "0",
      aggregate: "0",
      recentTxCount24h: 0,
      value_sum: "0",
    } as unknown as SignRequest;

    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "1000",
    });
    // Provider says the true aggregate is already 1000 → must deny regardless of
    // the spoofed "0" fields in the request.
    const result = await evaluateAggregation(r, {
      request: spoofed,
      aggregations: fixedLookup(1000n),
    });
    expect(result.passed).toBe(false);
  });

  test("the lookup is driven only by server-resolved query fields (agent/metric/window/scope)", async () => {
    const { lookup, calls } = capturingLookup(0n);
    const spoofed = {
      ...req({ value: "5", to: "0xAAaAAaaAaAaAaAaaAaaAAaAAaaAaAAAaAaAaAAaA", chainId: 8453 }),
      windowSeconds: 1, // attacker tries to shrink the window via request
      scopeKey: "attacker-controlled",
    } as unknown as SignRequest;

    await evaluateAggregation(
      rule({
        metric: "value_sum",
        window: { named: "7d" },
        scope: "per_recipient",
        comparator: "gte",
        threshold: "1000",
      }),
      { request: spoofed, aggregations: lookup },
    );
    // window comes from config (7d), not the request's spoofed windowSeconds.
    expect(calls[0].windowSeconds).toBe(604800);
    // scopeKey comes from the canonical `to`, not the spoofed scopeKey.
    expect(calls[0].scopeKey).toBe("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  });

  test("attacker lowering request value cannot evade a value_sum cap already met by history", async () => {
    // History already at threshold; attacker sends value "0" hoping the
    // contribution makes projected < threshold. With lte it would matter, but
    // for gte the existing aggregate alone trips.
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "1000",
    });
    const result = await evaluateAggregation(r, {
      request: req({ value: "0" }),
      aggregations: fixedLookup(1000n),
    });
    expect(result.passed).toBe(false);
  });
});

// ─── integration via evaluatePolicy dispatch ────────────────────────────────────

describe("dispatch through evaluatePolicy", () => {
  test("disabled aggregation policy passes (disabled short-circuit)", async () => {
    const r = rule(
      { metric: "value_sum", window: { named: "24h" }, comparator: "gte", threshold: "1" },
      { enabled: false },
    );
    const result = await evaluatePolicy(r, {
      request: req({ value: "1000000" }),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      // no aggregations wired — but disabled means it should still pass
    });
    expect(result.passed).toBe(true);
    expect(result.reason).toBe("Policy disabled");
  });

  test("enabled aggregation policy with no provider fails closed via dispatch", async () => {
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "1",
    });
    const result = await evaluatePolicy(r, {
      request: req({ value: "1" }),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
    });
    expect(result.passed).toBe(false);
  });

  test("enabled aggregation policy passes through provider when under threshold", async () => {
    const r = rule({
      metric: "tx_count",
      window: { named: "1h" },
      comparator: "gte",
      threshold: "10",
    });
    const result = await evaluatePolicy(r, {
      request: req(),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      aggregations: fixedLookup(3n),
    });
    expect(result.passed).toBe(true);
  });
});

// ─── query planning helpers ─────────────────────────────────────────────────────

describe("aggregationQueriesForPolicies + lookup map", () => {
  test("derives a deduped query set for well-formed aggregation policies only", () => {
    const policies: PolicyRule[] = [
      rule(
        { metric: "value_sum", window: { named: "24h" }, comparator: "gte", threshold: "1000" },
        { id: "a" },
      ),
      // duplicate of the first (same resolved query) → deduped
      rule(
        { metric: "value_sum", window: { seconds: 86400 }, comparator: "lt", threshold: "9" },
        { id: "b" },
      ),
      rule(
        {
          metric: "tx_count",
          window: { named: "1h" },
          scope: "per_chain",
          comparator: "gte",
          threshold: "5",
        },
        { id: "c" },
      ),
      // malformed (bad window) → skipped
      rule({ metric: "tx_count", window: {}, comparator: "gte", threshold: "5" }, { id: "d" }),
      // not an aggregation policy → ignored
      { id: "e", type: "rate-limit", enabled: true, config: {} },
    ];
    const queries = aggregationQueriesForPolicies(policies, req({ chainId: 8453 }));
    // value_sum/24h/agent (a & b dedupe to one) + tx_count/1h/per_chain = 2
    expect(queries).toHaveLength(2);
    const keys = queries.map(aggregationQueryKey);
    expect(new Set(keys).size).toBe(2);
  });

  test("aggregationLookupFromMap returns snapshot for known key, undefined otherwise", () => {
    const q: AggregationQuery = {
      agentId: "agent-1",
      tenantId: "tenant-1",
      metric: "value_sum",
      windowSeconds: 86400,
      scope: "agent",
      scopeKey: "",
    };
    const map = new Map<string, bigint>([[aggregationQueryKey(q), 777n]]);
    const lookup = aggregationLookupFromMap(map);
    expect(lookup(q)).toEqual({ value: 777n });
    expect(
      lookup({ ...q, windowSeconds: 3600 }), // different window → not in map
    ).toBeUndefined();
  });

  test("end-to-end: plan queries, build map, evaluate denies at cap", async () => {
    const r = rule({
      metric: "value_sum",
      window: { named: "24h" },
      comparator: "gte",
      threshold: "1000",
    });
    const request = req({ value: "100" });
    const queries = aggregationQueriesForPolicies([r], request);
    expect(queries).toHaveLength(1);
    // Simulate provider returning 900 for the planned query.
    const map = new Map<string, bigint>([[aggregationQueryKey(queries[0]), 900n]]);
    const result = await evaluateAggregation(r, {
      request,
      aggregations: aggregationLookupFromMap(map),
    });
    // 900 + 100 = 1000 >= 1000 → deny
    expect(result.passed).toBe(false);
  });
});
