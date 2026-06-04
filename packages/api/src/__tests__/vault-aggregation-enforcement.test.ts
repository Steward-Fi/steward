/**
 * Aggregation cap enforcement on the vault sign path.
 *
 * Two complementary layers:
 *
 *  1. BEHAVIORAL — drives the *real* {@link PolicyEngine} over the exact
 *     `AggregationLookup` composition that `loadAggregationsForPolicies`
 *     produces (a map keyed by `aggregationQueryKey`, wrapped by
 *     `aggregationLookupFromMap`). Proves that an authoritative aggregate at/over
 *     the threshold DENIES the over-threshold sign, stays APPROVED under it, and
 *     FAILS CLOSED (deny) when the aggregate is unavailable or no provider is
 *     wired. This is the enforcement contract vault.ts now depends on.
 *
 *  2. WIRING — reads routes/vault.ts and asserts the primary `POST /:agentId/sign`
 *     handler actually composes that contract on the money path: the aggregate
 *     snapshot is loaded INSIDE the per-agent spend lock and BEFORE policy
 *     evaluation, the lookup is passed into the evaluation context, and the
 *     authoritative event is recorded (awaited) on commit. This guards the route
 *     from silently drifting away from the behavior proven in layer 1.
 *
 * Neither layer needs a real Redis or Postgres: the behavioral layer feeds a
 * synthetic snapshot through the public policy-engine primitives, and the wiring
 * layer is a source-structure assertion; the behavioral spend-lock coverage on
 * the vault.ts money path lives in vault-spend-cap-enforcement.test.ts.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  aggregationLookupFromMap,
  aggregationQueriesForPolicies,
  aggregationQueryKey,
  PolicyEngine,
} from "@stwd/policy-engine";
import type { PolicyRule, SignRequest } from "@stwd/shared";

// ─── behavioral helpers ───────────────────────────────────────────────────────

/** A 24h cumulative value cap: deny once recorded + in-flight value ≥ 1000 wei. */
function valueCapPolicySet(): PolicyRule[] {
  return [
    {
      id: "agg-value-cap",
      type: "aggregation",
      enabled: true,
      config: {
        metric: "value_sum",
        window: { named: "24h" },
        scope: "agent",
        denomination: "raw",
        comparator: "gte",
        threshold: "1000",
      },
    } as unknown as PolicyRule,
  ];
}

function signReq(value: string): SignRequest {
  return {
    agentId: "agent-agg",
    tenantId: "tenant-agg",
    to: "0x1111111111111111111111111111111111111111",
    value,
    chainId: 8453,
  };
}

/**
 * Reproduce exactly what `loadAggregationsForPolicies` returns: a synchronous
 * lookup backed by a map keyed via `aggregationQueryKey`. `snapshot === null`
 * models an unavailable aggregate (key omitted → fail closed).
 */
function lookupFor(policySet: PolicyRule[], request: SignRequest, snapshot: bigint | null) {
  const queries = aggregationQueriesForPolicies(policySet, request);
  const map = new Map<string, bigint>();
  if (snapshot !== null) {
    for (const q of queries) map.set(aggregationQueryKey(q), snapshot);
  }
  return aggregationLookupFromMap(map);
}

// ─── 1. behavioral: the enforcement contract ───────────────────────────────────

describe("aggregation cap enforcement (behavioral)", () => {
  const engine = new PolicyEngine();
  const policySet = valueCapPolicySet();

  it("DENIES the sign when recorded + in-flight value crosses the cap", async () => {
    // 900 already recorded; this tx adds 100 → projected 1000 ≥ 1000 → deny.
    const request = signReq("100");
    const aggregations = lookupFor(policySet, request, 900n);
    const evaluation = await engine.evaluate(policySet, { request, aggregations });
    expect(evaluation.approved).toBe(false);
    expect(JSON.stringify(evaluation.results)).toContain("value_sum");
  });

  it("APPROVES the sign when projected value stays under the cap", async () => {
    // 900 recorded; this tx adds 99 → projected 999 < 1000 → allow.
    const request = signReq("99");
    const aggregations = lookupFor(policySet, request, 900n);
    const evaluation = await engine.evaluate(policySet, { request, aggregations });
    expect(evaluation.approved).toBe(true);
  });

  it("FAILS CLOSED (deny) when the authoritative aggregate is unavailable", async () => {
    // Snapshot could not be sourced → key omitted → lookup returns undefined.
    // Even a tiny tx must be denied: we never let an agent spend against an
    // unknown cumulative.
    const request = signReq("1");
    const aggregations = lookupFor(policySet, request, null);
    const evaluation = await engine.evaluate(policySet, { request, aggregations });
    expect(evaluation.approved).toBe(false);
  });

  it("FAILS CLOSED (deny) when NO aggregate provider is wired at all", async () => {
    // This models every vault sign path that does NOT pass `aggregations`: an
    // agent carrying an aggregation policy is denied there rather than bypassing
    // the cap.
    const request = signReq("1");
    const evaluation = await engine.evaluate(policySet, { request });
    expect(evaluation.approved).toBe(false);
  });
});

// ─── 2. wiring: vault.ts composes the contract on the money path ────────────────

describe("aggregation cap enforcement (vault.ts wiring)", () => {
  const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");

  it("imports the read-side bridge and the authoritative recorder", () => {
    expect(vaultSource).toContain("loadAggregationsForPolicies");
    expect(vaultSource).toContain('import { recordAggregationEvent } from "@stwd/redis"');
  });

  it("loads the aggregate in-lock and before evaluation, and passes it to the engine", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer/quote"');
    expect(routeEnd).toBeGreaterThan(routeStart);
    const route = vaultSource.slice(routeStart, routeEnd);

    const lock = route.indexOf("return withAgentSpendLock(agentId");
    const load = route.indexOf("await loadAggregationsForPolicies(policySet, signRequest)");
    const evaluate = route.indexOf("await policyEngine.evaluate(policySet");
    const ctxField = route.indexOf("aggregations,", evaluate);

    expect(lock).toBeGreaterThanOrEqual(0);
    // snapshot loaded inside the lock …
    expect(load).toBeGreaterThan(lock);
    // … and before the policy is evaluated …
    expect(evaluate).toBeGreaterThan(load);
    // … and the lookup is actually fed into the evaluation context.
    expect(ctxField).toBeGreaterThan(evaluate);
  });

  it("records the authoritative aggregation event (awaited) on commit, in-lock", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign"');
    const routeEnd = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer/quote"');
    const route = vaultSource.slice(routeStart, routeEnd);

    const sign = route.indexOf("await vault.signTransaction(signRequest");
    const record = route.indexOf("await recordAggregationEvent({");

    expect(sign).toBeGreaterThanOrEqual(0);
    // Recorded only AFTER the transaction is actually signed/committed …
    expect(record).toBeGreaterThan(sign);
    // … and AWAITED (not fire-and-forget) so the next in-lock snapshot includes it.
    expect(route).toContain("await recordAggregationEvent({");
    expect(route).toContain("valueRaw: signRequest.value");
  });
});
