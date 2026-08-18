import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  type AggregationLookup,
  aggregationQueriesForPolicies,
  PolicyEngine,
} from "@stwd/policy-engine";
import type { PolicyRule, SignRequest } from "@stwd/shared";

const tenantId = "tenant-aggregation";
const agentId = "agent-aggregation";
const recipientA = "0x1111111111111111111111111111111111111111";
const recipientB = "0x2222222222222222222222222222222222222222";

setDefaultTimeout(30_000);

let loadAggregationsForPolicies: (
  policySet: PolicyRule[],
  request: SignRequest,
  now?: number,
) => Promise<AggregationLookup>;

function rule(
  id: string,
  metric: "value_sum" | "tx_count" | "unique_recipients",
  scope: "agent" | "per_recipient" | "per_chain" = "agent",
): PolicyRule {
  return {
    id,
    type: "aggregation",
    enabled: true,
    config: {
      metric,
      window: { named: "24h" },
      scope,
      denomination: "raw",
      comparator: "gte",
      threshold: "1000",
    },
  } as unknown as PolicyRule;
}

function request(overrides: Partial<SignRequest> = {}): SignRequest {
  return {
    tenantId,
    agentId,
    to: recipientA,
    value: "1",
    chainId: 8453,
    ...overrides,
  };
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "aggregation-test-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "aggregation-test-audit-key-with-enough-entropy";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  ({ loadAggregationsForPolicies } = await import("../services/context"));

  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "Aggregation Tenant", apiKeyHash: "aggregation-key-hash" });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "Aggregation Agent",
    walletAddress: recipientA,
  });
  await getDb()
    .insert(transactions)
    .values([
      {
        id: "agg-broadcast-a",
        agentId,
        status: "broadcast",
        toAddress: recipientA,
        value: "400",
        chainId: 8453,
      },
      {
        id: "agg-confirmed-b",
        agentId,
        status: "confirmed",
        toAddress: recipientB,
        value: "500",
        chainId: 8453,
      },
      {
        id: "agg-other-chain",
        agentId,
        status: "signed",
        toAddress: recipientA,
        value: "100",
        chainId: 1,
      },
      {
        id: "agg-failed-excluded",
        agentId,
        status: "failed",
        toAddress: recipientA,
        value: "999999",
        chainId: 8453,
      },
    ]);
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
});

describe("durable vault aggregation snapshots", () => {
  it("derives value, count, recipient, and scope snapshots from committed rows", async () => {
    const policies = [
      rule("value-agent", "value_sum"),
      rule("count-chain", "tx_count", "per_chain"),
      rule("count-recipient", "tx_count", "per_recipient"),
      rule("recipients", "unique_recipients"),
    ];
    const signRequest = request();
    const lookup = await loadAggregationsForPolicies(policies, signRequest);
    const queries = aggregationQueriesForPolicies(policies, signRequest);
    const snapshots = Object.fromEntries(
      queries.map((query) => [`${query.metric}:${query.scope}`, lookup(query)?.value]),
    );

    expect(snapshots["value_sum:agent"]).toBe(1000n);
    expect(snapshots["tx_count:per_chain"]).toBe(2n);
    expect(snapshots["tx_count:per_recipient"]).toBe(2n);
    expect(snapshots["unique_recipients:agent"]).toBe(2n);
  });

  it("makes the policy engine deny when durable spend plus the request reaches the cap", async () => {
    const policy = rule("value-cap", "value_sum");
    policy.config.threshold = "1001";
    const signRequest = request({ value: "1" });
    const aggregations = await loadAggregationsForPolicies([policy], signRequest);
    const evaluation = await new PolicyEngine().evaluate([policy], {
      request: signRequest,
      aggregations,
    });

    expect(evaluation.approved).toBe(false);
    expect(JSON.stringify(evaluation.results)).toContain("value_sum");
  });
});
