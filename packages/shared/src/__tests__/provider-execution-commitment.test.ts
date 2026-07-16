import { describe, expect, test } from "bun:test";
import {
  buildProviderExecutionCommitmentV2,
  computeGrantDependencyHash,
  computeProviderExecutionCommitmentHash,
  type GithubCanonicalActionV1,
  type ProviderExecutionCommitmentBuildInput,
  providerExecutionCommitmentBytes,
  serializeCanonicalOutboundQuery,
} from "../provider-action.js";

// A minimal, valid canonical action (pinned github origin) reused across cases.
const ACTION: GithubCanonicalActionV1 = {
  profile: "github.provider-action.v1",
  method: "POST",
  origin: "https://api.github.com",
  normalizedPath: "/repos/acme/widgets/issues",
  orderedQueryPairs: [
    ["per_page", "30"],
    ["state", "open"],
    ["labels", "a,b c"],
  ],
  selectedHeaders: [
    ["accept", "application/vnd.github+json"],
    ["content-type", "application/json"],
  ],
  canonicalBody: { title: "hi" },
};

function baseInput(): ProviderExecutionCommitmentBuildInput {
  return {
    approval: {
      intentId: "intent-1",
      tenantId: "11111111-1111-1111-1111-111111111111",
      workspaceId: "22222222-2222-2222-2222-222222222222",
      requestActor: { id: "agent-1" },
      providerAccount: { id: "33333333-3333-3333-3333-333333333333" },
      operation: { id: "44444444-4444-4444-4444-444444444444", revision: 3 },
      requestHash: `sha256:${"a".repeat(64)}`,
      actionDigest: `sha256:${"b".repeat(64)}`,
      accessDecision: {
        id: "55555555-5555-5555-5555-555555555555",
        hash: `sha256:${"c".repeat(64)}`,
        matchedBindings: [{ id: "b0000000-0000-0000-0000-000000000002", revision: 1 }],
        matchedGrants: [
          { id: "a0000000-0000-0000-0000-000000000002", revision: 2 },
          { id: "a0000000-0000-0000-0000-000000000001", revision: 1 },
        ],
      },
      policyDecision: { policyRevisionHash: `sha256:${"d".repeat(64)}` },
      executionDependencies: {
        routeId: "66666666-6666-6666-6666-666666666666",
        routeRevision: 4,
        secretId: "77777777-7777-7777-7777-777777777777",
        secretVersion: 5,
      },
    },
    action: ACTION,
    approvalCommitmentHash: `sha256:${"e".repeat(64)}`,
    approvalId: "approval-1",
    authorizationId: "auth-1",
    executionId: "exec-1",
    requestId: "intent-1",
    providerIdempotencyKey: "prov-idem-1",
    nonce: "bm9uY2Vub25jZW5vbmNlbm9uY2U",
    issuedAt: "2026-07-14T20:00:00.000Z",
    expiresAt: "2026-07-14T20:05:00.000Z",
    keyId: "k1",
  };
}

describe("provider execution v2 commitment builder", () => {
  test("is deterministic: same input yields byte-identical bytes + hash", () => {
    const a = buildProviderExecutionCommitmentV2(baseInput());
    const b = buildProviderExecutionCommitmentV2(baseInput());
    expect(providerExecutionCommitmentBytes(a)).toBe(providerExecutionCommitmentBytes(b));
    expect(computeProviderExecutionCommitmentHash(a)).toBe(
      computeProviderExecutionCommitmentHash(b),
    );
  });

  test("target host + method + normalizedPath come from the canonical action", () => {
    const c = buildProviderExecutionCommitmentV2(baseInput());
    expect(c.target).toEqual({
      scheme: "https",
      host: "api.github.com",
      port: 443,
      normalizedPath: "/repos/acme/widgets/issues",
      method: "POST",
    });
  });

  test("route/secret/operation revisions + hashes come from the committed approval", () => {
    const c = buildProviderExecutionCommitmentV2(baseInput());
    expect(c.routeId).toBe("66666666-6666-6666-6666-666666666666");
    expect(c.routeRevision).toBe(4);
    expect(c.secretId).toBe("77777777-7777-7777-7777-777777777777");
    expect(c.secretVersion).toBe(5);
    expect(c.operationRevision).toBe(3);
    expect(c.requestHash).toBe(`sha256:${"a".repeat(64)}`);
    expect(c.actionDigest).toBe(`sha256:${"b".repeat(64)}`);
    expect(c.accessDecisionHash).toBe(`sha256:${"c".repeat(64)}`);
    expect(c.policyRevisionHash).toBe(`sha256:${"d".repeat(64)}`);
    expect(c.approvalCommitmentHash).toBe(`sha256:${"e".repeat(64)}`);
    expect(c.maxUses).toBe(1);
    expect(c.backend).toBe("credential-proxy");
  });

  test("grantDependencyHash is order-independent (grants sorted by uuid bytes)", () => {
    const input = baseInput();
    const h1 = computeGrantDependencyHash(input.approval.accessDecision);
    // Reverse the grant order; hash must not change.
    const reversed = {
      matchedBindings: input.approval.accessDecision.matchedBindings,
      matchedGrants: [...input.approval.accessDecision.matchedGrants].reverse(),
    };
    const h2 = computeGrantDependencyHash(reversed);
    expect(h1).toBe(h2);
    expect(buildProviderExecutionCommitmentV2(input).grantDependencyHash).toBe(h1);
  });

  test("grantDependencyHash changes when a grant revision changes (X5/P15)", () => {
    const input = baseInput();
    const before = computeGrantDependencyHash(input.approval.accessDecision);
    const bumped = {
      matchedBindings: input.approval.accessDecision.matchedBindings,
      matchedGrants: input.approval.accessDecision.matchedGrants.map((g, i) =>
        i === 0 ? { ...g, revision: g.revision + 1 } : g,
      ),
    };
    expect(computeGrantDependencyHash(bumped)).not.toBe(before);
  });

  test("headerAllowlistDigest binds selected header NAME set (order-independent)", () => {
    const c1 = buildProviderExecutionCommitmentV2(baseInput());
    const swapped = baseInput();
    swapped.action = {
      ...ACTION,
      selectedHeaders: [...ACTION.selectedHeaders].reverse(),
    };
    const c2 = buildProviderExecutionCommitmentV2(swapped);
    expect(c1.headerAllowlistDigest).toBe(c2.headerAllowlistDigest);

    const extra = baseInput();
    extra.action = {
      ...ACTION,
      selectedHeaders: [...ACTION.selectedHeaders, ["x-extra", "1"]],
    };
    expect(buildProviderExecutionCommitmentV2(extra).headerAllowlistDigest).not.toBe(
      c1.headerAllowlistDigest,
    );
  });

  test("outbound query serialization uses RFC3986 (%20 not +, uppercase hex), preserves order + dupes", () => {
    expect(serializeCanonicalOutboundQuery([])).toBe("");
    expect(
      serializeCanonicalOutboundQuery([
        ["per_page", "30"],
        ["state", "open"],
        ["labels", "a,b c"],
      ]),
    ).toBe("per_page=30&state=open&labels=a%2Cb%20c");
    // Duplicate keys preserved in order.
    expect(
      serializeCanonicalOutboundQuery([
        ["k", "1"],
        ["k", "2"],
      ]),
    ).toBe("k=1&k=2");
  });

  test("any committed field flip changes the commitment hash", () => {
    const base = buildProviderExecutionCommitmentV2(baseInput());
    const baseHash = computeProviderExecutionCommitmentHash(base);
    const drift = baseInput();
    drift.approval.executionDependencies.secretVersion = 6;
    expect(
      computeProviderExecutionCommitmentHash(buildProviderExecutionCommitmentV2(drift)),
    ).not.toBe(baseHash);
  });
});
