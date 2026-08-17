import { describe, expect, it } from "bun:test";
import type { GithubOperationKey } from "@stwd/provider-github";
import type { XOperationKey } from "@stwd/provider-x";
import { parseGovernedCanonicalActionForDispatch } from "@stwd/proxy/src/handlers/governed-execution";
import {
  CanonError,
  canonicalApprovalCommitmentObject,
  computeApprovalCommitmentHash,
  GENERIC_GOLDEN_DESCRIPTOR_A,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  GITHUB_PROVIDER_ACTION_PROFILE,
  inspectProviderProfileConformance,
  jcsStringify,
  type ProviderApprovalCommitmentV1,
  REGISTERED_PROFILES,
  strictParseJson,
  validateGenericHttpDescriptor,
  X_PROVIDER_ACTION_PROFILE,
} from "@stwd/shared";
import {
  PRODUCTION_PROVIDER_PROFILE_SPECS,
  type ProductionProviderProfileSpec,
} from "../services/provider-action-profile-specs";

const GENERIC_DESCRIPTOR = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_A);

const FIXTURES = {
  [GITHUB_PROVIDER_ACTION_PROFILE]: {
    operationKey: "github.issue.list" as const,
    method: undefined,
    args: { owner: "octo", repo: "hello", state: "open", perPage: 30 },
    traversalArgs: { owner: "..", repo: "hello" },
    traversalCode: "CANON_PATH_SEGMENT_INVALID",
  },
  [X_PROVIDER_ACTION_PROFILE]: {
    operationKey: "x.tweet.delete" as const,
    method: undefined,
    args: { tweetId: "1234567890" },
    traversalArgs: { tweetId: ".." },
    traversalCode: "CANON_PATH_SEGMENT_INVALID",
  },
  [GENERIC_HTTP_PROVIDER_ACTION_PROFILE]: {
    operationKey: "generic.items.list",
    method: "GET",
    args: {
      org: "octo",
      projectId: "123e4567-e89b-42d3-a456-426614174000",
      state: "open",
      perPage: 30,
    },
    traversalArgs: {
      org: "..",
      projectId: "123e4567-e89b-42d3-a456-426614174000",
    },
    traversalCode: "CANON_PATH_SEGMENT_INVALID",
  },
} as const;

const OPERATION_FIXTURES = {
  [GITHUB_PROVIDER_ACTION_PROFILE]: [
    {
      operationKey: "github.issue.list",
      args: { owner: "octo", repo: "hello", state: "open", perPage: 30 },
    },
    {
      operationKey: "github.pr.comment.create",
      args: { owner: "octo", repo: "hello", pullNumber: 42, body: "looks good" },
    },
  ],
  [X_PROVIDER_ACTION_PROFILE]: [
    {
      operationKey: "x.tweet.create",
      args: { text: "hello world", summoned: false },
    },
    {
      operationKey: "x.tweet.delete",
      args: { tweetId: "1234567890" },
    },
    {
      operationKey: "x.user.me.read",
      args: {},
    },
  ],
  [GENERIC_HTTP_PROVIDER_ACTION_PROFILE]: [
    {
      operationKey: "generic.items.list",
      method: "GET",
      args: {
        org: "octo",
        projectId: "123e4567-e89b-42d3-a456-426614174000",
        state: "open",
        perPage: 30,
      },
    },
  ],
} as const;

type OperationFixture = (typeof OPERATION_FIXTURES)[keyof typeof OPERATION_FIXTURES][number];

function buildFromProductionSpec(
  spec: ProductionProviderProfileSpec,
  args: Record<string, unknown>,
  fixture: OperationFixture = FIXTURES[spec.profile],
) {
  switch (spec.profile) {
    case GITHUB_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as GithubOperationKey, args);
    case X_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as XOperationKey, args);
    case GENERIC_HTTP_PROVIDER_ACTION_PROFILE:
      return spec.build(
        fixture.operationKey,
        args,
        "method" in fixture ? fixture.method : undefined,
        GENERIC_DESCRIPTOR,
      );
  }
}

function allowedOriginsFromProductionSpec(spec: ProductionProviderProfileSpec): readonly string[] {
  return spec.kind === "config-driven"
    ? spec.allowedOrigins(GENERIC_DESCRIPTOR)
    : spec.allowedOrigins;
}

function thrownCode(fn: () => unknown): string {
  try {
    fn();
    return "NO_ERROR";
  } catch (error) {
    return error instanceof CanonError ? error.code : `UNSTABLE:${String(error)}`;
  }
}

const HASH = `sha256:${"1".repeat(64)}`;

/**
 * One runner for every registered production profile and for mutation proof.
 * Every stage consumes the prior stage's serialized output, so a friendly
 * handwritten snapshot cannot hide drift at a later deserialization boundary.
 */
function runFullBoundaryConformance(
  spec: ProductionProviderProfileSpec,
  mutate?: (
    action: ReturnType<typeof buildFromProductionSpec>["action"],
  ) => ReturnType<typeof buildFromProductionSpec>["action"],
): string[] {
  const built = buildFromProductionSpec(spec, { ...FIXTURES[spec.profile].args });
  const apiAction = mutate ? mutate(built.action) : built.action;
  const allowedOrigins = allowedOriginsFromProductionSpec(spec);
  const apiViolations = inspectProviderProfileConformance(spec.profile, allowedOrigins, apiAction, [
    "registered-malicious-canary",
  ]);
  if (apiViolations.length > 0) throw new Error(`api:${apiViolations.join(",")}`);

  // Public wire snapshot: strict parser and exact JCS bytes used for persistence.
  const wireText = jcsStringify(apiAction);
  const wireAction = strictParseJson(wireText) as typeof apiAction;
  expect(jcsStringify(wireAction)).toBe(wireText);

  // Exact parser used by the governed proxy dispatch boundary.
  const proxyAction = parseGovernedCanonicalActionForDispatch(new TextEncoder().encode(wireText));
  expect(jcsStringify(proxyAction)).toBe(wireText);

  // Approval reconstruction binds the registered profile and action digest.
  const approval: ProviderApprovalCommitmentV1 = {
    schemaVersion: "steward.provider-approval-commitment.v1",
    intentId: "intent-conformance",
    tenantId: "tenant-conformance",
    workspaceId: "00000000-0000-4000-8000-000000000001",
    requestActor: { type: "agent", id: "agent-conformance", revision: 1 },
    providerAccount: {
      id: "00000000-0000-4000-8000-000000000002",
      revision: 1,
      status: "active",
    },
    operation: {
      id: "00000000-0000-4000-8000-000000000003",
      key: FIXTURES[spec.profile].operationKey,
      revision: 1,
      riskClass: "write",
      canonicalProfile: proxyAction.profile,
    },
    requestHash: HASH,
    actionDigest: HASH,
    accessDecision: {
      id: "00000000-0000-4000-8000-000000000004",
      hash: HASH,
      effect: "allow",
      matchedBindings: [],
      matchedGrants: [],
    },
    policyDecision: {
      id: "00000000-0000-4000-8000-000000000005",
      hash: HASH,
      effect: "approval_required",
      policyRevisionHash: HASH,
      approvalPolicyRevisionHash: HASH,
      evaluatorVersion: "conformance-v1",
    },
    executionDependencies: {
      routeId: "00000000-0000-4000-8000-000000000006",
      routeRevision: 1,
      secretId: "00000000-0000-4000-8000-000000000007",
      secretVersion: 1,
    },
    approvalRequirements: {
      role: "workspace_approver",
      requesterSeparation: true,
      maxMfaAgeSeconds: 300,
      requiredMfaAssurance: "current-session-mfa",
    },
    requestedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-01-01T00:05:00.000Z",
  };
  const approvalText = jcsStringify(canonicalApprovalCommitmentObject(approval));
  const reloadedApproval = strictParseJson(approvalText) as ProviderApprovalCommitmentV1;
  expect(reloadedApproval.operation.canonicalProfile).toBe(spec.profile);
  expect(computeApprovalCommitmentHash(reloadedApproval)).toBe(
    computeApprovalCommitmentHash(approval),
  );

  // Evidence reconstruction consumes only the persisted wire snapshot/profile.
  const evidenceText = jcsStringify({
    operation: { canonicalProfile: reloadedApproval.operation.canonicalProfile },
    canonicalAction: proxyAction,
  });
  const evidence = strictParseJson(evidenceText) as {
    operation: { canonicalProfile: string };
    canonicalAction: typeof apiAction;
  };
  expect(evidence.operation.canonicalProfile).toBe(spec.profile);
  expect(
    inspectProviderProfileConformance(spec.profile, allowedOrigins, evidence.canonicalAction),
  ).toEqual([]);
  return ["api", "wire", "proxy", "approval", "evidence"];
}

describe("#220 executable provider profile conformance", () => {
  it("runs every registered profile through every production boundary", () => {
    expect(PRODUCTION_PROVIDER_PROFILE_SPECS.map((spec) => spec.profile).sort()).toEqual(
      [...REGISTERED_PROFILES].sort(),
    );
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      expect(runFullBoundaryConformance(spec)).toEqual([
        "api",
        "wire",
        "proxy",
        "approval",
        "evidence",
      ]);
    }
  });

  it("has exactly one executable production spec for every registered profile", () => {
    expect(PRODUCTION_PROVIDER_PROFILE_SPECS.map((spec) => spec.profile).sort()).toEqual(
      [...REGISTERED_PROFILES].sort(),
    );
    expect(new Set(PRODUCTION_PROVIDER_PROFILE_SPECS.map((spec) => spec.profile)).size).toBe(
      REGISTERED_PROFILES.length,
    );
  });

  for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
    it(`${spec.profile}: every production operation is deterministic and credential-noninterfering`, () => {
      const fixtures = OPERATION_FIXTURES[spec.profile];
      if (spec.kind === "adapter-fixed") {
        expect(fixtures.map((fixture) => fixture.operationKey).sort()).toEqual(
          [...spec.operationKeys].sort(),
        );
      }
      const canaries = {
        authorization: "profile-auth-canary",
        apiKey: "profile-api-key-canary",
        password: "profile-password-canary",
        privateKeyPem: "profile-private-key-canary",
      };
      for (const fixture of fixtures) {
        const first = buildFromProductionSpec(spec, { ...fixture.args }, fixture);
        const reordered = buildFromProductionSpec(
          spec,
          Object.fromEntries(Object.entries(fixture.args).reverse()),
          fixture,
        );
        expect(jcsStringify(first.action)).toBe(jcsStringify(reordered.action));
        expect(
          inspectProviderProfileConformance(
            spec.profile,
            allowedOriginsFromProductionSpec(spec),
            first.action,
          ),
        ).toEqual([]);

        for (const [key, value] of Object.entries(canaries)) {
          const codeA = thrownCode(() =>
            buildFromProductionSpec(spec, { ...fixture.args, [key]: value }, fixture),
          );
          const codeB = thrownCode(() =>
            buildFromProductionSpec(spec, { ...fixture.args, [key]: value }, fixture),
          );
          expect(codeA).toBe("CANON_UNKNOWN_FIELD");
          expect(codeB).toBe(codeA);
        }
      }
    });

    it(`${spec.profile}: traversal and caller content-type mutations reject stably`, () => {
      const fixture = FIXTURES[spec.profile];
      const traversalField = Object.keys(fixture.traversalArgs)[0];
      if (!traversalField) throw new Error("traversal fixture missing");
      for (const traversal of ["..", "%2e%2e", "a/b", "a%2Fb"]) {
        expect(
          thrownCode(() =>
            buildFromProductionSpec(spec, {
              ...fixture.traversalArgs,
              [traversalField]: traversal,
            }),
          ),
        ).toBe(fixture.traversalCode);
      }
      expect(
        thrownCode(() =>
          buildFromProductionSpec(spec, { ...fixture.args, contentType: "text/plain" }),
        ),
      ).toBe("CANON_UNKNOWN_FIELD");
    });
  }

  it("strict public JSON parsing rejects duplicate members before every profile builder", () => {
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      const raw = `{"operationKey":"${spec.profile}","arguments":{"x":1,"x":2}}`;
      expect(thrownCode(() => strictParseJson(raw))).toBe("CANON_JSON_DUPLICATE_KEY");
    }
  });

  it("a malicious registered fixture makes the identical full runner fail", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    expect(() =>
      runFullBoundaryConformance(spec, (action) => ({
        ...action,
        selectedHeaders: [
          ...action.selectedHeaders,
          ["authorization", "registered-malicious-canary"],
        ],
      })),
    ).toThrow("api:credential-canary-present,credential-header");

    // Defense in depth: even bypassing API/storage, the exact production proxy
    // parser independently denies the same malicious registered snapshot.
    const built = buildFromProductionSpec(spec, FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args);
    const malicious = {
      ...built.action,
      selectedHeaders: [["authorization", "registered-malicious-canary"]] as Array<
        [string, string]
      >,
    };
    expect(() =>
      parseGovernedCanonicalActionForDispatch(new TextEncoder().encode(jcsStringify(malicious))),
    ).toThrow("canonical action conformance failed");
  });

  it("mutation proof catches an SSRF origin and noncanonical method", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    const built = buildFromProductionSpec(spec, {
      ...FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args,
    });
    expect(
      inspectProviderProfileConformance(spec.profile, allowedOriginsFromProductionSpec(spec), {
        ...built.action,
        origin: "https://attacker.example",
      }),
    ).toEqual(["origin-not-allowed"]);
    expect(
      inspectProviderProfileConformance(spec.profile, allowedOriginsFromProductionSpec(spec), {
        ...built.action,
        method: "get",
        origin: "https://127.0.0.1",
      }),
    ).toEqual(["method-not-canonical", "origin-not-allowed", "origin-not-canonical-https"]);
  });

  it("mutation proof catches nested-encoded path traversal", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    const built = buildFromProductionSpec(spec, {
      ...FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args,
    });
    for (const segment of [
      ".",
      "..",
      "a\\b",
      "%252e%252e",
      "%252f",
      "%255c",
      "%2525252e%2525252e",
      "%2525252f",
      "%2525255c",
    ]) {
      expect(
        inspectProviderProfileConformance(spec.profile, allowedOriginsFromProductionSpec(spec), {
          ...built.action,
          normalizedPath: `/repos/${segment}/hello/issues`,
        }),
      ).toContain("path-traversal");
    }
  });

  it("mutation proof catches invalid encoding hidden by an outer encoding", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    const built = buildFromProductionSpec(spec, {
      ...FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args,
    });
    expect(
      inspectProviderProfileConformance(spec.profile, {
        ...built.action,
        normalizedPath: "/repos/%25ZZ/hello/issues",
      }),
    ).toContain("path-encoding-invalid");
  });

  it("mutation proof catches duplicate query/header names and unsupported content type", () => {
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      const built = buildFromProductionSpec(spec, { ...FIXTURES[spec.profile].args });
      expect(
        inspectProviderProfileConformance(spec.profile, allowedOriginsFromProductionSpec(spec), {
          ...built.action,
          canonicalBody: { ok: true },
          orderedQueryPairs: [
            ...built.action.orderedQueryPairs,
            ["duplicate", "a"],
            ["duplicate", "b"],
          ],
          selectedHeaders: [
            ...built.action.selectedHeaders,
            ["content-type", "text/plain"],
            ["Content-Type", "text/plain"],
          ],
        }),
      ).toEqual(["content-type-unsupported", "header-duplicate", "query-duplicate"]);
    }
  });

  it("mutation proof catches credential-shaped query and nested body fields", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    const built = buildFromProductionSpec(spec, {
      ...FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args,
    });
    expect(
      inspectProviderProfileConformance(spec.profile, allowedOriginsFromProductionSpec(spec), {
        ...built.action,
        orderedQueryPairs: [...built.action.orderedQueryPairs, ["access_token", "mutation"]],
        canonicalBody: { nested: { client_secret: "mutation" } },
        selectedHeaders: [["content-type", "application/json"]],
      }),
    ).toEqual(["credential-body-field", "credential-query"]);
  });
});
