import { describe, expect, it } from "bun:test";
import type { GithubOperationKey } from "@stwd/provider-github";
import type { XOperationKey } from "@stwd/provider-x";
import {
  CanonError,
  GENERIC_GOLDEN_DESCRIPTOR_A,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  GITHUB_PROVIDER_ACTION_PROFILE,
  inspectProviderProfileConformance,
  jcsStringify,
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

function thrownCode(fn: () => unknown): string {
  try {
    fn();
    return "NO_ERROR";
  } catch (error) {
    return error instanceof CanonError ? error.code : `UNSTABLE:${String(error)}`;
  }
}

describe("#220 executable provider profile conformance", () => {
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
        expect(inspectProviderProfileConformance(spec.profile, first.action)).toEqual([]);

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

  it("mutation proof catches a credential header injected into real production output", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    const built = buildFromProductionSpec(spec, {
      ...FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args,
    });
    const mutated = {
      ...built.action,
      selectedHeaders: [...built.action.selectedHeaders, ["authorization", "mutation-canary"]],
    };
    expect(inspectProviderProfileConformance(spec.profile, mutated, ["mutation-canary"])).toEqual([
      "credential-canary-present",
      "credential-header",
    ]);
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
      inspectProviderProfileConformance(spec.profile, {
        ...built.action,
        method: "get",
        origin: "https://127.0.0.1",
      }),
    ).toEqual(["method-not-canonical", "origin-not-canonical-https"]);
  });

  it("mutation proof catches duplicate query/header names and unsupported content type", () => {
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      const built = buildFromProductionSpec(spec, { ...FIXTURES[spec.profile].args });
      expect(
        inspectProviderProfileConformance(spec.profile, {
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
});
