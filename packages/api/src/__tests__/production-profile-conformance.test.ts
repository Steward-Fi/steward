import { describe, expect, it } from "bun:test";
import type { AwsOperationKey } from "@stwd/provider-aws";
import type { GithubOperationKey } from "@stwd/provider-github";
import type { GoogleOperationKey } from "@stwd/provider-google";
import type { SlackOperationKey } from "@stwd/provider-slack";
import type { XOperationKey } from "@stwd/provider-x";
import { parseGovernedCanonicalActionForDispatch } from "@stwd/proxy/src/handlers/governed-execution";
import {
  buildGenericHttpAction,
  AWS_PROVIDER_ACTION_PROFILE,
  CanonError,
  GENERIC_GOLDEN_DESCRIPTOR_A,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  GITHUB_PROVIDER_ACTION_PROFILE,
  GOOGLE_PROVIDER_ACTION_PROFILE,
  inspectProviderProfileConformance,
  jcsStringify,
  REGISTERED_PROFILES,
  SLACK_PROVIDER_ACTION_PROFILE,
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
  [AWS_PROVIDER_ACTION_PROFILE]: {
    operationKey: "aws.ec2.DescribeInstances" as const,
    method: undefined,
    args: { region: "us-east-1", instanceIds: ["i-12345678"] },
    traversalArgs: { region: ".." },
    traversalCode: "CANON_FIELD_TYPE_INVALID",
  },
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
  [SLACK_PROVIDER_ACTION_PROFILE]: {
    operationKey: "slack.users.info" as const,
    method: undefined,
    args: { user: "U12345678" },
    traversalArgs: { user: ".." },
    traversalCode: "CANON_PATH_SEGMENT_INVALID",
  },
  [GOOGLE_PROVIDER_ACTION_PROFILE]: {
    operationKey: "google.calendar.events.list" as const,
    method: undefined,
    args: { maxResults: 50 },
    traversalArgs: { maxResults: 50 },
    traversalCode: "CANON_FIELD_TYPE_INVALID",
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
  [AWS_PROVIDER_ACTION_PROFILE]: [
    {
      operationKey: "aws.ec2.DescribeInstances",
      args: { region: "us-east-1", instanceIds: ["i-12345678"] },
    },
    {
      operationKey: "aws.ec2.StopInstances",
      args: { region: "eu-central-1", instanceIds: ["i-abcdef01234567890"], dryRun: true },
    },
  ],
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
      args: { text: "hello world", replyToTweetId: "42", summoned: false },
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
  [SLACK_PROVIDER_ACTION_PROFILE]: [
    {
      operationKey: "slack.chat.postMessage",
      args: { channel: "C12345678", text: "hello world" },
    },
    {
      operationKey: "slack.conversations.list",
      args: {},
    },
    {
      operationKey: "slack.users.info",
      args: { user: "U12345678" },
    },
  ],
  [GOOGLE_PROVIDER_ACTION_PROFILE]: [
    {
      operationKey: "google.gmail.messages.send",
      args: { to: ["person@example.com"], subject: "hello", body: "world" },
    },
    {
      operationKey: "google.calendar.events.list",
      args: { maxResults: 50 },
    },
    {
      operationKey: "google.calendar.events.insert",
      args: {
        summary: "meeting",
        start: "2026-08-17T10:00:00Z",
        end: "2026-08-17T11:00:00Z",
        attendees: ["person@example.com"],
      },
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
    case AWS_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as AwsOperationKey, args);
    case GITHUB_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as GithubOperationKey, args);
    case X_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as XOperationKey, args);
    case SLACK_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as SlackOperationKey, args);
    case GOOGLE_PROVIDER_ACTION_PROFILE:
      return spec.build(fixture.operationKey as GoogleOperationKey, args);
    case GENERIC_HTTP_PROVIDER_ACTION_PROFILE:
      return spec.build(
        fixture.operationKey,
        args,
        "method" in fixture ? fixture.method : undefined,
        GENERIC_DESCRIPTOR,
      );
  }
}

function allowedOriginsFromProductionSpec(
  spec: ProductionProviderProfileSpec,
  action = buildFromProductionSpec(spec, { ...FIXTURES[spec.profile].args }).action,
): readonly string[] {
  if (spec.kind === "config-driven") return spec.allowedOrigins(GENERIC_DESCRIPTOR);
  if (spec.profile === AWS_PROVIDER_ACTION_PROFILE) return spec.allowedOriginsForAction(action);
  return spec.allowedOrigins;
}

function operationContext(spec: ProductionProviderProfileSpec) {
  return {
    operationKey: FIXTURES[spec.profile].operationKey,
    requestProfile:
      spec.profile === GENERIC_HTTP_PROVIDER_ACTION_PROFILE
        ? {
            profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
            operationDescriptor: GENERIC_DESCRIPTOR,
          }
        : { profile: spec.profile },
  };
}

function thrownCode(fn: () => unknown): string {
  try {
    fn();
    return "NO_ERROR";
  } catch (error) {
    return error instanceof CanonError ? error.code : `UNSTABLE:${String(error)}`;
  }
}

/**
 * Pure canonicalization runner for every registered production profile and for
 * mutation proof.  The separate production-profile-boundary-e2e suite covers
 * authenticated ingress, durable reload, approval/resume, and case evidence.
 */
function runCanonicalBoundaryConformance(
  spec: ProductionProviderProfileSpec,
  mutate?: (
    action: ReturnType<typeof buildFromProductionSpec>["action"],
  ) => ReturnType<typeof buildFromProductionSpec>["action"],
): string[] {
  const built = buildFromProductionSpec(spec, { ...FIXTURES[spec.profile].args });
  const apiAction = mutate ? mutate(built.action) : built.action;
  const allowedOrigins = allowedOriginsFromProductionSpec(spec, apiAction);
  const apiViolations = inspectProviderProfileConformance(spec.profile, allowedOrigins, apiAction, [
    "registered-malicious-canary",
  ]);
  if (apiViolations.length > 0) throw new Error(`api:${apiViolations.join(",")}`);

  // Public wire snapshot: strict parser and exact JCS bytes used for persistence.
  const wireText = jcsStringify(apiAction);
  const wireAction = strictParseJson(wireText) as typeof apiAction;
  expect(jcsStringify(wireAction)).toBe(wireText);

  // Exact parser used by the governed proxy dispatch boundary.
  const proxyAction = parseGovernedCanonicalActionForDispatch(
    new TextEncoder().encode(wireText),
    spec.profile,
    allowedOrigins,
    operationContext(spec),
  );
  expect(jcsStringify(proxyAction)).toBe(wireText);

  return ["builder", "wire", "proxy"];
}

describe("#220 executable provider profile conformance", () => {
  it("runs every registered profile through canonical builder and proxy parsing", () => {
    expect(PRODUCTION_PROVIDER_PROFILE_SPECS.map((spec) => spec.profile).sort()).toEqual(
      [...REGISTERED_PROFILES].sort(),
    );
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      expect(runCanonicalBoundaryConformance(spec)).toEqual(["builder", "wire", "proxy"]);
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

  it("the proxy parser reconstructs every fixed operation and rejects widened fields", () => {
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      if (spec.kind !== "adapter-fixed") continue;
      for (const fixture of OPERATION_FIXTURES[spec.profile]) {
        const built = buildFromProductionSpec(spec, { ...fixture.args }, fixture);
        const parse = (action: typeof built.action) =>
          parseGovernedCanonicalActionForDispatch(
            new TextEncoder().encode(jcsStringify(action)),
            spec.profile,
            allowedOriginsFromProductionSpec(spec, built.action),
            { operationKey: fixture.operationKey, requestProfile: { profile: spec.profile } },
          );

        expect(jcsStringify(parse(built.action))).toBe(jcsStringify(built.action));
        expect(() =>
          parse({
            ...built.action,
            orderedQueryPairs: [...built.action.orderedQueryPairs, ["x-extra", "1"]],
          }),
        ).toThrow("operation-action-mismatch");
        expect(() =>
          parse({
            ...built.action,
            selectedHeaders: [...built.action.selectedHeaders, ["x-extra", "ok"]],
          }),
        ).toThrow("operation-action-mismatch");
      }
    }
  });

  it("the proxy parser rejects widened or type-confused fixed bodies", () => {
    const github = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    const x = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === X_PROVIDER_ACTION_PROFILE,
    );
    if (!github || github.kind !== "adapter-fixed" || !x || x.kind !== "adapter-fixed") {
      throw new Error("fixed production profiles missing");
    }

    const commentFixture = OPERATION_FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE][1];
    const comment = buildFromProductionSpec(github, { ...commentFixture.args }, commentFixture);
    expect(() =>
      parseGovernedCanonicalActionForDispatch(
        new TextEncoder().encode(
          jcsStringify({ ...comment.action, canonicalBody: { body: "looks good", extra: true } }),
        ),
        github.profile,
        github.allowedOrigins,
        { operationKey: commentFixture.operationKey, requestProfile: { profile: github.profile } },
      ),
    ).toThrow("operation-action-mismatch");

    const tweetFixture = OPERATION_FIXTURES[X_PROVIDER_ACTION_PROFILE][0];
    const tweet = buildFromProductionSpec(x, { ...tweetFixture.args }, tweetFixture);
    expect(() =>
      parseGovernedCanonicalActionForDispatch(
        new TextEncoder().encode(jcsStringify({ ...tweet.action, canonicalBody: null })),
        x.profile,
        x.allowedOrigins,
        { operationKey: tweetFixture.operationKey, requestProfile: { profile: x.profile } },
      ),
    ).toThrow("operation-action-mismatch");
    expect(() =>
      parseGovernedCanonicalActionForDispatch(
        new TextEncoder().encode(
          jcsStringify({
            ...tweet.action,
            canonicalBody: { text: "hello world", reply: { in_reply_to_tweet_id: 123 } },
          }),
        ),
        x.profile,
        x.allowedOrigins,
        { operationKey: tweetFixture.operationKey, requestProfile: { profile: x.profile } },
      ),
    ).toThrow("operation-action-mismatch");
  });

  it("accepts a descriptor-backed generic HEAD action at the proxy boundary", () => {
    const descriptor = validateGenericHttpDescriptor({
      profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
      origin: "https://api.example.com",
      methods: ["HEAD"],
      pathTemplate: [{ literal: "v1" }, { literal: "health" }],
      projection: { policyArgs: [], safeSummary: [] },
    });
    const built = buildGenericHttpAction("generic.health.head", descriptor, "HEAD", {});
    const parsed = parseGovernedCanonicalActionForDispatch(
      new TextEncoder().encode(jcsStringify(built.action)),
      GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
      [descriptor.origin],
      {
        operationKey: "generic.health.head",
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: descriptor,
        },
      },
    );
    expect(jcsStringify(parsed)).toBe(jcsStringify(built.action));
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
      runCanonicalBoundaryConformance(spec, (action) => ({
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
      parseGovernedCanonicalActionForDispatch(
        new TextEncoder().encode(jcsStringify(malicious)),
        spec.profile,
        allowedOriginsFromProductionSpec(spec),
        operationContext(spec),
      ),
    ).toThrow("canonical action conformance failed");
  });

  it("proxy parsing binds profile, origin, and the shared credential vocabulary externally", () => {
    const spec = PRODUCTION_PROVIDER_PROFILE_SPECS.find(
      (candidate) => candidate.profile === GITHUB_PROVIDER_ACTION_PROFILE,
    );
    if (!spec) throw new Error("github production profile missing");
    const built = buildFromProductionSpec(spec, FIXTURES[GITHUB_PROVIDER_ACTION_PROFILE].args);
    const parse = (action: typeof built.action) =>
      parseGovernedCanonicalActionForDispatch(
        new TextEncoder().encode(jcsStringify(action)),
        spec.profile,
        allowedOriginsFromProductionSpec(spec),
        operationContext(spec),
      );

    expect(() => parse({ ...built.action, origin: "https://attacker.example" })).toThrow(
      "origin-not-allowed",
    );
    expect(() => parse({ ...built.action, profile: X_PROVIDER_ACTION_PROFILE })).toThrow(
      "profile-mismatch",
    );

    for (const key of [
      "auth",
      "passphrase",
      "clientSecretValue",
      "cookieHeader",
      "privateKeyPem",
    ]) {
      expect(() =>
        parse({
          ...built.action,
          canonicalBody: { nested: { [key]: "registered-malicious-canary" } },
          selectedHeaders: [["content-type", "application/json"]],
        }),
      ).toThrow("credential-body-field");
    }
  });

  it("reconstructs every adapter-fixed operation exactly and rejects all target-surface substitutions", () => {
    for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
      if (spec.kind !== "adapter-fixed") continue;
      for (const fixture of OPERATION_FIXTURES[spec.profile]) {
        const built = buildFromProductionSpec(spec, { ...fixture.args }, fixture);
        const operation = {
          operationKey: fixture.operationKey,
          requestProfile: { profile: spec.profile },
        };
        const parse = (action: typeof built.action) =>
          parseGovernedCanonicalActionForDispatch(
            new TextEncoder().encode(jcsStringify(action)),
            spec.profile,
            allowedOriginsFromProductionSpec(spec),
            operation,
          );
        expect(parse(built.action)).toEqual(built.action);
        const mutations = [
          { ...built.action, method: built.action.method === "GET" ? "POST" : "GET" },
          { ...built.action, normalizedPath: `${built.action.normalizedPath}/attacker` },
          {
            ...built.action,
            orderedQueryPairs: [...built.action.orderedQueryPairs, ["attacker", "1"]] as Array<
              [string, string]
            >,
          },
          {
            ...built.action,
            selectedHeaders:
              built.action.selectedHeaders.length === 0
                ? [["x-attacker", "1"]]
                : built.action.selectedHeaders.map(([name, value], index) =>
                    index === 0 ? [name, `${value}-attacker`] : [name, value],
                  ),
          },
          {
            ...built.action,
            canonicalBody:
              built.action.canonicalBody === null
                ? { attacker: true }
                : { ...(built.action.canonicalBody as Record<string, unknown>), attacker: true },
          },
        ].filter((mutation) => jcsStringify(mutation) !== jcsStringify(built.action));
        expect(mutations).toHaveLength(5);
        for (const mutation of mutations) {
          expect(() => parse(mutation as typeof built.action)).toThrow("operation-action-mismatch");
        }
      }
    }
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
      inspectProviderProfileConformance(spec.profile, allowedOriginsFromProductionSpec(spec), {
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
