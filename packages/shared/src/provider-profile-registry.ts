/**
 * provider-profile-registry.ts - the versioned canonical-profile registry.
 *
 * Replaces the closed union `"github.provider-action.v1" | "x.provider-action.v1"`
 * (issue #201) with a code-side, fail-closed registry keyed by a stable profile
 * string. Every site that CONSUMES a canonical profile (store, eval, dispatch,
 * approval binding, evidence) resolves it through {@link isRegisteredProfile} /
 * {@link assertRegisteredProfile}: an UNREGISTERED profile string is REJECTED
 * everywhere, never stored, never dispatched.
 *
 * Registration is compile-time (a frozen set here), not runtime-mutable, so the
 * registry cannot be widened by an attacker-controlled value. Adding a profile
 * is a one-line code change plus its adapter. github + x + generic-http are the
 * initial members; github/x remain BYTE-IDENTICAL in behavior (their profile
 * string value is unchanged, so the golden digest corpus does not move).
 *
 * A profile descriptor also records whether the profile is "config-driven"
 * (operator authors a per-operation descriptor, e.g. generic-http) or
 * "adapter-fixed" (a hardcoded adapter, e.g. github/x). The service uses this to
 * decide whether to load + validate a stored operation descriptor before
 * building the action.
 */

import {
  buildGenericHttpAction,
  computeGenericHttpActionDigest,
  GENERIC_GOLDEN_DESCRIPTOR_A,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  genericHttpCanonicalActionBytes,
  validateGenericHttpDescriptor,
} from "./generic-http-provider-action.js";
import {
  canonicalActionBytes,
  canonicalizeRawInternalAction,
  computeActionDigest,
  GITHUB_PROVIDER_ACTION_PROFILE,
} from "./provider-action.js";
import {
  canonicalizeRawInternalXAction,
  computeXActionDigest,
  X_PROVIDER_ACTION_PROFILE,
  xCanonicalActionBytes,
} from "./x-provider-action.js";

/** Whether a profile's operation shape is fixed by an adapter or authored by config. */
export type ProfileKind = "adapter-fixed" | "config-driven";
export type RegisteredProviderProfile =
  | typeof GITHUB_PROVIDER_ACTION_PROFILE
  | typeof X_PROVIDER_ACTION_PROFILE
  | typeof GENERIC_HTTP_PROVIDER_ACTION_PROFILE;

export interface ProviderProfileDescriptor {
  /** The stable wire profile string (also stamped into every canonical action). */
  profile: string;
  kind: ProfileKind;
  /** Human label for logs/UX (never on the digest surface). */
  label: string;
  conformance: ProviderProfileConformance;
}

export const PROFILE_CONFORMANCE_INVARIANTS = [
  "credential-exclusion",
  "duplicate-key",
  "duplicate-query",
  "plain-traversal",
  "encoded-traversal",
  "unsupported-content-type",
] as const;

export type ProfileConformanceInvariant = (typeof PROFILE_CONFORMANCE_INVARIANTS)[number];

export interface ProviderProfileConformance {
  build(): { bytes: string; digest: string };
  rejects: Readonly<Record<ProfileConformanceInvariant, () => unknown>>;
}

function frozenConformance(
  build: ProviderProfileConformance["build"],
  rejects: Record<ProfileConformanceInvariant, () => unknown>,
): ProviderProfileConformance {
  return Object.freeze({ build, rejects: Object.freeze(rejects) });
}

const githubConformance = frozenConformance(
  () => {
    const action = canonicalizeRawInternalAction({
      method: "GET",
      origin: "https://api.github.com",
      path: "/repos/acme/widgets/issues",
    });
    return { bytes: canonicalActionBytes(action), digest: computeActionDigest(action) };
  },
  {
    "credential-exclusion": () =>
      canonicalizeRawInternalAction({
        method: "GET",
        origin: "https://api.github.com",
        path: "/repos/acme/widgets/issues",
        headers: [["authorization", "steward-secret-canary"]],
      }),
    "duplicate-key": () =>
      canonicalizeRawInternalAction({
        method: "GET",
        origin: "https://api.github.com",
        path: "/repos/acme/widgets/issues",
        headers: [
          ["accept", "a"],
          ["accept", "b"],
        ],
      }),
    "duplicate-query": () =>
      canonicalizeRawInternalAction({
        method: "GET",
        origin: "https://api.github.com",
        path: "/repos/acme/widgets/issues",
        query: [
          ["state", "open"],
          ["state", "closed"],
        ],
      }),
    "plain-traversal": () =>
      canonicalizeRawInternalAction({
        method: "GET",
        origin: "https://api.github.com",
        path: "/repos/../admin",
      }),
    "encoded-traversal": () =>
      canonicalizeRawInternalAction({
        method: "GET",
        origin: "https://api.github.com",
        path: "/repos/%2e%2e/admin",
      }),
    "unsupported-content-type": () =>
      canonicalizeRawInternalAction({
        method: "POST",
        origin: "https://api.github.com",
        path: "/repos/acme/widgets/issues",
        contentType: "application/xml",
        body: { title: "x" },
      }),
  },
);

const xConformance = frozenConformance(
  () => {
    const action = canonicalizeRawInternalXAction({
      method: "GET",
      origin: "https://api.x.com",
      path: "/2/users/me",
    });
    return { bytes: xCanonicalActionBytes(action), digest: computeXActionDigest(action) };
  },
  {
    "credential-exclusion": () =>
      canonicalizeRawInternalXAction({
        method: "GET",
        origin: "https://api.x.com",
        path: "/2/users/me",
        headers: [["authorization", "steward-secret-canary"]],
      }),
    "duplicate-key": () =>
      canonicalizeRawInternalXAction({
        method: "GET",
        origin: "https://api.x.com",
        path: "/2/users/me",
        headers: [
          ["x-a", "1"],
          ["x-a", "2"],
        ],
      }),
    "duplicate-query": () =>
      canonicalizeRawInternalXAction({
        method: "GET",
        origin: "https://api.x.com",
        path: "/2/users/me",
        query: [
          ["expansions", "a"],
          ["expansions", "b"],
        ],
      }),
    "plain-traversal": () =>
      canonicalizeRawInternalXAction({
        method: "GET",
        origin: "https://api.x.com",
        path: "/2/../admin",
      }),
    "encoded-traversal": () =>
      canonicalizeRawInternalXAction({
        method: "GET",
        origin: "https://api.x.com",
        path: "/2/%2e%2e/admin",
      }),
    "unsupported-content-type": () =>
      canonicalizeRawInternalXAction({
        method: "POST",
        origin: "https://api.x.com",
        path: "/2/tweets",
        contentType: "application/xml",
        body: { text: "x" },
      }),
  },
);

function genericBuildArgs() {
  return {
    org: "acme-inc",
    projectId: "11111111-1111-4111-8111-111111111111",
    state: "open",
    perPage: 30,
  };
}

const genericConformance = frozenConformance(
  () => {
    const descriptor = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_A);
    const action = buildGenericHttpAction(
      "items.list",
      descriptor,
      "GET",
      genericBuildArgs(),
    ).action;
    return {
      bytes: genericHttpCanonicalActionBytes(action),
      digest: computeGenericHttpActionDigest(action),
    };
  },
  {
    "credential-exclusion": () =>
      validateGenericHttpDescriptor({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        headers: [{ name: "authorization", value: "steward-secret-canary" }],
      }),
    "duplicate-key": () =>
      validateGenericHttpDescriptor({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        projection: { policyArgs: ["org", "org"], safeSummary: [] },
      }),
    "duplicate-query": () =>
      validateGenericHttpDescriptor({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        query: [
          { name: "state", type: "string", pattern: "^(open|closed)$" },
          { name: "state", type: "string", pattern: "^(open|closed)$" },
        ],
      }),
    "plain-traversal": () => {
      const descriptor = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_A);
      return buildGenericHttpAction("items.list", descriptor, "GET", {
        ...genericBuildArgs(),
        org: "..",
      });
    },
    "encoded-traversal": () => {
      const descriptor = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_A);
      return buildGenericHttpAction("items.list", descriptor, "GET", {
        ...genericBuildArgs(),
        org: "%2e%2e",
      });
    },
    "unsupported-content-type": () =>
      validateGenericHttpDescriptor({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        methods: ["POST"],
        body: { contentType: "application/xml", fields: [] },
      }),
  },
);

/**
 * The registered profiles. FROZEN: this is the single source of truth for which
 * profile strings are legal anywhere in the provider-action pipeline. github and
 * x are adapter-fixed; generic-http is config-driven.
 */
const REGISTRY: ReadonlyMap<string, ProviderProfileDescriptor> = new Map([
  [
    GITHUB_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: GITHUB_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "GitHub",
      conformance: githubConformance,
    }),
  ],
  [
    X_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: X_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "X",
      conformance: xConformance,
    }),
  ],
  [
    GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
      kind: "config-driven",
      label: "Generic HTTP",
      conformance: genericConformance,
    }),
  ],
]);

/** All registered profile strings (for enumerating consumption sites in tests). */
export const REGISTERED_PROFILES: readonly string[] = Object.freeze([...REGISTRY.keys()]);

/** True iff `profile` is a registered canonical profile string. */
export function isRegisteredProfile(profile: unknown): profile is RegisteredProviderProfile {
  return typeof profile === "string" && REGISTRY.has(profile);
}

/** Resolve the descriptor for a registered profile, or `undefined`. */
export function getProfileDescriptor(profile: unknown): ProviderProfileDescriptor | undefined {
  return typeof profile === "string" ? REGISTRY.get(profile) : undefined;
}

/**
 * A fail-closed rejection for an unregistered profile. Carries a stable code so
 * every consumption site denies uniformly rather than throwing a 500.
 */
export class UnregisteredProfileError extends Error {
  readonly code = "CANON_PROFILE_UNSUPPORTED" as const;
  readonly profile: unknown;
  constructor(profile: unknown) {
    super(`unregistered canonical profile '${String(profile)}'`);
    this.name = "UnregisteredProfileError";
    this.profile = profile;
  }
}

export function isUnregisteredProfileError(e: unknown): e is UnregisteredProfileError {
  return e instanceof UnregisteredProfileError;
}

/**
 * Assert `profile` is registered, returning the narrowed string. Throws
 * {@link UnregisteredProfileError} otherwise. Call at EVERY consumption site:
 * store insert, policy eval, dispatch, approval binding, evidence emission.
 */
export function assertRegisteredProfile(profile: unknown): RegisteredProviderProfile {
  if (!isRegisteredProfile(profile)) throw new UnregisteredProfileError(profile);
  return profile;
}

/** True iff the profile is registered AND config-driven (needs a descriptor). */
export function isConfigDrivenProfile(profile: unknown): boolean {
  return getProfileDescriptor(profile)?.kind === "config-driven";
}

/** Return invariant names that a descriptor fails; empty means conformant. */
export function runProfileConformance(descriptor: ProviderProfileDescriptor): string[] {
  const failures: string[] = [];
  const first = descriptor.conformance.build();
  const second = descriptor.conformance.build();
  if (first.bytes !== second.bytes || first.digest !== second.digest) failures.push("determinism");
  if (first.bytes.includes("steward-secret-canary")) failures.push("credential-exclusion");
  for (const invariant of PROFILE_CONFORMANCE_INVARIANTS) {
    const negative = descriptor.conformance.rejects[invariant];
    if (typeof negative !== "function") {
      failures.push(invariant);
      continue;
    }
    let rejected = false;
    try {
      negative();
    } catch {
      rejected = true;
    }
    if (!rejected) failures.push(invariant);
  }
  return failures;
}
