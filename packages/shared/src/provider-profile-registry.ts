/**
 * provider-profile-registry.ts - the versioned canonical-profile registry.
 *
 * This code-side, fail-closed registry is keyed by a stable profile string.
 * Every site that CONSUMES a canonical profile (store, eval, dispatch,
 * approval binding, evidence) resolves it through {@link isRegisteredProfile} /
 * {@link assertRegisteredProfile}: an UNREGISTERED profile string is REJECTED
 * everywhere, never stored, never dispatched.
 *
 * Registration is compile-time (a frozen set here), not runtime-mutable, so the
 * registry cannot be widened by an attacker-controlled value. Adding a profile
 * is a code change plus its adapter and matching database constraint migration.
 * github + x + Slack + Google Workspace + generic-http are the registered members;
 * github/x remain BYTE-IDENTICAL in behavior (their profile
 * string value is unchanged, so the golden digest corpus does not move).
 *
 * A profile descriptor also records whether the profile is "config-driven"
 * (operator authors a per-operation descriptor, e.g. generic-http) or
 * "adapter-fixed" (a hardcoded adapter, e.g. github/x/Slack/Google). The service uses this to
 * decide whether to load + validate a stored operation descriptor before
 * building the action.
 */

import { AWS_PROVIDER_ACTION_PROFILE } from "./aws-provider-action.js";
import { GENERIC_HTTP_PROVIDER_ACTION_PROFILE } from "./generic-http-provider-action.js";
import {
  GOOGLE_ALLOWED_ORIGINS,
  GOOGLE_PROVIDER_ACTION_PROFILE,
} from "./google-provider-action.js";
import { GITHUB_PROVIDER_ACTION_PROFILE } from "./provider-action.js";
import { SLACK_PROVIDER_ACTION_PROFILE } from "./slack-provider-action.js";
import { X_PROVIDER_ACTION_PROFILE } from "./x-provider-action.js";

/** Whether a profile's operation shape is fixed by an adapter or authored by config. */
export type ProfileKind = "adapter-fixed" | "config-driven";

interface ProviderProfileDescriptorBase {
  /** The stable wire profile string (also stamped into every canonical action). */
  profile: string;
  /** Human label for logs/UX (never on the digest surface). */
  label: string;
}

export type ProviderProfileDescriptor =
  | (ProviderProfileDescriptorBase & {
      kind: "adapter-fixed";
      /** Exact origins emitted by the hard-coded adapter. */
      allowedOrigins: readonly string[];
      /** Region-bound adapters derive one exact origin from canonical action bytes. */
      dynamicOriginPolicy?: "aws-ec2-region";
    })
  | (ProviderProfileDescriptorBase & {
      kind: "config-driven";
    });

/**
 * The registered profiles. FROZEN: this is the single source of truth for which
 * profile strings are legal anywhere in the provider-action pipeline. github,
 * x, Slack, and Google Workspace are adapter-fixed; generic-http is config-driven.
 */
const REGISTRY: ReadonlyMap<string, ProviderProfileDescriptor> = new Map([
  [
    AWS_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: AWS_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "AWS",
      allowedOrigins: Object.freeze([]),
      dynamicOriginPolicy: "aws-ec2-region",
    }),
  ],
  [
    GITHUB_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: GITHUB_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "GitHub",
      allowedOrigins: Object.freeze(["https://api.github.com"]),
    }),
  ],
  [
    X_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: X_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "X",
      allowedOrigins: Object.freeze(["https://api.x.com"]),
    }),
  ],
  [
    SLACK_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: SLACK_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "Slack",
      allowedOrigins: Object.freeze(["https://slack.com"]),
    }),
  ],
  [
    GOOGLE_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: GOOGLE_PROVIDER_ACTION_PROFILE,
      kind: "adapter-fixed",
      label: "Google Workspace",
      allowedOrigins: Object.freeze([...GOOGLE_ALLOWED_ORIGINS]),
    }),
  ],
  [
    GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
    Object.freeze<ProviderProfileDescriptor>({
      profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
      kind: "config-driven",
      label: "Generic HTTP",
    }),
  ],
]);

/** All registered profile strings (for enumerating consumption sites in tests). */
export const REGISTERED_PROFILES: readonly string[] = Object.freeze([...REGISTRY.keys()]);

/** True iff `profile` is a registered canonical profile string. */
export function isRegisteredProfile(profile: unknown): profile is string {
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
export function assertRegisteredProfile(profile: unknown): string {
  if (!isRegisteredProfile(profile)) throw new UnregisteredProfileError(profile);
  return profile;
}

/** True iff the profile is registered AND config-driven (needs a descriptor). */
export function isConfigDrivenProfile(profile: unknown): boolean {
  return getProfileDescriptor(profile)?.kind === "config-driven";
}
