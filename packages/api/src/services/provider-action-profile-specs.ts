import {
  buildGithubAction,
  GITHUB_OPERATION_KEYS,
  type GithubActionBuild,
  type GithubOperationKey,
} from "@stwd/provider-github";
import {
  buildSlackAction,
  SLACK_OPERATION_KEYS,
  type SlackActionBuild,
  type SlackOperationKey,
} from "@stwd/provider-slack";
import {
  buildXAction,
  X_OPERATION_KEYS,
  type XActionBuild,
  type XOperationKey,
} from "@stwd/provider-x";
import {
  buildGenericHttpAction,
  CanonError,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  type GenericHttpActionBuild,
  type GenericHttpOperationDescriptorV1,
  GITHUB_PROVIDER_ACTION_PROFILE,
  getProfileDescriptor,
  REGISTERED_PROFILES,
  SLACK_PROVIDER_ACTION_PROFILE,
  X_PROVIDER_ACTION_PROFILE,
} from "@stwd/shared";

export type AdapterFixedActionBuild = GithubActionBuild | SlackActionBuild | XActionBuild;

function fixedProfileOrigins(profile: string): readonly string[] {
  const descriptor = getProfileDescriptor(profile);
  if (!descriptor || descriptor.kind !== "adapter-fixed") {
    throw new Error(`adapter-fixed profile metadata missing for '${profile}'`);
  }
  return descriptor.allowedOrigins;
}

export type ProductionProviderProfileSpec =
  | {
      readonly profile: typeof GITHUB_PROVIDER_ACTION_PROFILE;
      readonly kind: "adapter-fixed";
      readonly operationKeys: readonly GithubOperationKey[];
      readonly allowedOrigins: readonly string[];
      build(operationKey: GithubOperationKey, args: unknown): GithubActionBuild;
    }
  | {
      readonly profile: typeof SLACK_PROVIDER_ACTION_PROFILE;
      readonly kind: "adapter-fixed";
      readonly operationKeys: readonly SlackOperationKey[];
      build(operationKey: SlackOperationKey, args: unknown): SlackActionBuild;
    }
  | {
      readonly profile: typeof X_PROVIDER_ACTION_PROFILE;
      readonly kind: "adapter-fixed";
      readonly operationKeys: readonly XOperationKey[];
      readonly allowedOrigins: readonly string[];
      build(operationKey: XOperationKey, args: unknown): XActionBuild;
    }
  | {
      readonly profile: typeof GENERIC_HTTP_PROVIDER_ACTION_PROFILE;
      readonly kind: "config-driven";
      readonly operationKeys: readonly [];
      allowedOrigins(descriptor: GenericHttpOperationDescriptorV1): readonly string[];
      build(
        operationKey: string,
        args: unknown,
        method: unknown,
        descriptor: GenericHttpOperationDescriptorV1,
      ): GenericHttpActionBuild;
    };

const GITHUB_SPEC = Object.freeze({
  profile: GITHUB_PROVIDER_ACTION_PROFILE,
  kind: "adapter-fixed" as const,
  operationKeys: Object.freeze([...GITHUB_OPERATION_KEYS]),
  allowedOrigins: fixedProfileOrigins(GITHUB_PROVIDER_ACTION_PROFILE),
  build: buildGithubAction,
});

const X_SPEC = Object.freeze({
  profile: X_PROVIDER_ACTION_PROFILE,
  kind: "adapter-fixed" as const,
  operationKeys: Object.freeze([...X_OPERATION_KEYS]),
  allowedOrigins: fixedProfileOrigins(X_PROVIDER_ACTION_PROFILE),
  build: buildXAction,
});

const SLACK_SPEC = Object.freeze({
  profile: SLACK_PROVIDER_ACTION_PROFILE,
  kind: "adapter-fixed" as const,
  operationKeys: Object.freeze([...SLACK_OPERATION_KEYS]),
  build: buildSlackAction,
});

const GENERIC_HTTP_SPEC = Object.freeze({
  profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  kind: "config-driven" as const,
  operationKeys: Object.freeze([]) as readonly [],
  allowedOrigins: (descriptor: GenericHttpOperationDescriptorV1) =>
    Object.freeze([descriptor.origin]),
  build: (
    operationKey: string,
    args: unknown,
    method: unknown,
    descriptor: GenericHttpOperationDescriptorV1,
  ) => buildGenericHttpAction(operationKey, descriptor, method, args),
});

/**
 * The executable profile registry. These are the exact builders used by public
 * ingress and config-driven finalization; conformance tests enumerate this same
 * frozen list rather than exercising handwritten lookalikes.
 */
export const PRODUCTION_PROVIDER_PROFILE_SPECS: readonly ProductionProviderProfileSpec[] =
  Object.freeze([GITHUB_SPEC, X_SPEC, SLACK_SPEC, GENERIC_HTTP_SPEC]);

const SPEC_BY_PROFILE: ReadonlyMap<string, ProductionProviderProfileSpec> = new Map(
  PRODUCTION_PROVIDER_PROFILE_SPECS.map((spec) => [spec.profile, spec] as const),
);

// Fail at module load if the metadata registry and executable registry drift.
if (SPEC_BY_PROFILE.size !== PRODUCTION_PROVIDER_PROFILE_SPECS.length) {
  throw new Error("duplicate executable provider profile");
}
const productionProfiles = [...SPEC_BY_PROFILE.keys()].sort();
const registeredProfiles = [...REGISTERED_PROFILES].sort();
if (JSON.stringify(productionProfiles) !== JSON.stringify(registeredProfiles)) {
  throw new Error("provider profile metadata/executable registry drift");
}
for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
  const descriptor = getProfileDescriptor(spec.profile);
  if (!descriptor || descriptor.kind !== spec.kind) {
    throw new Error(`provider profile kind drift for '${spec.profile}'`);
  }
}
const operationOwners = new Map<string, string>();
for (const spec of PRODUCTION_PROVIDER_PROFILE_SPECS) {
  for (const operationKey of spec.operationKeys) {
    const existingOwner = operationOwners.get(operationKey);
    if (existingOwner) {
      throw new Error(
        `provider operation '${operationKey}' is owned by both '${existingOwner}' and '${spec.profile}'`,
      );
    }
    operationOwners.set(operationKey, spec.profile);
  }
}

export function getProductionProviderProfileSpec(
  profile: string,
): ProductionProviderProfileSpec | undefined {
  return SPEC_BY_PROFILE.get(profile);
}

export function getGenericHttpProductionSpec() {
  return GENERIC_HTTP_SPEC;
}

/** Build through the executable adapter registry used by public ingress. */
export function buildAdapterFixedProviderAction(
  operationKey: string,
  args: unknown,
  method: unknown,
): AdapterFixedActionBuild | undefined {
  if ((GITHUB_SPEC.operationKeys as readonly string[]).includes(operationKey)) {
    if (method !== undefined)
      throw new CanonError("CANON_UNKNOWN_FIELD", "method is adapter-fixed");
    return GITHUB_SPEC.build(operationKey as GithubOperationKey, args);
  }
  if ((X_SPEC.operationKeys as readonly string[]).includes(operationKey)) {
    if (method !== undefined)
      throw new CanonError("CANON_UNKNOWN_FIELD", "method is adapter-fixed");
    return X_SPEC.build(operationKey as XOperationKey, args);
  }
  if ((SLACK_SPEC.operationKeys as readonly string[]).includes(operationKey)) {
    if (method !== undefined)
      throw new CanonError("CANON_UNKNOWN_FIELD", "method is adapter-fixed");
    return SLACK_SPEC.build(operationKey as SlackOperationKey, args);
  }
  return undefined;
}
