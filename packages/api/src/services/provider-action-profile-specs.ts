import {
  buildGithubAction,
  GITHUB_OPERATION_KEYS,
  type GithubActionBuild,
  type GithubOperationKey,
} from "@stwd/provider-github";
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
  X_PROVIDER_ACTION_PROFILE,
} from "@stwd/shared";

export type AdapterFixedActionBuild = GithubActionBuild | XActionBuild;

export type ProductionProviderProfileSpec =
  | {
      readonly profile: typeof GITHUB_PROVIDER_ACTION_PROFILE;
      readonly kind: "adapter-fixed";
      readonly operationKeys: readonly GithubOperationKey[];
      build(operationKey: GithubOperationKey, args: unknown): GithubActionBuild;
    }
  | {
      readonly profile: typeof X_PROVIDER_ACTION_PROFILE;
      readonly kind: "adapter-fixed";
      readonly operationKeys: readonly XOperationKey[];
      build(operationKey: XOperationKey, args: unknown): XActionBuild;
    }
  | {
      readonly profile: typeof GENERIC_HTTP_PROVIDER_ACTION_PROFILE;
      readonly kind: "config-driven";
      readonly operationKeys: readonly [];
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
  build: buildGithubAction,
});

const X_SPEC = Object.freeze({
  profile: X_PROVIDER_ACTION_PROFILE,
  kind: "adapter-fixed" as const,
  operationKeys: Object.freeze([...X_OPERATION_KEYS]),
  build: buildXAction,
});

const GENERIC_HTTP_SPEC = Object.freeze({
  profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  kind: "config-driven" as const,
  operationKeys: Object.freeze([]) as readonly [],
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
  Object.freeze([GITHUB_SPEC, X_SPEC, GENERIC_HTTP_SPEC]);

const SPEC_BY_PROFILE: ReadonlyMap<string, ProductionProviderProfileSpec> = new Map(
  PRODUCTION_PROVIDER_PROFILE_SPECS.map((spec) => [spec.profile, spec] as const),
);

// Fail at module load if the metadata registry and executable registry drift.
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
  return undefined;
}
