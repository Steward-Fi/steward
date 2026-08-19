import { runtimeEnvironmentFlag, runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

export interface RequestSecurityPosture {
  requestExpiryRequired: boolean;
  authorizationSignatureRequired: boolean;
}

/** Production is fail-closed; explicit flags can also enable the guards elsewhere. */
export function resolveRequestSecurityPosture(): RequestSecurityPosture {
  const production = runtimeEnvironmentValue("NODE_ENV") === "production";
  return {
    requestExpiryRequired: runtimeEnvironmentFlag("STEWARD_REQUIRE_REQUEST_EXPIRY") || production,
    authorizationSignatureRequired:
      runtimeEnvironmentFlag("STEWARD_REQUIRE_AUTH_SIGNATURE") || production,
  };
}

export function configuredRequestSigningSecrets(): string[] {
  return [
    ...(runtimeEnvironmentValue("STEWARD_REQUEST_SIGNING_SECRETS") ?? "").split(","),
    runtimeEnvironmentValue("STEWARD_REQUEST_SIGNING_SECRET") ?? "",
  ]
    .map((secret) => secret.trim())
    .filter(Boolean);
}
