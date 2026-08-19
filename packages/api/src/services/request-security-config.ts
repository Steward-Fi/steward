import { runtimeEnvironmentFlag, runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

export interface RequestSecurityPosture {
  requestExpiryRequired: boolean;
  authorizationSignatureRequired: boolean;
}

/** Sensitive-request enforcement remains an explicit operator rollout. */
export function resolveRequestSecurityPosture(): RequestSecurityPosture {
  return {
    requestExpiryRequired: runtimeEnvironmentFlag("STEWARD_REQUIRE_REQUEST_EXPIRY"),
    authorizationSignatureRequired: runtimeEnvironmentFlag("STEWARD_REQUIRE_AUTH_SIGNATURE"),
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
