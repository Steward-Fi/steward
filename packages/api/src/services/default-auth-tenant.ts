import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

/** Resolve the tenant-less auth target from the active request's immutable environment. */
export function defaultAuthTenantId(): string {
  return runtimeEnvironmentValue("STEWARD_DEFAULT_TENANT_ID")?.trim() || "default";
}
