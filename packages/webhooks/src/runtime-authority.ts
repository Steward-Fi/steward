import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

/** Immutable transport and destination policy for one webhook operation. */
export type WebhookRuntimeAuthority = Readonly<{
  allowInsecureHttp: boolean;
  allowPrivateNetwork: boolean;
}>;

/**
 * Snapshot webhook escape hatches from the current Worker request, or from the
 * Bun process when no request environment is active. Only the exact lowercase
 * acknowledgement enables either fail-open boundary.
 */
export function currentWebhookRuntimeAuthority(): WebhookRuntimeAuthority {
  return Object.freeze({
    allowInsecureHttp: runtimeEnvironmentValue("STEWARD_ALLOW_INSECURE_WEBHOOK_URLS") === "true",
    allowPrivateNetwork:
      runtimeEnvironmentValue("STEWARD_ALLOW_PRIVATE_WEBHOOK_NETWORKS") === "true",
  });
}
