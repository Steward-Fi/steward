import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

export type GlobalWalletFeatureFlags = Readonly<{
  unsafeMessageSigning: boolean;
  personalSign: boolean;
  typedDataSigning: boolean;
  sendTransaction: boolean;
}>;

/** Resolve security-sensitive wallet gates from the active request's immutable environment. */
export function globalWalletFeatureFlags(): GlobalWalletFeatureFlags {
  return {
    unsafeMessageSigning:
      runtimeEnvironmentValue("STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING") === "true",
    personalSign: runtimeEnvironmentValue("STEWARD_ALLOW_GLOBAL_WALLET_PERSONAL_SIGN") === "true",
    typedDataSigning:
      runtimeEnvironmentValue("STEWARD_ALLOW_GLOBAL_WALLET_TYPED_DATA_SIGNING") === "true",
    sendTransaction:
      runtimeEnvironmentValue("STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION") === "true",
  };
}
