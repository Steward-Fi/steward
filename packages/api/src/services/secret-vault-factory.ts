import { currentRuntimeEnvironment, runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { SecretVault } from "@stwd/vault";
import { processCacheIdentity } from "./process-cache-identity";

let processSecretVault: { identity: string; vault: SecretVault } | null = null;

export function getConfiguredSecretVault(): SecretVault {
  const masterPassword = runtimeEnvironmentValue("STEWARD_MASTER_PASSWORD");
  const masterSalt = runtimeEnvironmentValue("STEWARD_KDF_SALT");
  if (!masterPassword || !masterSalt) {
    throw new Error("STEWARD_MASTER_PASSWORD and STEWARD_KDF_SALT are required");
  }
  if (currentRuntimeEnvironment() !== process.env) {
    return new SecretVault(masterPassword, masterSalt);
  }
  const identity = processCacheIdentity([masterPassword, masterSalt]);
  if (processSecretVault?.identity === identity) return processSecretVault.vault;
  const vault = new SecretVault(masterPassword, masterSalt);
  processSecretVault = { identity, vault };
  return vault;
}
