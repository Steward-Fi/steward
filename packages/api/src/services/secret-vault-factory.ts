import { currentRuntimeEnvironment, runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { SecretVault } from "@stwd/vault";

let processSecretVault: { masterPassword: string; masterSalt: string; vault: SecretVault } | null =
  null;

export function getConfiguredSecretVault(): SecretVault {
  const masterPassword = runtimeEnvironmentValue("STEWARD_MASTER_PASSWORD");
  const masterSalt = runtimeEnvironmentValue("STEWARD_KDF_SALT");
  if (!masterPassword || !masterSalt) {
    throw new Error("STEWARD_MASTER_PASSWORD and STEWARD_KDF_SALT are required");
  }
  if (currentRuntimeEnvironment() !== process.env) {
    return new SecretVault(masterPassword, masterSalt);
  }
  if (
    processSecretVault?.masterPassword === masterPassword &&
    processSecretVault.masterSalt === masterSalt
  ) {
    return processSecretVault.vault;
  }
  const vault = new SecretVault(masterPassword, masterSalt);
  processSecretVault = { masterPassword, masterSalt, vault };
  return vault;
}
