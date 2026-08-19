import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { buildPluginContext } from "../plugin";
import { getConfiguredSecretVault } from "../services/secret-vault-factory";

const SALT_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SALT_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

describe("plugin credential roots", () => {
  it("binds lease encryption to the current immutable runtime environment", async () => {
    const first = await withRuntimeEnvironment(
      { STEWARD_MASTER_PASSWORD: "plugin-master-a", STEWARD_KDF_SALT: SALT_A },
      () => buildPluginContext(),
    );
    const second = await withRuntimeEnvironment(
      { STEWARD_MASTER_PASSWORD: "plugin-master-b", STEWARD_KDF_SALT: SALT_B },
      () => buildPluginContext(),
    );
    const sealed = await first.sealCredentialLeaseToken("tenant-a", "lease-a", "credential-a");

    await expect(
      first.exerciseCredentialLeaseToken("tenant-a", "lease-a", sealed, async (token) => token),
    ).resolves.toBe("credential-a");
    await expect(
      second.exerciseCredentialLeaseToken("tenant-a", "lease-a", sealed, async (token) => token),
    ).rejects.toThrow();
  });

  it("does not share SecretVault instances across request snapshots", async () => {
    const first = await withRuntimeEnvironment(
      { STEWARD_MASTER_PASSWORD: "secret-master-a", STEWARD_KDF_SALT: SALT_A },
      () => getConfiguredSecretVault(),
    );
    const second = await withRuntimeEnvironment(
      { STEWARD_MASTER_PASSWORD: "secret-master-b", STEWARD_KDF_SALT: SALT_B },
      () => getConfiguredSecretVault(),
    );

    expect(first).not.toBe(second);
  });
});
