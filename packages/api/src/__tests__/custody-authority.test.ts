import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { buildPluginContext } from "../plugin";
import { isRuntimeVaultRpcMethodAllowed, resolveRuntimeChainId } from "../services/custody-runtime";
import { resolveEvmReceiptRpcUrl } from "../services/transaction-receipt-poller";
import {
  _clearConfiguredVaultsForTests,
  _configuredCustodyInstanceCountForTests,
  getConfiguredKeyStore,
  getConfiguredSecretVault,
  getConfiguredVault,
  resolveCustodyAuthority,
} from "../services/vault-factory";
import { type Env, withWorkerRuntimeAuthority } from "../worker";

const SALT_A = "a1".repeat(16);
const SALT_B = "b2".repeat(16);

function authorityEnvironment(masterPassword: string, kdfSalt: string) {
  return {
    NODE_ENV: "test",
    STEWARD_MASTER_PASSWORD: masterPassword,
    STEWARD_KDF_SALT: kdfSalt,
    RPC_URL: "https://rpc.example.invalid",
    CHAIN_ID: "8453",
  };
}

function workerAuthorityEnvironment(masterPassword: string, kdfSalt: string): Env {
  return {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    ...authorityEnvironment(masterPassword, kdfSalt),
  };
}

describe("request-local custody authority", () => {
  it("rotates every shared custody factory and fails closed when the current binding is absent", () => {
    _clearConfiguredVaultsForTests();
    const envA = workerAuthorityEnvironment("worker-authority-a", SALT_A);
    const envB = workerAuthorityEnvironment("worker-authority-b", SALT_B);

    const a = withWorkerRuntimeAuthority(envA, () => ({
      authority: resolveCustodyAuthority(),
      vault: getConfiguredVault(),
      secrets: getConfiguredSecretVault(),
      oauth: getConfiguredKeyStore(),
      leases: getConfiguredKeyStore("credential-lease"),
    }));
    const b = withWorkerRuntimeAuthority(envB, () => ({
      authority: resolveCustodyAuthority(),
      vault: getConfiguredVault(),
      secrets: getConfiguredSecretVault(),
      oauth: getConfiguredKeyStore(),
      leases: getConfiguredKeyStore("credential-lease"),
    }));

    expect("fingerprint" in a.authority).toBe(false);
    expect("fingerprint" in b.authority).toBe(false);
    expect(b.vault).not.toBe(a.vault);
    expect(b.secrets).not.toBe(a.secrets);
    expect(b.oauth).not.toBe(a.oauth);
    expect(b.leases).not.toBe(a.leases);

    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    process.env.STEWARD_MASTER_PASSWORD = "stale-isolate-password";
    try {
      expect(() =>
        withWorkerRuntimeAuthority(
          {
            DATABASE_URL: "postgresql://worker.invalid/steward",
            NODE_ENV: "test",
            STEWARD_KDF_SALT: SALT_B,
          },
          () =>
            resolveCustodyAuthority({
              fallbackPassword: "captured-import-password",
              allowDevSecretFallback: true,
            }),
        ),
      ).toThrow("STEWARD_MASTER_PASSWORD is required");
    } finally {
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
    }
  });

  it("keys instances by KDF salt even when the password is unchanged", () => {
    _clearConfiguredVaultsForTests();
    const envA = authorityEnvironment("same-password", SALT_A);
    const envB = authorityEnvironment("same-password", SALT_B);

    const a = withRuntimeEnvironment(envA, () => ({
      authority: resolveCustodyAuthority(),
      vault: getConfiguredVault(),
      keyStore: getConfiguredKeyStore("secret-vault"),
    }));
    const b = withRuntimeEnvironment(envB, () => ({
      authority: resolveCustodyAuthority(),
      vault: getConfiguredVault(),
      keyStore: getConfiguredKeyStore("secret-vault"),
    }));

    expect(b.vault).not.toBe(a.vault);
    expect(b.keyStore).not.toBe(a.keyStore);
    const ciphertext = a.keyStore.encrypt("scope-a", {
      tenantId: "tenant-a",
      name: "authority-proof",
      version: 1,
    });
    expect(() =>
      b.keyStore.decrypt(ciphertext, {
        tenantId: "tenant-a",
        name: "authority-proof",
        version: 1,
      }),
    ).toThrow();
  });

  it("resolves the full RPC, chain, and legacy-gate tuple without a secret fingerprint", () => {
    const base = authorityEnvironment("full-authority", SALT_A);
    const first = withRuntimeEnvironment(base, () => resolveCustodyAuthority());
    const changed = withRuntimeEnvironment(
      {
        ...base,
        RPC_URL: "https://rotated-rpc.example.invalid",
        CHAIN_ID: "84532",
        STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK: "false",
        STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK: "true",
        STEWARD_SOLANA_PRIORITY_FEES: "0",
        STEWARD_VAULT_RPC_ALLOWLIST: "eth_chainId,eth_getCode",
      },
      () => resolveCustodyAuthority(),
    );

    expect(Object.isFrozen(first)).toBe(true);
    expect("fingerprint" in first).toBe(false);
    expect("fingerprint" in changed).toBe(false);
    expect(changed.rpcUrl).toBe("https://rotated-rpc.example.invalid");
    expect(changed.chainId).toBe(84532);
    expect(changed.allowLegacySecretRootFallback).toBe(false);
    expect(changed.allowLegacyKeystoreDecryptFallback).toBe(true);
    expect(changed.solanaPriorityFees).toBe(false);
  });

  it("fails closed on malformed request-local chain defaults", () => {
    expect(withRuntimeEnvironment({}, () => resolveRuntimeChainId(84532))).toBe(84532);
    expect(withRuntimeEnvironment({ CHAIN_ID: " 8453 " }, () => resolveRuntimeChainId(84532))).toBe(
      8453,
    );
    for (const malformed of ["1junk", "0", "-1", "1.5", "01", "9007199254740992"]) {
      expect(() =>
        withRuntimeEnvironment({ CHAIN_ID: malformed }, () => resolveRuntimeChainId(84532)),
      ).toThrow(/CHAIN_ID must be/);
      expect(() =>
        withRuntimeEnvironment(
          { ...authorityEnvironment("malformed-chain", SALT_A), CHAIN_ID: malformed },
          () => resolveCustodyAuthority(),
        ),
      ).toThrow(/CHAIN_ID must be/);
    }
    expect(() => withRuntimeEnvironment({}, () => resolveRuntimeChainId(0))).toThrow(
      /CHAIN_ID fallback must be/,
    );
  });

  it("survives hostile A-suspends, B-runs, A-resumes overlap", async () => {
    _clearConfiguredVaultsForTests();
    let releaseA: (() => void) | undefined;
    let signalAStarted: (() => void) | undefined;
    const aStarted = new Promise<void>((resolve) => {
      signalAStarted = resolve;
    });
    const aMayResume = new Promise<void>((resolve) => {
      releaseA = resolve;
    });

    const authorityA = {
      ...authorityEnvironment("overlap-a", SALT_A),
      CHAIN_ID: "1",
      RPC_URL: "https://rpc-a.example.invalid",
      STEWARD_RPC_1: "https://receipt-a.example.invalid",
      STEWARD_VAULT_RPC_ALLOWLIST: "eth_chainId,eth_aOnly",
    };
    const authorityB = {
      ...authorityEnvironment("overlap-b", SALT_B),
      CHAIN_ID: "8453",
      RPC_URL: "https://rpc-b.example.invalid",
      STEWARD_RPC_8453: "https://receipt-b.example.invalid",
      STEWARD_VAULT_RPC_ALLOWLIST: "eth_chainId,eth_bOnly",
    };

    const requestA = withRuntimeEnvironment(authorityA, async () => {
      const before = resolveCustodyAuthority();
      const beforeStore = getConfiguredKeyStore("credential-lease");
      signalAStarted?.();
      await aMayResume;
      return {
        before,
        after: resolveCustodyAuthority(),
        sameStore: beforeStore === getConfiguredKeyStore("credential-lease"),
        chainId: resolveRuntimeChainId(84532),
        receiptRpc: resolveEvmReceiptRpcUrl(1),
        allowsA: isRuntimeVaultRpcMethodAllowed("eth_aOnly"),
        allowsB: isRuntimeVaultRpcMethodAllowed("eth_bOnly"),
      };
    });

    await aStarted;
    const requestB = await withRuntimeEnvironment(authorityB, async () => ({
      authority: resolveCustodyAuthority(),
      store: getConfiguredKeyStore("credential-lease"),
      chainId: resolveRuntimeChainId(84532),
      receiptRpc: resolveEvmReceiptRpcUrl(8453),
      allowsA: isRuntimeVaultRpcMethodAllowed("eth_aOnly"),
      allowsB: isRuntimeVaultRpcMethodAllowed("eth_bOnly"),
    }));
    releaseA?.();
    const resumedA = await requestA;

    expect(resumedA.sameStore).toBe(true);
    expect(resumedA.after.masterPassword).toBe(resumedA.before.masterPassword);
    expect(resumedA.after.masterPassword).not.toBe(requestB.authority.masterPassword);
    expect(resumedA.chainId).toBe(1);
    expect(resumedA.receiptRpc).toBe("https://receipt-a.example.invalid");
    expect(resumedA.allowsA).toBe(true);
    expect(resumedA.allowsB).toBe(false);
    expect(requestB.chainId).toBe(8453);
    expect(requestB.receiptRpc).toBe("https://receipt-b.example.invalid");
    expect(requestB.allowsA).toBe(false);
    expect(requestB.allowsB).toBe(true);
    expect(
      withRuntimeEnvironment(authorityA, () => getConfiguredKeyStore("credential-lease")),
    ).not.toBe(requestB.store);
  });

  it("keys Worker AWS custody by explicit request-local credentials and rejects omissions", () => {
    const base = {
      ...workerAuthorityEnvironment("aws-authority", SALT_A),
      STEWARD_KMS_PROVIDER: "aws",
      STEWARD_KMS_KEY_ID: "test-kms-key",
      STEWARD_AWS_REGION: "us-west-2",
      AWS_ACCESS_KEY_ID: "access-a",
      AWS_SECRET_ACCESS_KEY: "secret-a",
      AWS_SESSION_TOKEN: "session-a",
    };
    const authorityA = withWorkerRuntimeAuthority(base, () => resolveCustodyAuthority());
    const authorityB = withWorkerRuntimeAuthority(
      { ...base, AWS_SECRET_ACCESS_KEY: "secret-b", AWS_SESSION_TOKEN: "session-b" },
      () => resolveCustodyAuthority(),
    );

    expect(authorityB.awsSecretAccessKey).not.toBe(authorityA.awsSecretAccessKey);
    expect(authorityA.awsAccessKeyId).toBe("access-a");
    expect(authorityA.awsSessionToken).toBe("session-a");
    expect(() =>
      withWorkerRuntimeAuthority(
        {
          ...workerAuthorityEnvironment("aws-authority", SALT_A),
          STEWARD_KMS_PROVIDER: "aws",
          STEWARD_KMS_KEY_ID: "test-kms-key",
          STEWARD_AWS_REGION: "us-west-2",
        },
        () => resolveCustodyAuthority(),
      ),
    ).toThrow(/AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be configured together/);

    expect(() =>
      withWorkerRuntimeAuthority(
        {
          ...base,
          STEWARD_AWS_REGION: undefined,
          AWS_REGION: undefined,
        },
        () => resolveCustodyAuthority(),
      ),
    ).toThrow("STEWARD_AWS_REGION or AWS_REGION is required for Worker AWS KMS custody");
  });

  it("fails closed when the current Worker authority omits its KDF salt", () => {
    const previousSalt = process.env.STEWARD_KDF_SALT;
    process.env.STEWARD_KDF_SALT = SALT_B;
    try {
      expect(() =>
        withWorkerRuntimeAuthority(
          {
            DATABASE_URL: "postgresql://worker.invalid/steward",
            NODE_ENV: "test",
            STEWARD_MASTER_PASSWORD: "request-password",
          },
          () => resolveCustodyAuthority(),
        ),
      ).toThrow("STEWARD_KDF_SALT is required for Worker custody authority");
    } finally {
      if (previousSalt === undefined) delete process.env.STEWARD_KDF_SALT;
      else process.env.STEWARD_KDF_SALT = previousSalt;
    }
  });

  it("classifies a blank Worker NODE_ENV as production", () => {
    expect(() =>
      withWorkerRuntimeAuthority(
        {
          ...workerAuthorityEnvironment("blank-node-env", SALT_A),
          NODE_ENV: "   ",
        },
        () => resolveCustodyAuthority(),
      ),
    ).toThrow(/STEWARD_ACK_LOCAL_CUSTODY=true/);
  });

  it("keeps an isolate-cached plugin context late-bound to each request", async () => {
    _clearConfiguredVaultsForTests();
    const pluginContext = buildPluginContext();
    const envA = authorityEnvironment("plugin-a", SALT_A);
    const envB = authorityEnvironment("plugin-b", SALT_B);
    const sealedA = await withRuntimeEnvironment(envA, () =>
      pluginContext.sealCredentialLeaseToken("tenant-a", "lease-a", "token-a"),
    );
    const sealedB = await withRuntimeEnvironment(envB, () =>
      pluginContext.sealCredentialLeaseToken("tenant-a", "lease-a", "token-b"),
    );

    await expect(
      withRuntimeEnvironment(envA, () =>
        pluginContext.exerciseCredentialLeaseToken(
          "tenant-a",
          "lease-a",
          sealedA,
          async (value) => value,
        ),
      ),
    ).resolves.toBe("token-a");
    await expect(
      withRuntimeEnvironment(envB, () =>
        pluginContext.exerciseCredentialLeaseToken(
          "tenant-a",
          "lease-a",
          sealedA,
          async (value) => value,
        ),
      ),
    ).rejects.toThrow();
    await expect(
      withRuntimeEnvironment(envB, () =>
        pluginContext.exerciseCredentialLeaseToken(
          "tenant-a",
          "lease-a",
          sealedB,
          async (value) => value,
        ),
      ),
    ).resolves.toBe("token-b");
  });

  it("keeps custody instances request-local and leaves no reachable rotation generations", () => {
    _clearConfiguredVaultsForTests();
    const identities = new Set<object>();
    for (let generation = 0; generation < 12; generation += 1) {
      withRuntimeEnvironment(
        authorityEnvironment(
          `rotation-${generation}`,
          generation.toString(16).padStart(2, "0").repeat(16),
        ),
        () => {
          const vault = getConfiguredVault();
          const secretVault = getConfiguredSecretVault();
          const oauth = getConfiguredKeyStore();
          const lease = getConfiguredKeyStore("credential-lease");
          identities.add(vault);
          identities.add(secretVault);
          identities.add(oauth);
          identities.add(lease);
          expect(getConfiguredVault()).toBe(vault);
          expect(getConfiguredSecretVault()).toBe(secretVault);
          expect(getConfiguredKeyStore()).toBe(oauth);
          expect(getConfiguredKeyStore("credential-lease")).toBe(lease);
          expect(_configuredCustodyInstanceCountForTests()).toBe(4);
        },
      );
      expect(_configuredCustodyInstanceCountForTests()).toBe(0);
    }
    expect(identities.size).toBe(48);
  });
});
