import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import {
  _clearConfiguredVaultsForTests,
  assertProductionCustodyAcknowledged,
  configuredVaultStartupLogLine,
  createConfiguredVault,
  getConfiguredVault,
  LOCAL_CUSTODY_ACK_ENV,
  modeExposesPlaintextAtSignTime,
  VAULT_CAPABILITY_REGISTRY,
  VAULT_SIGNING_CAPABILITIES,
  type VaultMode,
} from "../services/vault-factory";

const API_SRC_DIR = join(import.meta.dir, "..");

const ENV_KEYS = [
  "NODE_ENV",
  "STEWARD_ALLOW_DEV_SECRETS",
  "STEWARD_ALLOW_DEV_SECRET",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_KMS_PROVIDER",
  "STEWARD_EXTERNAL_CUSTODY_PROVIDER",
  "STEWARD_EXTERNAL_CUSTODY_AWS_REGION",
  "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT",
  "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI",
  "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI",
  "STEWARD_KMS_KEY_ID",
  "STEWARD_AWS_KMS_KEY_ARN",
  "STEWARD_AWS_REGION",
  "AWS_REGION",
  "STEWARD_PKCS11_MODULE",
  "STEWARD_PKCS11_PIN",
  "STEWARD_PKCS11_KEY_LABEL",
  "STEWARD_ACK_LOCAL_CUSTODY",
  "STEWARD_KDF_SALT",
  "RPC_URL",
  "CHAIN_ID",
] as const;

// A known-valid KDF salt (>=32 hex chars). Production-boot tests pin this
// unconditionally so the suite is hermetic: an invalid/short ambient
// STEWARD_KDF_SALT in the caller's shell or CI must not surface as a Vault
// salt-validation failure masquerading as an acknowledgement-gate result.
const TEST_KDF_SALT = "a".repeat(64);

const originalEnv: Record<(typeof ENV_KEYS)[number], string | undefined> = Object.fromEntries(
  ENV_KEYS.map((key) => [key, process.env[key]]),
) as Record<(typeof ENV_KEYS)[number], string | undefined>;
const VAULT_MODES: VaultMode[] = ["local", "kms-envelope:aws", "kms-envelope:pkcs11"];

function restoreEnv(): void {
  for (const key of ENV_KEYS) {
    const value = originalEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function productionTsFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const rel = relative(API_SRC_DIR, path);
    if (rel.split(/[\\/]/).includes("__tests__")) continue;
    const stat = statSync(path);
    if (stat.isDirectory()) {
      productionTsFiles(path).forEach((file) => files.push(file));
    } else if (path.endsWith(".ts") && !path.endsWith(".test.ts")) {
      files.push(path);
    }
  }
  return files;
}

beforeEach(() => {
  // Pin a known-valid KDF salt for the whole suite so no test inherits an
  // invalid/short ambient STEWARD_KDF_SALT from the caller's shell or CI. Tests
  // that specifically exercise salt-independent behaviour set their own env;
  // this only guarantees Vault construction is not blocked by a bad ambient salt
  // (which would masquerade as an acknowledgement-gate or fallback failure).
  process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
});

afterEach(() => {
  restoreEnv();
  _clearConfiguredVaultsForTests();
});

describe("vault factory", () => {
  function internals(vault: ReturnType<typeof getConfiguredVault>) {
    return vault as unknown as {
      config: { rpcUrl: string; chainId: number };
      keyStore: { options?: Record<string, string> };
      externalKeyCustodyProvider?: {
        region: string;
        maxGasLimit: bigint;
        maxGasPriceWei: bigint;
        maxTotalFeeWei: bigint;
      };
    };
  }

  it("memoizes configured vaults by effective password", () => {
    process.env.STEWARD_MASTER_PASSWORD = "factory-master-one";
    delete process.env.STEWARD_KMS_PROVIDER;

    const first = getConfiguredVault();
    const second = getConfiguredVault();
    expect(second).toBe(first);

    process.env.STEWARD_MASTER_PASSWORD = "factory-master-two";
    expect(getConfiguredVault()).not.toBe(first);
  });

  it("does not retain request-scoped vault master passwords across Worker snapshots", async () => {
    const first = await withRuntimeEnvironment(
      {
        NODE_ENV: "test",
        STEWARD_MASTER_PASSWORD: "request-vault-master-one",
        STEWARD_KDF_SALT: TEST_KDF_SALT,
      },
      () => getConfiguredVault(),
    );
    const second = await withRuntimeEnvironment(
      {
        NODE_ENV: "test",
        STEWARD_MASTER_PASSWORD: "request-vault-master-two",
        STEWARD_KDF_SALT: TEST_KDF_SALT,
      },
      () => getConfiguredVault(),
    );

    expect(second).not.toBe(first);
  });

  it("constructs overlapping non-local vaults entirely from their request snapshots", async () => {
    let started = 0;
    let release!: () => void;
    let bothStarted!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const ready = new Promise<void>((resolve) => {
      bothStarted = resolve;
    });
    const afterOverlap = async () => {
      started += 1;
      if (started === 2) bothStarted();
      await barrier;
      return getConfiguredVault();
    };

    const awsVaultPromise = withRuntimeEnvironment(
      {
        NODE_ENV: "test",
        STEWARD_MASTER_PASSWORD: "request-aws-master",
        STEWARD_KDF_SALT: "1".repeat(64),
        STEWARD_KMS_PROVIDER: "aws",
        STEWARD_KMS_KEY_ID: "alias/request-aws-key",
        STEWARD_AWS_REGION: "us-east-1",
        STEWARD_EXTERNAL_CUSTODY_PROVIDER: "aws-kms",
        STEWARD_EXTERNAL_CUSTODY_AWS_REGION: "us-west-2",
        STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT: "111111",
        STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI: "222222",
        STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI: "333333",
        RPC_URL: "https://request-one.invalid",
        CHAIN_ID: "111",
      },
      afterOverlap,
    );
    const pkcs11VaultPromise = withRuntimeEnvironment(
      {
        NODE_ENV: "test",
        STEWARD_MASTER_PASSWORD: "request-pkcs11-master",
        STEWARD_KDF_SALT: "2".repeat(64),
        STEWARD_KMS_PROVIDER: "pkcs11",
        STEWARD_PKCS11_MODULE: "/request/two/pkcs11.so",
        STEWARD_PKCS11_PIN: "request-two-pin",
        STEWARD_PKCS11_KEY_LABEL: "request-two-key",
        RPC_URL: "https://request-two.invalid",
        CHAIN_ID: "222",
      },
      afterOverlap,
    );

    await ready;
    process.env.STEWARD_KMS_PROVIDER = "aws";
    process.env.STEWARD_KMS_KEY_ID = "alias/poison-global-key";
    process.env.STEWARD_AWS_REGION = "eu-west-1";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_REGION = "eu-central-1";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT = "999999";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI = "999999";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI = "999999";
    process.env.RPC_URL = "https://poison-global.invalid";
    process.env.CHAIN_ID = "999";
    release();

    const [awsVault, pkcs11Vault] = await Promise.all([awsVaultPromise, pkcs11VaultPromise]);
    const aws = internals(awsVault);
    expect(aws.keyStore.options).toMatchObject({
      provider: "aws",
      keyId: "alias/request-aws-key",
      region: "us-east-1",
    });
    expect(aws.config).toMatchObject({ rpcUrl: "https://request-one.invalid", chainId: 111 });
    expect(aws.externalKeyCustodyProvider).toMatchObject({
      region: "us-west-2",
      maxGasLimit: 111111n,
      maxGasPriceWei: 222222n,
      maxTotalFeeWei: 333333n,
    });

    const pkcs11 = internals(pkcs11Vault);
    expect(pkcs11.keyStore.options).toMatchObject({
      provider: "pkcs11",
      modulePath: "/request/two/pkcs11.so",
      pin: "request-two-pin",
      keyLabel: "request-two-key",
    });
    expect(pkcs11.config).toMatchObject({ rpcUrl: "https://request-two.invalid", chainId: 222 });
    expect(pkcs11.externalKeyCustodyProvider).toBeUndefined();
  });

  it("rotates the process vault cache for every behavior-affecting custody setting", () => {
    process.env.NODE_ENV = "test";
    process.env.STEWARD_MASTER_PASSWORD = "cache-master";
    process.env.STEWARD_KDF_SALT = "3".repeat(64);
    process.env.RPC_URL = "https://cache-one.invalid";
    process.env.CHAIN_ID = "1001";
    delete process.env.STEWARD_KMS_PROVIDER;

    let previous = getConfiguredVault();
    const expectRotation = () => {
      const next = getConfiguredVault();
      expect(next).not.toBe(previous);
      previous = next;
    };

    process.env.STEWARD_KDF_SALT = "4".repeat(64);
    expectRotation();
    process.env.RPC_URL = "https://cache-two.invalid";
    expectRotation();
    process.env.CHAIN_ID = "1002";
    expectRotation();

    process.env.STEWARD_KMS_PROVIDER = "aws";
    process.env.STEWARD_KMS_KEY_ID = "alias/cache-one";
    process.env.STEWARD_AWS_REGION = "us-east-1";
    expectRotation();
    process.env.STEWARD_KMS_KEY_ID = "alias/cache-two";
    expectRotation();
    process.env.STEWARD_AWS_REGION = "us-west-2";
    expectRotation();

    process.env.STEWARD_KMS_PROVIDER = "pkcs11";
    process.env.STEWARD_PKCS11_MODULE = "/cache/one/pkcs11.so";
    process.env.STEWARD_PKCS11_PIN = "cache-pin-one";
    process.env.STEWARD_PKCS11_KEY_LABEL = "cache-label-one";
    expectRotation();
    process.env.STEWARD_PKCS11_MODULE = "/cache/two/pkcs11.so";
    expectRotation();
    process.env.STEWARD_PKCS11_PIN = "cache-pin-two";
    expectRotation();
    process.env.STEWARD_PKCS11_KEY_LABEL = "cache-label-two";
    expectRotation();

    delete process.env.STEWARD_KMS_PROVIDER;
    process.env.STEWARD_EXTERNAL_CUSTODY_PROVIDER = "aws-kms";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_REGION = "us-east-1";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT = "100000";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI = "2000000000";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI = "100000000000000";
    expectRotation();
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_REGION = "us-west-2";
    expectRotation();
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT = "100001";
    expectRotation();
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI = "2000000001";
    expectRotation();
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI = "100000000000001";
    expectRotation();
  });

  it("fails closed when non-platform callers have no master password", () => {
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_KMS_PROVIDER;

    expect(() => createConfiguredVault()).toThrow("STEWARD_MASTER_PASSWORD is required");
  });

  it("allows the dev-secret fallback only when explicitly requested", () => {
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_KMS_PROVIDER;
    process.env.NODE_ENV = "test";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";

    expect(() => createConfiguredVault()).toThrow("STEWARD_MASTER_PASSWORD is required");
    expect(() => createConfiguredVault({ allowDevSecretFallback: true })).not.toThrow();
  });

  it("fails closed in production when configured KMS cannot initialize", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_MASTER_PASSWORD = "factory-master";
    process.env.STEWARD_KMS_PROVIDER = "aws";
    delete process.env.STEWARD_KMS_KEY_ID;
    delete process.env.STEWARD_AWS_KMS_KEY_ARN;

    expect(() => createConfiguredVault()).toThrow(
      "STEWARD_KMS_KEY_ID or STEWARD_AWS_KMS_KEY_ARN is required for AWS KMS",
    );

    process.env.STEWARD_KMS_PROVIDER = "pkcs11";
    expect(() => createConfiguredVault()).toThrow("required for PKCS#11 KMS");
  });

  it("reports a one-line sanitized mode and all signing capabilities", () => {
    process.env.STEWARD_MASTER_PASSWORD = "super-secret-password";
    process.env.STEWARD_KMS_PROVIDER = "aws";
    process.env.STEWARD_KMS_KEY_ID = "alias/steward-test";

    const line = configuredVaultStartupLogLine();
    expect(line).toContain("mode=kms-envelope:aws");
    expect(line).not.toContain("super-secret-password");
    expect(line).not.toContain("alias/steward-test");
    for (const capability of VAULT_SIGNING_CAPABILITIES) {
      expect(line).toContain(capability);
    }
  });

  it("wires AWS asymmetric external custody separately from KMS envelope mode", () => {
    process.env.STEWARD_MASTER_PASSWORD = "factory-master";
    delete process.env.STEWARD_KMS_PROVIDER;
    process.env.STEWARD_EXTERNAL_CUSTODY_PROVIDER = "aws-kms";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_REGION = "us-east-1";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT = "100000";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI = "2000000000";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI = "100000000000000";

    expect(() => createConfiguredVault()).not.toThrow();
    const line = configuredVaultStartupLogLine();
    expect(line).toContain("mode=local");
    expect(line).toContain("external_custody=aws-kms");
    expect(line).not.toContain("us-east-1");
  });

  it("requires a dedicated explicit AWS external-custody region", () => {
    process.env.STEWARD_MASTER_PASSWORD = "factory-master";
    process.env.STEWARD_EXTERNAL_CUSTODY_PROVIDER = "aws-kms";
    process.env.AWS_REGION = "us-west-2";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT = "100000";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI = "2000000000";
    process.env.STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI = "100000000000000";

    expect(() => createConfiguredVault()).toThrow("explicit AWS region");
  });

  it("fails closed for an unknown external custody provider", () => {
    process.env.STEWARD_MASTER_PASSWORD = "factory-master";
    process.env.STEWARD_EXTERNAL_CUSTODY_PROVIDER = "not-a-provider";
    expect(() => createConfiguredVault()).toThrow("Unsupported STEWARD_EXTERNAL_CUSTODY_PROVIDER");
  });

  it("marks every signing operation supported for local and KMS envelope modes", () => {
    for (const mode of VAULT_MODES) {
      expect(Object.keys(VAULT_CAPABILITY_REGISTRY[mode]).sort()).toEqual(
        [...VAULT_SIGNING_CAPABILITIES].sort(),
      );
      for (const capability of VAULT_SIGNING_CAPABILITIES) {
        expect(VAULT_CAPABILITY_REGISTRY[mode][capability]).toBe(true);
      }
    }
  });

  describe("production local-custody acknowledgement gate", () => {
    it("fails closed in production with local plaintext custody and no acknowledgement", () => {
      process.env.NODE_ENV = "production";
      process.env.STEWARD_MASTER_PASSWORD = "prod-master-password";
      process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
      delete process.env.STEWARD_KMS_PROVIDER;
      delete process.env.STEWARD_ACK_LOCAL_CUSTODY;

      // Both the direct assertion and the real composition boundary must refuse.
      expect(() => assertProductionCustodyAcknowledged("local")).toThrow(
        /local_custody_acknowledgement_required|Refusing to boot/,
      );
      expect(() => createConfiguredVault()).toThrow(LOCAL_CUSTODY_ACK_ENV);
      expect(() => getConfiguredVault()).toThrow(LOCAL_CUSTODY_ACK_ENV);
    });

    it("boots in production with local custody when explicitly acknowledged", () => {
      process.env.NODE_ENV = "production";
      process.env.STEWARD_MASTER_PASSWORD = "prod-master-password";
      process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
      delete process.env.STEWARD_KMS_PROVIDER;
      process.env.STEWARD_ACK_LOCAL_CUSTODY = "true";

      expect(() => assertProductionCustodyAcknowledged("local")).not.toThrow();
      expect(() => createConfiguredVault()).not.toThrow();
    });

    it("rejects a malformed acknowledgement value (only exact 'true' passes)", () => {
      process.env.NODE_ENV = "production";
      process.env.STEWARD_MASTER_PASSWORD = "prod-master-password";
      process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
      delete process.env.STEWARD_KMS_PROVIDER;

      for (const value of ["TRUE", "1", "yes", "true ", " true", "True", ""]) {
        process.env.STEWARD_ACK_LOCAL_CUSTODY = value;
        expect(() => assertProductionCustodyAcknowledged("local")).toThrow(LOCAL_CUSTODY_ACK_ENV);
        expect(() => createConfiguredVault()).toThrow(LOCAL_CUSTODY_ACK_ENV);
      }
    });

    it("does not require acknowledgement outside production (dev/test ergonomics unchanged)", () => {
      process.env.STEWARD_MASTER_PASSWORD = "dev-master-password";
      process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
      delete process.env.STEWARD_KMS_PROVIDER;
      delete process.env.STEWARD_ACK_LOCAL_CUSTODY;

      for (const env of ["test", "development", undefined]) {
        if (env === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = env;
        expect(() => assertProductionCustodyAcknowledged("local")).not.toThrow();
        expect(() => createConfiguredVault()).not.toThrow();
        _clearConfiguredVaultsForTests();
      }
    });

    it("lets stronger KMS-envelope modes boot in production without the local ack", () => {
      process.env.NODE_ENV = "production";
      process.env.STEWARD_MASTER_PASSWORD = "prod-master-password";
      process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
      delete process.env.STEWARD_ACK_LOCAL_CUSTODY;

      // The gate is scoped to local; stronger modes are unaffected by the ack.
      expect(() => assertProductionCustodyAcknowledged("kms-envelope:aws")).not.toThrow();
      expect(() => assertProductionCustodyAcknowledged("kms-envelope:pkcs11")).not.toThrow();
    });

    it("treats local and both KMS-envelope modes as plaintext-at-sign-time", () => {
      expect(modeExposesPlaintextAtSignTime("local")).toBe(true);
      expect(modeExposesPlaintextAtSignTime("kms-envelope:aws")).toBe(true);
      expect(modeExposesPlaintextAtSignTime("kms-envelope:pkcs11")).toBe(true);
      // Unknown mode fails closed (treated as plaintext-exposing).
      expect(modeExposesPlaintextAtSignTime("totally-unknown-mode" as VaultMode)).toBe(true);
    });

    it("never leaks secret material in the gate error or the boot log", () => {
      process.env.NODE_ENV = "production";
      process.env.STEWARD_MASTER_PASSWORD = "top-secret-master-password-xyz";
      process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
      delete process.env.STEWARD_KMS_PROVIDER;
      delete process.env.STEWARD_ACK_LOCAL_CUSTODY;

      let message = "";
      try {
        createConfiguredVault();
      } catch (err) {
        message = err instanceof Error ? err.message : String(err);
      }
      expect(message).not.toContain("top-secret-master-password-xyz");

      process.env.STEWARD_ACK_LOCAL_CUSTODY = "true";
      const line = configuredVaultStartupLogLine();
      expect(line).toContain("mode=local");
      expect(line).toContain("plaintext_at_sign_time=true");
      expect(line).toContain("local_custody_acknowledged=true");
      expect(line).not.toContain("top-secret-master-password-xyz");
    });
  });

  it("disallows production new Vault construction outside the factory", () => {
    const offenders = productionTsFiles(API_SRC_DIR)
      .filter((file) => relative(API_SRC_DIR, file) !== "services/vault-factory.ts")
      .filter((file) => /\bnew\s+Vault\s*\(/.test(stripComments(readFileSync(file, "utf8"))))
      .map((file) => relative(API_SRC_DIR, file));

    expect(offenders).toEqual([]);
  });
});
