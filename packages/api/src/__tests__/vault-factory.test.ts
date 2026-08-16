import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
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
  "STEWARD_KMS_KEY_ID",
  "STEWARD_AWS_KMS_KEY_ARN",
  "STEWARD_AWS_REGION",
  "AWS_REGION",
  "STEWARD_PKCS11_MODULE",
  "STEWARD_PKCS11_PIN",
  "STEWARD_PKCS11_KEY_LABEL",
  "STEWARD_ACK_LOCAL_CUSTODY",
  "STEWARD_KDF_SALT",
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
  it("memoizes configured vaults by effective password", () => {
    process.env.STEWARD_MASTER_PASSWORD = "factory-master-one";
    delete process.env.STEWARD_KMS_PROVIDER;

    const first = getConfiguredVault();
    const second = getConfiguredVault();
    expect(second).toBe(first);

    process.env.STEWARD_MASTER_PASSWORD = "factory-master-two";
    expect(getConfiguredVault()).not.toBe(first);
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

    expect(() => createConfiguredVault()).not.toThrow();
    const line = configuredVaultStartupLogLine();
    expect(line).toContain("mode=local");
    expect(line).toContain("external_custody=aws-kms");
    expect(line).not.toContain("us-east-1");
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
