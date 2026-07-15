import { afterEach, describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import {
  _clearConfiguredVaultsForTests,
  configuredVaultStartupLogLine,
  createConfiguredVault,
  getConfiguredVault,
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
  "STEWARD_KMS_KEY_ID",
  "STEWARD_AWS_KMS_KEY_ARN",
  "STEWARD_AWS_REGION",
  "AWS_REGION",
  "STEWARD_PKCS11_MODULE",
  "STEWARD_PKCS11_PIN",
  "STEWARD_PKCS11_KEY_LABEL",
] as const;

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

  it("disallows production new Vault construction outside the factory", () => {
    const offenders = productionTsFiles(API_SRC_DIR)
      .filter((file) => relative(API_SRC_DIR, file) !== "services/vault-factory.ts")
      .filter((file) => /\bnew\s+Vault\s*\(/.test(stripComments(readFileSync(file, "utf8"))))
      .map((file) => relative(API_SRC_DIR, file));

    expect(offenders).toEqual([]);
  });
});
