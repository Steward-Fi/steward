import { createRequire } from "node:module";
import { isDevSecretAllowed } from "@stwd/auth";
import { KmsEnvelopeKeystore, Vault } from "@stwd/vault";

const require = createRequire(import.meta.url);

export type VaultMode = "local" | "kms-envelope:aws" | "kms-envelope:pkcs11";

export const VAULT_SIGNING_CAPABILITIES = Object.freeze([
  "sign_transaction",
  "sign_message",
  "sign_raw_hash",
  "sign_raw_digest",
  "sign_typed_data",
  "sign_user_operation",
  "sign_eip7702_authorization",
  "sign_solana_transaction",
  "sign_solana_message",
  "sign_bitcoin_psbt",
  "sign_monero_transfer",
] as const);

export type VaultSigningCapability = (typeof VAULT_SIGNING_CAPABILITIES)[number];

export const VAULT_CAPABILITY_REGISTRY: Readonly<
  Record<VaultMode, Readonly<Record<VaultSigningCapability, true>>>
> = Object.freeze({
  local: Object.freeze(Object.fromEntries(VAULT_SIGNING_CAPABILITIES.map((name) => [name, true]))),
  "kms-envelope:aws": Object.freeze(
    Object.fromEntries(VAULT_SIGNING_CAPABILITIES.map((name) => [name, true])),
  ),
  "kms-envelope:pkcs11": Object.freeze(
    Object.fromEntries(VAULT_SIGNING_CAPABILITIES.map((name) => [name, true])),
  ),
}) as Readonly<Record<VaultMode, Readonly<Record<VaultSigningCapability, true>>>>;

export interface ConfiguredVaultOptions {
  allowDevSecretFallback?: boolean;
  fallbackPassword?: string;
}

const vaultsByKey = new Map<string, Vault>();
let warnedDevSecretFallback = false;

function configuredKmsProvider(): "aws" | "pkcs11" | undefined {
  const value = process.env.STEWARD_KMS_PROVIDER?.trim();
  if (!value) return undefined;
  if (value === "aws" || value === "pkcs11") return value;
  throw new Error(`Unsupported STEWARD_KMS_PROVIDER: ${value}`);
}

function requireKmsConfiguration(provider: "aws" | "pkcs11"): void {
  if (provider === "aws") {
    if (!process.env.STEWARD_KMS_KEY_ID?.trim() && !process.env.STEWARD_AWS_KMS_KEY_ARN?.trim()) {
      throw new Error("STEWARD_KMS_KEY_ID or STEWARD_AWS_KMS_KEY_ARN is required for AWS KMS");
    }
    return;
  }

  const missing = [
    ["STEWARD_PKCS11_MODULE", process.env.STEWARD_PKCS11_MODULE],
    ["STEWARD_PKCS11_PIN", process.env.STEWARD_PKCS11_PIN],
    ["STEWARD_PKCS11_KEY_LABEL", process.env.STEWARD_PKCS11_KEY_LABEL],
  ]
    .filter(([, value]) => !value?.trim())
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`${missing.join(", ")} required for PKCS#11 KMS`);
  }
}

function configuredMode(): VaultMode {
  const provider = configuredKmsProvider();
  if (!provider) return "local";
  requireKmsConfiguration(provider);

  // KMS clients are optional peers and KmsEnvelopeKeystore loads them lazily.
  // Resolve them here so the API startup check fails before accepting traffic.
  const moduleName = provider === "aws" ? "@aws-sdk/client-kms" : "graphene-pk11";
  try {
    require.resolve(moduleName);
  } catch {
    throw new Error(`${moduleName} is required when STEWARD_KMS_PROVIDER=${provider}`);
  }
  if (provider === "pkcs11") {
    throw new Error(
      "STEWARD_KMS_PROVIDER=pkcs11 requires a configured PKCS#11 adapter; fromEnv does not provide one in this release",
    );
  }
  return "kms-envelope:aws";
}

function resolveMasterPassword(options: ConfiguredVaultOptions): string {
  const configured = process.env.STEWARD_MASTER_PASSWORD?.trim();
  if (configured) return configured;
  if (options.fallbackPassword?.trim()) return options.fallbackPassword.trim();

  if (options.allowDevSecretFallback) {
    if (!isDevSecretAllowed()) {
      throw new Error(
        "STEWARD_MASTER_PASSWORD must be set. For local development only, opt in to the insecure dev fallback with STEWARD_ALLOW_DEV_SECRETS=true.",
      );
    }
    if (!warnedDevSecretFallback) {
      warnedDevSecretFallback = true;
      console.warn(
        "[steward] DEV ONLY: using insecure dev-secret as vault master password. Set STEWARD_MASTER_PASSWORD before production.",
      );
    }
    return "dev-secret";
  }

  throw new Error("STEWARD_MASTER_PASSWORD is required");
}

export function createConfiguredVault(options: ConfiguredVaultOptions = {}): Vault {
  const mode = configuredMode();
  const masterPassword = resolveMasterPassword(options);
  return new Vault({
    masterPassword,
    rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
    chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
    ...(mode === "local" ? {} : { keystoreBackend: KmsEnvelopeKeystore.fromEnv() }),
  });
}

export function getConfiguredVault(options: ConfiguredVaultOptions = {}): Vault {
  const mode = configuredMode();
  const masterPassword = resolveMasterPassword(options);
  const key = `${mode}:${masterPassword}`;
  let vault = vaultsByKey.get(key);
  if (!vault) {
    vault = createConfiguredVault({ ...options, fallbackPassword: masterPassword });
    vaultsByKey.set(key, vault);
  }
  return vault;
}

export function configuredVaultStartupLogLine(): string {
  const provider = configuredKmsProvider();
  const mode: VaultMode = provider ? `kms-envelope:${provider}` : "local";
  return `[steward] vault mode=${mode} capabilities=${VAULT_SIGNING_CAPABILITIES.join(",")}`;
}

export function _clearConfiguredVaultsForTests(): void {
  vaultsByKey.clear();
  warnedDevSecretFallback = false;
}
