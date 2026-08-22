import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import {
  AwsKmsExternalKeyCustodyProvider,
  createMoneroBackendFromEnv,
  KeyStore,
  type KeyStoreDomain,
  KmsEnvelopeKeystore,
  SecretVault,
  Vault,
} from "@stwd/vault";
import { resolveRuntimeChainId } from "./custody-runtime";

const require = createRequire(import.meta.url);

export type VaultMode = "local" | "kms-envelope:aws" | "kms-envelope:pkcs11";
export type ExternalCustodyProviderName = "aws-kms";

/**
 * Explicit acknowledgement that this deployment runs the weakest custody
 * posture (`local`: AES-256-GCM at rest, plaintext key bytes in application
 * memory at sign time) in production. Set to `"true"` to proceed.
 *
 * This mirrors the adapter-registry `STEWARD_ALLOW_MOCK_ADAPTERS` gate: a silent
 * weak default in production becomes a deliberate, recorded operator decision.
 * Unlike the `STEWARD_ALLOW_*` family (which unblocks an otherwise-refused
 * capability), this flag does not change WHAT local mode can do — it only forces
 * the operator to acknowledge the posture before the root of trust boots.
 *
 * See docs/security/custody-posture.md for the full threat model.
 */
export const LOCAL_CUSTODY_ACK_ENV = "STEWARD_ACK_LOCAL_CUSTODY";

export class LocalCustodyAcknowledgementRequiredError extends Error {
  readonly code = "local_custody_acknowledgement_required";
  constructor() {
    super(
      "Refusing to boot: NODE_ENV=production with local plaintext custody " +
        "(mode=local). In local mode the private key is decrypted to plaintext in " +
        "application memory at sign time, so a memory-scrape of this process " +
        `exposes every key. Acknowledge this posture explicitly by setting ${LOCAL_CUSTODY_ACK_ENV}=true, ` +
        "or move to a stronger backend (STEWARD_KMS_PROVIDER=aws|pkcs11, or an " +
        "external-custody provider). See docs/security/custody-posture.md.",
    );
  }
}

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

export interface CustodyAuthority {
  readonly fingerprint: string;
  readonly workerRuntime: boolean;
  readonly nodeEnvironment?: string;
  readonly masterPassword: string;
  readonly kdfSalt?: string;
  readonly mode: VaultMode;
  readonly kmsKeyId?: string;
  readonly awsRegion?: string;
  readonly awsAccessKeyId?: string;
  readonly awsSecretAccessKey?: string;
  readonly awsSessionToken?: string;
  readonly pkcs11Module?: string;
  readonly pkcs11Pin?: string;
  readonly pkcs11KeyLabel?: string;
  readonly externalCustodyProvider?: ExternalCustodyProviderName;
  readonly externalCustodyAwsRegion?: string;
  readonly externalCustodyAwsMaxGasLimit?: string;
  readonly externalCustodyAwsMaxGasPriceWei?: string;
  readonly externalCustodyAwsMaxTotalFeeWei?: string;
  readonly localCustodyAcknowledged: boolean;
  readonly rpcUrl: string;
  readonly chainId: number;
  readonly solanaPriorityFees: boolean;
  readonly vaultRpcAllowlist?: string;
  readonly moneroWalletRpcUrl?: string;
  readonly moneroWalletRpcLogin?: string;
  readonly moneroDaemonUrl?: string;
  readonly moneroNetwork?: string;
  readonly webhookSecretEncryptionKey?: string;
  readonly webhookSecretKdfSalt?: string;
  readonly allowLegacyKeystoreDecryptFallback: boolean;
  readonly allowLegacySecretRootFallback: boolean;
}

const vaultsByKey = new Map<string, Vault>();
const secretVaultsByKey = new Map<string, SecretVault>();
const keyStoresByKey = new Map<string, KeyStore>();
const MAX_CACHED_CUSTODY_INSTANCES = 24;
let warnedDevSecretFallback = false;

function cacheCustodyInstance<T>(cache: Map<string, T>, key: string, value: T): T {
  if (cache.size >= MAX_CACHED_CUSTODY_INSTANCES) {
    const oldest = cache.keys().next().value as string | undefined;
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, value);
  return value;
}

function runtimeValue(name: string): string | undefined {
  return runtimeEnvironmentValue(name)?.trim() || undefined;
}

function runtimeRaw(name: string): string | undefined {
  return runtimeEnvironmentValue(name) || undefined;
}

function runtimeNodeEnvironment(): string | undefined {
  return (
    runtimeRaw("NODE_ENV") ??
    (runtimeRaw("STEWARD_RUNTIME") === "workers" ? "production" : undefined)
  );
}

function configuredKmsProvider(): "aws" | "pkcs11" | undefined {
  const value = runtimeValue("STEWARD_KMS_PROVIDER");
  if (!value) return undefined;
  if (value === "aws" || value === "pkcs11") return value;
  throw new Error(`Unsupported STEWARD_KMS_PROVIDER: ${value}`);
}

function configuredExternalCustodyProvider(): ExternalCustodyProviderName | undefined {
  const value = runtimeValue("STEWARD_EXTERNAL_CUSTODY_PROVIDER");
  if (!value) return undefined;
  if (value === "aws-kms") return value;
  throw new Error(`Unsupported STEWARD_EXTERNAL_CUSTODY_PROVIDER: ${value}`);
}

function positiveBigInt(value: string | undefined, name: string): bigint {
  if (!value || !/^\d+$/.test(value) || BigInt(value) <= 0n) {
    throw new Error(`${name} is required and must be a positive integer`);
  }
  return BigInt(value);
}

function awsCredentials(authority: CustodyAuthority) {
  if (!authority.awsAccessKeyId || !authority.awsSecretAccessKey) return undefined;
  return {
    accessKeyId: authority.awsAccessKeyId,
    secretAccessKey: authority.awsSecretAccessKey,
    sessionToken: authority.awsSessionToken,
  };
}

function createExternalCustodyProvider(authority: CustodyAuthority) {
  const provider = authority.externalCustodyProvider;
  if (!provider) return undefined;
  // External signing uses the same optional AWS SDK package as envelope mode,
  // but it is deliberately selected by a separate configuration key and never
  // changes the keystore backend.
  try {
    require.resolve("@aws-sdk/client-kms");
  } catch {
    throw new Error(
      "@aws-sdk/client-kms is required when STEWARD_EXTERNAL_CUSTODY_PROVIDER=aws-kms",
    );
  }
  return new AwsKmsExternalKeyCustodyProvider({
    region: authority.externalCustodyAwsRegion,
    credentials: awsCredentials(authority),
    maxGasLimit: positiveBigInt(
      authority.externalCustodyAwsMaxGasLimit,
      "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT",
    ),
    maxGasPriceWei: positiveBigInt(
      authority.externalCustodyAwsMaxGasPriceWei,
      "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI",
    ),
    maxTotalFeeWei: positiveBigInt(
      authority.externalCustodyAwsMaxTotalFeeWei,
      "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI",
    ),
  });
}

function requireKmsConfiguration(provider: "aws" | "pkcs11"): void {
  if (provider === "aws") {
    if (!runtimeValue("STEWARD_KMS_KEY_ID") && !runtimeValue("STEWARD_AWS_KMS_KEY_ARN")) {
      throw new Error("STEWARD_KMS_KEY_ID or STEWARD_AWS_KMS_KEY_ARN is required for AWS KMS");
    }
    return;
  }

  const missing = [
    ["STEWARD_PKCS11_MODULE", runtimeValue("STEWARD_PKCS11_MODULE")],
    ["STEWARD_PKCS11_PIN", runtimeValue("STEWARD_PKCS11_PIN")],
    ["STEWARD_PKCS11_KEY_LABEL", runtimeValue("STEWARD_PKCS11_KEY_LABEL")],
  ]
    .filter(([, value]) => !value?.trim())
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`${missing.join(", ")} required for PKCS#11 KMS`);
  }
}

/**
 * True when the resolved custody mode materializes plaintext private-key bytes
 * in this process's memory at sign time. This is the honest boundary from
 * VISION.md: `local` AND both `kms-envelope:*` modes decrypt the key to a
 * plaintext string in-process before signing. Only an external-custody provider
 * (wired via VaultConfig.externalKeyCustodyProvider, not a vault-factory mode)
 * keeps plaintext out of this process entirely.
 *
 * The acknowledgement gate below is scoped narrowly to `local` — the weakest
 * mode, where the key is ALSO plaintext at rest inside the app's own DB unless
 * an operator adds a KMS/HSM wrap. KMS-envelope modes already require explicit
 * KMS configuration, which is itself a deliberate operator decision.
 */
export function modeExposesPlaintextAtSignTime(mode: VaultMode): boolean {
  // Every vault-factory mode currently decrypts to plaintext in-process before
  // signing. Enumerated (not a blanket `true`) so a future signing-in-HSM mode
  // must be added here deliberately rather than defaulting into "safe".
  switch (mode) {
    case "local":
    case "kms-envelope:aws":
    case "kms-envelope:pkcs11":
      return true;
    default: {
      // Unknown mode: fail closed (treat as plaintext-exposing).
      const _exhaustive: never = mode;
      return true;
    }
  }
}

function localCustodyAcknowledged(): boolean {
  return runtimeRaw(LOCAL_CUSTODY_ACK_ENV) === "true";
}

/**
 * Fail closed if this deployment would silently boot the weakest custody
 * posture in production. The root of trust must never boot weak SILENTLY:
 * production + local plaintext custody + no explicit acknowledgement => throw.
 *
 * Development/test ergonomics are unchanged (the gate only fires when
 * NODE_ENV === "production"). Stronger modes (KMS-envelope) pass without the
 * ack because selecting them is already an explicit configuration decision.
 */
export function assertProductionCustodyAcknowledged(mode: VaultMode): void {
  if (runtimeNodeEnvironment() !== "production") return;
  if (mode !== "local") return;
  if (localCustodyAcknowledged()) return;
  throw new LocalCustodyAcknowledgementRequiredError();
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
  return provider === "aws" ? "kms-envelope:aws" : "kms-envelope:pkcs11";
}

function resolveMasterPassword(options: ConfiguredVaultOptions): string {
  const configured = runtimeValue("STEWARD_MASTER_PASSWORD");
  if (configured) return configured;
  const requestLocalAuthority = runtimeRaw("STEWARD_RUNTIME") === "workers";

  // An active runtime snapshot is authoritative. Never fall back to a password
  // captured by an older isolate/request when the current binding is absent.
  if (!requestLocalAuthority && options.fallbackPassword?.trim()) {
    return options.fallbackPassword.trim();
  }

  if (options.allowDevSecretFallback && !requestLocalAuthority) {
    const devSecretAllowed =
      runtimeNodeEnvironment() !== "production" &&
      (runtimeRaw("STEWARD_ALLOW_DEV_SECRETS") === "true" ||
        runtimeRaw("STEWARD_ALLOW_DEV_SECRET") === "true");
    if (!devSecretAllowed) {
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

function authorityFingerprint(authority: Omit<CustodyAuthority, "fingerprint">): string {
  return createHash("sha256").update(JSON.stringify(authority)).digest("hex");
}

/** Resolve and freeze the complete custody root from this request's authority. */
export function resolveCustodyAuthority(options: ConfiguredVaultOptions = {}): CustodyAuthority {
  const mode = configuredMode();
  assertProductionCustodyAcknowledged(mode);
  const masterPassword = resolveMasterPassword(options);
  const nodeEnvironment = runtimeNodeEnvironment();
  const workerRuntime = runtimeRaw("STEWARD_RUNTIME") === "workers";
  const legacySecretRoot = runtimeRaw("STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK");
  const chainId = resolveRuntimeChainId(84532);
  const resolved = {
    workerRuntime,
    nodeEnvironment,
    masterPassword,
    kdfSalt: runtimeRaw("STEWARD_KDF_SALT"),
    mode,
    kmsKeyId: runtimeRaw("STEWARD_KMS_KEY_ID") ?? runtimeRaw("STEWARD_AWS_KMS_KEY_ARN"),
    awsRegion: runtimeRaw("STEWARD_AWS_REGION") ?? runtimeRaw("AWS_REGION"),
    awsAccessKeyId: runtimeRaw("AWS_ACCESS_KEY_ID"),
    awsSecretAccessKey: runtimeRaw("AWS_SECRET_ACCESS_KEY"),
    awsSessionToken: runtimeRaw("AWS_SESSION_TOKEN"),
    pkcs11Module: runtimeRaw("STEWARD_PKCS11_MODULE"),
    pkcs11Pin: runtimeRaw("STEWARD_PKCS11_PIN"),
    pkcs11KeyLabel: runtimeRaw("STEWARD_PKCS11_KEY_LABEL"),
    externalCustodyProvider: configuredExternalCustodyProvider(),
    externalCustodyAwsRegion: runtimeRaw("STEWARD_EXTERNAL_CUSTODY_AWS_REGION"),
    externalCustodyAwsMaxGasLimit: runtimeValue("STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_LIMIT"),
    externalCustodyAwsMaxGasPriceWei: runtimeValue(
      "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_GAS_PRICE_WEI",
    ),
    externalCustodyAwsMaxTotalFeeWei: runtimeValue(
      "STEWARD_EXTERNAL_CUSTODY_AWS_MAX_TOTAL_FEE_WEI",
    ),
    localCustodyAcknowledged: localCustodyAcknowledged(),
    rpcUrl: runtimeRaw("RPC_URL") ?? "https://sepolia.base.org",
    chainId,
    solanaPriorityFees: runtimeRaw("STEWARD_SOLANA_PRIORITY_FEES") !== "0",
    vaultRpcAllowlist: runtimeRaw("STEWARD_VAULT_RPC_ALLOWLIST"),
    moneroWalletRpcUrl: runtimeRaw("STEWARD_MONERO_WALLET_RPC_URL"),
    moneroWalletRpcLogin: runtimeRaw("STEWARD_MONERO_WALLET_RPC_LOGIN"),
    moneroDaemonUrl: runtimeRaw("STEWARD_MONERO_DAEMON_URL"),
    moneroNetwork: runtimeRaw("STEWARD_MONERO_NETWORK"),
    webhookSecretEncryptionKey: runtimeEnvironmentValue("STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY"),
    webhookSecretKdfSalt: runtimeEnvironmentValue("STEWARD_WEBHOOK_SECRET_KDF_SALT"),
    allowLegacyKeystoreDecryptFallback:
      nodeEnvironment !== "production" &&
      runtimeRaw("STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK") === "true",
    allowLegacySecretRootFallback:
      legacySecretRoot === "true" ||
      (legacySecretRoot !== "false" && nodeEnvironment !== "production"),
  } satisfies Omit<CustodyAuthority, "fingerprint">;
  const usesAws = mode === "kms-envelope:aws" || resolved.externalCustodyProvider === "aws-kms";
  const hasAwsCredentialPart = Boolean(
    resolved.awsAccessKeyId || resolved.awsSecretAccessKey || resolved.awsSessionToken,
  );
  const hasAwsCredentials = Boolean(resolved.awsAccessKeyId && resolved.awsSecretAccessKey);
  if (workerRuntime && !resolved.kdfSalt) {
    throw new Error("STEWARD_KDF_SALT is required for Worker custody authority");
  }
  if (workerRuntime && mode === "kms-envelope:aws" && !resolved.awsRegion) {
    throw new Error("STEWARD_AWS_REGION or AWS_REGION is required for Worker AWS KMS custody");
  }
  if (usesAws && !hasAwsCredentials && (workerRuntime || hasAwsCredentialPart)) {
    throw new Error(
      "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be configured together for AWS custody",
    );
  }
  return Object.freeze({ ...resolved, fingerprint: authorityFingerprint(resolved) });
}

function createVaultForAuthority(authority: CustodyAuthority): Vault {
  const kmsEnvelope =
    authority.mode === "kms-envelope:aws"
      ? new KmsEnvelopeKeystore({
          provider: "aws",
          environmentFallback: false,
          keyId: authority.kmsKeyId,
          region: authority.awsRegion,
          credentials: awsCredentials(authority),
        })
      : authority.mode === "kms-envelope:pkcs11"
        ? new KmsEnvelopeKeystore({
            provider: "pkcs11",
            environmentFallback: false,
            modulePath: authority.pkcs11Module,
            pin: authority.pkcs11Pin,
            keyLabel: authority.pkcs11KeyLabel,
          })
        : undefined;
  const moneroBackend = createMoneroBackendFromEnv({
    STEWARD_MONERO_WALLET_RPC_URL: authority.moneroWalletRpcUrl,
    STEWARD_MONERO_WALLET_RPC_LOGIN: authority.moneroWalletRpcLogin,
    STEWARD_MONERO_DAEMON_URL: authority.moneroDaemonUrl,
    STEWARD_MONERO_NETWORK: authority.moneroNetwork,
  });
  return new Vault({
    masterPassword: authority.masterPassword,
    masterSalt: authority.kdfSalt,
    nodeEnvironment: authority.nodeEnvironment,
    allowLegacyKeystoreDecryptFallback: authority.allowLegacyKeystoreDecryptFallback,
    rpcUrl: authority.rpcUrl,
    chainId: authority.chainId,
    solanaPriorityFees: authority.solanaPriorityFees,
    rpcPassthroughAllowlist: authority.vaultRpcAllowlist ?? null,
    ...(moneroBackend ? { moneroBackend } : {}),
    ...(kmsEnvelope ? { keystoreBackend: kmsEnvelope } : {}),
    ...(authority.externalCustodyProvider
      ? { externalKeyCustodyProvider: createExternalCustodyProvider(authority) }
      : {}),
  });
}

export function createConfiguredVault(options: ConfiguredVaultOptions = {}): Vault {
  return createVaultForAuthority(resolveCustodyAuthority(options));
}

export function getConfiguredVault(options: ConfiguredVaultOptions = {}): Vault {
  const authority = resolveCustodyAuthority(options);
  let vault = vaultsByKey.get(authority.fingerprint);
  if (!vault) {
    vault = cacheCustodyInstance(
      vaultsByKey,
      authority.fingerprint,
      createVaultForAuthority(authority),
    );
  }
  return vault;
}

export function getConfiguredSecretVault(options: ConfiguredVaultOptions = {}): SecretVault {
  const authority = resolveCustodyAuthority(options);
  let vault = secretVaultsByKey.get(authority.fingerprint);
  if (!vault) {
    vault = new SecretVault(authority.masterPassword, authority.kdfSalt, {
      nodeEnvironment: authority.nodeEnvironment,
      allowLegacyDecryptFallback: authority.allowLegacyKeystoreDecryptFallback,
      allowLegacySecretRootFallback: authority.allowLegacySecretRootFallback,
    });
    cacheCustodyInstance(secretVaultsByKey, authority.fingerprint, vault);
  }
  return vault;
}

export function getConfiguredKeyStore(
  domain?: KeyStoreDomain,
  options: ConfiguredVaultOptions = {},
): KeyStore {
  const authority = resolveCustodyAuthority(options);
  const key = `${authority.fingerprint}:${domain ?? "legacy"}`;
  let keyStore = keyStoresByKey.get(key);
  if (!keyStore) {
    keyStore = new KeyStore(authority.masterPassword, authority.kdfSalt, domain, {
      nodeEnvironment: authority.nodeEnvironment,
      allowLegacyDecryptFallback: authority.allowLegacyKeystoreDecryptFallback,
    });
    cacheCustodyInstance(keyStoresByKey, key, keyStore);
  }
  return keyStore;
}

export function configuredVaultStartupLogLine(): string {
  const authority = resolveCustodyAuthority();
  const mode = authority.mode;
  const plaintextAtSignTime = modeExposesPlaintextAtSignTime(mode);
  const externalCustody = authority.externalCustodyProvider ?? "none";
  // In production, local mode only reaches this point when the operator has
  // explicitly acknowledged the weak posture (see assertProductionCustodyAcknowledged).
  // Surface that acknowledgement in the boot log so it is auditable. Never emit
  // key material, KMS key ids, or the master password here.
  const ack =
    mode === "local" && authority.nodeEnvironment === "production"
      ? ` local_custody_acknowledged=${authority.localCustodyAcknowledged}`
      : "";
  return (
    `[steward] vault mode=${mode} external_custody=${externalCustody} ` +
    `plaintext_at_sign_time=${plaintextAtSignTime}${ack} ` +
    `capabilities=${VAULT_SIGNING_CAPABILITIES.join(",")}`
  );
}

export function _clearConfiguredVaultsForTests(): void {
  vaultsByKey.clear();
  secretVaultsByKey.clear();
  keyStoresByKey.clear();
  warnedDevSecretFallback = false;
}
