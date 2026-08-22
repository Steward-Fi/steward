import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

const PREFIX = "stwd_whsec_v1:";
const DEFAULT_KDF_SALT = "steward-webhook-secret-v1";

type EncryptedWebhookSecret = {
  ciphertext: string;
  iv: string;
  tag: string;
  salt: string;
};

let warnedDevSecret = false;
const rootKeysByAuthority = new Map<string, Buffer>();
const MAX_CACHED_WEBHOOK_AUTHORITIES = 8;

export interface WebhookSecretAuthority {
  readonly fingerprint: string;
  readonly nodeEnvironment?: string;
  readonly encryptionKey: string;
  readonly kdfSalt: string;
  readonly kdfSaltIsHex: boolean;
}

function runtimeValue(name: string): string | undefined {
  const value = runtimeEnvironmentValue(name);
  return value ? value : undefined;
}

/** Resolve one immutable webhook encryption root from the current runtime. */
export function resolveWebhookSecretAuthority(): WebhookSecretAuthority {
  const configuredNodeEnvironment = runtimeValue("NODE_ENV")?.trim();
  const nodeEnvironment =
    configuredNodeEnvironment ||
    (runtimeValue("STEWARD_RUNTIME") === "workers" ? "production" : undefined);
  let encryptionKey =
    runtimeValue("STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY") ??
    runtimeValue("STEWARD_MASTER_PASSWORD");
  let kdfSalt = runtimeValue("STEWARD_WEBHOOK_SECRET_KDF_SALT") ?? runtimeValue("STEWARD_KDF_SALT");
  let kdfSaltIsHex = kdfSalt !== undefined;
  if (!encryptionKey) {
    if (nodeEnvironment === "production") {
      throw new Error(
        "STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY or STEWARD_MASTER_PASSWORD is required to encrypt webhook secrets",
      );
    }
    if (nodeEnvironment !== "development" && nodeEnvironment !== "test") {
      throw new Error(
        `Refusing the insecure webhook dev key: NODE_ENV is not an explicit development value (${
          nodeEnvironment === undefined ? "unset" : JSON.stringify(nodeEnvironment)
        }). Set NODE_ENV=development for local development, or configure STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY / STEWARD_MASTER_PASSWORD.`,
      );
    }
    if (
      runtimeValue("STEWARD_ALLOW_DEV_SECRETS") !== "true" &&
      runtimeValue("STEWARD_ALLOW_DEV_SECRET") !== "true"
    ) {
      throw new Error(
        "No webhook secret encryption key set. Set STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY / STEWARD_MASTER_PASSWORD, or set STEWARD_ALLOW_DEV_SECRETS=true to use the insecure dev key (local development only).",
      );
    }
    if (!warnedDevSecret) {
      warnedDevSecret = true;
      console.warn(
        "[steward] WARNING: using the insecure hardcoded dev key to encrypt webhook secrets (STEWARD_ALLOW_DEV_SECRET=true). Secrets are trivially decryptable. Never use this outside local development.",
      );
    }
    encryptionKey = "dev-secret";
    kdfSalt = DEFAULT_KDF_SALT;
    kdfSaltIsHex = false;
  } else if (!kdfSalt && nodeEnvironment === "production") {
    throw new Error(
      "STEWARD_WEBHOOK_SECRET_KDF_SALT or STEWARD_KDF_SALT is required in production",
    );
  }
  if (!kdfSalt) {
    kdfSalt = DEFAULT_KDF_SALT;
    kdfSaltIsHex = false;
  }
  const salt = Buffer.from(kdfSalt, kdfSaltIsHex ? "hex" : "utf8");
  if (kdfSaltIsHex && salt.length < 16) {
    throw new Error("Webhook secret KDF salt must decode to at least 16 bytes");
  }
  const fingerprint = createHash("sha256")
    .update(JSON.stringify({ nodeEnvironment, encryptionKey, kdfSalt, kdfSaltIsHex }))
    .digest("hex");
  return Object.freeze({
    fingerprint,
    nodeEnvironment,
    encryptionKey,
    kdfSalt,
    kdfSaltIsHex,
  });
}

function rootKey(): Buffer {
  const authority = resolveWebhookSecretAuthority();
  let key = rootKeysByAuthority.get(authority.fingerprint);
  if (key) return key;
  const salt = Buffer.from(authority.kdfSalt, authority.kdfSaltIsHex ? "hex" : "utf8");
  key = scryptSync(authority.encryptionKey, salt, 32) as Buffer;
  if (rootKeysByAuthority.size >= MAX_CACHED_WEBHOOK_AUTHORITIES) {
    const oldest = rootKeysByAuthority.keys().next().value as string | undefined;
    if (oldest) {
      rootKeysByAuthority.get(oldest)?.fill(0);
      rootKeysByAuthority.delete(oldest);
    }
  }
  rootKeysByAuthority.set(authority.fingerprint, key);
  return key;
}

function deriveRecordKey(recordSalt: Buffer): Buffer {
  return scryptSync(rootKey(), recordSalt, 32) as Buffer;
}

export function isEncryptedWebhookSecret(value: string): boolean {
  return value.startsWith(PREFIX);
}

export function encryptWebhookSecret(secret: string): string {
  if (isEncryptedWebhookSecret(secret)) return secret;
  const iv = randomBytes(16);
  const salt = randomBytes(16);
  const cipher = createCipheriv("aes-256-gcm", deriveRecordKey(salt), iv);
  let ciphertext = cipher.update(secret, "utf8", "hex");
  ciphertext += cipher.final("hex");
  const payload: EncryptedWebhookSecret = {
    ciphertext,
    iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    salt: salt.toString("hex"),
  };
  return `${PREFIX}${JSON.stringify(payload)}`;
}

export function decryptWebhookSecret(secret: string): string {
  if (!isEncryptedWebhookSecret(secret)) return secret;
  const encoded = secret.slice(PREFIX.length);
  const payload = JSON.parse(encoded) as EncryptedWebhookSecret;
  const iv = Buffer.from(payload.iv, "hex");
  const salt = Buffer.from(payload.salt, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const decipher = createDecipheriv("aes-256-gcm", deriveRecordKey(salt), iv);
  decipher.setAuthTag(tag);
  let plaintext = decipher.update(payload.ciphertext, "hex", "utf8");
  plaintext += decipher.final("utf8");
  return plaintext;
}
