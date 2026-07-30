/**
 * AgeFileSecretStore — the default OSS backend for {@link SecretStoreBackend}.
 *
 * Secrets are sealed with the age file-encryption format (https://age-encryption.org)
 * via the pure-TypeScript `age-encryption` library, which depends only on the
 * noble crypto primitives already used across `@stwd/vault`. No native binary,
 * no cloud dependency, no vendor lock-in — an operator can decrypt any entry
 * with the standard `age` CLI given the identity, and can encrypt to the store
 * with the standard `age` CLI given the recipient. This is the `--no-cloud`
 * path the sovereign-custody plan mandates.
 *
 * ON-DISK LAYOUT (all under `storeDir`):
 *   recipient.txt          the age1... public recipient (safe to publish)
 *   secrets/<enc>.age      armored age ciphertext, one file per secret
 *   secrets/<enc>.json     metadata sidecar (path, version, timestamps, note)
 * where <enc> is the URL-safe-base64 of the logical path, so arbitrary
 * slash-separated paths map to flat, collision-free file names.
 *
 * The PRIVATE identity (`AGE-SECRET-KEY-1...`) is NEVER written by this class.
 * The operator provisions it out of band and provides it to the running process
 * at boot (env/file/secret-manager) via {@link AgeIdentitySource}. For the
 * production sovereign path the identity is decrypt-at-boot into memory only; on
 * a TEE host (Pillar B) it is released by the KMS to an attested measurement,
 * at which point this whole class is swapped for the TEE backend behind the same
 * interface — callers do not change.
 *
 * NO READ-BACK: this class implements `putSealed` + `exercise` (+ metadata) and
 * deliberately exposes no method that returns a plaintext value. `exercise`
 * decrypts into a local variable, passes it to the caller's closure, and drops
 * the reference when the closure resolves.
 */

import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import * as age from "age-encryption";
import {
  assertValidSecretPath,
  SecretAlreadyExistsError,
  SecretNotFoundError,
  type SecretStoreBackend,
  type SecretStoreEntryMetadata,
  type SecretStorePutOptions,
} from "./secret-store";

/**
 * How the running process obtains the PRIVATE age identity at boot. The store
 * only needs it to `exercise` (decrypt) — `putSealed`/`list`/`stat`/`rotate`
 * work with the public recipient alone, so an onboarding-only deployment can
 * run without ever loading the identity.
 */
export type AgeIdentitySource =
  | { kind: "identity"; identity: string }
  | { kind: "env"; var: string }
  | { kind: "file"; path: string }
  | { kind: "none" };

export interface AgeFileSecretStoreConfig {
  /** Directory that holds recipient.txt + secrets/. Created if absent. */
  storeDir: string;
  /**
   * Where to get the private identity for `exercise`. Default: read env var
   * STEWARD_SECRET_STORE_IDENTITY if set, else "none" (put/list/rotate only).
   */
  identitySource?: AgeIdentitySource;
  /**
   * Explicit recipient override. If omitted, read from `<storeDir>/recipient.txt`.
   * Provided so a KMS-fronted deployment can inject the recipient without a file.
   */
  recipient?: string;
}

interface StoredMetadata {
  path: string;
  version: number;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

function encodePath(path: string): string {
  // Hex-encode the logical path to a flat, collision-free, filesystem-safe name.
  // (base64url would be shorter but the repo's Buffer typings only permit
  // utf8/hex; hex is deterministic and equally safe here.)
  return Buffer.from(path, "utf8").toString("hex");
}

export class AgeFileSecretStore implements SecretStoreBackend {
  readonly id = "age-file:v1";

  private readonly storeDir: string;
  private readonly secretsDir: string;
  private readonly recipientPath: string;
  private readonly identitySource: AgeIdentitySource;
  private cachedRecipient?: string;

  constructor(config: AgeFileSecretStoreConfig) {
    this.storeDir = config.storeDir;
    this.secretsDir = join(config.storeDir, "secrets");
    this.recipientPath = join(config.storeDir, "recipient.txt");
    this.cachedRecipient = config.recipient;
    this.identitySource =
      config.identitySource ??
      (process.env.STEWARD_SECRET_STORE_IDENTITY
        ? { kind: "env", var: "STEWARD_SECRET_STORE_IDENTITY" }
        : { kind: "none" });
  }

  /**
   * Initialize a brand-new store: generate an age identity/recipient pair,
   * write ONLY the recipient to disk, and return the private identity to the
   * caller EXACTLY ONCE. The store never persists the identity — the operator
   * is responsible for sealing it (e.g. to a TEE KMS, a hardware token, or an
   * offline backup). This is called by `steward secrets init`, not at boot.
   */
  static async initStore(storeDir: string): Promise<{ recipient: string; identity: string }> {
    await mkdir(join(storeDir, "secrets"), { recursive: true });
    const recipientPath = join(storeDir, "recipient.txt");
    if (existsSync(recipientPath)) {
      throw new Error(
        `secret store already initialized at ${storeDir} (recipient.txt exists); refusing to overwrite`,
      );
    }
    const identity = await age.generateIdentity();
    const recipient = await age.identityToRecipient(identity);
    await writeFile(recipientPath, `${recipient}\n`, { mode: 0o644 });
    return { recipient, identity };
  }

  async recipient(): Promise<string> {
    if (this.cachedRecipient) return this.cachedRecipient;
    if (!existsSync(this.recipientPath)) {
      throw new Error(
        `no recipient configured: ${this.recipientPath} missing. Run "steward secrets init" first.`,
      );
    }
    const raw = (await readFile(this.recipientPath, "utf8")).trim();
    if (!raw.startsWith("age1")) {
      throw new Error(
        `recipient.txt does not contain a valid age recipient: ${this.recipientPath}`,
      );
    }
    this.cachedRecipient = raw;
    return raw;
  }

  async putSealed(
    path: string,
    ciphertext: string,
    options?: SecretStorePutOptions,
  ): Promise<SecretStoreEntryMetadata> {
    assertValidSecretPath(path);
    this.assertArmoredAge(ciphertext);
    await mkdir(this.secretsDir, { recursive: true });
    const existing = await this.readMetadata(path);
    if (existing && !options?.overwrite) {
      throw new SecretAlreadyExistsError(path);
    }
    const now = new Date().toISOString();
    const meta: StoredMetadata = existing
      ? { ...existing, description: options?.description ?? existing.description, updatedAt: now }
      : {
          path,
          version: 1,
          description: options?.description,
          createdAt: now,
          updatedAt: now,
        };
    await this.writeEntry(path, ciphertext, meta);
    return this.toPublic(meta);
  }

  async stat(path: string): Promise<SecretStoreEntryMetadata | null> {
    assertValidSecretPath(path);
    const meta = await this.readMetadata(path);
    return meta ? this.toPublic(meta) : null;
  }

  async list(): Promise<SecretStoreEntryMetadata[]> {
    if (!existsSync(this.secretsDir)) return [];
    const files = await readdir(this.secretsDir);
    const out: SecretStoreEntryMetadata[] = [];
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      const raw = await readFile(join(this.secretsDir, file), "utf8");
      const meta = JSON.parse(raw) as StoredMetadata;
      out.push(this.toPublic(meta));
    }
    out.sort((a, b) => a.path.localeCompare(b.path));
    return out;
  }

  async rotateSealed(path: string, ciphertext: string): Promise<SecretStoreEntryMetadata> {
    assertValidSecretPath(path);
    this.assertArmoredAge(ciphertext);
    const existing = await this.readMetadata(path);
    if (!existing) throw new SecretNotFoundError(path);
    const now = new Date().toISOString();
    const meta: StoredMetadata = {
      ...existing,
      version: existing.version + 1,
      updatedAt: now,
    };
    await this.writeEntry(path, ciphertext, meta);
    return this.toPublic(meta);
  }

  async delete(path: string): Promise<boolean> {
    assertValidSecretPath(path);
    const enc = encodePath(path);
    const cipherPath = join(this.secretsDir, `${enc}.age`);
    const metaPath = join(this.secretsDir, `${enc}.json`);
    if (!existsSync(metaPath)) return false;
    await rm(cipherPath, { force: true });
    await rm(metaPath, { force: true });
    return true;
  }

  async exercise<T>(path: string, use: (plaintext: string) => T | Promise<T>): Promise<T> {
    assertValidSecretPath(path);
    const enc = encodePath(path);
    const cipherPath = join(this.secretsDir, `${enc}.age`);
    if (!existsSync(cipherPath)) throw new SecretNotFoundError(path);
    const armored = await readFile(cipherPath, "utf8");
    const identity = await this.loadIdentity();
    const decrypter = new age.Decrypter();
    decrypter.addIdentity(identity);
    // Decrypt into a locally-scoped variable only; it is handed to the caller's
    // closure and never returned or stored by this method.
    let plaintext = await decrypter.decrypt(age.armor.decode(armored), "text");
    try {
      return await use(plaintext);
    } finally {
      // Best-effort drop of the reference. JS strings are immutable so we cannot
      // truly zero the buffer, but we avoid keeping a live reference around.
      plaintext = "";
      void plaintext;
    }
  }

  // ─── internals ──────────────────────────────────────────────────────────────

  private async loadIdentity(): Promise<string> {
    const src = this.identitySource;
    let identity: string | undefined;
    switch (src.kind) {
      case "identity":
        identity = src.identity;
        break;
      case "env":
        identity = process.env[src.var];
        if (!identity) {
          throw new Error(
            `secret store identity env var ${src.var} is not set; cannot exercise secrets`,
          );
        }
        break;
      case "file":
        if (!existsSync(src.path)) {
          throw new Error(`secret store identity file not found: ${src.path}`);
        }
        identity = (await readFile(src.path, "utf8")).trim();
        break;
      default:
        throw new Error(
          "secret store has no identity source configured; it can accept and list secrets but cannot exercise them",
        );
    }
    if (!identity.startsWith("AGE-SECRET-KEY-1")) {
      throw new Error("configured secret store identity is not a valid age identity");
    }
    return identity;
  }

  private assertArmoredAge(ciphertext: string): void {
    if (!ciphertext.includes("-----BEGIN AGE ENCRYPTED FILE-----")) {
      throw new Error(
        "ciphertext must be an ASCII-armored age file (encrypt with the store recipient before putting)",
      );
    }
  }

  private async readMetadata(path: string): Promise<StoredMetadata | null> {
    const metaPath = join(this.secretsDir, `${encodePath(path)}.json`);
    if (!existsSync(metaPath)) return null;
    return JSON.parse(await readFile(metaPath, "utf8")) as StoredMetadata;
  }

  private async writeEntry(path: string, ciphertext: string, meta: StoredMetadata): Promise<void> {
    const enc = encodePath(path);
    await writeFile(join(this.secretsDir, `${enc}.age`), ciphertext, { mode: 0o600 });
    await writeFile(join(this.secretsDir, `${enc}.json`), `${JSON.stringify(meta, null, 2)}\n`, {
      mode: 0o600,
    });
  }

  private toPublic(meta: StoredMetadata): SecretStoreEntryMetadata {
    return {
      path: meta.path,
      version: meta.version,
      description: meta.description,
      createdAt: meta.createdAt,
      updatedAt: meta.updatedAt,
    };
  }
}

/**
 * Encrypt a plaintext to a recipient, producing armored age ciphertext. Used by
 * the onboarding CLI on the OPERATOR machine so the store never sees plaintext.
 * Exported from the vault so both the CLI and tests share one code path.
 */
export async function sealToRecipient(recipient: string, plaintext: string): Promise<string> {
  if (!recipient.startsWith("age1")) {
    throw new Error("recipient must be an age1... recipient string");
  }
  const encrypter = new age.Encrypter();
  encrypter.addRecipient(recipient);
  const ciphertext = await encrypter.encrypt(plaintext);
  return age.armor.encode(ciphertext);
}
