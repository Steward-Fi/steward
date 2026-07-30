/**
 * SecretStore — sealed store for NON-key operator secrets (API tokens, bot
 * tokens, webhook signing secrets, etc.).
 *
 * This is a deliberately DIFFERENT abstraction from `KeystoreBackend` (which
 * wraps private *signing* keys and is exercised through the signing path) and
 * from `SecretVault` (the DB-backed, per-tenant credential store fronted by the
 * proxy's secret-route injection). Those exist and stay. This one exists for
 * the sovereign-custody onboarding model:
 *
 *   1. Operator encrypts a secret DIRECTLY to the store's public key on their
 *      own machine (`steward secrets put`). The plaintext never transits an env
 *      var, a shell history, a repo, or a log.
 *   2. Steward decrypts the store at boot INTO MEMORY ONLY and exercises secrets
 *      internally (broker a call, inject a header, sign a webhook).
 *   3. There is NO general read-back API. You can `put` and you can `exercise`.
 *      You cannot ask the store to hand a plaintext secret back to a caller.
 *
 * The no-read-back asymmetry is the security property, not an inconvenience:
 * a compromised control plane cannot exfiltrate the vault by calling a getter,
 * because the getter does not exist. Exercise happens behind a caller-supplied
 * closure so the plaintext's lifetime is bounded to a single use and never
 * crosses the API boundary.
 *
 * The interface is intentionally backend-agnostic so Pillar B (P1) can swap the
 * default age-file backend for a TEE-KMS-sealed backend (dstack KMS releasing
 * the store's identity only to an attested measurement) WITHOUT changing this
 * API or any caller. See SECRET-STORE.md for the migration shape.
 */

/**
 * Metadata about a stored secret. This is the ONLY shape a caller can read
 * back — never the plaintext value. `exercise` is the sole path to the value,
 * and even that hands it to a closure rather than returning it.
 */
export interface SecretStoreEntryMetadata {
  /** Logical path/name, e.g. "discord/soliza-bot-token". */
  path: string;
  /** Monotonic version; bumped by `rotate`. Starts at 1. */
  version: number;
  /** Free-form operator note. Never contains secret material. */
  description?: string;
  createdAt: string; // ISO-8601
  updatedAt: string; // ISO-8601
}

/** Options accepted when writing a new secret. */
export interface SecretStorePutOptions {
  description?: string;
  /**
   * If false (default) and the path already exists, `put` rejects. Use `rotate`
   * to replace an existing secret so the version history is explicit. Set true
   * only for idempotent re-onboarding of the SAME value.
   */
  overwrite?: boolean;
}

/**
 * The sealed backend contract. Implementations MUST NOT expose a plaintext
 * read-back method. The store is write + exercise only.
 *
 * - The DEFAULT implementation (`AgeFileSecretStore`) seals to an age identity
 *   held in a file (or, in production, decrypt-at-boot into memory).
 * - The P1 implementation seals the identity behind a TEE KMS: the identity is
 *   released only to an attested CVM, so even the host operator cannot decrypt.
 *   Both satisfy THIS interface, so no caller changes when the backend swaps.
 */
export interface SecretStoreBackend {
  /** Human-readable id for logs/audit, e.g. "age-file:v1". Not a security input. */
  readonly id: string;

  /**
   * The public recipient an operator encrypts TO. For age this is an
   * `age1...` recipient string. For a TEE-KMS backend this is the enclave's
   * public sealing key. Returned so the CLI can encrypt on the operator machine
   * without ever touching the private identity.
   */
  recipient(): Promise<string>;

  /**
   * Ingest a secret that was ALREADY encrypted to this backend's recipient on
   * the operator machine. The backend never sees the plaintext at ingest time —
   * it stores the ciphertext as-is. This is the zero-plaintext-transit path.
   *
   * @param path       logical name
   * @param ciphertext armored age ciphertext (or backend-native sealed blob)
   * @param options    metadata / overwrite policy
   */
  putSealed(
    path: string,
    ciphertext: string,
    options?: SecretStorePutOptions,
  ): Promise<SecretStoreEntryMetadata>;

  /**
   * Metadata for one path, or null if absent. NEVER returns the value.
   */
  stat(path: string): Promise<SecretStoreEntryMetadata | null>;

  /** Metadata for all live secrets. NEVER returns values. */
  list(): Promise<SecretStoreEntryMetadata[]>;

  /**
   * Replace an existing secret with new sealed ciphertext, bumping the version.
   * Rejects if the path does not already exist (use `putSealed` to create).
   */
  rotateSealed(path: string, ciphertext: string): Promise<SecretStoreEntryMetadata>;

  /** Permanently remove a secret. Returns true if something was removed. */
  delete(path: string): Promise<boolean>;

  /**
   * Decrypt ONE secret and hand the plaintext to `use`. The plaintext is
   * returned by NO public method; it exists only for the duration of the `use`
   * callback. Backends should avoid retaining a reference after `use` resolves.
   *
   * This is the ONLY way to reach a plaintext value, and it never crosses the
   * store's API boundary — the caller receives whatever `use` returns, which is
   * expected to be a RESULT (e.g. an HTTP response), not the secret itself.
   */
  exercise<T>(path: string, use: (plaintext: string) => T | Promise<T>): Promise<T>;
}

/** Thrown when a requested secret path does not exist. */
export class SecretNotFoundError extends Error {
  constructor(path: string) {
    super(`secret not found: ${path}`);
    this.name = "SecretNotFoundError";
  }
}

/** Thrown when `putSealed` would clobber an existing path without overwrite. */
export class SecretAlreadyExistsError extends Error {
  constructor(path: string) {
    super(`secret already exists: ${path} (use rotate, or put --overwrite for the same value)`);
    this.name = "SecretAlreadyExistsError";
  }
}

/**
 * Validate a logical secret path. Keeps paths filesystem-safe and prevents
 * traversal / injection into the on-disk layout. Shared by every backend so the
 * naming rules do not drift.
 */
export function assertValidSecretPath(path: string): void {
  if (!path || typeof path !== "string") {
    throw new Error("secret path must be a non-empty string");
  }
  if (path.length > 255) {
    throw new Error("secret path must be at most 255 characters");
  }
  // Allow slash-separated segments of [a-z0-9._-], each 1..64 chars, no dot
  // segments, no leading/trailing slash. This mirrors the tenant-secret naming
  // discipline and keeps paths safe to use as file names after encoding.
  const segments = path.split("/");
  for (const segment of segments) {
    if (!segment || segment === "." || segment === "..") {
      throw new Error(`secret path has an invalid segment: ${JSON.stringify(path)}`);
    }
    if (segment.length > 64) {
      throw new Error(`secret path segment too long (max 64): ${segment}`);
    }
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(segment)) {
      throw new Error(
        `secret path segment must match [a-z0-9][a-z0-9._-]* (lowercase): ${segment}`,
      );
    }
  }
}
