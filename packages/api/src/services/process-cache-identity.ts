import { createHmac, randomBytes } from "node:crypto";

const processCacheIdentityKey = randomBytes(32);

/**
 * Opaque, process-local cache identity. This is not authentication or password
 * verification: the random key is never persisted, so the digest cannot be
 * reused as an offline verifier after process exit.
 */
export function processCacheIdentity(parts: readonly string[]): string {
  const hmac = createHmac("sha256", processCacheIdentityKey);
  for (const part of parts) {
    const bytes = Buffer.from(part);
    hmac.update(String(bytes.length));
    hmac.update(":");
    // codeql[js/insufficient-password-hash] This keyed, ephemeral digest is only
    // a cache discriminator; cryptographic keys still use their owning KDF.
    hmac.update(bytes);
    hmac.update(";");
  }
  return hmac.digest("hex");
}
