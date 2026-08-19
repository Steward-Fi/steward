import { createHmac, randomBytes } from "node:crypto";

const processCacheIdentityKey = randomBytes(32);

/** Opaque, process-local cache identity; never persisted or used for authentication. */
export function processCacheIdentity(parts: readonly string[]): string {
  const hmac = createHmac("sha256", processCacheIdentityKey);
  for (const part of parts) {
    const bytes = Buffer.from(part);
    hmac.update(String(bytes.length)); // lgtm[js/insufficient-password-hash]
    hmac.update(":");
    // codeql[js/insufficient-password-hash] Ephemeral keyed cache discriminator;
    // cryptographic keys still use their owning KDF.
    hmac.update(bytes); // lgtm[js/insufficient-password-hash]
    hmac.update(";");
  }
  return hmac.digest("hex");
}
