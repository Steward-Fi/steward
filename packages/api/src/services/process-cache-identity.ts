import { hkdfSync, randomBytes } from "node:crypto";

const processCacheIdentitySalt = randomBytes(32);
const processCacheIdentityInfo = Buffer.from("steward:process-cache-identity:v1");

/** Opaque, process-local cache identity; never persisted or used for authentication. */
export function processCacheIdentity(parts: readonly string[]): string {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    const bytes = Buffer.from(part);
    chunks.push(Buffer.from(`${bytes.length}:`), bytes, Buffer.from(";"));
  }
  return Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.concat(chunks),
      processCacheIdentitySalt,
      processCacheIdentityInfo,
      32,
    ),
  ).toString("hex");
}
