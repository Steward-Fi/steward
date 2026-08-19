import { createHmac, randomBytes } from "node:crypto";

const processFingerprintKey = randomBytes(32);

/** Build an in-process cache identity without retaining a reusable hash of secret configuration. */
export function configurationFingerprint(configuration: unknown): string {
  return createHmac("sha256", processFingerprintKey)
    .update(JSON.stringify(configuration))
    .digest("hex");
}
