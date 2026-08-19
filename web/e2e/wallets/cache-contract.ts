import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const PHANTOM_CHROME_EXTENSION_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa";
export const PHANTOM_ARTIFACT_SHA256 =
  "24226235e21defc34868487f9e205bb63dcdf4dc0d277a9afac48f98c2bae265";

export async function assertWalletExtensionIntegrity(
  artifactPath: string,
  expectedSha256: string,
): Promise<void> {
  const digest = createHash("sha256")
    .update(await readFile(artifactPath))
    .digest("hex");
  if (digest !== expectedSha256) {
    throw new Error("Wallet extension artifact failed SHA-256 integrity verification");
  }
}

export function phantomExtensionPath(cwd = process.cwd()): string {
  return resolve(cwd, ".cache-synpress", PHANTOM_CHROME_EXTENSION_ID);
}
