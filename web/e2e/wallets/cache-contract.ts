import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const PHANTOM_CHROME_EXTENSION_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa";
export const METAMASK_VERSION = "12.20.1";
export const METAMASK_ARTIFACT_SHA256 =
  "498247c0fe6040652ec4b51ca43461cb6b2a99d389e17216ee48d1670ddc1101";
export const PHANTOM_EXTENSION_VERSION = "26.26.0";
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
    throw new Error(
      `Wallet extension artifact failed SHA-256 integrity verification: ${artifactPath}`,
    );
  }
}

export function phantomExtensionPath(cwd = process.cwd()): string {
  return resolve(cwd, ".cache-synpress", PHANTOM_CHROME_EXTENSION_ID);
}
