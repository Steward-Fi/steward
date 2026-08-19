import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { downloadFile, ensureCacheDirExists, unzipArchive } from "@synthetixio/synpress-cache";

// MetaMask 12 retains the stable notification-page flow supported by the
// pinned Synpress driver. Newer multichain onboarding builds replace the
// popup during eth_requestAccounts under Playwright Chromium.
export const METAMASK_VERSION = "12.20.1";
export const METAMASK_EXTENSION_SHA256 =
  "498247c0fe6040652ec4b51ca43461cb6b2a99d389e17216ee48d1670ddc1101";

export async function assertExtensionDigest(
  filePath: string,
  expectedSha256: string,
): Promise<void> {
  const actualSha256 = createHash("sha256")
    .update(await readFile(filePath))
    .digest("hex");
  if (actualSha256 !== expectedSha256) {
    throw new Error(`Downloaded wallet extension failed SHA-256 verification: ${filePath}`);
  }
}

export async function prepareStewardMetaMaskExtension(): Promise<string> {
  const fileName = `metamask-chrome-${METAMASK_VERSION}.zip`;
  const download = await downloadFile({
    fileName,
    outputDir: ensureCacheDirExists(),
    url: `https://github.com/MetaMask/metamask-extension/releases/download/v${METAMASK_VERSION}/${fileName}`,
  });
  await assertExtensionDigest(download.filePath, METAMASK_EXTENSION_SHA256);
  const unpacked = await unzipArchive({ archivePath: download.filePath });
  return unpacked.outputPath;
}
