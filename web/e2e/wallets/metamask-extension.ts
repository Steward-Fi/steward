import { downloadFile, ensureCacheDirExists, unzipArchive } from "@synthetixio/synpress-cache";
import {
  assertWalletExtensionIntegrity,
  METAMASK_ARTIFACT_SHA256,
  METAMASK_VERSION,
} from "./cache-contract";

// MetaMask 12 retains the stable notification-page flow supported by the
// pinned Synpress driver. Newer multichain onboarding builds replace the
// popup during eth_requestAccounts under Playwright Chromium.
export async function prepareStewardMetaMaskExtension(): Promise<string> {
  const fileName = `metamask-chrome-${METAMASK_VERSION}.zip`;
  const download = await downloadFile({
    fileName,
    outputDir: ensureCacheDirExists(),
    url: `https://github.com/MetaMask/metamask-extension/releases/download/v${METAMASK_VERSION}/${fileName}`,
  });
  await assertWalletExtensionIntegrity(download.filePath, METAMASK_ARTIFACT_SHA256);
  const unpacked = await unzipArchive({ archivePath: download.filePath });
  return unpacked.outputPath;
}
