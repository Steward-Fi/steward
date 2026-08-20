import { resolve } from "node:path";
import {
  createCache,
  downloadFile,
  ensureCacheDirExists,
  unzipArchivePhantom,
} from "@synthetixio/synpress-cache";
import {
  assertWalletExtensionIntegrity,
  METAMASK_ARTIFACT_SHA256,
  METAMASK_VERSION,
  PHANTOM_ARTIFACT_SHA256,
  PHANTOM_CHROME_EXTENSION_ID,
  PHANTOM_EXTENSION_VERSION,
  phantomExtensionPath,
} from "../e2e/wallets/cache-contract";
import {
  assertWalletE2ECredentials,
  withWalletCredentialsRemoved,
} from "../e2e/wallets/credentials";
import { prepareStewardMetaMaskExtension } from "../e2e/wallets/metamask-extension";
import metamaskSetup from "../e2e/wallets/setup/metamask/metamask.setup";
import phantomSetup from "../e2e/wallets/setup/phantom/phantom.setup";
import { writeWalletCacheManifest } from "../e2e/wallets/wallet-cache-provenance";

const PHANTOM_CHROME_UPDATE_URL =
  "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=131.0.0.0&acceptformat=crx2,crx3&x=id%3Dbfnaelmomeimhlpmgjnjophhpkkoljpa%26uc";
// The Chrome update endpoint is mutable. Pin the accepted archive bytes so a
// publisher update requires an explicit, reviewed digest change here.
async function preparePhantomExtension(): Promise<string> {
  const download = await downloadFile({
    fileName: `${PHANTOM_CHROME_EXTENSION_ID}.crx`,
    outputDir: ensureCacheDirExists(),
    url: PHANTOM_CHROME_UPDATE_URL,
  });
  await assertWalletExtensionIntegrity(download.filePath, PHANTOM_ARTIFACT_SHA256);
  const unpacked = await unzipArchivePhantom({ archivePath: download.filePath });
  return unpacked.outputPath;
}

export async function cacheWallet(wallet: "metamask" | "phantom"): Promise<void> {
  if (wallet === "metamask") {
    await createCache(
      resolve("e2e/wallets/setup/metamask"),
      [metamaskSetup.hash],
      prepareStewardMetaMaskExtension,
      true,
    );
    await writeWalletCacheManifest(resolve(".cache-synpress", metamaskSetup.hash), {
      wallet: "metamask",
      cacheId: metamaskSetup.hash,
      extensionVersion: METAMASK_VERSION,
      extensionSha256: METAMASK_ARTIFACT_SHA256,
    });
    return;
  }

  await createCache(
    resolve("e2e/wallets/setup/phantom"),
    [phantomSetup.hash],
    preparePhantomExtension,
    true,
  );
  await writeWalletCacheManifest(resolve(".cache-synpress", phantomSetup.hash), {
    wallet: "phantom",
    cacheId: phantomSetup.hash,
    extensionVersion: PHANTOM_EXTENSION_VERSION,
    extensionSha256: PHANTOM_ARTIFACT_SHA256,
  });
  await writeWalletCacheManifest(phantomExtensionPath(), {
    wallet: "phantom",
    cacheId: PHANTOM_CHROME_EXTENSION_ID,
    extensionVersion: PHANTOM_EXTENSION_VERSION,
    extensionSha256: PHANTOM_ARTIFACT_SHA256,
  });
}

if (import.meta.main) {
  assertWalletE2ECredentials();
  const wallet = process.argv[2];
  if (wallet !== "metamask" && wallet !== "phantom") {
    throw new Error("Usage: bun run scripts/cache-wallet-e2e.ts <metamask|phantom>");
  }
  // Setup modules above have already captured only the values their wallet
  // needs. Synpress Cache does not expose browser launch options, so remove
  // all wallet material from process.env for the lifetime of its Chromium.
  await withWalletCredentialsRemoved(() => cacheWallet(wallet));
}
