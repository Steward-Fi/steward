import { resolve } from "node:path";
import {
  createCache,
  downloadFile,
  ensureCacheDirExists,
  unzipArchivePhantom,
} from "@synthetixio/synpress-cache";
import { PHANTOM_CHROME_EXTENSION_ID } from "../e2e/wallets/cache-contract";
import { assertWalletE2ECredentials } from "../e2e/wallets/credentials";
import {
  assertExtensionDigest,
  prepareStewardMetaMaskExtension,
} from "../e2e/wallets/metamask-extension";
import metamaskSetup from "../e2e/wallets/setup/metamask/metamask.setup";
import phantomSetup from "../e2e/wallets/setup/phantom/phantom.setup";

const PHANTOM_CHROME_UPDATE_URL =
  "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=131.0.0.0&acceptformat=crx2,crx3&x=id%3Dbfnaelmomeimhlpmgjnjophhpkkoljpa%26uc";
// The Chrome update endpoint is mutable. Pin the accepted archive bytes so a
// publisher update requires an explicit, reviewed digest change here.
export const PHANTOM_EXTENSION_VERSION = "26.26.0";
export const PHANTOM_EXTENSION_SHA256 =
  "24226235e21defc34868487f9e205bb63dcdf4dc0d277a9afac48f98c2bae265";

async function preparePhantomExtension(): Promise<string> {
  const download = await downloadFile({
    fileName: `${PHANTOM_CHROME_EXTENSION_ID}.crx`,
    outputDir: ensureCacheDirExists(),
    url: PHANTOM_CHROME_UPDATE_URL,
  });
  await assertExtensionDigest(download.filePath, PHANTOM_EXTENSION_SHA256);
  const unpacked = await unzipArchivePhantom({ archivePath: download.filePath });
  return unpacked.outputPath;
}

export async function cacheWallet(wallet: "metamask" | "phantom", force = false): Promise<void> {
  if (wallet === "metamask") {
    await createCache(
      resolve("e2e/wallets/setup/metamask"),
      [metamaskSetup.hash],
      prepareStewardMetaMaskExtension,
      force,
    );
    return;
  }

  await createCache(
    resolve("e2e/wallets/setup/phantom"),
    [phantomSetup.hash],
    preparePhantomExtension,
    force,
  );
}

if (import.meta.main) {
  assertWalletE2ECredentials();
  const wallet = process.argv[2];
  if (wallet !== "metamask" && wallet !== "phantom") {
    throw new Error("Usage: bun run scripts/cache-wallet-e2e.ts <metamask|phantom> [--force]");
  }
  await cacheWallet(wallet, process.argv.includes("--force"));
}
