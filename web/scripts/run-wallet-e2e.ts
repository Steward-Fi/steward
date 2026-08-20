import { rm } from "node:fs/promises";
import { resolve } from "node:path";
import {
  METAMASK_ARTIFACT_SHA256,
  METAMASK_VERSION,
  PHANTOM_ARTIFACT_SHA256,
  PHANTOM_CHROME_EXTENSION_ID,
  PHANTOM_EXTENSION_VERSION,
  phantomExtensionPath,
} from "../e2e/wallets/cache-contract";
import { assertWalletE2EPasswords } from "../e2e/wallets/credentials";
import { runProcessGroup } from "../e2e/wallets/process-group";
import metamaskSetup from "../e2e/wallets/setup/metamask/metamask.setup";
import phantomSetup from "../e2e/wallets/setup/phantom/phantom.setup";
import { assertWalletCacheIdentity } from "../e2e/wallets/wallet-cache-provenance";

export const walletCacheRequirements = (cwd = process.cwd()) => [
  {
    name: "MetaMask",
    path: resolve(cwd, ".cache-synpress", metamaskSetup.hash),
    identity: {
      wallet: "metamask" as const,
      cacheId: metamaskSetup.hash,
      extensionVersion: METAMASK_VERSION,
      extensionSha256: METAMASK_ARTIFACT_SHA256,
    },
  },
  {
    name: "Phantom",
    path: resolve(cwd, ".cache-synpress", phantomSetup.hash),
    identity: {
      wallet: "phantom" as const,
      cacheId: phantomSetup.hash,
      extensionVersion: PHANTOM_EXTENSION_VERSION,
      extensionSha256: PHANTOM_ARTIFACT_SHA256,
    },
  },
  {
    name: "Phantom extension",
    path: phantomExtensionPath(cwd),
    identity: {
      wallet: "phantom" as const,
      cacheId: PHANTOM_CHROME_EXTENSION_ID,
      extensionVersion: PHANTOM_EXTENSION_VERSION,
      extensionSha256: PHANTOM_ARTIFACT_SHA256,
    },
  },
];

export async function assertWalletCaches(cwd = process.cwd()): Promise<void> {
  const missing: string[] = [];
  for (const requirement of walletCacheRequirements(cwd)) {
    try {
      await assertWalletCacheIdentity(requirement.path, requirement.identity);
    } catch {
      missing.push(requirement.name);
    }
  }

  if (missing.length > 0) {
    throw new Error(
      `Missing Synpress cache for ${missing.join(", ")}. Run \`bun run e2e:wallets:cache\` from web/ first.`,
    );
  }
}

if (import.meta.main) {
  assertWalletE2EPasswords();
  await assertWalletCaches();
  const profileRoot = resolve(process.cwd(), ".wallet-e2e-profiles");
  try {
    process.exitCode = await runProcessGroup(
      [
        "bunx",
        "playwright",
        "test",
        "--config=playwright.wallets.config.ts",
        "--headed",
        ...process.argv.slice(2),
      ],
      {
        cwd: process.cwd(),
        env: { ...process.env, STEWARD_WALLET_PROFILE_ROOT: profileRoot },
        stdin: "inherit",
        stdout: "inherit",
        stderr: "inherit",
      },
    );
  } finally {
    await rm(profileRoot, { force: true, recursive: true });
  }
}
