import { readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { assertWalletE2ECredentials } from "../e2e/wallets/credentials";
import metamaskSetup from "../e2e/wallets/setup/metamask/metamask.setup";
import phantomSetup from "../e2e/wallets/setup/phantom/phantom.setup";

export const walletCacheRequirements = (cwd = process.cwd()) => [
  {
    name: "MetaMask",
    path: resolve(cwd, ".cache-synpress", metamaskSetup.hash),
  },
  {
    name: "Phantom",
    path: resolve(cwd, ".cache-synpress", phantomSetup.hash),
  },
];

export async function assertWalletCaches(cwd = process.cwd()): Promise<void> {
  const missing: string[] = [];
  for (const requirement of walletCacheRequirements(cwd)) {
    try {
      if ((await readdir(requirement.path)).length === 0) {
        missing.push(requirement.name);
      }
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
  assertWalletE2ECredentials();
  await assertWalletCaches();
  const child = Bun.spawn(
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
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  process.exitCode = await child.exited;
}
