import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertWalletCaches, walletCacheRequirements } from "../../scripts/run-wallet-e2e";
import { readWalletE2ECredentials } from "./credentials";
import { METAMASK_CACHE_ID } from "./setup/metamask/metamask.setup";
import { PHANTOM_CACHE_ID } from "./setup/phantom/phantom.setup";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("wallet extension E2E contract", () => {
  test("fails closed with variable names but no credential values", () => {
    expect(() => readWalletE2ECredentials({})).toThrow(
      "Wallet E2E credentials are not provisioned. Missing: E2E_METAMASK_SEED_PHRASE, E2E_METAMASK_PASSWORD, E2E_PHANTOM_SEED_PHRASE, E2E_PHANTOM_PASSWORD",
    );

    const secret = "credential-value-that-must-not-be-logged";
    expect(() =>
      readWalletE2ECredentials({
        E2E_METAMASK_SEED_PHRASE: secret,
        E2E_METAMASK_PASSWORD: secret,
        E2E_PHANTOM_SEED_PHRASE: secret,
        E2E_PHANTOM_PASSWORD: secret,
      }),
    ).toThrow("E2E_METAMASK_SEED_PHRASE must contain a complete BIP-39 word count");
    try {
      readWalletE2ECredentials({
        E2E_METAMASK_SEED_PHRASE: secret,
        E2E_METAMASK_PASSWORD: secret,
        E2E_PHANTOM_SEED_PHRASE: secret,
        E2E_PHANTOM_PASSWORD: secret,
      });
    } catch (error) {
      expect(String(error)).not.toContain(secret);
    }
  });

  test("accepts complete dedicated test-wallet credentials", () => {
    const seed = Array.from({ length: 12 }, (_, index) => `word${index}`).join(" ");
    expect(
      readWalletE2ECredentials({
        E2E_METAMASK_SEED_PHRASE: seed,
        E2E_METAMASK_PASSWORD: "metamask-test-password",
        E2E_PHANTOM_SEED_PHRASE: seed,
        E2E_PHANTOM_PASSWORD: "phantom-test-password",
      }),
    ).toEqual({
      metamaskSeedPhrase: seed,
      metamaskPassword: "metamask-test-password",
      phantomSeedPhrase: seed,
      phantomPassword: "phantom-test-password",
    });
  });

  test("requires non-empty caches for the exact MetaMask and Phantom setups", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-e2e-"));
    temporaryDirectories.push(cwd);

    const requirements = walletCacheRequirements(cwd);
    expect(requirements.map(({ name }) => name)).toEqual(["MetaMask", "Phantom"]);
    expect(requirements.map(({ path }) => path.split("/").at(-1))).toEqual([
      METAMASK_CACHE_ID,
      PHANTOM_CACHE_ID,
    ]);
    await expect(assertWalletCaches(cwd)).rejects.toThrow(
      "Missing Synpress cache for MetaMask, Phantom",
    );

    for (const requirement of requirements) {
      await mkdir(requirement.path, { recursive: true });
      await writeFile(join(requirement.path, "cache-ready"), "test cache marker");
    }
    await expect(assertWalletCaches(cwd)).resolves.toBeUndefined();
  });

  test("collects only the two wallet specs and excludes them from the default suite", async () => {
    const walletList = Bun.spawnSync(
      ["bunx", "playwright", "test", "--config=playwright.wallets.config.ts", "--list"],
      { cwd: join(import.meta.dir, "../.."), stderr: "pipe", stdout: "pipe" },
    );
    expect(walletList.exitCode).toBe(0);
    const walletOutput = walletList.stdout.toString();
    expect(walletOutput).toContain("metamask-siwe.spec.ts");
    expect(walletOutput).toContain("phantom-siws.spec.ts");
    expect(walletOutput).toContain("Total: 2 tests in 2 files");

    const defaultList = Bun.spawnSync(["bunx", "playwright", "test", "--list"], {
      cwd: join(import.meta.dir, "../.."),
      stderr: "pipe",
      stdout: "pipe",
    });
    expect(defaultList.exitCode).toBe(0);
    const defaultOutput = defaultList.stdout.toString();
    expect(defaultOutput).not.toContain("metamask-siwe.spec.ts");
    expect(defaultOutput).not.toContain("phantom-siws.spec.ts");
  });
});
