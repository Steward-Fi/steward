import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import walletConfig from "../../playwright.wallets.config";
import { cleanupWalletE2E } from "../../scripts/cleanup-wallet-e2e";
import { assertWalletCaches, walletCacheRequirements } from "../../scripts/run-wallet-e2e";
import { e2eChildProcessEnvironment } from "../global-setup";
import {
  assertWalletExtensionIntegrity,
  METAMASK_CACHE_ID,
  PHANTOM_CACHE_ID,
} from "./cache-contract";
import {
  assertWalletE2EPasswords,
  environmentWithoutWalletCredentials,
  readWalletE2ECredentials,
  WALLET_E2E_CREDENTIAL_NAMES,
  WALLET_E2E_PASSWORD_NAMES,
  withWalletCredentialsRemoved,
} from "./credentials";
import { withWalletBrowserProfile } from "./wallet-browser-profile";
import {
  assertWalletCacheIdentity,
  walletCacheContentSha256,
  writeWalletCacheManifest,
} from "./wallet-cache-provenance";

const temporaryDirectories: string[] = [];

async function waitForFile(path: string): Promise<string> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const value = await readFile(path, "utf8").catch(() => "");
    if (value) return value;
    await Bun.sleep(20);
  }
  throw new Error(`Timed out waiting for ${path}`);
}

async function stopHarness(child: ReturnType<typeof Bun.spawn>): Promise<void> {
  if (child.exitCode === null) {
    child.kill("SIGTERM");
    await Promise.race([child.exited, Bun.sleep(1000)]);
  }
  if (child.exitCode === null) child.kill("SIGKILL");
  await child.exited;
}

async function processExited(pid: number): Promise<boolean> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      process.kill(pid, 0);
      await Bun.sleep(20);
    } catch {
      return true;
    }
  }
  return false;
}

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
    const seed =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
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

  test("real flows require only passwords and reject missing or short values", () => {
    expect(() =>
      assertWalletE2EPasswords({
        E2E_METAMASK_PASSWORD: "metamask-test-password",
        E2E_PHANTOM_PASSWORD: "phantom-test-password",
      }),
    ).not.toThrow();
    expect(() => assertWalletE2EPasswords({})).toThrow(
      "Wallet E2E passwords are not provisioned. Missing: E2E_METAMASK_PASSWORD, E2E_PHANTOM_PASSWORD",
    );
    expect(() =>
      assertWalletE2EPasswords({
        E2E_METAMASK_PASSWORD: "short",
        E2E_PHANTOM_PASSWORD: "phantom-test-password",
      }),
    ).toThrow("E2E_METAMASK_PASSWORD must contain at least 12 characters");
  });

  test("rejects a mnemonic with the right word count but an invalid checksum", () => {
    const invalidSeed = Array.from({ length: 12 }, () => "abandon").join(" ");
    expect(() =>
      readWalletE2ECredentials({
        E2E_METAMASK_SEED_PHRASE: invalidSeed,
        E2E_METAMASK_PASSWORD: "metamask-test-password",
        E2E_PHANTOM_SEED_PHRASE: invalidSeed,
        E2E_PHANTOM_PASSWORD: "phantom-test-password",
      }),
    ).toThrow("E2E_METAMASK_SEED_PHRASE must contain a valid BIP-39 mnemonic");
  });

  test("keeps wallet credentials out of every harness child process", () => {
    const secretEnvironment = Object.fromEntries(
      WALLET_E2E_CREDENTIAL_NAMES.map((name) => [name, `${name}-secret`]),
    );
    const serviceEnvironment = environmentWithoutWalletCredentials({
      ...secretEnvironment,
      PATH: "/test/bin",
      E2E_WEB_URL: "http://localhost:3499",
    });
    const childEnvironment = e2eChildProcessEnvironment(serviceEnvironment, {
      NODE_ENV: "test",
    });

    expect(Object.isFrozen(serviceEnvironment)).toBe(true);
    expect(childEnvironment.PATH).toBe("/test/bin");
    expect(childEnvironment.E2E_WEB_URL).toBe("http://localhost:3499");
    expect(childEnvironment.NODE_ENV).toBe("test");
    for (const name of WALLET_E2E_CREDENTIAL_NAMES) {
      expect(childEnvironment[name]).toBeUndefined();
    }
  });

  test("passes a credential-free environment to wallet browser children", async () => {
    const secretEnvironment = Object.fromEntries(
      WALLET_E2E_CREDENTIAL_NAMES.map((name) => [name, `${name}-browser-secret`]),
    );
    let profilePath = "";
    let browserEnvironment: Readonly<NodeJS.ProcessEnv> | undefined;

    await expect(
      withWalletBrowserProfile({
        prefix: "steward-wallet-browser-env-",
        environment: { ...secretEnvironment, PATH: "/test/bin" },
        launch: async (profile, environment) => {
          profilePath = profile;
          browserEnvironment = environment;
          throw new Error("injected browser launch failure");
        },
        use: async () => {},
      }),
    ).rejects.toThrow("injected browser launch failure");

    expect(Object.isFrozen(browserEnvironment)).toBe(true);
    expect(browserEnvironment?.PATH).toBe("/test/bin");
    for (const name of WALLET_E2E_CREDENTIAL_NAMES) {
      expect(browserEnvironment?.[name]).toBeUndefined();
    }
    await expect(stat(profilePath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("removes temporary wallet profiles when preparation fails before launch", async () => {
    let profilePath = "";
    let launchCalls = 0;

    await expect(
      withWalletBrowserProfile({
        prefix: "steward-wallet-prepare-failure-",
        prepare: async (profile) => {
          profilePath = profile;
          await writeFile(join(profile, "partial-sensitive-profile"), "encrypted wallet state");
          throw new Error("injected profile copy failure");
        },
        launch: async () => {
          launchCalls += 1;
          throw new Error("launch must not run");
        },
        use: async () => {},
      }),
    ).rejects.toThrow("injected profile copy failure");

    expect(launchCalls).toBe(0);
    await expect(stat(profilePath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("forwards TERM, escalates to KILL, and removes the wallet child process group", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-process-group-"));
    temporaryDirectories.push(cwd);
    const childPidFile = join(cwd, "child-pid");
    const descendantPidFile = join(cwd, "descendant-pid");
    const childTermFile = join(cwd, "child-term");
    const descendantTermFile = join(cwd, "descendant-term");
    const fixture = join(import.meta.dir, "process-group-fixture.ts");
    const parent = Bun.spawn(
      [
        process.execPath,
        fixture,
        "harness",
        "term-tree",
        cwd,
        childPidFile,
        descendantPidFile,
        childTermFile,
        descendantTermFile,
      ],
      { cwd, stderr: "pipe", stdout: "pipe" },
    );
    try {
      const childPid = Number(await waitForFile(childPidFile));
      const descendantPid = Number(await waitForFile(descendantPidFile));
      parent.kill("SIGTERM");

      expect(await parent.exited).toBe(143);
      expect(await readFile(childTermFile, "utf8")).toBe("term");
      expect(await readFile(descendantTermFile, "utf8")).toBe("term");
      expect(await processExited(childPid)).toBe(true);
      expect(await processExited(descendantPid)).toBe(true);
    } finally {
      await stopHarness(parent);
    }
  });

  test("removes a browser descendant left behind by a successful child", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-final-cleanup-"));
    temporaryDirectories.push(cwd);
    const descendantPidFile = join(cwd, "descendant-pid");
    const descendantTermFile = join(cwd, "descendant-term");
    const fixture = join(import.meta.dir, "process-group-fixture.ts");
    const parent = Bun.spawn(
      [
        process.execPath,
        fixture,
        "harness",
        "clean-tree",
        cwd,
        join(cwd, "unused-child-pid"),
        descendantPidFile,
        join(cwd, "unused-child-term"),
        descendantTermFile,
      ],
      { cwd, stderr: "pipe", stdout: "pipe" },
    );
    try {
      const descendantPid = Number(await waitForFile(descendantPidFile));

      expect(await parent.exited).toBe(0);
      expect(await readFile(descendantTermFile, "utf8")).toBe("term");
      expect(await processExited(descendantPid)).toBe(true);
    } finally {
      await stopHarness(parent);
    }
  });

  test("scrubs Synpress Cache child environment and restores the owning process", async () => {
    const originals = new Map(
      WALLET_E2E_CREDENTIAL_NAMES.map((name) => [name, process.env[name]] as const),
    );
    try {
      for (const name of WALLET_E2E_CREDENTIAL_NAMES) process.env[name] = `${name}-cache-secret`;
      const childValues = await withWalletCredentialsRemoved(async () => {
        const fixture = join(import.meta.dir, "process-group-fixture.ts");
        const child = Bun.spawn([process.execPath, fixture, "wallet-environment"], {
          env: process.env,
          stderr: "pipe",
          stdout: "pipe",
        });
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        expect(stderr).toBe("");
        expect(exitCode).toBe(0);
        return JSON.parse(stdout) as Array<string | null>;
      });
      expect(childValues).toEqual(WALLET_E2E_CREDENTIAL_NAMES.map(() => null));
      for (const name of WALLET_E2E_CREDENTIAL_NAMES) {
        expect(process.env[name]).toBe(`${name}-cache-secret`);
      }
    } finally {
      for (const [name, value] of originals) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("disables credential-bearing wallet diagnostics", () => {
    const use = walletConfig.use as { screenshot?: unknown; trace?: unknown; video?: unknown };
    expect(use).toMatchObject({ screenshot: "off", trace: "off", video: "off" });
  });

  test("scopes protected wallet credentials to the three steps that consume them", async () => {
    const workflowPath = join(import.meta.dir, "../../../.github/workflows/wallet-e2e.yml");
    const workflowSource = await readFile(workflowPath, "utf8");
    const workflow = Bun.YAML.parse(workflowSource) as {
      permissions?: Record<string, string>;
      on?: {
        workflow_dispatch?: {
          inputs?: Record<string, { required?: boolean; type?: string }>;
        };
      };
      jobs?: Record<
        string,
        {
          env?: Record<string, string>;
          environment?: string;
          needs?: string;
          permissions?: Record<string, string>;
          steps?: Array<{
            env?: Record<string, string>;
            name?: string;
            run?: string;
            uses?: string;
            with?: Record<string, unknown>;
          }>;
        }
      >;
    };
    const authorize = workflow.jobs?.["authorize-target"];
    const job = workflow.jobs?.["wallet-e2e"];
    expect(Object.keys(workflow.on ?? {})).toEqual(["workflow_dispatch"]);
    expect(workflow.on?.workflow_dispatch?.inputs?.target_sha).toMatchObject({
      required: true,
      type: "string",
    });
    expect(workflow.permissions).toEqual({});
    expect(authorize?.environment).toBeUndefined();
    expect(authorize?.permissions).toEqual({
      checks: "read",
      contents: "read",
      "pull-requests": "read",
      statuses: "read",
    });
    expect(JSON.stringify(authorize)).not.toContain("secrets.");
    expect(authorize?.steps?.[0]?.run).toContain('"refs/heads/develop"');
    expect(authorize?.steps?.[0]?.run).toContain("group_by(.user.login | ascii_downcase)");
    expect(authorize?.steps?.[0]?.run).toContain("map(sort_by(.submitted_at, .id) | last)");
    expect(job?.environment).toBe("wallet-e2e");
    expect(job?.needs).toBe("authorize-target");
    expect(job?.env).toBeUndefined();
    expect(job?.permissions).toEqual({ contents: "read" });
    expect(workflowSource).toContain("if: github.ref == 'refs/heads/develop'");
    expect(workflowSource).toContain("bunx turbo run build --filter=@stwd/web...");
    const checkout = job?.steps?.find((step) => step.name === "Checkout");
    expect(checkout?.with).toMatchObject({
      "persist-credentials": false,
      ref: "${{ needs.authorize-target.outputs.target_sha }}",
    });

    const secretSteps = (job?.steps ?? [])
      .filter((step) => WALLET_E2E_CREDENTIAL_NAMES.some((name) => step.env?.[name] !== undefined))
      .map((step) => ({ names: Object.keys(step.env ?? {}).sort(), step: step.name }));
    expect(secretSteps).toEqual([
      ...[
        "Fail closed when wallet credentials are not provisioned",
        "Build isolated wallet-extension profiles",
      ].map((step) => ({ names: [...WALLET_E2E_CREDENTIAL_NAMES].sort(), step })),
      {
        names: [...WALLET_E2E_PASSWORD_NAMES].sort(),
        step: "Run real wallet authentication flows",
      },
    ]);
  });

  test("rejects downloaded wallet extension bytes that do not match the reviewed digest", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-extension-"));
    temporaryDirectories.push(cwd);
    const extension = join(cwd, "wallet-extension.zip");
    await writeFile(extension, "unreviewed extension bytes");

    await expect(assertWalletExtensionIntegrity(extension, "0".repeat(64))).rejects.toThrow(
      "Wallet extension artifact failed SHA-256 integrity verification",
    );
  });

  test("removes generated profiles and Playwright artifacts after a failed run", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-cleanup-"));
    temporaryDirectories.push(cwd);
    const nextBuild = join(cwd, ".next");
    const generatedPaths = [join(cwd, ".cache-synpress"), join(cwd, "test-results")];
    for (const path of [nextBuild, ...generatedPaths]) {
      await mkdir(path, { recursive: true });
      await writeFile(join(path, "sensitive-output"), "generated test data");
    }

    await cleanupWalletE2E(join(cwd, ".e2e-pids.json"), nextBuild, generatedPaths);
    for (const path of [nextBuild, ...generatedPaths]) {
      await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
    }
  });

  test("requires non-empty caches for the exact MetaMask and Phantom setups", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-e2e-"));
    temporaryDirectories.push(cwd);

    const requirements = walletCacheRequirements(cwd);
    expect(requirements.map(({ name }) => name)).toEqual([
      "MetaMask",
      "Phantom",
      "Phantom extension",
    ]);
    expect(requirements.map(({ path }) => path.split("/").at(-1))).toEqual([
      METAMASK_CACHE_ID,
      PHANTOM_CACHE_ID,
      "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    ]);
    await expect(assertWalletCaches(cwd)).rejects.toThrow(
      "Missing Synpress cache for MetaMask, Phantom, Phantom extension",
    );

    for (const requirement of requirements) {
      await mkdir(requirement.path, { recursive: true });
      await writeFile(join(requirement.path, "cache-ready"), "test cache marker");
      await writeWalletCacheManifest(requirement.path, requirement.identity);
    }
    await expect(assertWalletCaches(cwd)).resolves.toBeUndefined();

    await writeFile(join(requirements[0].path, "cache-ready"), "tampered cache marker");
    await expect(assertWalletCaches(cwd)).rejects.toThrow("Missing Synpress cache for MetaMask");

    await writeFile(join(requirements[0].path, "cache-ready"), "test cache marker");
    await writeWalletCacheManifest(requirements[0].path, requirements[0].identity);
    const external = join(cwd, "external-cache-entry");
    await writeFile(external, "external wallet state");
    await rm(join(requirements[0].path, "cache-ready"));
    await symlink(external, join(requirements[0].path, "cache-ready"));
    await expect(assertWalletCaches(cwd)).rejects.toThrow("Missing Synpress cache for MetaMask");
  }, 20_000);

  test("rejects symlinked cache files and manifests without following them", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-cache-links-"));
    temporaryDirectories.push(cwd);
    const cache = join(cwd, "cache");
    const outside = join(cwd, "outside");
    await mkdir(cache);
    await mkdir(outside);
    const outsideFile = join(outside, "credential-bearing-state");
    await writeFile(outsideFile, "must not be read through a cache link");
    await symlink(outsideFile, join(cache, "linked-state"));
    await expect(walletCacheContentSha256(cache)).rejects.toThrow();

    await rm(join(cache, "linked-state"));
    await writeFile(join(cache, "cache-ready"), "ready");
    const identity = {
      wallet: "metamask" as const,
      cacheId: "cache-id",
      extensionVersion: "1.0.0",
      extensionSha256: "0".repeat(64),
    };
    await writeWalletCacheManifest(cache, identity);
    const realManifest = join(outside, "manifest");
    await rename(join(cache, ".steward-wallet-cache.json"), realManifest);
    await symlink(realManifest, join(cache, ".steward-wallet-cache.json"));
    await expect(assertWalletCacheIdentity(cache, identity)).rejects.toThrow();
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
  }, 20_000);
});
