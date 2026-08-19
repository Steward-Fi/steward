import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import walletConfig from "../../playwright.wallets.config";
import { cleanupWalletE2E } from "../../scripts/cleanup-wallet-e2e";
import { assertWalletCaches, walletCacheRequirements } from "../../scripts/run-wallet-e2e";
import { e2eChildProcessEnvironment } from "../global-setup";
import {
  environmentWithoutWalletCredentials,
  readWalletE2ECredentials,
  WALLET_E2E_CREDENTIAL_NAMES,
  withWalletCredentialsRemoved,
} from "./credentials";
import { assertExtensionDigest } from "./metamask-extension";
import { METAMASK_CACHE_ID } from "./setup/metamask/metamask.setup";
import { PHANTOM_CACHE_ID } from "./setup/phantom/phantom.setup";
import { withWalletBrowserProfile } from "./wallet-browser-profile";

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

  test("scrubs Synpress Cache child environment and restores the owning process", async () => {
    const originals = new Map(
      WALLET_E2E_CREDENTIAL_NAMES.map((name) => [name, process.env[name]] as const),
    );
    try {
      for (const name of WALLET_E2E_CREDENTIAL_NAMES) process.env[name] = `${name}-cache-secret`;
      const childValues = await withWalletCredentialsRemoved(async () => {
        const child = Bun.spawn(
          [
            "bun",
            "-e",
            `console.log(JSON.stringify(${JSON.stringify(WALLET_E2E_CREDENTIAL_NAMES)}.map((name) => process.env[name])))`,
          ],
          { env: process.env, stderr: "pipe", stdout: "pipe" },
        );
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
    expect(authorize?.environment).toBeUndefined();
    expect(JSON.stringify(authorize)).not.toContain("secrets.");
    expect(authorize?.steps?.[0]?.run).toContain('"refs/heads/develop"');
    expect(job?.environment).toBe("wallet-e2e");
    expect(job?.needs).toBe("authorize-target");
    expect(job?.env).toBeUndefined();
    expect(workflowSource).toContain("if: github.ref == 'refs/heads/develop'");
    expect(workflowSource).toContain("bunx turbo run build --filter=@stwd/api...");
    const checkout = job?.steps?.find((step) => step.name === "Checkout");
    expect(checkout?.with).toMatchObject({
      "persist-credentials": false,
      ref: "${{ needs.authorize-target.outputs.target_sha }}",
    });

    const secretSteps = (job?.steps ?? [])
      .filter((step) => WALLET_E2E_CREDENTIAL_NAMES.some((name) => step.env?.[name] !== undefined))
      .map((step) => ({ names: Object.keys(step.env ?? {}).sort(), step: step.name }));
    expect(secretSteps).toEqual(
      [
        "Fail closed when wallet credentials are not provisioned",
        "Build isolated wallet-extension profiles",
        "Run real wallet authentication flows",
      ].map((step) => ({ names: [...WALLET_E2E_CREDENTIAL_NAMES].sort(), step })),
    );
  });

  test("rejects downloaded wallet extension bytes that do not match the reviewed digest", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "steward-wallet-extension-"));
    temporaryDirectories.push(cwd);
    const extension = join(cwd, "wallet-extension.zip");
    await writeFile(extension, "unreviewed extension bytes");

    await expect(assertExtensionDigest(extension, "0".repeat(64))).rejects.toThrow(
      "Downloaded wallet extension failed SHA-256 verification",
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
  }, 20_000);
});
