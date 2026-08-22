import { describe, expect, test } from "bun:test";
import { join } from "node:path";

const fixturePath = join(import.meta.dir, "__fixtures__", "import-wagmi.ts");
const guardPath = join(import.meta.dir, "..", "..", "scripts", "assert-production-deploy-env.mjs");
const SHARED_FALLBACK_PROJECT_ID = "2c7ddf841a48e522748c5e2782d73443";

function childEnv(values: Record<string, string | undefined>): Record<string, string> {
  const env = { ...process.env } as Record<string, string>;
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  return env;
}

function runWagmiImport(environment: "production" | "development", projectId?: string) {
  const child = Bun.spawnSync({
    cmd: [process.execPath, fixturePath],
    env: childEnv({
      NODE_ENV: environment,
      NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID: projectId,
    }),
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(child.exitCode, child.stderr.toString()).toBe(0);
  return JSON.parse(child.stdout.toString()) as {
    projectId: string;
    warnings: string[];
    browserGlobalsPresent: boolean;
  };
}

function runDeployGuard(projectId?: string) {
  return Bun.spawnSync({
    cmd: [process.execPath, guardPath],
    env: childEnv({
      E2E_ALLOW_INSECURE_HTTP: undefined,
      NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID: projectId,
    }),
    stdout: "pipe",
    stderr: "pipe",
  });
}

describe("WalletConnect projectId fallback is dev-only (SEC-157)", () => {
  test("production import warns and resolves the shared fallback when configuration is absent", () => {
    const result = runWagmiImport("production");
    expect(result.projectId).toBe(SHARED_FALLBACK_PROJECT_ID);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is unset");
    expect(result.browserGlobalsPresent).toBe(false);
  });

  test("configured production and unconfigured development imports resolve without warnings", () => {
    const configured = runWagmiImport("production", "dedicated-walletconnect-project");
    expect(configured.projectId).toBe("dedicated-walletconnect-project");
    expect(configured.warnings).toEqual([]);
    expect(configured.browserGlobalsPresent).toBe(false);

    const development = runWagmiImport("development");
    expect(development.projectId).toBe(SHARED_FALLBACK_PROJECT_ID);
    expect(development.warnings).toEqual([]);
    expect(development.browserGlobalsPresent).toBe(false);
  });

  test("the checked-in production deploy guard fails closed without a dedicated project id", () => {
    const missing = runDeployGuard();
    expect(missing.exitCode).not.toBe(0);
    expect(missing.stderr.toString()).toContain("NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is unset");

    const configured = runDeployGuard("dedicated-walletconnect-project");
    expect(configured.exitCode, configured.stderr.toString()).toBe(0);
  });
});
