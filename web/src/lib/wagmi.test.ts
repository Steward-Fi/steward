// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const guard = join(import.meta.dir, "..", "..", "scripts", "assert-production-deploy-env.mjs");

/**
 * SEC-157: the hardcoded shared WalletConnect projectId must not silently
 * serve production builds — the deploy pipeline requires the env var and
 * production builds warn at runtime when the shared fallback is in use.
 */
describe("WalletConnect projectId fallback is dev-only (SEC-157)", () => {
  test("the production deploy guard fails without a dedicated projectId", () => {
    const env = { ...process.env };
    delete env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID;
    delete env.E2E_ALLOW_INSECURE_HTTP;
    const result = spawnSync(process.execPath, [guard], { env, encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is unset");
  });

  test("the production deploy guard accepts a dedicated projectId", () => {
    const result = spawnSync(process.execPath, [guard], {
      env: {
        ...process.env,
        E2E_ALLOW_INSECURE_HTTP: "false",
        NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID: "steward-production-project",
      },
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
  });
});
