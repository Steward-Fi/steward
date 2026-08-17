// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const wagmiSource = readFileSync(join(import.meta.dir, "wagmi.ts"), "utf8");
const guardSource = readFileSync(
  join(import.meta.dir, "..", "..", "scripts", "assert-production-deploy-env.mjs"),
  "utf8",
);

/**
 * SEC-157: the hardcoded shared WalletConnect projectId must not silently
 * serve production builds — the deploy pipeline requires the env var and
 * production builds warn at runtime when the shared fallback is in use.
 */
describe("WalletConnect projectId fallback is dev-only (SEC-157)", () => {
  test("production builds warn when the shared fallback is in use", () => {
    expect(wagmiSource).toContain('process.env.NODE_ENV === "production"');
    expect(wagmiSource).toContain("SHARED_FALLBACK_PROJECT_ID");
    expect(wagmiSource).toContain("NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is unset");
  });

  test("the production deploy guard requires NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID", () => {
    expect(guardSource).toContain("!process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID");
  });
});
