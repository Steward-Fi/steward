import { rm } from "node:fs/promises";
import { resolve } from "node:path";
import { runGlobalTeardown } from "../e2e/global-teardown";

const WEB_ROOT = resolve(import.meta.dir, "..");
const PID_FILE = resolve(WEB_ROOT, "e2e/.e2e-pids.json");
const NEXT_BUILD_DIR = resolve(WEB_ROOT, ".next");
const GENERATED_WALLET_PATHS = [
  resolve(WEB_ROOT, ".cache-synpress"),
  resolve(WEB_ROOT, ".wallet-e2e-profiles"),
  resolve(WEB_ROOT, "test-results"),
  resolve(WEB_ROOT, "playwright-report"),
  resolve(WEB_ROOT, "blob-report"),
] as const;

export async function cleanupWalletE2E(
  pidFile = PID_FILE,
  nextBuildDir = NEXT_BUILD_DIR,
  generatedPaths: readonly string[] = GENERATED_WALLET_PATHS,
): Promise<void> {
  let cleanupError: unknown;
  try {
    await runGlobalTeardown(pidFile, nextBuildDir);
  } catch (error) {
    cleanupError = error;
  }

  for (const path of generatedPaths) {
    try {
      await rm(path, { force: true, recursive: true });
    } catch (error) {
      cleanupError ??= error;
    }
  }

  if (cleanupError) throw cleanupError;
}

if (import.meta.main) await cleanupWalletE2E();
