#!/usr/bin/env bun

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import net from "node:net";
import { setTimeout as sleep } from "node:timers/promises";

const bunCmd = process.env.npm_execpath || process.env.BUN || "bun";
const skipRequested =
  process.env.MILADY_SKIP_STEWARD_FI_LIVE_SMOKE?.trim() === "1";
const explicitStewardUrl = process.env.STEWARD_URL?.trim();
const authSmokeScript = new URL("./e2e-auth-test.ts", import.meta.url);
const LOCAL_READY_TIMEOUT_MS = 120_000;

function firstNonEmpty(...values: Array<string | null | undefined>): string {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "";
}

function firstPlatformKeyFromList(value?: string): string {
  if (!value) {
    return "";
  }

  return (
    value
      .split(",")
      .map((entry) => entry.trim())
      .find(Boolean) || ""
  );
}

async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Failed to allocate a loopback port"));
        return;
      }

      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(address.port);
      });
    });
  });
}

async function waitForChildExit(
  child: ChildProcess,
  timeoutMs: number,
): Promise<boolean> {
  if (child.exitCode !== null) {
    return true;
  }

  return await Promise.race([
    new Promise<boolean>((resolve) => {
      child.once("exit", () => resolve(true));
    }),
    sleep(timeoutMs).then(() => false),
  ]);
}

async function stopChild(child: ChildProcess | null): Promise<void> {
  if (!child || child.exitCode !== null) {
    return;
  }

  child.kill("SIGTERM");
  const exitedAfterTerm = await waitForChildExit(child, 5_000);
  if (exitedAfterTerm || child.exitCode !== null) {
    return;
  }

  child.kill("SIGKILL");
  await waitForChildExit(child, 5_000);
}

async function waitForReady(
  stewardUrl: string,
  child: ChildProcess,
  timeoutMs = LOCAL_READY_TIMEOUT_MS,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const readyUrl = `${stewardUrl}/ready`;
  let lastError = "server did not become ready";

  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `[steward-fi] Embedded steward exited before readiness (code ${child.exitCode})`,
      );
    }

    try {
      const response = await fetch(readyUrl);
      if (response.ok) {
        const body = (await response.json()) as {
          status?: string;
          checks?: Record<string, boolean>;
        };
        if (body.status === "ready") {
          return;
        }
        lastError = `readiness returned ${JSON.stringify(body)}`;
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }

    await sleep(500);
  }

  throw new Error(
    `[steward-fi] Embedded steward did not become ready at ${readyUrl} within ${timeoutMs}ms (${lastError})`,
  );
}

function runAuthSmoke(env: NodeJS.ProcessEnv): number {
  const result = spawnSync(bunCmd, ["run", "scripts/e2e-auth-test.ts"], {
    cwd: process.cwd(),
    stdio: "inherit",
    env,
  });

  if (result.error?.code === "ENOENT") {
    console.log(
      `[steward-fi] Skipping e2e smoke because the test runner could not be launched: ${result.error.message}`,
    );
    return 0;
  }

  return result.status ?? 1;
}

async function main(): Promise<void> {
  if (skipRequested) {
    console.log(
      "[steward-fi] Skipping e2e smoke because MILADY_SKIP_STEWARD_FI_LIVE_SMOKE=1.",
    );
    process.exit(0);
  }

  if (!existsSync(authSmokeScript)) {
    console.log(
      "[steward-fi] Skipping e2e smoke because the auth smoke script is not available in this checkout.",
    );
    process.exit(0);
  }

  if (explicitStewardUrl) {
    process.exit(
      runAuthSmoke({
        ...process.env,
        STEWARD_URL: explicitStewardUrl,
      }),
    );
  }

  const port = await getFreePort();
  const stewardUrl = `http://127.0.0.1:${port}`;
  const platformKey =
    firstNonEmpty(
      process.env.PLATFORM_KEY,
      process.env.STEWARD_PLATFORM_KEY,
      firstPlatformKeyFromList(process.env.STEWARD_PLATFORM_KEYS),
    ) || `steward-platform-${crypto.randomUUID()}`;

  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    APP_URL: stewardUrl,
    DATABASE_URL: "pglite://embedded",
    PASSKEY_ALLOWED_ORIGINS: stewardUrl,
    PASSKEY_ORIGIN: stewardUrl,
    PLATFORM_KEY: platformKey,
    PORT: String(port),
    STEWARD_DB_MODE: "pglite",
    STEWARD_PGLITE_MEMORY: "true",
    STEWARD_PLATFORM_KEY: platformKey,
    STEWARD_PLATFORM_KEYS:
      process.env.STEWARD_PLATFORM_KEYS?.trim() || platformKey,
    STEWARD_URL: stewardUrl,
  };

  console.log(
    `[steward-fi] Starting local embedded steward at ${stewardUrl} for smoke.`,
  );

  const child = spawn(bunCmd, ["run", "scripts/start-local.ts"], {
    cwd: process.cwd(),
    env: childEnv,
    stdio: "inherit",
  });

  try {
    await waitForReady(stewardUrl, child);
    process.exit(runAuthSmoke(childEnv));
  } finally {
    await stopChild(child);
  }
}

await main();
