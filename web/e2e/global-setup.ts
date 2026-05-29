/**
 * Playwright global-setup.
 *
 * Boots three local processes for the e2e suite and tears them down again
 * in global-teardown:
 *
 *   1. fake-oauth-server  — stub Google / Discord OAuth provider
 *   2. Steward API        — embedded PGLite + MockEmailProvider + OAuth
 *                            URL overrides pointing at the fake server
 *   3. Next.js web app    — production-mode `next start`, pointed at the API
 *
 * Each process is started detached and its pid stored in `.e2e-pids.json`
 * so global-teardown can stop everything even if the test run crashes.
 */

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FullConfig } from "@playwright/test";

const REPO_ROOT = join(__dirname, "..", "..");
const PID_FILE = join(__dirname, ".e2e-pids.json");

export const E2E_PORTS = {
  fakeOAuth: 5599,
  api: 3299,
  web: 3499,
} as const;

const E2E_DATA_DIR = join(tmpdir(), `steward-e2e-${process.pid}`);

async function waitForUrl(url: string, label: string, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (res.status < 500) return;
      lastErr = new Error(`status ${res.status}`);
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${label} did not become ready at ${url}: ${String(lastErr)}`);
}

function startProcess(
  cmd: string,
  args: string[],
  env: Record<string, string>,
  cwd = REPO_ROOT,
): ChildProcess {
  const child = spawn(cmd, args, {
    cwd,
    env: { ...process.env, ...env },
    stdio: "inherit",
    detached: false,
  });
  child.on("error", (err) => {
    console.error(`[e2e setup] ${cmd} ${args.join(" ")} failed:`, err);
  });
  return child;
}

function runCommand(
  cmd: string,
  args: string[],
  env: Record<string, string>,
  cwd = REPO_ROOT,
): void {
  const result = spawnSync(cmd, args, {
    cwd,
    env: { ...process.env, ...env },
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed with status ${result.status}`);
  }
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  if (existsSync(PID_FILE)) rmSync(PID_FILE, { force: true });
  mkdirSync(E2E_DATA_DIR, { recursive: true });

  const fakeOAuthOrigin = `http://localhost:${E2E_PORTS.fakeOAuth}`;
  const apiOrigin = `http://localhost:${E2E_PORTS.api}`;
  const webOrigin = `http://localhost:${E2E_PORTS.web}`;

  const apiEnv: Record<string, string> = {
    PORT: String(E2E_PORTS.api),
    STEWARD_BIND_HOST: "127.0.0.1",
    NODE_ENV: "test",

    // Embedded PGLite — write to a temp dir we tear down afterward.
    STEWARD_PGLITE_PATH: E2E_DATA_DIR,
    STEWARD_MASTER_PASSWORD: "e2e-master-password-32bytes--ok",
    JWT_SECRET: "e2e-jwt-secret-please-ignore-me-0000",

    APP_URL: apiOrigin,

    // Mock email provider for magic-link e2e
    EMAIL_PROVIDER: "mock",

    // OAuth provider overrides → fake server
    GOOGLE_CLIENT_ID: "e2e-google",
    GOOGLE_CLIENT_SECRET: "e2e-google-secret",
    GOOGLE_AUTHORIZATION_URL: `${fakeOAuthOrigin}/google/authorize`,
    GOOGLE_TOKEN_URL: `${fakeOAuthOrigin}/google/token`,
    GOOGLE_USERINFO_URL: `${fakeOAuthOrigin}/google/userinfo`,
    DISCORD_CLIENT_ID: "e2e-discord",
    DISCORD_CLIENT_SECRET: "e2e-discord-secret",
    DISCORD_AUTHORIZATION_URL: `${fakeOAuthOrigin}/discord/authorize`,
    DISCORD_TOKEN_URL: `${fakeOAuthOrigin}/discord/token`,
    DISCORD_USERINFO_URL: `${fakeOAuthOrigin}/discord/userinfo`,

    // Allow the web app + API itself to be redirect targets
    STEWARD_OAUTH_REDIRECT_ALLOWLIST: `${webOrigin},${apiOrigin}`,
    SIWE_ALLOWED_DOMAINS: `localhost:${E2E_PORTS.web},localhost`,
  };

  const fakeOAuth = startProcess("bun", ["run", "scripts/fake-oauth-server.ts"], {
    FAKE_OAUTH_PORT: String(E2E_PORTS.fakeOAuth),
  });
  await waitForUrl(`${fakeOAuthOrigin}/`, "fake-oauth-server");

  const api = startProcess("bun", ["run", "packages/api/src/embedded.ts"], apiEnv);
  await waitForUrl(`${apiOrigin}/auth/providers`, "api");

  runCommand(
    "bun",
    ["run", "build"],
    {
      NEXT_PUBLIC_STEWARD_API_URL: apiOrigin,
    },
    join(REPO_ROOT, "web"),
  );

  const web = startProcess(
    "bun",
    ["run", "start"],
    {
      PORT: String(E2E_PORTS.web),
      NEXT_PUBLIC_STEWARD_API_URL: apiOrigin,
    },
    join(REPO_ROOT, "web"),
  );
  await waitForUrl(`${webOrigin}/login`, "web", 120_000);

  writeFileSync(
    PID_FILE,
    JSON.stringify({
      fakeOAuth: fakeOAuth.pid,
      api: api.pid,
      web: web.pid,
      dataDir: E2E_DATA_DIR,
    }),
  );

  process.env.E2E_API_URL = apiOrigin;
  process.env.E2E_WEB_URL = webOrigin;
  process.env.E2E_FAKE_OAUTH_URL = fakeOAuthOrigin;
}
