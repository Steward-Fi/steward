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
import { connect } from "node:net";
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
const DEV_SERVER_SPECS = new Set(["intents-reviewer-mfa.spec.ts"]);

function shouldUseNextDevServer(): boolean {
  if (process.env.E2E_NEXT_DEV === "true") return true;
  return process.argv.some((arg) =>
    [...DEV_SERVER_SPECS].some((spec) => arg.endsWith(spec) || arg.includes(`/${spec}`)),
  );
}

function configuredOrigin(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  try {
    return new URL(value).origin;
  } catch {
    return fallback;
  }
}

function originPort(origin: string, fallback: number): number {
  try {
    const port = Number(new URL(origin).port);
    return Number.isSafeInteger(port) && port > 0 ? port : fallback;
  } catch {
    return fallback;
  }
}

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

async function waitForTcp(origin: string, label: string, timeoutMs = 60_000): Promise<void> {
  const url = new URL(origin);
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      await new Promise<void>((resolve, reject) => {
        const socket = connect({ host: url.hostname, port });
        const timer = setTimeout(() => {
          socket.destroy();
          reject(new Error("timeout"));
        }, 2_000);
        socket.once("connect", () => {
          clearTimeout(timer);
          socket.end();
          resolve();
        });
        socket.once("error", (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
      return;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${label} did not open a TCP listener at ${origin}: ${String(lastErr)}`);
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

function listeningPids(port: number): number[] {
  const result = spawnSync("lsof", [`-tiTCP:${port}`, "-sTCP:LISTEN"], {
    encoding: "utf8",
  });
  return result.stdout
    .split(/\s+/)
    .map((pid) => Number(pid))
    .filter((pid) => Number.isSafeInteger(pid) && pid > 0);
}

async function clearPort(port: number): Promise<void> {
  const pids = listeningPids(port);
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  const deadline = Date.now() + 5_000;
  while (listeningPids(port).length > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  if (existsSync(PID_FILE)) rmSync(PID_FILE, { force: true });
  mkdirSync(E2E_DATA_DIR, { recursive: true });
  const fakeOAuthOrigin = configuredOrigin(
    process.env.E2E_FAKE_OAUTH_URL,
    `http://localhost:${E2E_PORTS.fakeOAuth}`,
  );
  const apiOrigin = configuredOrigin(process.env.E2E_API_URL, `http://127.0.0.1:${E2E_PORTS.api}`);
  const webOrigin = configuredOrigin(process.env.E2E_WEB_URL, `http://localhost:${E2E_PORTS.web}`);
  const ports = {
    fakeOAuth: originPort(fakeOAuthOrigin, E2E_PORTS.fakeOAuth),
    api: originPort(apiOrigin, E2E_PORTS.api),
    web: originPort(webOrigin, E2E_PORTS.web),
  };
  await clearPort(ports.fakeOAuth);
  await clearPort(ports.api);
  await clearPort(ports.web);

  const useNextDevServer = shouldUseNextDevServer();

  const apiEnv: Record<string, string> = {
    PORT: String(ports.api),
    STEWARD_BIND_HOST: "127.0.0.1",
    NODE_ENV: "test",

    // The whole suite drives one API instance from a single socket IP, which
    // the production-default global limiter (100 req/60s per IP) trips partway
    // through. Raise the ceiling for the test run only; the production default
    // is unchanged when this env var is absent.
    STEWARD_RATE_LIMIT_MAX_REQUESTS: "100000",

    // Embedded PGLite — write to a temp dir we tear down afterward.
    STEWARD_PGLITE_PATH: E2E_DATA_DIR,
    STEWARD_MASTER_PASSWORD: "e2e-master-password-32bytes--ok",
    JWT_SECRET: "e2e-jwt-secret-please-ignore-me-0000",
    STEWARD_AUDIT_HMAC_KEY: "e2e-audit-hmac-key-32-bytes-minimum-for-tamper-chain-tests",

    APP_URL: apiOrigin,

    // Mock email provider for magic-link e2e
    EMAIL_PROVIDER: "mock",
    STEWARD_TEST_INBOX: "true",

    // The fake OAuth provider is plain http://localhost — the OAuthClient
    // constructor otherwise rejects non-https provider URLs. This opt-in is
    // gated behind NODE_ENV !== "production" in @stwd/auth, so it cannot relax
    // the production guard; it only takes effect for this local test run.
    STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS: "true",

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

    // Allow the web app + API itself to be redirect targets. The OAuth e2e flow
    // redirects to a sub-path (/auth/oauth/<provider>/callback); origin-only
    // allowlist entries match only path "/", so the exact callback URLs must be
    // listed explicitly to satisfy isOAuthRedirectEntryMatch's full-path branch.
    STEWARD_OAUTH_REDIRECT_ALLOWLIST: [
      `${webOrigin}/auth/oauth/google/callback`,
      `${webOrigin}/auth/oauth/discord/callback`,
      webOrigin,
      apiOrigin,
    ].join(","),
    SIWE_ALLOWED_DOMAINS: `localhost:${ports.web},localhost`,
  };

  const fakeOAuth = startProcess("bun", ["run", "scripts/fake-oauth-server.ts"], {
    FAKE_OAUTH_PORT: String(ports.fakeOAuth),
  });
  await waitForUrl(`${fakeOAuthOrigin}/`, "fake-oauth-server");

  const api = startProcess("bun", ["run", "packages/api/src/embedded.ts"], apiEnv);
  await waitForUrl(`${apiOrigin}/auth/providers`, "api");

  let web: ChildProcess;
  if (useNextDevServer) {
    web = startProcess(
      "bunx",
      ["next", "dev", "--port", String(ports.web)],
      {
        NEXT_PUBLIC_STEWARD_API_URL: apiOrigin,
        STEWARD_ALLOW_INSECURE_HTTP: "true",
      },
      join(REPO_ROOT, "web"),
    );
  } else {
    // Serve over plain http://localhost: omit HSTS + CSP `upgrade-insecure-requests`
    // so WebKit doesn't upgrade same-origin asset requests to https:// (which the
    // http-only server can't answer, blanking the page). next.config.ts headers()
    // and the edge-middleware `process.env` reads are both resolved at BUILD time,
    // so the flag must be present for the build, not just `start`. It is a
    // secure-by-default opt-OUT — production never sets it, so HSTS stays on there.
    rmSync(join(REPO_ROOT, "web", ".next"), { recursive: true, force: true });
    runCommand(
      "bun",
      ["run", "build"],
      {
        NEXT_PUBLIC_STEWARD_API_URL: apiOrigin,
        STEWARD_ALLOW_INSECURE_HTTP: "true",
      },
      join(REPO_ROOT, "web"),
    );

    web = startProcess(
      "bun",
      ["run", "start"],
      {
        PORT: String(ports.web),
        NEXT_PUBLIC_STEWARD_API_URL: apiOrigin,
        STEWARD_ALLOW_INSECURE_HTTP: "true",
      },
      join(REPO_ROOT, "web"),
    );
  }
  if (useNextDevServer) {
    await waitForTcp(webOrigin, "web", 60_000);
    await waitForUrl(`${webOrigin}/login`, "web", 120_000);
  } else {
    await waitForUrl(`${webOrigin}/login`, "web", 120_000);
  }

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
