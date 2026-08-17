/**
 * SEC-100: proxy resource-limit env vars fail closed at startup.
 *
 * Response, stream, concurrency, and Redis rate limits reject `0` (or a
 * non-numeric value) instead of silently disabling enforcement. The limits
 * are validated at module load, so each case runs in a subprocess.
 */

import { describe, expect, test } from "bun:test";

const PROXY_MODULE = `${import.meta.dir}/../handlers/proxy.ts`;
const AUTH_MODULE = `${import.meta.dir}/../middleware/auth.ts`;
const CONFIG_MODULE = `${import.meta.dir}/../config.ts`;

function loadModule(module: string, env: Record<string, string>) {
  return Bun.spawnSync({
    cmd: [
      "bun",
      "-e",
      `import(${JSON.stringify(module)}).then(() => process.exit(0), (e) => { console.error(e?.message ?? e); process.exit(1); })`,
    ],
    cwd: `${import.meta.dir}/..`,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
}

function loadProxyModule(env: Record<string, string>) {
  return loadModule(PROXY_MODULE, env);
}

describe("proxy resource-limit env validation (SEC-100)", () => {
  test("rejects 0 (disable-the-limit) at startup for every capped resource", () => {
    for (const name of [
      "STEWARD_PROXY_MAX_SPEND_BODY_BYTES",
      "STEWARD_PROXY_IDEMPOTENCY_TTL_MS",
      "STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES",
      "STEWARD_PROXY_UPSTREAM_TIMEOUT_MS",
      "STEWARD_PROXY_RESPONSE_BYTES",
      "STEWARD_PROXY_STREAM_DURATION_MS",
      "STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT",
      "STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT",
      "STEWARD_PROXY_APPROVAL_MAX_BODY_BYTES",
      "STEWARD_PROXY_APPROVAL_TTL_MS",
      "STEWARD_PROXY_RATE_LIMIT_MAX",
      "STEWARD_PROXY_RATE_LIMIT_WINDOW_MS",
    ]) {
      const result = loadProxyModule({ [name]: "0" });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(name);
    }
  }, 45_000);

  test("rejects disabled signed-body and invalid port limits", () => {
    const signedBody = loadModule(AUTH_MODULE, { STEWARD_PROXY_SIGNED_BODY_BYTES: "0" });
    expect(signedBody.exitCode).not.toBe(0);
    expect(signedBody.stderr.toString()).toContain("STEWARD_PROXY_SIGNED_BODY_BYTES");

    const port = loadModule(CONFIG_MODULE, { STEWARD_PROXY_PORT: "65536" });
    expect(port.exitCode).not.toBe(0);
    expect(port.stderr.toString()).toContain("STEWARD_PROXY_PORT");
  });

  test("rejects non-numeric values at startup", () => {
    const result = loadProxyModule({ STEWARD_PROXY_RESPONSE_BYTES: "unlimited" });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("STEWARD_PROXY_RESPONSE_BYTES");
  });

  test("loads with positive integer overrides", () => {
    const result = loadProxyModule({
      STEWARD_PROXY_MAX_SPEND_BODY_BYTES: "1048576",
      STEWARD_PROXY_IDEMPOTENCY_TTL_MS: "86400000",
      STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES: "1048576",
      STEWARD_PROXY_UPSTREAM_TIMEOUT_MS: "30000",
      STEWARD_PROXY_RESPONSE_BYTES: "1048576",
      STEWARD_PROXY_STREAM_DURATION_MS: "60000",
      STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT: "7",
      STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT: "70",
      STEWARD_PROXY_APPROVAL_MAX_BODY_BYTES: "1048576",
      STEWARD_PROXY_APPROVAL_TTL_MS: "60000",
      STEWARD_PROXY_RATE_LIMIT_MAX: "600",
      STEWARD_PROXY_RATE_LIMIT_WINDOW_MS: "30000",
    });
    expect(result.exitCode).toBe(0);
  });
});
