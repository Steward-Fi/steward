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

function loadProxyModule(env: Record<string, string>, module = PROXY_MODULE) {
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

describe("proxy resource-limit env validation (SEC-100)", () => {
  test("rejects 0 (disable-the-limit) at startup for every capped resource", () => {
    for (const name of [
      "STEWARD_PROXY_RESPONSE_BYTES",
      "STEWARD_PROXY_STREAM_DURATION_MS",
      "STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT",
      "STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT",
      "STEWARD_PROXY_RATE_LIMIT_MAX",
      "STEWARD_PROXY_RATE_LIMIT_WINDOW_MS",
      "STEWARD_PROXY_APPROVAL_MAX_BODY_BYTES",
      "STEWARD_PROXY_APPROVAL_TTL_MS",
      "STEWARD_PROXY_MAX_SPEND_BODY_BYTES",
      "STEWARD_PROXY_IDEMPOTENCY_TTL_MS",
      "STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES",
      "STEWARD_PROXY_UPSTREAM_TIMEOUT_MS",
      "STEWARD_PROXY_PORT",
    ]) {
      const result = loadProxyModule({ [name]: "0" });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(name);
    }
  }, 60_000);

  test("rejects non-numeric values at startup", () => {
    const result = loadProxyModule({ STEWARD_PROXY_RESPONSE_BYTES: "unlimited" });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("STEWARD_PROXY_RESPONSE_BYTES");
  });

  test("rejects disabled signed-body limits at startup", () => {
    const result = loadProxyModule({ STEWARD_PROXY_SIGNED_BODY_BYTES: "0" }, AUTH_MODULE);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain("STEWARD_PROXY_SIGNED_BODY_BYTES");
  });

  test("rejects unsafe or excessive values instead of effectively unbounded limits", () => {
    for (const [name, value] of [
      ["STEWARD_PROXY_RESPONSE_BYTES", String(Number.MAX_SAFE_INTEGER + 1)],
      ["STEWARD_PROXY_UPSTREAM_TIMEOUT_MS", "300001"],
      ["STEWARD_PROXY_PORT", "65536"],
    ]) {
      const result = loadProxyModule({ [name]: value });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(name);
    }
  });

  test("loads with positive integer overrides", () => {
    const result = loadProxyModule({
      STEWARD_PROXY_RESPONSE_BYTES: "1048576",
      STEWARD_PROXY_STREAM_DURATION_MS: "60000",
      STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT: "7",
      STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT: "70",
      STEWARD_PROXY_RATE_LIMIT_MAX: "600",
      STEWARD_PROXY_RATE_LIMIT_WINDOW_MS: "30000",
      STEWARD_PROXY_APPROVAL_MAX_BODY_BYTES: "1048576",
      STEWARD_PROXY_APPROVAL_TTL_MS: "60000",
      STEWARD_PROXY_MAX_SPEND_BODY_BYTES: "1048576",
      STEWARD_PROXY_IDEMPOTENCY_TTL_MS: "60000",
      STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES: "1048576",
      STEWARD_PROXY_UPSTREAM_TIMEOUT_MS: "10000",
      STEWARD_PROXY_PORT: "8081",
    });
    expect(result.exitCode).toBe(0);
  });
});
