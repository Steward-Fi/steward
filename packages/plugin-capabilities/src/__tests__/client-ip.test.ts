/**
 * client-ip.test.ts - the capability audit trail must never record a
 * caller-spoofable IP (SEC-096): with no trusted-edge env configured the
 * forwarded headers are ignored entirely (NULL recorded); once the operator
 * opts in, the client entry is read positionally from the RIGHT of
 * x-forwarded-for and every candidate is isIP-validated.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { trustedClientIp } from "../client-ip";

const TRUST_ENV_KEYS = [
  "STEWARD_TRUSTED_PROXY_HOPS",
  "STEWARD_TRUST_PROXY_HEADERS",
  "STEWARD_TRUST_CLOUDFLARE",
] as const;

const savedEnv = new Map<string, string | undefined>();

/** Tiny probe app so trustedClientIp can be exercised with crafted headers. */
const probe = new Hono().get("/ip", (c) => c.json({ ip: trustedClientIp(c) ?? null }));

async function requestIp(headers: Record<string, string>): Promise<string | null> {
  const res = await probe.request("http://test/ip", { headers });
  const body = (await res.json()) as { ip: string | null };
  return body.ip;
}

beforeEach(() => {
  for (const key of TRUST_ENV_KEYS) {
    savedEnv.set(key, process.env[key]);
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of TRUST_ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("trustedClientIp (capability audit)", () => {
  test("ignores x-forwarded-for entirely when no trust is configured", async () => {
    expect(await requestIp({ "x-forwarded-for": "203.0.113.9" })).toBeNull();
  });

  test("ignores cf-connecting-ip unless Cloudflare trust is enabled", async () => {
    expect(await requestIp({ "cf-connecting-ip": "203.0.113.9" })).toBeNull();
    process.env.STEWARD_TRUST_CLOUDFLARE = "true";
    expect(await requestIp({ "cf-connecting-ip": "203.0.113.9" })).toBe("203.0.113.9");
  });

  test("with hops=1 the right-most x-forwarded-for entry wins (left-most is spoofable)", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await requestIp({ "x-forwarded-for": "198.51.100.1, 203.0.113.9" })).toBe(
      "203.0.113.9",
    );
  });

  test("with hops=2 the client entry is the second from the right", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "2";
    expect(
      await requestIp({ "x-forwarded-for": "10.0.0.1, 198.51.100.1, 203.0.113.9" }),
    ).toBe("198.51.100.1");
  });

  test("honors x-envoy-external-address with port stripping once trust is opted in", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await requestIp({ "x-envoy-external-address": "203.0.113.9:51234" })).toBe(
      "203.0.113.9",
    );
  });

  test("never records header garbage: non-IP candidates yield NULL", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await requestIp({ "x-forwarded-for": "not-an-ip" })).toBeNull();
  });

  test("legacy STEWARD_TRUST_PROXY_HEADERS=true maps to hops=1", async () => {
    process.env.STEWARD_TRUST_PROXY_HEADERS = "true";
    expect(await requestIp({ "x-forwarded-for": "198.51.100.1, 203.0.113.9" })).toBe(
      "203.0.113.9",
    );
  });
});
