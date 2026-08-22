/**
 * Redis client singleton for Steward.
 *
 * Selects an implementation based on the `REDIS_DRIVER` env var:
 *   - "ioredis" (default)  — long-lived TCP connection via the `ioredis`
 *                            package. Used by Bun/Node entry points and
 *                            `getRedis()` returns the underlying client
 *                            unchanged for backward compatibility.
 *   - "upstash"            — HTTP-only adapter over `@upstash/redis`. Used by
 *                            Cloudflare Workers (no TCP). The adapter exposes
 *                            the subset of ioredis method shapes that the
 *                            rate-limiter, spend-tracker, policy-cache, and
 *                            auth `RedisLike` consumer rely on.
 *
 * Reading the connection URL:
 *   - ioredis : REDIS_URL (default redis://localhost:6379). In production the
 *               URL must use rediss:// (TLS) unless it points at localhost or
 *               STEWARD_ALLOW_INSECURE_REDIS=true is set (assertRedisUrlTls).
 *   - upstash : KV_REST_API_URL + KV_REST_API_TOKEN
 *               (or UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN).
 *               In production the REST URL must be https:// — the REST token
 *               rides every request, so http:// exposes it cleartext — unless
 *               it targets localhost or STEWARD_ALLOW_INSECURE_REDIS=true is
 *               set (assertUpstashRestUrlTls).
 */

import {
  type RuntimeEnvironment,
  runtimeEnvironmentSnapshot,
  runtimeEnvironmentValue,
} from "@stwd/shared/runtime-env";
import { Redis as UpstashRedis } from "@upstash/redis";
import { Redis } from "ioredis";
import { createUpstashIoredisAdapter, type IoredisLike } from "./upstash-adapter.js";

export type RedisDriver = "ioredis" | "upstash";

const instances = new Map<string, IoredisLike>();
let shutdownRegistered = false;

function redisAuthority(): RuntimeEnvironment {
  return runtimeEnvironmentSnapshot();
}

function authorityFingerprint(environment: RuntimeEnvironment): string {
  return JSON.stringify([
    environment.REDIS_DRIVER ?? "ioredis",
    environment.REDIS_URL ?? "",
    environment.KV_REST_API_URL ?? environment.UPSTASH_REDIS_REST_URL ?? "",
    environment.KV_REST_API_TOKEN ?? environment.UPSTASH_REDIS_REST_TOKEN ?? "",
    environment.NODE_ENV ?? "",
    environment.STEWARD_RUNTIME ?? "",
    environment.STEWARD_ALLOW_INSECURE_REDIS ?? "",
  ]);
}

/**
 * Refuse to start in production if REDIS_URL is not using TLS (rediss://).
 * Redis carries spend-limit state, rate-limit state, policy cache, and auth KV
 * (SIWE nonces), so a cleartext link lets a network-positioned attacker read
 * and tamper with enforcement data. Localhost connections are exempt. Set
 * STEWARD_ALLOW_INSECURE_REDIS=true to override for private-network
 * deployments (logs a loud warning), matching the STEWARD_ALLOW_INSECURE_DB
 * posture in @stwd/db.
 */
export function assertRedisUrlTls(
  url: string,
  env: Readonly<Record<string, string | undefined>> = redisAuthority(),
): void {
  if (env.NODE_ENV !== "production") return;

  const allowInsecure = env.STEWARD_ALLOW_INSECURE_REDIS === "true";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    if (allowInsecure) {
      console.warn(
        "[steward:redis] WARNING: STEWARD_ALLOW_INSECURE_REDIS=true — REDIS_URL is not a valid URL, so TLS cannot be verified.",
      );
      return;
    }
    throw new Error("REDIS_URL must be a valid URL so TLS settings can be verified in production");
  }

  if (parsed.protocol === "rediss:") return;
  if (parsed.protocol !== "redis:") {
    throw new Error("REDIS_URL must use the redis:// or rediss:// scheme");
  }

  const host = parsed.hostname.toLowerCase();
  // URL.hostname keeps the brackets on IPv6 literals ([::1]).
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]") return;

  if (allowInsecure) {
    console.warn(
      "[steward:redis] WARNING: STEWARD_ALLOW_INSECURE_REDIS=true — REDIS_URL is cleartext redis://. " +
        "This is only safe on a private network. SOC2 CC6.7 requires encryption in transit.",
    );
    return;
  }

  throw new Error(
    "REDIS_URL must use rediss:// (TLS) in production. " +
      "Set STEWARD_ALLOW_INSECURE_REDIS=true to override for private-network deployments.",
  );
}

/**
 * SEC-032, upstash path: the Upstash REST token authenticates every request,
 * so a cleartext http:// endpoint exposes it (and lets a network-positioned
 * attacker read/tamper with spend-limit, rate-limit, and auth KV state) even
 * though the ioredis path is TLS-asserted. In production require https://
 * unless the endpoint is loopback; STEWARD_ALLOW_INSECURE_REDIS=true overrides
 * (loud warning), matching assertRedisUrlTls.
 */
export function assertUpstashRestUrlTls(
  url: string,
  env: Readonly<Record<string, string | undefined>> = redisAuthority(),
): void {
  const allowInsecure = env.STEWARD_ALLOW_INSECURE_REDIS === "true";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(
      "KV_REST_API_URL must be a valid URL so TLS settings can be verified in production",
    );
  }

  if (parsed.protocol !== "http:") {
    if (parsed.protocol !== "https:") {
      throw new Error("KV_REST_API_URL must use the http:// or https:// scheme");
    }
    return;
  }

  if (env.NODE_ENV !== "production") return;
  const host = parsed.hostname.toLowerCase();
  // URL.hostname keeps the brackets on IPv6 literals ([::1]).
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]") return;

  if (allowInsecure) {
    console.warn(
      "[steward:redis] WARNING: STEWARD_ALLOW_INSECURE_REDIS=true — Upstash REST URL is cleartext http://. " +
        "The REST token crosses the network unencrypted. This is only safe on a private network. " +
        "SOC2 CC6.7 requires encryption in transit.",
    );
    return;
  }

  throw new Error(
    "KV_REST_API_URL must use https:// in production — the Upstash REST token would otherwise cross the network in cleartext. " +
      "Set STEWARD_ALLOW_INSECURE_REDIS=true to override for private-network deployments.",
  );
}

export function getRedisDriver(): RedisDriver {
  const raw = runtimeEnvironmentValue("REDIS_DRIVER")?.trim().toLowerCase();
  if (raw === "upstash") return "upstash";
  return "ioredis";
}

function buildIoredis(environment: RuntimeEnvironment): Redis {
  const configuredUrl = environment.REDIS_URL?.trim();
  if (!configuredUrl && environment.STEWARD_RUNTIME === "workers") {
    throw new Error("REDIS_URL is required for the ioredis driver on Workers");
  }
  const url = configuredUrl || "redis://localhost:6379";
  assertRedisUrlTls(url, environment);
  const client = new Redis(url, {
    maxRetriesPerRequest: 3,
    retryStrategy(times: number) {
      if (times > 10) return null; // stop retrying after 10 attempts
      return Math.min(times * 200, 5000); // exponential backoff, max 5s
    },
    lazyConnect: false,
    enableReadyCheck: true,
  });

  client.on("error", (err) => {
    // Redis client errors can embed the configured URL (including its
    // password). Keep diagnostics fixed in this low-level package, which must
    // not depend on the shared logging layer.
    console.error("[steward:redis] connection error");
  });

  client.on("connect", () => {
    console.log("[steward:redis] connected to", url.replace(/\/\/.*@/, "//***@"));
  });

  if (!shutdownRegistered) {
    shutdownRegistered = true;
    const shutdown = async () => {
      for (const client of instances.values()) {
        if ("quit" in client && typeof client.quit === "function") {
          console.log("[steward:redis] shutting down connection...");
          await (client as Redis).quit().catch(() => {});
        }
      }
      instances.clear();
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    process.on("beforeExit", shutdown);
  }

  return client;
}

function buildUpstash(environment: RuntimeEnvironment): IoredisLike {
  const url = environment.KV_REST_API_URL || environment.UPSTASH_REDIS_REST_URL || "";
  const token = environment.KV_REST_API_TOKEN || environment.UPSTASH_REDIS_REST_TOKEN || "";

  if (!url || !token) {
    throw new Error(
      "REDIS_DRIVER=upstash requires KV_REST_API_URL + KV_REST_API_TOKEN " +
        "(or UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN) to be set",
    );
  }

  // SEC-032: same TLS posture as the ioredis path — the REST token rides every
  // request, so a cleartext http:// endpoint in production is fail-closed.
  assertUpstashRestUrlTls(url, environment);

  const upstash = new UpstashRedis({ url, token });
  console.log("[steward:redis] using upstash REST adapter");
  return createUpstashIoredisAdapter(upstash);
}

/**
 * Get the Redis client singleton.
 * Creates the connection on first call.
 */
export function getRedis(): IoredisLike {
  const environment = redisAuthority();
  const fingerprint = authorityFingerprint(environment);
  const cached = instances.get(fingerprint);
  if (cached) return cached;
  const driver = getRedisDriver();
  const client =
    driver === "upstash"
      ? buildUpstash(environment)
      : (buildIoredis(environment) as unknown as IoredisLike);
  instances.set(fingerprint, client);
  return client;
}

/**
 * Disconnect and reset the singleton (useful for tests).
 */
export async function disconnectRedis(): Promise<void> {
  for (const client of instances.values()) {
    if ("quit" in client && typeof client.quit === "function") {
      await (client as Redis).quit().catch(() => {});
    }
  }
  instances.clear();
}

export type { IoredisLike };
