/**
 * Runtime-safe global request rate limiting (SEC-068).
 *
 * Production uses the shared Redis sliding window in both Bun and Workers so
 * replicas and restarts cannot mint fresh budgets. Bun may use the bounded
 * in-memory implementation only after an exact single-instance acknowledgement;
 * development and test use it by default. Workers never accept that
 * acknowledgement because one deployment can have many isolates.
 */

import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import type { Context, MiddlewareHandler, Next } from "hono";
import { checkAuthRateLimit } from "../routes/auth";
import { RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS } from "../services/context";
import {
  DEFAULT_RATE_LIMIT_MAX_KEYS,
  InMemoryRateLimiter,
  parseNonNegativeInt,
  parsePositiveInt,
  resolveClientIp,
  socketPeerFromEnv,
} from "../services/runtime-gate";
import { isRedisAvailable } from "./redis";

export const SINGLE_INSTANCE_GLOBAL_RATE_LIMIT_ACK =
  "STEWARD_ACKNOWLEDGE_SINGLE_INSTANCE_GLOBAL_RATE_LIMIT";

export type GlobalRateLimitPosture = "durable" | "memory-development" | "memory-acknowledged";

/** Resolve posture from the immutable Worker request snapshot or Bun process env. */
export function globalRateLimitPosture(
  durableAvailable: () => boolean = isRedisAvailable,
): GlobalRateLimitPosture {
  const workers = runtimeEnvironmentValue("STEWARD_RUNTIME") === "workers";
  if (workers) return "durable";
  const nodeEnv = runtimeEnvironmentValue("NODE_ENV");
  if (nodeEnv === "development" || nodeEnv === "test") return "memory-development";
  if (
    nodeEnv === "production" &&
    runtimeEnvironmentValue(SINGLE_INSTANCE_GLOBAL_RATE_LIMIT_ACK) === "true"
  ) {
    return durableAvailable() ? "durable" : "memory-acknowledged";
  }
  return "durable";
}

export function globalRateLimitRequiresRedis(): boolean {
  return globalRateLimitPosture() === "durable";
}

type DurableRateLimitCheck = (
  c: Context,
  windowMs: number,
  maxRequests: number,
) => Promise<{ allowed: boolean; retryAfterSecs?: number }>;

const checkDurableGlobalRateLimit: DurableRateLimitCheck = (c, windowMs, maxRequests) =>
  checkAuthRateLimit(c, "global", windowMs, maxRequests, undefined, { strictDurable: true });

export function createGlobalRateLimitMiddleware(options?: {
  maxRequests?: number;
  windowMs?: number;
  checkDurable?: DurableRateLimitCheck;
  durableAvailable?: () => boolean;
}): MiddlewareHandler {
  const memoryLimiter = new InMemoryRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS);
  const checkDurable = options?.checkDurable ?? checkDurableGlobalRateLimit;

  return async (c: Context, next: Next): Promise<Response | undefined> => {
    // Probes remain reachable so orchestration can observe a failed durable
    // dependency instead of receiving a misleading rate-limit response.
    if (c.req.path === "/health" || c.req.path === "/ready") {
      await next();
      return undefined;
    }

    const maxRequests =
      options?.maxRequests ??
      parsePositiveInt(
        runtimeEnvironmentValue("STEWARD_RATE_LIMIT_MAX_REQUESTS"),
        RATE_LIMIT_MAX_REQUESTS,
      );
    const windowMs =
      options?.windowMs ??
      parsePositiveInt(
        runtimeEnvironmentValue("STEWARD_RATE_LIMIT_WINDOW_MS"),
        RATE_LIMIT_WINDOW_MS,
      );
    const posture = globalRateLimitPosture(options?.durableAvailable);
    let verdict: { allowed: boolean; retryAfterSecs?: number };
    if (posture === "durable") {
      try {
        verdict = await checkDurable(c, windowMs, maxRequests);
      } catch {
        verdict = { allowed: false, retryAfterSecs: Math.ceil(windowMs / 1000) };
      }
    } else {
      const peer = socketPeerFromEnv(c.env) ?? null;
      const trustedProxyHops = parseNonNegativeInt(
        runtimeEnvironmentValue("STEWARD_TRUSTED_PROXY_HOPS"),
        0,
      );
      const clientKey = resolveClientIp(c.req.raw.headers, peer, trustedProxyHops);
      const maxKeys = parsePositiveInt(
        runtimeEnvironmentValue("STEWARD_RATE_LIMIT_MAX_KEYS"),
        DEFAULT_RATE_LIMIT_MAX_KEYS,
      );
      // A binding/config generation gets its own canonical numeric budget key,
      // so overlapping Worker snapshots cannot reinterpret another generation's
      // count or reset timestamp under different limits.
      const key = `${maxRequests}:${windowMs}:${clientKey}`;
      const local = memoryLimiter.check(key, Date.now(), maxKeys, maxRequests, windowMs);
      verdict = local.limited
        ? { allowed: false, retryAfterSecs: local.retryAfterSeconds }
        : { allowed: true };
    }

    if (!verdict.allowed) {
      return c.json(
        { ok: false, error: "Rate limit exceeded" },
        429,
        verdict.retryAfterSecs ? { "Retry-After": String(verdict.retryAfterSecs) } : undefined,
      );
    }
    await next();
    return undefined;
  };
}

export const globalRateLimit = createGlobalRateLimitMiddleware();
