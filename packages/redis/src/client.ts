/**
 * Redis client singleton for Steward.
 *
 * Reads REDIS_URL from environment (default: redis://localhost:6379).
 * Exports a lazy singleton — connection is established on first use.
 * Registers graceful shutdown on process exit signals.
 */

import { Redis } from "ioredis";

let instance: Redis | null = null;
let shutdownRegistered = false;

/**
 * Get the Redis client singleton.
 * Creates the connection on first call.
 */
export function getRedis(): Redis {
  if (!instance) {
    const url = process.env.REDIS_URL || "redis://localhost:6379";
    instance = new Redis(url, {
      maxRetriesPerRequest: 3,
      retryStrategy(times: number) {
        if (times > 10) return null; // stop retrying after 10 attempts
        return Math.min(times * 200, 5000); // exponential backoff, max 5s
      },
      lazyConnect: false,
      enableReadyCheck: true,
    });

    instance.on("error", (err) => {
      console.error("[steward:redis] connection error:", (err as Error).message);
    });

    instance.on("connect", () => {
      console.log("[steward:redis] connected to", url.replace(/\/\/.*@/, "//***@"));
    });

    if (!shutdownRegistered) {
      shutdownRegistered = true;
      const shutdown = async () => {
        if (instance) {
          console.log("[steward:redis] shutting down connection...");
          await instance.quit().catch(() => {});
          instance = null;
        }
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
      process.on("beforeExit", shutdown);
    }
  }

  return instance;
}

/**
 * Disconnect and reset the singleton (useful for tests).
 */
export async function disconnectRedis(): Promise<void> {
  if (instance) {
    await instance.quit().catch(() => {});
    instance = null;
  }
}
