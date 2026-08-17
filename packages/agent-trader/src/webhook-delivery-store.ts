import { createHash } from "node:crypto";
import { Redis } from "ioredis";

export const WEBHOOK_DELIVERY_REPLAY_TTL_MS = 10 * 60 * 1000;
export const SINGLE_INSTANCE_REPLAY_ACK_ENV =
  "STEWARD_AGENT_TRADER_ACKNOWLEDGE_SINGLE_INSTANCE_REPLAY";
const MAX_REMEMBERED_WEBHOOK_DELIVERIES = 10_000;
const REDIS_KEY_PREFIX = "steward:agent-trader:webhook-delivery:";
const UPSTASH_REQUEST_TIMEOUT_MS = 3_000;
const UPSTASH_MAX_RESPONSE_BYTES = 16 * 1024;

/** Atomic, single-use claim for an authenticated webhook delivery. */
export interface WebhookDeliveryStore {
  readonly durable: boolean;
  claim(deliveryScope: string, ttlMs: number): Promise<boolean>;
}

/** Process-local implementation suitable only for development or one replica. */
export class MemoryWebhookDeliveryStore implements WebhookDeliveryStore {
  readonly durable = false;
  private readonly consumed = new Map<string, number>();

  async claim(deliveryScope: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    for (const [id, expiresAt] of this.consumed) {
      if (expiresAt <= now) this.consumed.delete(id);
    }
    if (this.consumed.has(deliveryScope)) return false;

    // This mutation occurs before the async method yields, making concurrent
    // claims atomic within this process.
    this.consumed.set(deliveryScope, now + ttlMs);
    while (this.consumed.size > MAX_REMEMBERED_WEBHOOK_DELIVERIES) {
      const oldest = this.consumed.keys().next().value;
      if (typeof oldest !== "string") break;
      this.consumed.delete(oldest);
    }
    return true;
  }
}

export interface RedisSetNxPx {
  set(
    key: string,
    value: string,
    mode: "PX",
    ttlMs: number,
    condition: "NX",
  ): Promise<string | null>;
}

/** Shared Redis implementation. SET NX PX is atomic across all replicas. */
export class RedisWebhookDeliveryStore implements WebhookDeliveryStore {
  readonly durable = true;
  constructor(private readonly redis: RedisSetNxPx) {}

  async claim(deliveryScope: string, ttlMs: number): Promise<boolean> {
    // Hash the tenant/delivery scope so attacker-controlled identifiers cannot
    // create ambiguous Redis key segments or leak tenant metadata in key lists.
    const digest = createHash("sha256").update(deliveryScope).digest("hex");
    const result = await this.redis.set(`${REDIS_KEY_PREFIX}${digest}`, "1", "PX", ttlMs, "NX");
    return result === "OK";
  }
}

function configured(value: string | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

type ReplayRedisFactory = (kind: "redis" | "upstash", env: NodeJS.ProcessEnv) => RedisSetNxPx;

interface UpstashReplayClientOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

async function readBoundedJsonResponse(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<{ error?: unknown; result?: unknown }> {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    void response.body?.cancel().catch(() => {});
    throw new Error("Upstash replay claim response too large");
  }
  if (!response.body) throw new Error("Upstash replay claim returned an invalid response");

  const reader = response.body.getReader();
  const cancelOnAbort = () => {
    // Cancellation is deliberately fire-and-forget: a hostile implementation
    // must not be able to hang cleanup after the outward request has timed out.
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancelOnAbort, { once: true });
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        // Do not await cancellation: a hostile stream must not extend the
        // request deadline by hanging its cancellation promise.
        void reader.cancel().catch(() => {});
        throw new Error("Upstash replay claim response too large");
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", cancelOnAbort);
    reader.releaseLock();
  }

  const combined = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(combined)) as { error?: unknown; result?: unknown };
  } catch {
    throw new Error("Upstash replay claim returned an invalid response");
  }
}

export function createUpstashReplaySetClient(
  url: string,
  token: string,
  options: UpstashReplayClientOptions = {},
): RedisSetNxPx {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? UPSTASH_REQUEST_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? UPSTASH_MAX_RESPONSE_BYTES;
  return {
    async set(key, value, mode, ttlMs, condition): Promise<string | null> {
      const controller = new AbortController();
      let timeout: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(new Error("Upstash replay claim request failed"));
        }, timeoutMs);
      });
      const request = async (): Promise<string | null> => {
        let response: Response;
        try {
          response = await fetchImpl(url, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(["SET", key, value, mode, ttlMs, condition]),
            signal: controller.signal,
          });
        } catch {
          throw new Error("Upstash replay claim request failed");
        }
        if (!response.ok) throw new Error(`Upstash replay claim failed (${response.status})`);
        const payload = await readBoundedJsonResponse(
          response,
          maxResponseBytes,
          controller.signal,
        );
        if (payload.error) throw new Error("Upstash replay claim returned an error");
        return payload.result === "OK" ? "OK" : null;
      };
      try {
        // Race the whole operation (headers and streaming body), not only
        // fetch(), so a peer that stalls after sending headers cannot hang us.
        return await Promise.race([request(), deadline]);
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}

function defaultRedisFactory(kind: "redis" | "upstash", env: NodeJS.ProcessEnv): RedisSetNxPx {
  if (kind === "redis") {
    const client = new Redis(env.REDIS_URL as string, {
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
      retryStrategy: (attempt) => (attempt > 10 ? null : Math.min(attempt * 200, 5_000)),
    });
    // Prevent an EventEmitter "error" event from terminating the process. SET
    // still rejects, and the request path converts that failure to a 503.
    client.on("error", (error) => {
      console.error("[agent-trader] webhook replay Redis error:", error.message);
    });
    return client;
  }

  const url = (env.KV_REST_API_URL ?? env.UPSTASH_REDIS_REST_URL) as string;
  const token = (env.KV_REST_API_TOKEN ?? env.UPSTASH_REDIS_REST_TOKEN) as string;
  return createUpstashReplaySetClient(url, token);
}

/**
 * Resolve durable replay storage from runtime configuration. In production,
 * missing shared storage is rejected before trading starts unless the operator
 * explicitly acknowledges that the service is guaranteed to be single-instance.
 */
export function createConfiguredWebhookDeliveryStore(
  env: NodeJS.ProcessEnv = process.env,
  redisFactory: ReplayRedisFactory = defaultRedisFactory,
): WebhookDeliveryStore | undefined {
  const hasRedisUrl = configured(env.REDIS_URL);
  const upstashUrl = env.KV_REST_API_URL ?? env.UPSTASH_REDIS_REST_URL;
  const upstashToken = env.KV_REST_API_TOKEN ?? env.UPSTASH_REDIS_REST_TOKEN;
  const hasUpstashUrl = configured(upstashUrl);
  const hasUpstashToken = configured(upstashToken);

  if (hasUpstashUrl !== hasUpstashToken) {
    throw new Error("Upstash webhook replay storage requires both REST URL and token");
  }
  if (!hasRedisUrl && !hasUpstashUrl) {
    if (env.NODE_ENV === "production" && env[SINGLE_INSTANCE_REPLAY_ACK_ENV] !== "true") {
      throw new Error(
        `Durable webhook replay storage is required in production. Configure REDIS_URL/Upstash, or set ${SINGLE_INSTANCE_REPLAY_ACK_ENV}=true only for a guaranteed single-instance deployment.`,
      );
    }
    return undefined;
  }

  if (!hasRedisUrl && hasUpstashUrl) {
    let parsed: URL;
    try {
      parsed = new URL(upstashUrl as string);
    } catch {
      throw new Error("Upstash webhook replay storage URL is invalid");
    }
    if (parsed.protocol !== "https:") {
      throw new Error("Upstash webhook replay storage URL must use HTTPS");
    }
    if (parsed.username || parsed.password) {
      throw new Error("Upstash webhook replay storage URL must not contain credentials");
    }
  }

  const kind = hasRedisUrl ? "redis" : "upstash";
  return new RedisWebhookDeliveryStore(redisFactory(kind, env));
}
