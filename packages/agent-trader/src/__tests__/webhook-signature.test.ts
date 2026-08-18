import { describe, expect, it } from "bun:test";
import { createServer } from "node:net";
import { signWebhookPayload } from "@stwd/sdk";
import type { WebhookEvent } from "@stwd/shared";
import { createWebhookServer } from "../webhook";
import {
  createConfiguredWebhookDeliveryStore,
  createUpstashReplaySetClient,
  MemoryWebhookDeliveryStore,
  RedisWebhookDeliveryStore,
  type WebhookDeliveryStore,
} from "../webhook-delivery-store";

const SECRET = "agent-trader-webhook-secret";

/** Produce a v2 (nonce/event-bound) signature header + delivery id for a body. */
async function v2Headers(
  body: string,
  eventType: string,
  deliveryId = "del-1",
): Promise<Record<string, string>> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const canonical = `v2:${timestamp}.${deliveryId.length}:${deliveryId}.${eventType.length}:${eventType}.${body}`;
  const signature = `v2=${await signWebhookPayload(canonical, SECRET)}`;
  return {
    "Content-Type": "application/json",
    "X-Steward-Timestamp": timestamp,
    "X-Steward-Event": eventType,
    "X-Steward-Delivery-Id": deliveryId,
    "X-Steward-Signature": signature,
  };
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Failed to allocate a test port")));
        return;
      }
      const port = address.port;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function makeEvent(): WebhookEvent {
  return {
    type: "tx_confirmed",
    tenantId: "tenant-1",
    agentId: "agent-1",
    timestamp: new Date().toISOString(),
    data: { txHash: "0xabc" },
  } as WebhookEvent;
}

describe("agent trader webhook receiver signatures", () => {
  it("fails closed when no webhook secret is configured", () => {
    expect(() => createWebhookServer(4210)).toThrow("Webhook secret is required");
  });

  it("rejects unsigned forged events when a webhook secret is configured", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET);
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeEvent()),
      });

      expect(response.status).toBe(401);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("accepts events with a valid v2 (nonce/event-bound) signature", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET);
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const headers = await v2Headers(body, "tx_confirmed");

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers,
        body,
      });

      expect(response.status).toBe(200);
      expect(received).toHaveLength(1);
      expect(received[0]?.agentId).toBe("agent-1");
    } finally {
      await server.stop();
    }
  });

  it("dispatches a signed delivery id at most once", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET);
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const headers = await v2Headers(body, "tx_confirmed", "delivery-replay-1");

    await server.start();
    try {
      const first = await fetch(`http://127.0.0.1:${port}`, { method: "POST", headers, body });
      const replay = await fetch(`http://127.0.0.1:${port}`, { method: "POST", headers, body });

      expect(first.status).toBe(200);
      expect(replay.status).toBe(200);
      expect(received).toHaveLength(1);
    } finally {
      await server.stop();
    }
  });

  it("suppresses a duplicate atomically across two server instances sharing a store", async () => {
    const firstPort = await getFreePort();
    const secondPort = await getFreePort();
    const sharedStore = new MemoryWebhookDeliveryStore();
    const firstServer = createWebhookServer(firstPort, SECRET, { deliveryStore: sharedStore });
    const secondServer = createWebhookServer(secondPort, SECRET, { deliveryStore: sharedStore });
    const received: WebhookEvent[] = [];
    firstServer.on("tx_confirmed", (event) => received.push(event));
    secondServer.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const headers = await v2Headers(body, "tx_confirmed", "delivery-shared-store-1");

    await Promise.all([firstServer.start(), secondServer.start()]);
    try {
      const responses = await Promise.all([
        fetch(`http://127.0.0.1:${firstPort}`, { method: "POST", headers, body }),
        fetch(`http://127.0.0.1:${secondPort}`, { method: "POST", headers, body }),
      ]);

      expect(responses.map((response) => response.status)).toEqual([200, 200]);
      expect(received).toHaveLength(1);
    } finally {
      await Promise.all([firstServer.stop(), secondServer.stop()]);
    }
  });

  it("fails closed without dispatch when the replay backend errors", async () => {
    const port = await getFreePort();
    const failingStore: WebhookDeliveryStore = {
      durable: true,
      async claim() {
        throw new Error("redis unavailable");
      },
    };
    const server = createWebhookServer(port, SECRET, { deliveryStore: failingStore });
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const headers = await v2Headers(body, "tx_confirmed", "delivery-store-error-1");

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, { method: "POST", headers, body });
      expect(response.status).toBe(503);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("uses Redis SET NX PX for an atomic, hashed delivery claim", async () => {
    const calls: unknown[][] = [];
    const redis = {
      async set(...args: unknown[]) {
        calls.push(args);
        return "OK";
      },
    };
    const store = new RedisWebhookDeliveryStore(redis as never);

    expect(await store.claim("tenant-secret:delivery-1", 60_000)).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.[0]).toMatch(/^steward:agent-trader:webhook-delivery:[a-f0-9]{64}$/);
    expect(calls[0]?.[0]).not.toContain("tenant-secret");
    expect(calls[0]?.slice(1)).toEqual(["1", "PX", 60_000, "NX"]);
  });

  it("rejects a signed header whose event type differs from the payload", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET);
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const headers = await v2Headers(body, "tx_failed", "delivery-type-confusion-1");

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers,
        body,
      });
      expect(response.status).toBe(401);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("rejects a legacy timestamp signature now that v2 is required", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET);
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signature = await signWebhookPayload(`${timestamp}.${body}`, SECRET);

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Timestamp": timestamp,
          "X-Steward-Signature": signature,
        },
        body,
      });

      expect(response.status).toBe(401);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("rejects a v2 signature whose event-type header was tampered", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET);
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify(makeEvent());
    const headers = await v2Headers(body, "tx_confirmed");
    headers["X-Steward-Event"] = "tx_failed"; // attacker swaps the header post-sign

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers,
        body,
      });

      expect(response.status).toBe(401);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("rejects signed events for the wrong tenant", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET, {
      expectedTenantId: "tenant-1",
      allowedAgentIds: ["agent-1"],
    });
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify({ ...makeEvent(), tenantId: "attacker-tenant" });
    const headers = await v2Headers(body, "tx_confirmed");

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers,
        body,
      });

      expect(response.status).toBe(403);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("rejects signed events for unconfigured agents", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET, {
      expectedTenantId: "tenant-1",
      allowedAgentIds: ["agent-1"],
    });
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    const body = JSON.stringify({ ...makeEvent(), agentId: "attacker-agent" });
    const headers = await v2Headers(body, "tx_confirmed");

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers,
        body,
      });

      expect(response.status).toBe(403);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });

  it("refuses the unsigned-webhook flag in production", () => {
    const prevAllow = process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS;
    const prevEnv = process.env.NODE_ENV;
    try {
      process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS = "true";
      process.env.NODE_ENV = "production";
      // The flag must be ignored in prod, so a missing secret still fails closed.
      expect(() => createWebhookServer(4210)).toThrow("Webhook secret is required");
    } finally {
      if (prevAllow === undefined) delete process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS;
      else process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS = prevAllow;
      if (prevEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevEnv;
    }
  });

  it("honors the unsigned-webhook flag outside production (local dev)", () => {
    const prevAllow = process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS;
    const prevEnv = process.env.NODE_ENV;
    try {
      process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS = "true";
      process.env.NODE_ENV = "development";
      // No throw: unsigned server is allowed in dev.
      const server = createWebhookServer(4210);
      expect(server).toBeDefined();
    } finally {
      if (prevAllow === undefined) delete process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS;
      else process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS = prevAllow;
      if (prevEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevEnv;
    }
  });

  it("requires durable replay storage in production unless single-instance is acknowledged", () => {
    const previousEnv = process.env.NODE_ENV;
    const ackName = "STEWARD_AGENT_TRADER_ACKNOWLEDGE_SINGLE_INSTANCE_REPLAY";
    const previousAck = process.env[ackName];
    try {
      process.env.NODE_ENV = "production";
      delete process.env[ackName];
      expect(() => createWebhookServer(4210, SECRET)).toThrow(
        "Durable webhook replay storage is required in production",
      );

      process.env[ackName] = "true";
      expect(createWebhookServer(4210, SECRET)).toBeDefined();

      delete process.env[ackName];
      expect(() =>
        createWebhookServer(4210, SECRET, { deliveryStore: new MemoryWebhookDeliveryStore() }),
      ).toThrow("Durable webhook replay storage is required in production");
      expect(
        createWebhookServer(4210, SECRET, {
          deliveryStore: new RedisWebhookDeliveryStore({ set: async () => "OK" }),
        }),
      ).toBeDefined();
    } finally {
      if (previousEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousEnv;
      if (previousAck === undefined) delete process.env[ackName];
      else process.env[ackName] = previousAck;
    }
  });

  it("selects configured Redis or Upstash replay storage and rejects partial credentials", () => {
    let factoryCalls = 0;
    const fakeRedis = { set: async () => "OK" };
    const kinds: string[] = [];
    const factory = (kind: "redis" | "upstash") => {
      factoryCalls += 1;
      kinds.push(kind);
      return fakeRedis as never;
    };

    expect(
      createConfiguredWebhookDeliveryStore({ REDIS_URL: "redis://redis:6379" }, factory),
    ).toBeInstanceOf(RedisWebhookDeliveryStore);
    const upstashEnv: NodeJS.ProcessEnv = {
      UPSTASH_REDIS_REST_URL: "https://example.upstash.io",
      UPSTASH_REDIS_REST_TOKEN: "test-token",
    };
    expect(createConfiguredWebhookDeliveryStore(upstashEnv, factory)).toBeInstanceOf(
      RedisWebhookDeliveryStore,
    );
    expect(factoryCalls).toBe(2);
    expect(kinds).toEqual(["redis", "upstash"]);
    expect(() =>
      createConfiguredWebhookDeliveryStore(
        { UPSTASH_REDIS_REST_URL: "https://example.upstash.io" },
        factory,
      ),
    ).toThrow("requires both REST URL and token");
    expect(() =>
      createConfiguredWebhookDeliveryStore(
        {
          UPSTASH_REDIS_REST_URL: "http://example.upstash.io",
          UPSTASH_REDIS_REST_TOKEN: "test-token",
        },
        factory,
      ),
    ).toThrow("must use HTTPS");
    expect(() => createConfiguredWebhookDeliveryStore({ NODE_ENV: "production" }, factory)).toThrow(
      "Durable webhook replay storage is required in production",
    );
    expect(
      createConfiguredWebhookDeliveryStore(
        {
          NODE_ENV: "production",
          STEWARD_AGENT_TRADER_ACKNOWLEDGE_SINGLE_INSTANCE_REPLAY: "true",
        },
        factory,
      ),
    ).toBeUndefined();
  });

  it("rejects cleartext redis:// replay storage in production (SEC-032)", () => {
    // The default factory builds a raw ioredis client; it must route through
    // the shared assertRedisUrlTls so a remote cleartext REDIS_URL fails
    // closed in production. The assertion throws before any socket opens.
    const previousEnv = process.env.NODE_ENV;
    const previousOverride = process.env.STEWARD_ALLOW_INSECURE_REDIS;
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    try {
      expect(() =>
        createConfiguredWebhookDeliveryStore({
          NODE_ENV: "production",
          REDIS_URL: "redis://redis.example.internal:6379",
        }),
      ).toThrow("rediss://");
    } finally {
      if (previousEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousEnv;
      if (previousOverride === undefined) delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
      else process.env.STEWARD_ALLOW_INSECURE_REDIS = previousOverride;
    }
  });

  it("uses the supplied environment for replay-store TLS policy", () => {
    const previousEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "development";
    try {
      expect(() =>
        createConfiguredWebhookDeliveryStore({
          NODE_ENV: "production",
          REDIS_URL: "redis://redis.example.internal:6379",
        }),
      ).toThrow("rediss://");
    } finally {
      if (previousEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousEnv;
    }
  });

  it("times out and aborts a stalled Upstash replay claim with a sanitized error", async () => {
    let aborted = false;
    const stalledFetch = ((_input: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("secret backend diagnostic containing test-token"));
        });
      })) as typeof fetch;
    const client = createUpstashReplaySetClient("https://example.upstash.io", "test-token", {
      fetchImpl: stalledFetch,
      timeoutMs: 5,
    });

    const claim = client.set("key", "1", "PX", 60_000, "NX");
    await expect(claim).rejects.toThrow("Upstash replay claim request failed");
    await expect(claim).rejects.not.toThrow("test-token");
    expect(aborted).toBe(true);
  });

  it("bounds and cancels an oversized Upstash response without leaking its body", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`sensitive-body-${"x".repeat(128)}`));
      },
      cancel() {
        cancelled = true;
      },
    });
    const oversizedFetch = (async () => new Response(body, { status: 200 })) as typeof fetch;
    const client = createUpstashReplaySetClient("https://example.upstash.io", "test-token", {
      fetchImpl: oversizedFetch,
      maxResponseBytes: 16,
    });

    const claim = client.set("key", "1", "PX", 60_000, "NX");
    await expect(claim).rejects.toThrow("Upstash replay claim response too large");
    await expect(claim).rejects.not.toThrow("sensitive-body");
    expect(cancelled).toBe(true);
  });

  it("times out and cancels an Upstash response body that stalls after headers", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
    });
    const stalledBodyFetch = (async () => new Response(body, { status: 200 })) as typeof fetch;
    const client = createUpstashReplaySetClient("https://example.upstash.io", "test-token", {
      fetchImpl: stalledBodyFetch,
      timeoutMs: 5,
    });

    await expect(client.set("key", "1", "PX", 60_000, "NX")).rejects.toThrow(
      "Upstash replay claim request failed",
    );
    expect(cancelled).toBe(true);
  });

  it("rejects oversized webhook bodies before dispatch", async () => {
    const port = await getFreePort();
    const server = createWebhookServer(port, SECRET, { maxBodyBytes: 1024 });
    const received: WebhookEvent[] = [];
    server.on("tx_confirmed", (event) => received.push(event));

    await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...makeEvent(), data: { blob: "x".repeat(2048) } }),
      });

      expect(response.status).toBe(413);
      expect(received).toHaveLength(0);
    } finally {
      await server.stop();
    }
  });
});
