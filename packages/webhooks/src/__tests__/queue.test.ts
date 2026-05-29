import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo, LookupFunction } from "node:net";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";
import { RetryQueue } from "../queue";

const persistentQueueSource = readFileSync(
  new URL("../persistent-queue.ts", import.meta.url),
  "utf8",
);

const makeEvent = (overrides: Partial<WebhookEvent> = {}): WebhookEvent => ({
  type: "tx_signed",
  tenantId: "test-tenant",
  agentId: "test-agent",
  data: { txHash: "0xabc" },
  timestamp: new Date(),
  ...overrides,
});

type CapturedWebhookRequest = {
  method: string;
  path: string;
  headers: IncomingMessage["headers"];
  bodyText: string;
};

async function readRequestBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const secretBytes = encoder.encode(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes.buffer.slice(
      secretBytes.byteOffset,
      secretBytes.byteOffset + secretBytes.byteLength,
    ) as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const payloadBytes = encoder.encode(payload);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    payloadBytes.buffer.slice(
      payloadBytes.byteOffset,
      payloadBytes.byteOffset + payloadBytes.byteLength,
    ) as ArrayBuffer,
  );
  return toHex(signature);
}

async function startWebhookServer(statuses: number[]) {
  const requests: CapturedWebhookRequest[] = [];
  let responseIndex = 0;
  const server = createServer(async (req, res) => {
    const bodyText = await readRequestBody(req);
    requests.push({
      method: req.method ?? "GET",
      path: req.url ?? "/",
      headers: req.headers,
      bodyText,
    });

    const status = statuses[responseIndex] ?? statuses[statuses.length - 1] ?? 200;
    responseIndex += 1;
    res.writeHead(status, { "Content-Type": "text/plain" });
    res.end(status >= 200 && status < 300 ? "ok" : "error");
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", (error?: Error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  const { port } = server.address() as AddressInfo;
  return {
    webhook: {
      url: `http://127.0.0.1:${port}/hook`,
      secret: "test-secret",
    },
    requests,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    },
  };
}

describe("RetryQueue", () => {
  it("enqueues and delivers a webhook against a real HTTP endpoint", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });
    const server = await startWebhookServer([200]);

    try {
      const queue = new RetryQueue(dispatcher, {
        maxRetries: 3,
        retryDelayMs: 100,
      });
      const event = makeEvent();

      const id = queue.enqueue(event, server.webhook);
      expect(id).toBeTruthy();
      expect(queue.getStats()).toMatchObject({
        pending: 1,
        delivered: 0,
        failed: 0,
      });

      const results = await queue.processQueue();
      expect(results).toHaveLength(1);
      expect(results[0]?.success).toBe(true);
      expect(queue.getStats()).toMatchObject({
        pending: 0,
        delivered: 1,
        failed: 0,
      });
      expect(server.requests).toHaveLength(1);
      expect(server.requests[0]?.method).toBe("POST");
      expect(server.requests[0]?.path).toBe("/hook");
      expect(server.requests[0]?.headers["x-steward-event"]).toBe("tx_signed");
      const timestamp = server.requests[0]?.headers["x-steward-timestamp"];
      const signature = server.requests[0]?.headers["x-steward-signature"];
      // deliveryId is now mandatory: a UUID is generated when the event omits one.
      const deliveryId = server.requests[0]?.headers["x-steward-delivery-id"];
      expect(typeof timestamp).toBe("string");
      expect(typeof signature).toBe("string");
      expect(typeof deliveryId).toBe("string");
      const timestampValue = String(timestamp);
      const signatureValue = String(signature);
      const deliveryIdValue = String(deliveryId);
      expect(timestampValue).toMatch(/^\d+$/);
      expect(signatureValue).toBe(
        `v2=${await signPayload(
          `v2:${timestampValue}.${deliveryIdValue.length}:${deliveryIdValue}.${"tx_signed".length}:tx_signed.${server.requests[0]?.bodyText}`,
          server.webhook.secret,
        )}`,
      );
      expect(JSON.parse(server.requests[0]?.bodyText ?? "{}")).toMatchObject({
        tenantId: "test-tenant",
        agentId: "test-agent",
        deliveryId: deliveryIdValue,
      });
    } finally {
      await server.close();
    }
  });

  it("rejects cleartext HTTP webhook delivery by default", async () => {
    const server = await startWebhookServer([200]);
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1000,
      allowPrivateNetwork: true,
    });

    try {
      const result = await dispatcher.dispatch(makeEvent(), server.webhook);

      expect(result.success).toBe(false);
      expect(result.error).toBe("Webhook URL must use https");
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });

  it("allows cleartext HTTP webhook delivery only with explicit opt-in", async () => {
    const server = await startWebhookServer([200]);
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });

    try {
      const result = await dispatcher.dispatch(makeEvent(), server.webhook);

      expect(result.success).toBe(true);
      expect(server.requests).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it("includes delivery ids in the signed webhook body and headers when provided", async () => {
    const server = await startWebhookServer([200]);
    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        allowPrivateNetwork: true,
        allowInsecureHttp: true,
      });
      const result = await dispatcher.dispatch(
        makeEvent({ deliveryId: "delivery-123" }),
        server.webhook,
      );

      expect(result.success).toBe(true);
      expect(server.requests).toHaveLength(1);
      expect(server.requests[0]?.headers["x-steward-delivery-id"]).toBe("delivery-123");
      const timestamp = String(server.requests[0]?.headers["x-steward-timestamp"]);
      expect(server.requests[0]?.headers["x-steward-signature"]).toBe(
        `v2=${await signPayload(
          `v2:${timestamp}.${"delivery-123".length}:delivery-123.${"tx_signed".length}:tx_signed.${server.requests[0]?.bodyText}`,
          server.webhook.secret,
        )}`,
      );
      expect(JSON.parse(server.requests[0]?.bodyText ?? "{}")).toMatchObject({
        deliveryId: "delivery-123",
      });
    } finally {
      await server.close();
    }
  });

  it("reuses a stable delivery id, timestamp, and signature across in-process retries", async () => {
    const server = await startWebhookServer([500, 200]);
    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 1,
        retryDelayMs: 1,
        allowPrivateNetwork: true,
        allowInsecureHttp: true,
      });
      const result = await dispatcher.dispatch(makeEvent(), server.webhook);

      expect(result.success).toBe(true);
      expect(server.requests).toHaveLength(2);
      const [a, b] = server.requests;
      // A retry must look identical to the first send so a receiver can dedup it.
      expect(a?.headers["x-steward-delivery-id"]).toBe(b?.headers["x-steward-delivery-id"]);
      expect(a?.headers["x-steward-timestamp"]).toBe(b?.headers["x-steward-timestamp"]);
      expect(a?.headers["x-steward-signature"]).toBe(b?.headers["x-steward-signature"]);
      expect(a?.bodyText).toBe(b?.bodyText);
    } finally {
      await server.close();
    }
  });

  it("retries failed deliveries up to maxRetries", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 100,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });
    const server = await startWebhookServer([500, 500]);

    try {
      const queue = new RetryQueue(dispatcher, {
        maxRetries: 2,
        retryDelayMs: 10,
      });
      queue.enqueue(makeEvent(), server.webhook);

      let results = await queue.processQueue();
      expect(results[0]?.success).toBe(false);
      expect(queue.getStats().pending).toBe(1);
      expect(server.requests).toHaveLength(1);

      await new Promise((resolve) => setTimeout(resolve, 20));

      results = await queue.processQueue();
      expect(results[0]?.success).toBe(false);
      expect(queue.getStats()).toMatchObject({
        pending: 0,
        delivered: 0,
        failed: 1,
      });
      expect(server.requests).toHaveLength(2);
    } finally {
      await server.close();
    }
  });

  it("does not process deliveries before their retry time", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 100,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });
    const server = await startWebhookServer([500, 500]);

    try {
      const queue = new RetryQueue(dispatcher, {
        maxRetries: 3,
        retryDelayMs: 5_000,
      });
      queue.enqueue(makeEvent(), server.webhook);

      await queue.processQueue();
      expect(queue.getStats().pending).toBe(1);
      expect(server.requests).toHaveLength(1);

      const results = await queue.processQueue();
      expect(results).toHaveLength(0);
      expect(server.requests).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it("claims persistent deliveries before dispatch to prevent double sends", () => {
    expect(persistentQueueSource).toContain("FOR UPDATE SKIP LOCKED");
    expect(persistentQueueSource).toContain("CLAIM_VISIBILITY_TIMEOUT_MS");
    expect(persistentQueueSource).toContain("\"status\" = 'processing'");
    expect(persistentQueueSource).toContain("OR ${webhookDeliveries.status} = 'processing'");
    expect(persistentQueueSource.indexOf("UPDATE ${webhookDeliveries}")).toBeLessThan(
      persistentQueueSource.indexOf("this.dispatcher.dispatch(event, {"),
    );
  });

  it("uses a no-internal-retry dispatcher for persistent delivery attempts", () => {
    expect(persistentQueueSource).toContain("new WebhookDispatcher({ maxRetries: 0 })");
  });

  it("handles multiple enqueued events", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });
    const server = await startWebhookServer([200, 200, 200]);

    try {
      const queue = new RetryQueue(dispatcher, { maxRetries: 3 });

      queue.enqueue(makeEvent({ agentId: "agent-1" }), server.webhook);
      queue.enqueue(makeEvent({ agentId: "agent-2" }), server.webhook);
      queue.enqueue(makeEvent({ agentId: "agent-3" }), server.webhook);

      expect(queue.getStats().pending).toBe(3);

      const results = await queue.processQueue();
      expect(results).toHaveLength(3);
      expect(results.every((result) => result.success)).toBe(true);
      expect(queue.getStats()).toMatchObject({
        pending: 0,
        delivered: 3,
        failed: 0,
      });
      expect(server.requests).toHaveLength(3);
    } finally {
      await server.close();
    }
  });

  it("blocks DNS rebinding to private addresses at connection time", async () => {
    const server = await startWebhookServer([200]);
    const lookup: LookupFunction = (_hostname, _options, callback) => {
      callback(null, "127.0.0.1", 4);
    };
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1000,
      lookup,
      allowInsecureHttp: true,
    });

    try {
      const result = await dispatcher.dispatch(makeEvent(), {
        url: server.webhook.url.replace("127.0.0.1", "rebind.example.test"),
        secret: server.webhook.secret,
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Webhook host must resolve to a public address");
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });

  it("blocks DNS rebinding to IPv4-mapped private IPv6 addresses", async () => {
    const server = await startWebhookServer([200]);
    const lookup: LookupFunction = (_hostname, _options, callback) => {
      callback(null, "::ffff:7f00:1", 6);
    };
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1000,
      lookup,
      allowInsecureHttp: true,
    });

    try {
      const result = await dispatcher.dispatch(makeEvent(), {
        url: server.webhook.url.replace("127.0.0.1", "rebind.example.test"),
        secret: server.webhook.secret,
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Webhook host must resolve to a public address");
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });

  it("blocks DNS rebinding to NAT64 and 6to4 embedded private IPv4 addresses", async () => {
    for (const address of ["64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "2002:a9fe:a9fe::"]) {
      const server = await startWebhookServer([200]);
      const lookup: LookupFunction = (_hostname, _options, callback) => {
        callback(null, address, 6);
      };
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1000,
        lookup,
        allowInsecureHttp: true,
      });

      try {
        const result = await dispatcher.dispatch(makeEvent(), {
          url: server.webhook.url.replace("127.0.0.1", "rebind.example.test"),
          secret: server.webhook.secret,
        });

        expect(result.success).toBe(false);
        expect(result.error).toBe("Webhook host must resolve to a public address");
        expect(server.requests).toHaveLength(0);
      } finally {
        await server.close();
      }
    }
  });

  it("blocks the full IPv6 link-local fe80::/10 range", async () => {
    for (const address of ["fe80::1", "fe90::1", "fea0::1", "febf::1"]) {
      const server = await startWebhookServer([200]);
      const lookup: LookupFunction = (_hostname, _options, callback) => {
        callback(null, address, 6);
      };
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1000,
        lookup,
        allowInsecureHttp: true,
      });

      try {
        const result = await dispatcher.dispatch(makeEvent(), {
          url: server.webhook.url.replace("127.0.0.1", "rebind.example.test"),
          secret: server.webhook.secret,
        });

        expect(result.success).toBe(false);
        expect(result.error).toBe("Webhook host must resolve to a public address");
        expect(server.requests).toHaveLength(0);
      } finally {
        await server.close();
      }
    }
  });

  it("blocks the IPv6 site-local fec0::/10 range", async () => {
    for (const address of ["fec0::1", "fed0::1", "feff::1"]) {
      const server = await startWebhookServer([200]);
      const lookup: LookupFunction = (_hostname, _options, callback) => {
        callback(null, address, 6);
      };
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1000,
        lookup,
        allowInsecureHttp: true,
      });

      try {
        const result = await dispatcher.dispatch(makeEvent(), {
          url: server.webhook.url.replace("127.0.0.1", "rebind.example.test"),
          secret: server.webhook.secret,
        });

        expect(result.success).toBe(false);
        expect(result.error).toBe("Webhook host must resolve to a public address");
        expect(server.requests).toHaveLength(0);
      } finally {
        await server.close();
      }
    }
  });

  it("enforces an absolute response deadline for slow-drip webhooks", async () => {
    const server = createServer(async (req, res) => {
      await readRequestBody(req);
      res.writeHead(200, { "Content-Type": "text/plain" });
      const interval = setInterval(() => {
        res.write(".");
      }, 10);
      res.on("close", () => clearInterval(interval));
    });

    await new Promise<void>((resolve, reject) => {
      server.listen(0, "127.0.0.1", (error?: Error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
    const { port } = server.address() as AddressInfo;
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 50,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });

    try {
      const startedAt = Date.now();
      const result = await dispatcher.dispatch(makeEvent(), {
        url: `http://127.0.0.1:${port}/slow`,
        secret: "test-secret",
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Webhook delivery timed out");
      expect(Date.now() - startedAt).toBeLessThan(500);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  });

  it("uses original webhook config identity and snapshots for persistent retries", () => {
    const processStart = persistentQueueSource.indexOf("async processQueue()");
    expect(processStart).toBeGreaterThanOrEqual(0);
    expect(persistentQueueSource.indexOf("webhookConfigId", processStart)).toBeGreaterThan(
      processStart,
    );
    const dispatchStart = persistentQueueSource.indexOf(
      "this.dispatcher.dispatch(event, {",
      processStart,
    );
    expect(
      persistentQueueSource.indexOf(
        "eq(webhookConfigs.id, delivery.webhookConfigId)",
        processStart,
      ),
    ).toBeLessThan(dispatchStart);
    expect(
      persistentQueueSource.indexOf("eq(webhookConfigs.enabled, true)", processStart),
    ).toBeLessThan(dispatchStart);
    expect(
      persistentQueueSource.indexOf("webhook.url !== delivery.url", processStart),
    ).toBeLessThan(dispatchStart);
    expect(persistentQueueSource.indexOf("webhook.events.length > 0", processStart)).toBeLessThan(
      dispatchStart,
    );
    expect(persistentQueueSource).toContain(
      "Webhook configuration no longer subscribes to this event",
    );
    expect(persistentQueueSource).toContain(
      "Webhook delivery URL no longer matches its original configuration",
    );
    expect(persistentQueueSource).toContain("secret: decryptWebhookSecret(delivery.secret)");
    expect(persistentQueueSource).toContain("events: delivery.events ?? undefined");
    expect(persistentQueueSource).toContain(
      "Webhook delivery is missing original configuration snapshot",
    );
    expect(persistentQueueSource).not.toContain("this.dispatcher.dispatch(event, delivery.url)");
  });
});
