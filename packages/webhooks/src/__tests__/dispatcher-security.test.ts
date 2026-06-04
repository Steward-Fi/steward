import { describe, expect, it } from "bun:test";
import { createHmac } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";
import { RetryQueue } from "../queue";

const SECRET = "super-secret-webhook-key";
const LOCAL_WEBHOOK_OPTIONS = {
  allowInsecureHttp: true,
  allowPrivateNetwork: true,
};

const makeEvent = (overrides: Partial<WebhookEvent> = {}): WebhookEvent => ({
  type: "tx_signed",
  tenantId: "tenant-a",
  agentId: "agent-a",
  data: { txHash: "0xabc", amount: "100" },
  timestamp: new Date("2026-05-30T09:00:00.000Z"),
  ...overrides,
});

type CapturedRequest = {
  headers: IncomingMessage["headers"];
  bodyText: string;
};

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function withWebhookServer(
  handler: (
    request: CapturedRequest,
  ) => { status: number; body?: string } | Promise<{ status: number; body?: string }>,
) {
  const requests: CapturedRequest[] = [];
  const server = createServer(async (req, res) => {
    const request = { headers: req.headers, bodyText: await readBody(req) };
    requests.push(request);
    const response = await handler(request);
    res.writeHead(response.status, { "Content-Type": "text/plain" });
    res.end(response.body ?? "");
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", (error?: Error) => {
      if (error) reject(error);
      else resolve();
    });
  });

  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/hook`,
    requests,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}

function hmac(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

function expectedSignature(request: CapturedRequest, secret = SECRET): string {
  const timestamp = String(request.headers["x-steward-timestamp"]);
  const deliveryId = String(request.headers["x-steward-delivery-id"]);
  const eventType = String(request.headers["x-steward-event"]);
  const canonical = `v2:${timestamp}.${deliveryId.length}:${deliveryId}.${eventType.length}:${eventType}.${request.bodyText}`;
  return `v2=${hmac(canonical, secret)}`;
}

describe("WebhookDispatcher HMAC signing", () => {
  it("sends an HMAC-SHA256 signature that verifies against the exact request body", async () => {
    const server = await withWebhookServer((request) => {
      const signature = String(request.headers["x-steward-signature"]);
      const expected = expectedSignature(request);
      return { status: signature === expected ? 200 : 401 };
    });

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const result = await dispatcher.dispatch(makeEvent(), { url: server.url, secret: SECRET });

      expect(result.success).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(server.requests).toHaveLength(1);
      expect(server.requests[0]?.headers["x-steward-event"]).toBe("tx_signed");
    } finally {
      await server.close();
    }
  });

  it("proves the signature rejects a tampered payload and a wrong secret", async () => {
    const server = await withWebhookServer((request) => {
      const signature = String(request.headers["x-steward-signature"]);
      const tamperedBody = request.bodyText.replace("0xabc", "0xdef");
      expect(signature).not.toBe(expectedSignature({ ...request, bodyText: tamperedBody }));
      expect(signature).not.toBe(expectedSignature(request, "wrong-secret"));
      return { status: signature === expectedSignature(request) ? 200 : 401 };
    });

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const result = await dispatcher.dispatch(makeEvent(), { url: server.url, secret: SECRET });

      expect(result.success).toBe(true);
      expect(server.requests).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it("does not retry deterministic 4xx responses", async () => {
    const server = await withWebhookServer(() => ({ status: 401, body: "bad signature" }));

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 3,
        retryDelayMs: 5,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const result = await dispatcher.dispatch(makeEvent(), { url: server.url, secret: SECRET });

      expect(result.success).toBe(false);
      expect(result.statusCode).toBe(401);
      expect(result.attempts).toBe(1);
      expect(server.requests).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it("retries transient 5xx responses with exponential backoff until success", async () => {
    const statuses = [500, 502, 200];
    const server = await withWebhookServer(() => ({ status: statuses.shift() ?? 200 }));

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 3,
        retryDelayMs: 10,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const started = Date.now();
      const result = await dispatcher.dispatch(makeEvent(), { url: server.url, secret: SECRET });

      expect(result.success).toBe(true);
      expect(result.attempts).toBe(3);
      expect(server.requests).toHaveLength(3);
      expect(Date.now() - started).toBeGreaterThanOrEqual(25);
    } finally {
      await server.close();
    }
  });

  it("filters out unsubscribed event types without making a network request", async () => {
    const server = await withWebhookServer(() => ({ status: 500 }));

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const result = await dispatcher.dispatch(makeEvent({ type: "tx_failed" }), {
        url: server.url,
        secret: SECRET,
        events: ["tx_signed"],
      });

      expect(result).toEqual({ success: true, attempts: 0 });
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });
});

describe("RetryQueue delivery invariants", () => {
  it("removes a delivered item so repeated processing is idempotent", async () => {
    const server = await withWebhookServer(() => ({ status: 200 }));

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const queue = new RetryQueue(dispatcher, { maxRetries: 2, retryDelayMs: 1 });
      queue.enqueue(makeEvent(), { url: server.url, secret: SECRET });

      expect(await queue.processQueue()).toHaveLength(1);
      expect(await queue.processQueue()).toHaveLength(0);
      expect(server.requests).toHaveLength(1);
      expect(queue.getStats()).toEqual({ pending: 0, delivered: 1, failed: 0 });
    } finally {
      await server.close();
    }
  });

  it("dead-letters after the configured queue attempts and preserves the final failure", async () => {
    const server = await withWebhookServer(() => ({ status: 500, body: "down" }));

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 1_000,
        ...LOCAL_WEBHOOK_OPTIONS,
      });
      const queue = new RetryQueue(dispatcher, { maxRetries: 2, retryDelayMs: 1 });
      queue.enqueue(makeEvent(), { url: server.url, secret: SECRET });

      const first = await queue.processQueue();
      expect(first[0]).toMatchObject({ success: false, attempts: 1, statusCode: 500 });
      expect(queue.getStats()).toEqual({ pending: 1, delivered: 0, failed: 0 });

      await new Promise((resolve) => setTimeout(resolve, 5));
      const second = await queue.processQueue();
      expect(second[0]).toMatchObject({ success: false, attempts: 2, statusCode: 500 });
      expect(queue.getStats()).toEqual({ pending: 0, delivered: 0, failed: 1 });
      expect(server.requests).toHaveLength(2);
    } finally {
      await server.close();
    }
  });
});
