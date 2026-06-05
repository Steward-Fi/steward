import { describe, expect, it } from "bun:test";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";

const SECRET = "super-secret-webhook-key";

const makeEvent = (overrides: Partial<WebhookEvent> = {}): WebhookEvent => ({
  type: "tx_signed",
  tenantId: "tenant-a",
  agentId: "agent-a",
  data: { txHash: "0xabc", amount: "100" },
  timestamp: new Date("2026-05-30T09:00:00.000Z"),
  ...overrides,
});

type CapturedRequest = { headers: IncomingMessage["headers"]; bodyText: string };

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function withWebhookServer(statuses: number[]) {
  const requests: CapturedRequest[] = [];
  let index = 0;
  const server = createServer(async (req, res) => {
    requests.push({ headers: req.headers, bodyText: await readBody(req) });
    const status = statuses[index] ?? statuses[statuses.length - 1] ?? 200;
    index += 1;
    res.writeHead(status, { "Content-Type": "text/plain" });
    res.end(status >= 200 && status < 300 ? "ok" : "error");
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
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

// Regression for Steward-Fi/steward#103 and #115: a slow retry must carry a
// fresh per-attempt timestamp, and that freshness value must be signed while
// the delivery id stays stable for deduplication.
describe("WebhookDispatcher per-attempt sent-at freshness", () => {
  it("emits a fresh signed X-Steward-Sent-At on retry while keeping the delivery id stable", async () => {
    const server = await withWebhookServer([500, 200]);

    try {
      const dispatcher = new WebhookDispatcher({
        maxRetries: 1,
        retryDelayMs: 1_100,
        timeoutMs: 1_000,
        allowPrivateNetwork: true,
        allowInsecureHttp: true,
      });
      const result = await dispatcher.dispatch(makeEvent(), { url: server.url, secret: SECRET });

      expect(result.success).toBe(true);
      expect(server.requests).toHaveLength(2);
      const [first, second] = server.requests;

      // Every attempt carries a numeric (unix seconds) sent-at header.
      const firstSentAt = String(first?.headers["x-steward-sent-at"]);
      const secondSentAt = String(second?.headers["x-steward-sent-at"]);
      expect(firstSentAt).toMatch(/^\d+$/);
      expect(secondSentAt).toMatch(/^\d+$/);

      expect(first?.headers["x-steward-timestamp"]).toBe(firstSentAt);
      expect(second?.headers["x-steward-timestamp"]).toBe(secondSentAt);
      expect(first?.headers["x-steward-delivery-id"]).toBe(
        second?.headers["x-steward-delivery-id"],
      );

      expect(first?.headers["x-steward-signature"]).not.toBe(
        second?.headers["x-steward-signature"],
      );
      expect(Number(secondSentAt)).toBeGreaterThanOrEqual(Number(firstSentAt));
    } finally {
      await server.close();
    }
  });
});
