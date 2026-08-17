import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHmac } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";

const MASTER_SECRET = "legacy-master-secret-for-tests";

const makeEvent = (tenantId: string): WebhookEvent => ({
  type: "tx_signed",
  tenantId,
  agentId: "agent-a",
  data: { txHash: "0xabc" },
  timestamp: new Date("2026-05-30T09:00:00.000Z"),
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

async function withWebhookServer() {
  const requests: CapturedRequest[] = [];
  const server = createServer(async (req, res) => {
    requests.push({ headers: req.headers, bodyText: await readBody(req) });
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("");
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

function canonicalSignedPayload(
  timestamp: string,
  deliveryId: string,
  eventType: string,
  body: string,
): string {
  return `v2:${timestamp}.${deliveryId.length}:${deliveryId}.${eventType.length}:${eventType}.${body}`;
}

function deriveLegacySecret(masterSecret: string, tenantId: string): string {
  return createHmac("sha256", masterSecret)
    .update(`steward-legacy-webhook-secret:${tenantId}`)
    .digest("hex");
}

function signatureFor(request: CapturedRequest, secret: string): string {
  const sentAt = String(request.headers["x-steward-sent-at"]);
  const deliveryId = String(request.headers["x-steward-delivery-id"]);
  const eventType = String(request.headers["x-steward-event"]);
  return `v2=${hmac(canonicalSignedPayload(sentAt, deliveryId, eventType, request.bodyText), secret)}`;
}

describe("WebhookDispatcher legacy string-URL signing (SEC-101)", () => {
  const ORIGINAL_SECRET = process.env.STEWARD_WEBHOOK_SECRET;

  beforeAll(() => {
    process.env.STEWARD_WEBHOOK_SECRET = MASTER_SECRET;
  });

  afterAll(() => {
    if (ORIGINAL_SECRET === undefined) delete process.env.STEWARD_WEBHOOK_SECRET;
    else process.env.STEWARD_WEBHOOK_SECRET = ORIGINAL_SECRET;
  });

  it("signs the legacy path with a per-tenant derived key, not the global master secret", async () => {
    const server = await withWebhookServer();
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1_000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });

    try {
      // Bare string URL — the legacy tenant-config fan-out form.
      const resultA = await dispatcher.dispatch(makeEvent("tenant-a"), server.url);
      const resultB = await dispatcher.dispatch(makeEvent("tenant-b"), server.url);
      expect(resultA.success).toBe(true);
      expect(resultB.success).toBe(true);
      expect(server.requests).toHaveLength(2);

      const [requestA, requestB] = server.requests;
      const signatureA = String(requestA?.headers["x-steward-signature"]);
      const signatureB = String(requestB?.headers["x-steward-signature"]);

      // Tenant A's delivery verifies under A's derived key only.
      expect(signatureA).toBe(signatureFor(requestA!, deriveLegacySecret(MASTER_SECRET, "tenant-a")));
      expect(signatureA).not.toBe(
        signatureFor(requestA!, deriveLegacySecret(MASTER_SECRET, "tenant-b")),
      );
      // Tenant B's delivery verifies under B's derived key only.
      expect(signatureB).toBe(signatureFor(requestB!, deriveLegacySecret(MASTER_SECRET, "tenant-b")));
      expect(signatureB).not.toBe(
        signatureFor(requestB!, deriveLegacySecret(MASTER_SECRET, "tenant-a")),
      );
      // Neither is signed with the raw process-wide master secret.
      expect(signatureA).not.toBe(signatureFor(requestA!, MASTER_SECRET));
      expect(signatureB).not.toBe(signatureFor(requestB!, MASTER_SECRET));
    } finally {
      await server.close();
    }
  });

  it("still requires STEWARD_WEBHOOK_SECRET for the string form", async () => {
    delete process.env.STEWARD_WEBHOOK_SECRET;
    const dispatcher = new WebhookDispatcher({ maxRetries: 0, timeoutMs: 1_000 });
    await expect(dispatcher.dispatch(makeEvent("tenant-a"), "https://example.com/hook")).rejects.toThrow(
      "Webhook secret is required",
    );
  });
});
