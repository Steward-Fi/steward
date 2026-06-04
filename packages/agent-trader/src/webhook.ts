/**
 * Webhook receiver.
 *
 * Listens for inbound HTTP POST events from Steward and dispatches them to
 * registered handlers.  The server uses Bun.serve when available, falling back
 * to Node's built-in `http` module.
 *
 * Supported event types (from @stwd/shared WebhookEvent):
 *   approval_required  — human review needed before tx proceeds
 *   tx_signed          — transaction was signed and broadcast
 *   tx_confirmed       — on-chain confirmation received
 *   tx_failed          — broadcast / confirmation failure
 *   tx_rejected        — policy or manual rejection
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { verifyWebhookSignature } from "@stwd/sdk";
import type { WebhookEvent } from "@stwd/shared";
import { logError, logInfo, logWebhook } from "./logger.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type WebhookEventType = WebhookEvent["type"];

export type WebhookHandler = (event: WebhookEvent) => void | Promise<void>;

export interface WebhookServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  on(event: WebhookEventType | "*", handler: WebhookHandler): void;
}

export interface WebhookServerOptions {
  expectedTenantId?: string;
  allowedAgentIds?: string[];
  maxBodyBytes?: number;
}

// ─── Internal state ────────────────────────────────────────────────────────────

type HandlerMap = Map<string, WebhookHandler[]>;

type BunServeServer = {
  stop(): void | Promise<void>;
};

type BunServeRuntime = typeof globalThis & {
  Bun?: {
    serve(options: {
      port: number;
      fetch(req: Request): Response | Promise<Response>;
    }): BunServeServer;
  };
};

interface WebhookHeaders {
  get(name: string): string | null | undefined;
}

const DEFAULT_MAX_WEBHOOK_BODY_BYTES = 256 * 1024;

/**
 * Whether unsigned webhooks are permitted. The escape hatch is for local dev
 * only and is hard-disabled in production: mirroring the proxy's
 * `isRedisRequired` production gate, the flag is ignored (with an error logged)
 * when NODE_ENV === "production" so a stray env var cannot strip signature
 * verification on a live deployment.
 */
function allowUnsignedWebhooks(): boolean {
  if (process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS !== "true") return false;
  if (process.env.NODE_ENV === "production") {
    logError(
      "STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS is set but ignored in production; webhook signature verification stays required.",
    );
    return false;
  }
  return true;
}

function buildHandlerMap(): HandlerMap {
  return new Map();
}

function addHandler(map: HandlerMap, event: string, handler: WebhookHandler): void {
  const list = map.get(event) ?? [];
  list.push(handler);
  map.set(event, list);
}

async function dispatchEvent(map: HandlerMap, event: WebhookEvent): Promise<void> {
  const specific = map.get(event.type) ?? [];
  const wildcard = map.get("*") ?? [];

  for (const handler of [...specific, ...wildcard]) {
    try {
      await handler(event);
    } catch (err) {
      logError("Webhook handler threw", err, { eventType: event.type });
    }
  }
}

// ─── Request parsing ──────────────────────────────────────────────────────────

async function parseBody(body: string): Promise<WebhookEvent | null> {
  try {
    const parsed = JSON.parse(body) as WebhookEvent;
    if (!parsed.type || !parsed.tenantId || !parsed.agentId) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function readBunRequestBody(req: Request, maxBytes: number): Promise<string | null> {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maxBytes) return null;
  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export function createWebhookServer(
  port: number,
  secret?: string,
  options: WebhookServerOptions = {},
): WebhookServer {
  if (!secret && !allowUnsignedWebhooks()) {
    throw new Error(
      "Webhook secret is required. Set STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS=true only for local development.",
    );
  }
  const handlers = buildHandlerMap();
  let stopFn: (() => Promise<void>) | null = null;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_WEBHOOK_BODY_BYTES;
  const allowedAgentIds = new Set(options.allowedAgentIds ?? []);

  const handleRequest = async (
    body: string,
    headers: WebhookHeaders,
  ): Promise<{ status: number; message: string }> => {
    if (!body) {
      return { status: 400, message: "Empty body" };
    }
    if (secret) {
      // Verify the nonce/event-bound v2 signature: pass the delivery id and event
      // type headers so a captured event cannot be replayed with a tampered type.
      // Legacy `${ts}.${body}` signatures are now rejected by default (SDK).
      const verification = await verifyWebhookSignature(
        body,
        headers.get("x-steward-signature"),
        secret,
        headers.get("x-steward-timestamp"),
        {
          eventType: headers.get("x-steward-event") ?? null,
          deliveryId: headers.get("x-steward-delivery-id") ?? null,
        },
      );
      if (!verification.valid) {
        return { status: 401, message: "Invalid webhook signature" };
      }
    }

    const event = await parseBody(body);
    if (!event) {
      return { status: 400, message: "Invalid event payload" };
    }
    const eventAgentId = event.agentId;
    if (!eventAgentId) {
      return { status: 400, message: "Invalid event payload" };
    }
    if (options.expectedTenantId && event.tenantId !== options.expectedTenantId) {
      return { status: 403, message: "Webhook tenant mismatch" };
    }
    if (allowedAgentIds.size > 0 && !allowedAgentIds.has(eventAgentId)) {
      return { status: 403, message: "Webhook agent is not allowed" };
    }

    logWebhook({
      event: event.type,
      agentId: eventAgentId,
      data: event.data,
    });

    await dispatchEvent(handlers, event);
    return { status: 200, message: "ok" };
  };

  return {
    on(event: WebhookEventType | "*", handler: WebhookHandler): void {
      addHandler(handlers, event, handler);
    },

    async start(): Promise<void> {
      // Try Bun.serve first (runtime available in bun)
      const bunRuntime = (globalThis as BunServeRuntime).Bun;
      if (bunRuntime) {
        const server = bunRuntime.serve({
          port,
          async fetch(req: Request) {
            if (req.method !== "POST") {
              return new Response("Method Not Allowed", { status: 405 });
            }
            const body = await readBunRequestBody(req, maxBodyBytes);
            if (body === null) {
              return new Response(
                JSON.stringify({ ok: false, message: "Webhook body too large" }),
                {
                  status: 413,
                  headers: { "Content-Type": "application/json" },
                },
              );
            }
            const result = await handleRequest(body, req.headers);
            return new Response(
              JSON.stringify({
                ok: result.status === 200,
                message: result.message,
              }),
              {
                status: result.status,
                headers: { "Content-Type": "application/json" },
              },
            );
          },
        });

        stopFn = async () => server.stop();
        logInfo(`Webhook server listening on port ${port} (Bun)`);
        return;
      }

      // Fallback: Node http
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const http = await import("node:http");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const srv = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
        if (req.method !== "POST") {
          res.writeHead(405);
          res.end("Method Not Allowed");
          return;
        }

        const contentLength = Number(req.headers["content-length"] ?? "0");
        if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) {
          res.writeHead(413, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, message: "Webhook body too large" }));
          req.destroy();
          return;
        }

        let body = "";
        let bodyBytes = 0;
        let tooLarge = false;
        req.on("data", (chunk: { toString(): string }) => {
          const value = chunk.toString();
          bodyBytes += new TextEncoder().encode(value).byteLength;
          if (bodyBytes > maxBodyBytes) {
            tooLarge = true;
            res.writeHead(413, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ ok: false, message: "Webhook body too large" }));
            req.destroy();
            return;
          }
          body += value;
        });
        req.on("end", async () => {
          if (tooLarge) return;
          const result = await handleRequest(body, {
            get(name: string) {
              const value = req.headers[name.toLowerCase()];
              return Array.isArray(value) ? value[0] : value;
            },
          });
          res.writeHead(result.status, {
            "Content-Type": "application/json",
          });
          res.end(
            JSON.stringify({
              ok: result.status === 200,
              message: result.message,
            }),
          );
        });
      });

      await new Promise<void>((resolve) => srv.listen(port, resolve));
      stopFn = () =>
        new Promise<void>((resolve, reject) =>
          srv.close((err?: Error) => (err ? reject(err) : resolve())),
        );
      logInfo(`Webhook server listening on port ${port} (Node http)`);
    },

    async stop(): Promise<void> {
      if (stopFn) await stopFn();
      logInfo("Webhook server stopped");
    },
  };
}

// ─── Default handlers (wired up in loop.ts) ───────────────────────────────────

/**
 * Register standard logging handlers for all Steward event types.
 * Additional handlers (e.g. alerting, state adjustment) can be registered
 * separately with server.on(...).
 */
export function registerDefaultHandlers(server: WebhookServer): void {
  server.on("approval_required", (event) => {
    logInfo("⏳ Approval required — operator action needed", {
      agentId: event.agentId,
      data: event.data,
    });
  });

  server.on("tx_signed", (event) => {
    logInfo("✅ Transaction signed and broadcast", {
      agentId: event.agentId,
      txHash: event.data.txHash,
    });
  });

  server.on("tx_confirmed", (event) => {
    logInfo("⛓️  Transaction confirmed on-chain", {
      agentId: event.agentId,
      txHash: event.data.txHash,
      blockNumber: event.data.blockNumber,
    });
  });

  server.on("tx_failed", (event) => {
    logError("❌ Transaction failed", undefined, {
      agentId: event.agentId,
      data: event.data,
    });
  });

  server.on("tx_rejected", (event) => {
    logError("🚫 Transaction rejected by policy", undefined, {
      agentId: event.agentId,
      data: event.data,
    });
  });
}
