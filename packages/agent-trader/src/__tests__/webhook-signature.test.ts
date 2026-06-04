import { describe, expect, it } from "bun:test";
import { createServer } from "node:net";
import { signWebhookPayload } from "@stwd/sdk";
import type { WebhookEvent } from "@stwd/shared";
import { createWebhookServer } from "../webhook";

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
