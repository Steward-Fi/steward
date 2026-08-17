import { describe, expect, it } from "bun:test";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";

const SECRET = "ssrf-literal-test-secret";

const makeEvent = (): WebhookEvent => ({
  type: "tx_signed",
  tenantId: "tenant-a",
  agentId: "agent-a",
  data: { txHash: "0xabc" },
  timestamp: new Date("2026-05-30T09:00:00.000Z"),
});

async function withLoopbackServer() {
  let hits = 0;
  const server = createServer((_req: IncomingMessage, res) => {
    hits += 1;
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", (error?: Error) => {
      if (error) reject(error);
      else resolve();
    });
  });
  const { port } = server.address() as AddressInfo;
  return {
    port,
    hits: () => hits,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}

describe("WebhookDispatcher SSRF guard for IP-literal URLs", () => {
  // Node's http client skips options.lookup for IPv4 literals, so the guarded
  // lookup alone never fired for these forms (SEC-006). The guard must reject
  // the literal hostname before any socket is opened.
  it("rejects loopback IPv4 literals in every canonicalized form without connecting", async () => {
    const server = await withLoopbackServer();
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: true,
    });

    try {
      for (const url of [
        `http://127.0.0.1:${server.port}/hook`,
        `http://2130706433:${server.port}/hook`, // 127.0.0.1 as decimal
        `http://0x7f000001:${server.port}/hook`, // 127.0.0.1 as hex
        `http://127.1:${server.port}/hook`, // shorthand
      ]) {
        const result = await dispatcher.dispatch(makeEvent(), { url, secret: SECRET });
        expect(result.success).toBe(false);
        expect(result.error).toContain("must resolve to a public address");
      }
      expect(server.hits()).toBe(0);
    } finally {
      await server.close();
    }
  });

  it("rejects private-range and link-local IPv4 literals", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: true,
    });

    for (const url of [
      "http://169.254.169.254/latest/meta-data",
      "http://10.0.0.8/hook",
      "http://192.168.1.1/hook",
      "http://172.16.0.1/hook",
      "http://[::1]/hook",
    ]) {
      const result = await dispatcher.dispatch(makeEvent(), { url, secret: SECRET });
      expect(result.success).toBe(false);
      expect(result.error).toContain("must resolve to a public address");
    }
  });

  it("rejects IPv4-translated and special-use IPv6 literals (SEC-178)", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: true,
    });

    for (const url of [
      "http://[::ffff:0:7f00:1]/hook", // RFC 8215 translated, embeds 127.0.0.1
      "http://[::ffff:0:a00:1]/hook", // translated, embeds 10.0.0.1
      "http://[::ffff:0:ac10:1]/hook", // translated, embeds 172.16.0.1
      "http://[::ffff:7f00:1]/hook", // IPv4-mapped hex form of 127.0.0.1
      "http://[::7f00:1]/hook", // deprecated IPv4-compatible ::/96 form
      "http://[64:ff9b:1:beef::808:808]/hook", // RFC 8215 local-use /48, public IPv4 payload
      "http://[100::5]/hook", // 100::/64 discard-only (RFC 6666)
      "http://[2001:2::1]/hook", // 2001:2::/48 benchmarking (RFC 5180)
    ]) {
      const result = await dispatcher.dispatch(makeEvent(), { url, secret: SECRET });
      expect(result.success).toBe(false);
      expect(result.error).toContain("must resolve to a public address");
    }
  });

  it("does not over-block adjacent public IPv6 prefixes", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: true,
    });

    for (const url of [
      "http://[100:1::]/hook", // outside 100::/64
      "http://[2001:2:1::]/hook", // outside 2001:2::/48
      "http://[::ffff:1:7f00:1]/hook", // words[5] !== 0: not the translated prefix
    ]) {
      const result = await dispatcher.dispatch(makeEvent(), { url, secret: SECRET });
      expect(result.success).toBe(false);
      // Rejected by the network failure path (no route), NOT by the SSRF guard.
      expect(result.error ?? "").not.toContain("must resolve to a public address");
    }
  });

  it("still delivers to loopback when the private-network escape hatch is explicit", async () => {
    const server = await withLoopbackServer();
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 1_000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });

    try {
      const result = await dispatcher.dispatch(makeEvent(), {
        url: `http://127.0.0.1:${server.port}/hook`,
        secret: SECRET,
      });
      expect(result.success).toBe(true);
      expect(server.hits()).toBe(1);
    } finally {
      await server.close();
    }
  });
});
