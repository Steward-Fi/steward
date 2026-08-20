import { describe, expect, it } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";

const SECRET = "retry-classification-secret";

const makeEvent = (): WebhookEvent => ({
  type: "tx_signed",
  tenantId: "tenant-a",
  agentId: "agent-a",
  data: { txHash: "0xabc" },
  timestamp: new Date("2026-05-30T09:00:00.000Z"),
});

describe("WebhookDispatcher retry classification (SEC-179)", () => {
  it("does not retry deterministic validation rejections", async () => {
    const dispatcher = new WebhookDispatcher({
      maxRetries: 3,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: true,
    });

    // SSRF-guard rejection: permanent, must not burn maxRetries+1 attempts.
    const ssrf = await dispatcher.dispatch(makeEvent(), {
      url: "http://127.0.0.1:9/hook",
      secret: SECRET,
    });
    expect(ssrf.success).toBe(false);
    expect(ssrf.attempts).toBe(1);
    expect(ssrf.error).toBe("Webhook validation failed");

    // https-scheme rejection (no insecure-http escape hatch): permanent as well.
    const httpsOnly = new WebhookDispatcher({
      maxRetries: 3,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: false,
    });
    const plainHttp = await httpsOnly.dispatch(makeEvent(), {
      url: "http://example.com/hook",
      secret: SECRET,
    });
    expect(plainHttp.success).toBe(false);
    expect(plainHttp.attempts).toBe(1);
    expect(plainHttp.error).toBe("Webhook validation failed");

    const badScheme = await dispatcher.dispatch(makeEvent(), {
      url: "ftp://example.com/hook",
      secret: SECRET,
    });
    expect(badScheme.success).toBe(false);
    expect(badScheme.attempts).toBe(1);

    const unparseable = await dispatcher.dispatch(makeEvent(), {
      url: "not a url",
      secret: SECRET,
    });
    expect(unparseable.success).toBe(false);
    expect(unparseable.attempts).toBe(1);
  });

  it("still retries transient network failures", async () => {
    // A private-network-enabled dispatcher skips the SSRF guard, so a dead
    // loopback port is a plain connection-refused network error: retryable.
    const dispatcher = new WebhookDispatcher({
      maxRetries: 2,
      retryDelayMs: 1,
      timeoutMs: 500,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });

    const result = await dispatcher.dispatch(makeEvent(), {
      url: "http://127.0.0.1:9/hook",
      secret: SECRET,
    });
    expect(result.success).toBe(false);
    expect(result.attempts).toBe(3);
  });

  it("does not return transport exception text", async () => {
    const canary = "https://user:webhook-secret@internal.example/";
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      timeoutMs: 500,
      allowPrivateNetwork: false,
      allowInsecureHttp: true,
      lookup: (_hostname, _options, callback) =>
        callback(new Error(canary), "" as never, 0 as never),
    });

    const result = await dispatcher.dispatch(makeEvent(), {
      url: "http://example.test/hook",
      secret: SECRET,
    });
    expect(result.error).toBe("Webhook delivery failed");
    expect(JSON.stringify(result)).not.toContain(canary);
  });
});
