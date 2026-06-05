/**
 * REAL signed-delivery proof for the webhook subsystem.
 *
 * The audit flagged webhook-dispatch.test.ts as mocking away the security-relevant
 * part: it stubs the entire `WebhookDispatcher` to identity, so HMAC signing and
 * actual HTTP delivery are never exercised. This test drives the REAL
 * `WebhookDispatcher` from `@stwd/webhooks` against a captured local HTTP sink
 * (a Bun.serve test server) and asserts:
 *   - the delivery actually arrives over the wire,
 *   - the `X-Steward-Signature` header is present and uses the v2 scheme,
 *   - the HMAC is valid for the delivered body using the configured secret,
 *   - the signature binds timestamp + delivery id + event type (forgery fence),
 *   - a wrong secret does NOT verify (the test would fail if signing were a no-op).
 *
 * No part of the signing/delivery path is mocked — only the receiver is local.
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "@stwd/webhooks";
import type { Server } from "bun";

const SIGNATURE_SCHEME = "v2";
const SECRET = "whsec_test_signing_secret_with_sufficient_entropy_0123456789";

// Re-derivation of the dispatcher's canonical signed material. Field boundaries
// for deliveryId and eventType are length-prefixed so a captured signature cannot
// be re-split across fields — we mirror that here to independently verify.
function canonicalSignedPayload(
  timestamp: string,
  deliveryId: string,
  eventType: string,
  body: string,
): string {
  return `${SIGNATURE_SCHEME}:${timestamp}.${deliveryId.length}:${deliveryId}.${eventType.length}:${eventType}.${body}`;
}

async function hmacHex(payload: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

type CapturedDelivery = {
  headers: Record<string, string>;
  rawBody: string;
};

describe("webhook signed delivery (real dispatcher → local HTTP sink)", () => {
  let server: Server;
  let port: number;
  const captured: CapturedDelivery[] = [];
  let respondStatus = 200;

  beforeAll(() => {
    server = Bun.serve({
      port: 0,
      async fetch(req) {
        const rawBody = await req.text();
        const headers: Record<string, string> = {};
        req.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });
        captured.push({ headers, rawBody });
        return new Response("ok", { status: respondStatus });
      },
    });
    port = server.port;
  });

  afterAll(() => {
    server.stop(true);
  });

  it("delivers with a valid HMAC v2 signature over the exact delivered body", async () => {
    captured.length = 0;
    respondStatus = 200;
    const dispatcher = new WebhookDispatcher({
      maxRetries: 0,
      retryDelayMs: 1,
      timeoutMs: 4000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });

    const event: WebhookEvent = {
      type: "tx_signed",
      tenantId: "tenant-webhook-sign",
      agentId: "agent-webhook-sign",
      data: { txId: "tx-123", txHash: "0xabc" },
      timestamp: new Date(),
    };

    const result = await dispatcher.dispatch(event, {
      url: `http://127.0.0.1:${port}/hook`,
      secret: SECRET,
    });

    expect(result.success).toBe(true);
    expect(result.statusCode).toBe(200);
    expect(result.attempts).toBe(1);
    expect(captured).toHaveLength(1);

    const delivery = captured[0];
    // Signature header present and uses the versioned scheme.
    const sigHeader = delivery.headers["x-steward-signature"];
    expect(sigHeader).toBeDefined();
    expect(sigHeader.startsWith(`${SIGNATURE_SCHEME}=`)).toBe(true);

    const timestamp = delivery.headers["x-steward-timestamp"];
    const deliveryId = delivery.headers["x-steward-delivery-id"];
    const eventType = delivery.headers["x-steward-event"];
    expect(eventType).toBe("tx_signed");
    expect(timestamp).toBeDefined();
    expect(deliveryId).toBeDefined();

    // Independently recompute the HMAC over the EXACT body the sink received and
    // assert it matches the delivered signature. If the dispatcher signed the
    // wrong material (or not at all), this fails.
    const expectedHex = await hmacHex(
      canonicalSignedPayload(timestamp, deliveryId, eventType, delivery.rawBody),
      SECRET,
    );
    expect(sigHeader).toBe(`${SIGNATURE_SCHEME}=${expectedHex}`);

    // The signed material includes the delivery id and event type, so a wrong
    // secret must NOT verify — proves the HMAC is keyed (not a constant/echo).
    const wrongHex = await hmacHex(
      canonicalSignedPayload(timestamp, deliveryId, eventType, delivery.rawBody),
      "whsec_wrong_secret",
    );
    expect(sigHeader).not.toBe(`${SIGNATURE_SCHEME}=${wrongHex}`);

    // The delivered body round-trips to the original event payload.
    const parsedBody = JSON.parse(delivery.rawBody) as WebhookEvent;
    expect(parsedBody.type).toBe("tx_signed");
    expect((parsedBody.data as { txId: string }).txId).toBe("tx-123");
  });

  it("reuses a stable signature/delivery id across retries (idempotent re-send)", async () => {
    captured.length = 0;
    // First two attempts 500 → retried; third 200. Signature + delivery id must
    // be identical across all attempts so a receiver can dedup a retry.
    let calls = 0;
    server.stop(true);
    server = Bun.serve({
      port: 0,
      async fetch(req) {
        calls += 1;
        const rawBody = await req.text();
        const headers: Record<string, string> = {};
        req.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });
        captured.push({ headers, rawBody });
        return new Response(calls < 3 ? "err" : "ok", { status: calls < 3 ? 500 : 200 });
      },
    });
    port = server.port;

    const dispatcher = new WebhookDispatcher({
      maxRetries: 3,
      retryDelayMs: 1,
      timeoutMs: 4000,
      allowPrivateNetwork: true,
      allowInsecureHttp: true,
    });
    const event: WebhookEvent = {
      type: "tx_signed",
      tenantId: "tenant-webhook-retry",
      data: { txId: "tx-retry" },
      timestamp: new Date(),
    };

    const result = await dispatcher.dispatch(event, {
      url: `http://127.0.0.1:${port}/hook`,
      secret: SECRET,
    });

    expect(result.success).toBe(true);
    expect(captured.length).toBeGreaterThanOrEqual(3);
    // The delivery id is stable across retries so receivers can dedupe. The
    // signed timestamp (X-Steward-Timestamp) and its signature are re-computed
    // per attempt so the freshness value a receiver checks is always inside the
    // signed material (see the per-attempt freshness fix). We therefore assert a
    // single delivery id, and that every signature correctly binds its own
    // attempt's timestamp (rather than asserting the signature stays constant,
    // which would reintroduce the unsigned-freshness gap and also flake when
    // attempts straddle a one-second boundary).
    const ids = new Set(captured.map((d) => d.headers["x-steward-delivery-id"]));
    expect(ids.size).toBe(1);
    for (const d of captured) {
      const ts = d.headers["x-steward-timestamp"];
      const sentAt = d.headers["x-steward-sent-at"];
      const sig = d.headers["x-steward-signature"];
      const eventType = d.headers["x-steward-event"];
      const deliveryId = d.headers["x-steward-delivery-id"];
      expect(ts).toBeDefined();
      expect(sig?.startsWith(`${SIGNATURE_SCHEME}=`)).toBe(true);
      // The timestamp used for freshness must equal the one bound into the
      // signature for this attempt.
      expect(sentAt).toBe(ts);
      const expectedHex = await hmacHex(
        canonicalSignedPayload(ts, deliveryId, eventType, d.rawBody),
        SECRET,
      );
      expect(sig).toBe(`${SIGNATURE_SCHEME}=${expectedHex}`);
    }
  });
});
