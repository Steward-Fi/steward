import { describe, expect, test } from "bun:test";

import { signWebhookPayload, verifyWebhookSignature } from "../webhook-verify";

const SECRET = "whsec_test_secret_abc123";
const BODY = JSON.stringify({ event: "tx.signed", txId: "0xfeed", agentId: "agent-1" });

describe("verifyWebhookSignature", () => {
  test("accepts a correctly-signed body (no timestamp)", async () => {
    const sig = await signWebhookPayload(BODY, SECRET);
    const result = await verifyWebhookSignature(BODY, sig, SECRET);
    expect(result.valid).toBe(true);
  });

  test("accepts a correctly-signed `${ts}.${body}` form", async () => {
    const ts = Math.floor(Date.now() / 1000);
    const sig = await signWebhookPayload(`${ts}.${BODY}`, SECRET);
    const result = await verifyWebhookSignature(BODY, sig, SECRET, ts);
    expect(result.valid).toBe(true);
  });

  test("rejects when signature is missing", async () => {
    const r = await verifyWebhookSignature(BODY, null, SECRET);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("missing-signature");
  });

  test("rejects when signature is wrong length / different secret", async () => {
    const bad = await signWebhookPayload(BODY, "another-secret");
    const r = await verifyWebhookSignature(BODY, bad, SECRET);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("bad-signature");
  });

  test("rejects when body has been tampered", async () => {
    const sig = await signWebhookPayload(BODY, SECRET);
    const tampered = BODY.replace("0xfeed", "0xdead");
    const r = await verifyWebhookSignature(tampered, sig, SECRET);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("bad-signature");
  });

  test("rejects a stale timestamp beyond tolerance", async () => {
    const ts = 1_000_000_000;
    const sig = await signWebhookPayload(`${ts}.${BODY}`, SECRET);
    const r = await verifyWebhookSignature(BODY, sig, SECRET, ts, {
      nowSec: ts + 1000,
      toleranceSec: 300,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("stale-timestamp");
  });

  test("accepts an old timestamp when tolerance is Infinity", async () => {
    const ts = 1_000_000_000;
    const sig = await signWebhookPayload(`${ts}.${BODY}`, SECRET);
    const r = await verifyWebhookSignature(BODY, sig, SECRET, ts, {
      nowSec: ts + 1_000_000_000,
      toleranceSec: Number.POSITIVE_INFINITY,
    });
    expect(r.valid).toBe(true);
  });

  test("rejects a non-numeric timestamp", async () => {
    const sig = await signWebhookPayload(BODY, SECRET);
    const r = await verifyWebhookSignature(BODY, sig, SECRET, "not-a-number");
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("bad-timestamp");
  });

  test("rejects garbage in the signature header", async () => {
    const r = await verifyWebhookSignature(BODY, "definitely-not-hex!!!", SECRET);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("bad-signature");
  });

  test("rejects an empty signature without throwing", async () => {
    const r = await verifyWebhookSignature(BODY, "", SECRET);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("missing-signature");
  });
});
