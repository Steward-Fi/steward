import { describe, expect, it } from "bun:test";
import { createHmac } from "node:crypto";
import { canonicalSignedPayload } from "../dispatcher";
import { verifyWebhookSignature } from "../verify";

const SECRET = "receiver-side-secret";

function sign(input: {
  sentAt: string;
  deliveryId: string;
  eventType: string;
  body: string;
  secret?: string;
}): string {
  const hex = createHmac("sha256", input.secret ?? SECRET)
    .update(canonicalSignedPayload(input.sentAt, input.deliveryId, input.eventType, input.body))
    .digest("hex");
  return `v2=${hex}`;
}

const NOW = 1_800_000_000;
const baseInput = {
  body: '{"type":"tx_signed"}',
  deliveryId: "delivery-123",
  eventType: "tx_signed",
  sentAt: String(NOW),
  secret: SECRET,
  nowSeconds: NOW,
};

describe("verifyWebhookSignature (SEC-177)", () => {
  it("accepts a correctly signed delivery", () => {
    const signature = sign(baseInput);
    expect(verifyWebhookSignature({ ...baseInput, signature })).toBe(true);
  });

  it("rejects a tampered body, wrong secret, and re-split fields", () => {
    const signature = sign(baseInput);
    expect(verifyWebhookSignature({ ...baseInput, signature, body: '{"type":"tx_failed"}' })).toBe(
      false,
    );
    expect(
      verifyWebhookSignature({ ...baseInput, signature: sign({ ...baseInput, secret: "nope" }) }),
    ).toBe(false);
    // Field-boundary shift: same dotted string, different field split.
    const shifted = sign({
      sentAt: baseInput.sentAt,
      deliveryId: "delivery-12",
      eventType: "3tx_signed",
      body: baseInput.body,
    });
    expect(verifyWebhookSignature({ ...baseInput, signature: shifted })).toBe(false);
  });

  it("rejects replays outside the freshness window", () => {
    const stale = { ...baseInput, sentAt: String(NOW - 400) };
    expect(verifyWebhookSignature({ ...stale, signature: sign(stale) })).toBe(false);
    const future = { ...baseInput, sentAt: String(NOW + 400) };
    expect(verifyWebhookSignature({ ...future, signature: sign(future) })).toBe(false);
    const within = { ...baseInput, sentAt: String(NOW - 299) };
    expect(verifyWebhookSignature({ ...within, signature: sign(within) })).toBe(true);
  });

  it("honours a custom tolerance", () => {
    const skewed = { ...baseInput, sentAt: String(NOW - 60), toleranceSeconds: 30 };
    expect(verifyWebhookSignature({ ...skewed, signature: sign(skewed) })).toBe(false);
    expect(
      verifyWebhookSignature({ ...skewed, toleranceSeconds: 120, signature: sign(skewed) }),
    ).toBe(true);
  });

  it("fails closed on malformed headers", () => {
    const signature = sign(baseInput);
    expect(verifyWebhookSignature({ ...baseInput, signature: signature.slice(2) })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature: "v2=nothex" })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature: `v1=${signature.slice(3)}` })).toBe(
      false,
    );
    expect(verifyWebhookSignature({ ...baseInput, signature, sentAt: "soon" })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, deliveryId: "" })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, eventType: "" })).toBe(false);
    // Uppercase hex is not the emitted format; reject rather than coerce.
    expect(verifyWebhookSignature({ ...baseInput, signature: signature.toUpperCase() })).toBe(
      false,
    );
  });

  it("rejects non-canonical timestamps and invalid verifier clocks/tolerances", () => {
    for (const sentAt of [`${NOW}.5`, `${NOW}e0`, `0${NOW}`, "-1"]) {
      const candidate = { ...baseInput, sentAt };
      expect(verifyWebhookSignature({ ...candidate, signature: sign(candidate) })).toBe(false);
    }
    const signature = sign(baseInput);
    expect(verifyWebhookSignature({ ...baseInput, signature, toleranceSeconds: Number.NaN })).toBe(
      false,
    );
    expect(
      verifyWebhookSignature({
        ...baseInput,
        signature,
        toleranceSeconds: Number.POSITIVE_INFINITY,
      }),
    ).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, nowSeconds: Number.NaN })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, toleranceSeconds: 1.5 })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, deliveryId: "   " })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, eventType: "   " })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, secret: "" })).toBe(false);
    expect(verifyWebhookSignature({ ...baseInput, signature, secret: "   " })).toBe(false);
  });
});
