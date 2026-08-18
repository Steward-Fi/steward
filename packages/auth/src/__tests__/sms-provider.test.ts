/**
 * sms-provider.test.ts — SEC-061: a failed Twilio send must surface only a
 * generic SmsDeliveryError. The provider error body can carry account/phone
 * metadata, so it is discarded — never thrown, never logged verbatim.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { SmsDeliveryError, TwilioSmsProvider } from "../sms-provider";

const ORIGINAL_FETCH = globalThis.fetch;
const ORIGINAL_WARN = console.warn;

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
  console.warn = ORIGINAL_WARN;
});

const PROVIDER = new TwilioSmsProvider({
  accountSid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  authToken: "twilio-auth-token",
  from: "+14155550000",
});

// A realistic Twilio error payload — it names the account SID and the
// destination number, exactly the metadata that must not propagate.
const TWILIO_ERROR_BODY = JSON.stringify({
  code: 21608,
  message:
    "The number +14155550999 is unverified. Trial accounts cannot send to unverified numbers.",
  more_info: "https://www.twilio.com/docs/errors/21608",
  status: 400,
  account_sid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
});

describe("TwilioSmsProvider failure redaction (SEC-061)", () => {
  test("a failed send throws a generic SmsDeliveryError and discards the provider body", async () => {
    globalThis.fetch = (async () =>
      new Response(TWILIO_ERROR_BODY, {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    const warnings: string[] = [];
    console.warn = (message?: unknown, ...rest: unknown[]) => {
      warnings.push([message, ...rest].join(" "));
    };

    const failure = await PROVIDER.send("+14155550999", "Your code is 123456").then(
      () => null,
      (error: unknown) => error,
    );

    expect(failure).toBeInstanceOf(SmsDeliveryError);
    expect((failure as Error).message).toBe("SMS delivery failed");
    // No provider-body bytes in the thrown error…
    expect((failure as Error).message).not.toContain("21608");
    expect((failure as Error).message).not.toContain("+14155550999");
    expect((failure as Error).message).not.toContain("unverified");
    expect((failure as Error).stack ?? "").not.toContain("21608");

    // …nor in the server-side log line, which may carry the status code only.
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("400");
    expect(warnings[0]).not.toContain("21608");
    expect(warnings[0]).not.toContain("+14155550999");
    expect(warnings[0]).not.toContain("unverified");
    expect(warnings[0]).not.toContain("ACxxxxxxxx");
  });

  test("a successful send resolves without logging", async () => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ sid: "SMxxxxxxxx" }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    const warnings: string[] = [];
    console.warn = (message?: unknown, ...rest: unknown[]) => {
      warnings.push([message, ...rest].join(" "));
    };

    await expect(PROVIDER.send("+14155550999", "Your code is 123456")).resolves.toBeUndefined();
    expect(warnings).toHaveLength(0);
  });
});
