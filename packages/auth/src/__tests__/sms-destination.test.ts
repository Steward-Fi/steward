import { describe, expect, test } from "bun:test";

import { PhoneAuth } from "../phone";
import {
  isSmsDestinationAllowed,
  parseAllowedSmsCountryCodes,
  SmsDestinationNotAllowedError,
  smsSendGlobalMaxPerHour,
} from "../sms-destination";
import { MockSmsInbox, MockSmsProvider } from "../sms-provider";

describe("SMS destination policy", () => {
  test("default policy: US and Canada only, NANP Caribbean and toll-free refused", () => {
    // Destinations seen in the 2026-10 pumping incident.
    for (const phone of [
      "+998995073528", // Uzbekistan
      "+94785196335", // Sri Lanka
      "+9779747694922", // Nepal
      "+21629473789", // Tunisia
      "+25765517171", // Burundi
      "+18765550123", // Jamaica (+1 876)
      "+12425550123", // Bahamas (+1 242)
      "+18005550123", // toll-free
      "+19005550123", // premium
    ]) {
      expect(isSmsDestinationAllowed(phone, {})).toBe(false);
    }
    for (const phone of ["+14155550123", "+16475550123", "+17875550123"]) {
      expect(isSmsDestinationAllowed(phone, {})).toBe(true);
    }
  });

  test("allowlist is configurable and never fails open on a malformed value", () => {
    expect(
      isSmsDestinationAllowed("+447700900123", { STEWARD_SMS_ALLOWED_COUNTRY_CODES: "1,44" }),
    ).toBe(true);
    expect(
      isSmsDestinationAllowed("+18765550123", { STEWARD_SMS_ALLOWED_COUNTRY_CODES: "1,1876" }),
    ).toBe(true);
    expect(
      isSmsDestinationAllowed("+998995073528", { STEWARD_SMS_ALLOWED_COUNTRY_CODES: "garbage" }),
    ).toBe(false);
    expect(
      isSmsDestinationAllowed("+998995073528", { STEWARD_SMS_ALLOWED_COUNTRY_CODES: "*" }),
    ).toBe(true);
    expect(parseAllowedSmsCountryCodes(" +44 , 1 ")).toEqual(["44", "1"]);
  });

  test("hourly budget parses only complete non-negative safe integers", () => {
    expect(smsSendGlobalMaxPerHour({})).toBe(300);
    for (const raw of ["0invalid", "0.5", "-1", "Infinity", "9007199254740992"]) {
      expect(smsSendGlobalMaxPerHour({ STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR: raw })).toBe(300);
    }
    expect(smsSendGlobalMaxPerHour({ STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR: "0" })).toBe(0);
    expect(smsSendGlobalMaxPerHour({ STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR: "1e3" })).toBe(1000);
  });
});

describe("PhoneAuth sendGuard", () => {
  test("a refusing guard runs before the provider and the code is never delivered", async () => {
    const phone = "+998995073528";
    MockSmsInbox.clear(phone);
    const seen: string[] = [];
    const auth = new PhoneAuth({
      provider: new MockSmsProvider(),
      sendGuard: async (to) => {
        seen.push(to);
        if (!isSmsDestinationAllowed(to, {})) throw new SmsDestinationNotAllowedError();
      },
    });
    await expect(auth.sendOtp(phone, "login:test", "sms")).rejects.toBeInstanceOf(
      SmsDestinationNotAllowedError,
    );
    expect(seen).toEqual([phone]);
    expect(MockSmsInbox.all(phone)).toHaveLength(0);
  });

  test("an admitting guard leaves delivery unchanged", async () => {
    const phone = "+14155550188";
    MockSmsInbox.clear(phone);
    const auth = new PhoneAuth({ provider: new MockSmsProvider(), sendGuard: async () => {} });
    await auth.sendOtp(phone, "login:test", "sms");
    expect(MockSmsInbox.all(phone)).toHaveLength(1);
  });
});
