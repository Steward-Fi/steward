import { afterEach, describe, expect, test } from "bun:test";

import { isValidE164, PhoneAuth } from "../phone";
import { MockSmsInbox, MockSmsProvider } from "../sms-provider";

function makeAuth(opts: Partial<ConstructorParameters<typeof PhoneAuth>[0]> = {}) {
  return new PhoneAuth({ provider: new MockSmsProvider(), ...opts });
}

afterEach(() => {
  MockSmsInbox.clear();
});

describe("isValidE164", () => {
  test("accepts standard E.164", () => {
    expect(isValidE164("+14155551234")).toBe(true);
    expect(isValidE164("+447700900000")).toBe(true);
  });

  test("rejects local formats and garbage", () => {
    expect(isValidE164("4155551234")).toBe(false);
    expect(isValidE164("+1-415-555-1234")).toBe(false);
    expect(isValidE164("+0123")).toBe(false);
    expect(isValidE164("")).toBe(false);
    expect(isValidE164(null)).toBe(false);
  });
});

describe("PhoneAuth", () => {
  test("sendOtp dispatches a 6-digit code via the provider", async () => {
    const auth = makeAuth();
    try {
      const phone = "+14155551111";
      await auth.sendOtp(phone);
      const msg = MockSmsInbox.last(phone);
      expect(msg?.code).toMatch(/^\d{6}$/);
    } finally {
      auth.destroy();
    }
  });

  test("verifyOtp accepts the issued code exactly once", async () => {
    const auth = makeAuth();
    try {
      const phone = "+14155552222";
      await auth.sendOtp(phone);
      const code = MockSmsInbox.last(phone)!.code!;
      expect(await auth.verifyOtp(phone, code)).toEqual({ valid: true, phone });
      expect((await auth.verifyOtp(phone, code)).valid).toBe(false);
    } finally {
      auth.destroy();
    }
  });

  test("verifyOtp rejects mismatched phone (no cross-phone reuse)", async () => {
    const auth = makeAuth();
    try {
      const a = "+14155553333";
      const b = "+14155554444";
      await auth.sendOtp(a);
      const code = MockSmsInbox.last(a)!.code!;
      expect((await auth.verifyOtp(b, code)).valid).toBe(false);
      expect((await auth.verifyOtp(a, code)).valid).toBe(true);
    } finally {
      auth.destroy();
    }
  });

  test("verifyOtp rejects expired code", async () => {
    const auth = makeAuth({ tokenTtlMs: 10 });
    try {
      const phone = "+14155555555";
      await auth.sendOtp(phone);
      const code = MockSmsInbox.last(phone)!.code!;
      await new Promise((r) => setTimeout(r, 30));
      expect((await auth.verifyOtp(phone, code)).valid).toBe(false);
    } finally {
      auth.destroy();
    }
  });

  test("sendOtp throws on non-E.164 phone", async () => {
    const auth = makeAuth();
    try {
      await expect(auth.sendOtp("4155551234")).rejects.toThrow();
    } finally {
      auth.destroy();
    }
  });

  test("verifyOtp rejects non-numeric codes silently", async () => {
    const auth = makeAuth();
    try {
      const phone = "+14155556666";
      await auth.sendOtp(phone);
      expect((await auth.verifyOtp(phone, "abcdef")).valid).toBe(false);
    } finally {
      auth.destroy();
    }
  });
});
