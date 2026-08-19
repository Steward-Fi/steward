/**
 * Fail-closed email delivery (elizaOS/eliza#18452).
 *
 * A magic-link/OTP send may return success ONLY after the provider ACCEPTED
 * the message. Before this hardening a rejecting provider left the challenge
 * redeemable behind a 500, and a production deployment without a real
 * provider silently "delivered" via ConsoleProvider and returned ok:true —
 * a false green for a challenge no one could ever receive.
 */
import { afterEach, describe, expect, it } from "bun:test";

import { hashSha256Hex } from "../crypto";
import { EmailAuth } from "../email";
import {
  ConsoleProvider,
  EmailDeliveryError,
  EmailDeliveryNotConfiguredError,
  type EmailDeliveryReceipt,
  type EmailProvider,
  MockEmailInbox,
  MockEmailProvider,
  ResendProvider,
} from "../email-provider";
import { MemoryBackend, type StoreBackend } from "../store-backends";
import { TokenStore } from "../token-store";

class CapturingBackend implements StoreBackend {
  values = new Map<string, { value: string; expiresAt: number }>();
  failWrites = false;
  failActiveWrites = false;
  failActiveWritesAfterCommit = false;
  failReadsAfterActiveCommit = false;
  activeTransitionFailuresAfterCommit = 0;
  failDeletes = false;
  replaceGuardBeforeTransition = false;

  private isActivation(value: string): boolean {
    return (
      value.includes('"status":"active"') ||
      (value.includes('"purpose":"email-login"') && value.includes('"status":"pending"'))
    );
  }

  async set(key: string, value: string, ttlMs: number): Promise<void> {
    if (this.failWrites) throw new Error("durable store unavailable");
    if (this.failActiveWrites && this.isActivation(value)) {
      throw new Error("durable activation unavailable");
    }
    this.values.set(key, { value, expiresAt: Date.now() + ttlMs });
    if (this.failActiveWritesAfterCommit && this.isActivation(value)) {
      throw new Error("durable activation response lost");
    }
  }

  async setIfNotExists(key: string, value: string, ttlMs: number): Promise<boolean> {
    if (await this.get(key)) return false;
    await this.set(key, value, ttlMs);
    return true;
  }

  async get(key: string): Promise<string | null> {
    if (this.failReadsAfterActiveCommit && this.activeTransitionFailuresAfterCommit > 0) {
      throw new Error("durable read unavailable");
    }
    const entry = this.values.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.values.delete(key);
      return null;
    }
    return entry.value;
  }

  async consume(key: string): Promise<string | null> {
    const value = await this.get(key);
    this.values.delete(key);
    return value;
  }

  async transition(
    key: string,
    expected: string,
    desired: string,
    ttlMs: number,
    guard?: { key: string; expected: string },
  ): Promise<boolean> {
    if (guard && this.replaceGuardBeforeTransition) {
      const current = this.values.get(guard.key);
      if (current) current.value = "newer-challenge";
      this.replaceGuardBeforeTransition = false;
    }
    if (guard && this.values.get(guard.key)?.value !== guard.expected) return false;
    const entry = this.values.get(key);
    const current = entry && Date.now() <= entry.expiresAt ? entry.value : null;
    if (current !== expected && current !== desired) return false;
    if (this.failActiveWrites) throw new Error("durable activation unavailable");
    this.values.set(key, { value: desired, expiresAt: Date.now() + ttlMs });
    if (this.failActiveWritesAfterCommit && this.activeTransitionFailuresAfterCommit++ === 0) {
      throw new Error("durable activation response lost");
    }
    return true;
  }

  async delete(key: string): Promise<void> {
    if (this.failDeletes) throw new Error("durable delete unavailable");
    this.values.delete(key);
  }
}

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
const ORIGINAL_CODE_SECRET = process.env.STEWARD_EMAIL_CODE_SECRET;
const ORIGINAL_ALLOW_DEV_SECRETS = process.env.STEWARD_ALLOW_DEV_SECRETS;
const ORIGINAL_ALLOW_DEV_SECRET = process.env.STEWARD_ALLOW_DEV_SECRET;

function restoreEnv(): void {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  if (ORIGINAL_CODE_SECRET === undefined) delete process.env.STEWARD_EMAIL_CODE_SECRET;
  else process.env.STEWARD_EMAIL_CODE_SECRET = ORIGINAL_CODE_SECRET;
  if (ORIGINAL_ALLOW_DEV_SECRETS === undefined) delete process.env.STEWARD_ALLOW_DEV_SECRETS;
  else process.env.STEWARD_ALLOW_DEV_SECRETS = ORIGINAL_ALLOW_DEV_SECRETS;
  if (ORIGINAL_ALLOW_DEV_SECRET === undefined) delete process.env.STEWARD_ALLOW_DEV_SECRET;
  else process.env.STEWARD_ALLOW_DEV_SECRET = ORIGINAL_ALLOW_DEV_SECRET;
}

function buildAuth(provider: EmailProvider | undefined, backend: CapturingBackend): EmailAuth {
  return new EmailAuth({
    from: "login@steward.fi",
    baseUrl: "https://steward.fi",
    ...(provider ? { provider } : {}),
    tokenStore: new TokenStore({ backend }),
    codeVerifierSecret: "fail-closed-test-secret-at-least-32-characters",
  });
}

describe("fail-closed magic-link delivery", () => {
  afterEach(() => {
    restoreEnv();
  });

  it("leaves a delivered-but-rejected challenge durably staged even when delete is unavailable", async () => {
    const backend = new CapturingBackend();
    backend.failDeletes = true;
    let text = "";
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body; // capture what WOULD have been delivered, then reject
          throw new Error("Resend error: API key is invalid");
        },
      },
      backend,
    );

    await expect(
      auth.sendMagicLink("victim@example.com", { tenantId: "tenant-a" }),
    ).rejects.toThrow(EmailDeliveryError);

    const remaining = [...backend.values.keys()].filter((k) => k.startsWith("email-login:"));
    expect(remaining.length).toBeGreaterThan(0);
    expect(
      [...backend.values.values()].some((entry) => entry.value.includes('"delivery_pending"')),
    ).toBe(true);
    expect(
      [...backend.values.values()].some((entry) => entry.value.includes('"status":"active"')),
    ).toBe(false);

    const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(token).not.toBe("");
    expect(code).not.toBe("");
    const linkResult = await auth.verifyMagicLink(token, "victim@example.com", "tenant-a");
    expect(linkResult.valid).toBe(false);
    const codeResult = await auth.verifyEmailLoginCode("victim@example.com", code, "tenant-a");
    expect(codeResult.valid).toBe(false);

    auth.destroy();
  });

  it("bounds provider waits and keeps timed-out credentials staged", async () => {
    expect(
      () =>
        new EmailAuth({
          from: "login@steward.fi",
          baseUrl: "https://steward.fi",
          provider: new MockEmailProvider(),
          tokenStore: new TokenStore({ backend: new CapturingBackend() }),
          codeVerifierSecret: "fail-closed-test-secret-at-least-32-characters",
          deliveryTimeoutMs: Number.MAX_SAFE_INTEGER,
        }),
    ).toThrow("deliveryTimeoutMs must be an integer between");

    const backend = new CapturingBackend();
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider: { send: () => new Promise(() => {}) },
      tokenStore: new TokenStore({ backend }),
      codeVerifierSecret: "fail-closed-test-secret-at-least-32-characters",
      deliveryTimeoutMs: 10,
    });
    await expect(auth.sendMagicLink("timeout@example.com")).rejects.toThrow(EmailDeliveryError);
    expect(
      [...backend.values.values()].some(({ value }) => value.includes('"delivery_pending"')),
    ).toBe(true);
    auth.destroy();
  });

  it("redacts failures from hostile receipt getters", async () => {
    const backend = new CapturingBackend();
    const secret = "receipt-getter-secret-canary";
    const errors: unknown[] = [];
    const originalError = console.error;
    console.error = (...args: unknown[]) => errors.push(args);
    try {
      const auth = buildAuth(
        {
          send: async () =>
            Object.defineProperty({}, "provider", {
              get: () => {
                throw new Error(secret);
              },
            }) as never,
        },
        backend,
      );
      await expect(auth.sendMagicLink("getter@example.com")).rejects.toThrow(EmailDeliveryError);
      expect(JSON.stringify(errors)).not.toContain(secret);
      auth.destroy();
    } finally {
      console.error = originalError;
    }
  });

  it("treats a missing acceptance receipt as delivery failure without activating", async () => {
    const backend = new CapturingBackend();
    // Legacy void-returning provider: resolves but produces NO receipt.
    const voidProvider = { send: async () => undefined } as unknown as EmailProvider;
    const auth = buildAuth(voidProvider, backend);

    await expect(auth.sendMagicLink("void@example.com", { tenantId: "tenant-a" })).rejects.toThrow(
      EmailDeliveryError,
    );

    const remaining = [...backend.values.keys()].filter((k) => k.startsWith("email-login:"));
    expect(remaining.length).toBeGreaterThan(0);
    expect(
      [...backend.values.values()].some((entry) => entry.value.includes('"status":"active"')),
    ).toBe(false);

    auth.destroy();
  });

  it("rejects oversized and accessor-backed acceptance receipts without activating", async () => {
    for (const receipt of [
      { provider: "x".repeat(65) },
      { provider: "test", id: "x".repeat(513) },
      Object.defineProperty({}, "provider", {
        get() {
          throw new Error("receipt getter must not run");
        },
      }),
    ]) {
      const backend = new CapturingBackend();
      const auth = buildAuth({ send: async () => receipt as EmailDeliveryReceipt }, backend);
      await expect(
        auth.sendMagicLink("receipt@example.com", { tenantId: "tenant-a" }),
      ).rejects.toThrow(EmailDeliveryError);
      expect(
        [...backend.values.values()].some((entry) => entry.value.includes('"status":"active"')),
      ).toBe(false);
      auth.destroy();
    }
  });

  it("succeeds and keeps the challenge redeemable when the provider returns a receipt", async () => {
    const backend = new CapturingBackend();
    let text = "";
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          return { provider: "test", id: "accepted-1" };
        },
      },
      backend,
    );

    const issued = await auth.sendMagicLink("ok@example.com", { tenantId: "tenant-a" });
    expect(await auth.getEmailLoginStatus(issued.challengeId, issued.pollSecret)).toMatchObject({
      status: "pending",
    });
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
    const result = await auth.verifyEmailLoginCode("ok@example.com", code, "tenant-a");
    expect(result.valid).toBe(true);

    auth.destroy();
  });

  it("writes committed credentials in the legacy-readable rolling-deploy format", async () => {
    const backend = new CapturingBackend();
    let text = "";
    const writer = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          return { provider: "test", id: "rolling-compatible" };
        },
      },
      backend,
    );

    await writer.sendMagicLink("rolling@example.com", { tenantId: "tenant-a" });
    const linkAlias = [...backend.values.entries()].find(([key]) =>
      key.startsWith("email-login:link:"),
    )?.[1].value;
    expect(linkAlias).toBeTruthy();
    const oldMagicRecord = JSON.parse(
      backend.values.get(`email-login:pending:${linkAlias}`)?.value ?? "null",
    );
    expect(oldMagicRecord).toMatchObject({ status: "pending", purpose: "email-login" });

    await writer.sendOtp("rolling@example.com", { tenantId: "tenant-a" });
    const otpKey = [...backend.values.entries()].find(([key]) =>
      key.startsWith("email-otp:active:"),
    )?.[1].value;
    const oldOtpRecord = JSON.parse(backend.values.get(otpKey ?? "")?.value ?? "null");
    expect(oldOtpRecord).toEqual({
      email: "rolling@example.com",
      tenantId: "tenant-a",
    });
    expect(text).not.toBe("");
    writer.destroy();
  });

  it("allows exactly one redemption across independent instances sharing a backend", async () => {
    const backend = new MemoryBackend();
    let text = "";
    const config = {
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider: {
        send: async (_to: string, _subject: string, body: string) => {
          text = body;
          return { provider: "test", id: "shared-backend" };
        },
      },
      codeVerifierSecret: "fail-closed-test-secret-at-least-32-characters",
    };
    const writer = new EmailAuth({ ...config, tokenStore: new TokenStore({ backend }) });
    const verifier = new EmailAuth({ ...config, tokenStore: new TokenStore({ backend }) });
    await writer.sendMagicLink("multi@example.com", { tenantId: "tenant-a" });
    const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    const results = await Promise.all([
      writer.verifyMagicLink(token, "multi@example.com", "tenant-a"),
      verifier.verifyMagicLink(token, "multi@example.com", "tenant-a"),
    ]);
    expect(results.filter((result) => result.valid)).toHaveLength(1);
    writer.destroy();
    verifier.destroy();
    backend.destroy();
  });

  it("reads mixed-case OTP records issued by a legacy pod", async () => {
    const backend = new CapturingBackend();
    const auth = buildAuth({ send: async () => ({ provider: "test" }) }, backend);
    const code = "123456";
    const legacyEmail = "MixedCase@Example.com";
    const key = hashSha256Hex(`email-otp:tenant-a:${legacyEmail}:${code}`);
    await backend.set(key, JSON.stringify({ email: legacyEmail, tenantId: "tenant-a" }), 60_000);
    expect(await auth.verifyOtp(legacyEmail, code, "tenant-a")).toBe(true);
    expect(await auth.verifyOtp(legacyEmail, code, "tenant-a")).toBe(false);
    auth.destroy();
  });

  it("never leaks the recipient, token, code, or poll secret through the error or logs", async () => {
    const backend = new CapturingBackend();
    let text = "";
    const originalError = console.error;
    const logged: string[] = [];
    console.error = (...args: unknown[]) => {
      logged.push(args.map(String).join(" "));
    };
    try {
      const auth = buildAuth(
        {
          send: async (to, _subject, body) => {
            text = body;
            throw new Error(`refused delivery to ${to}`);
          },
        },
        backend,
      );

      let thrown: unknown;
      try {
        await auth.sendMagicLink("secret-recipient@example.com", { tenantId: "tenant-a" });
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(EmailDeliveryError);

      const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
      const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
      const message = (thrown as Error).message;
      const allLogs = logged.join("\n");
      for (const surface of [message, allLogs]) {
        expect(surface).not.toContain("secret-recipient");
        expect(surface).not.toContain("@example.com");
        expect(surface).not.toContain(token);
        expect(surface).not.toContain(code);
        expect(surface).not.toContain("refused delivery");
      }

      auth.destroy();
    } finally {
      console.error = originalError;
    }
  });

  it("leaves a rejected OTP durably staged and non-redeemable", async () => {
    const backend = new CapturingBackend();
    backend.failDeletes = true;
    let text = "";
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          throw new Error("provider down");
        },
      },
      backend,
    );

    await expect(auth.sendOtp("otp@example.com", { tenantId: "tenant-a" })).rejects.toThrow(
      EmailDeliveryError,
    );

    expect(backend.values.size).toBeGreaterThan(0);
    expect(
      [...backend.values.values()].some((entry) => entry.value.includes('"delivery_pending"')),
    ).toBe(true);
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(code).not.toBe("");
    expect(await auth.verifyOtp("otp@example.com", code, "tenant-a")).toBe(false);

    auth.destroy();
  });

  it("does not redeem a magic link or companion code while delivery is in flight", async () => {
    const backend = new CapturingBackend();
    let text = "";
    let accept!: () => void;
    const accepted = new Promise<void>((resolve) => {
      accept = resolve;
    });
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          await accepted;
          return { provider: "test", id: "accepted-after-race" };
        },
      },
      backend,
    );

    const sending = auth.sendMagicLink("race@example.com", { tenantId: "tenant-a" });
    while (!text) await Bun.sleep(1);
    const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";

    expect(await auth.verifyMagicLink(token, "race@example.com", "tenant-a")).toMatchObject({
      valid: false,
    });
    expect(await auth.verifyEmailLoginCode("race@example.com", code, "tenant-a")).toMatchObject({
      valid: false,
    });

    accept();
    await sending;
    expect(await auth.verifyMagicLink(token, "race@example.com", "tenant-a")).toMatchObject({
      valid: true,
    });
    auth.destroy();
  });

  it("does not redeem an OTP while delivery is in flight", async () => {
    const backend = new CapturingBackend();
    let text = "";
    let accept!: () => void;
    const accepted = new Promise<void>((resolve) => {
      accept = resolve;
    });
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          await accepted;
          return { provider: "test", id: "accepted-otp-after-race" };
        },
      },
      backend,
    );

    const sending = auth.sendOtp("otp-race@example.com", { tenantId: "tenant-a" });
    while (!text) await Bun.sleep(1);
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(await auth.verifyOtp("otp-race@example.com", code, "tenant-a")).toBe(false);

    accept();
    await sending;
    expect(await auth.verifyOtp("otp-race@example.com", code, "tenant-a")).toBe(true);
    auth.destroy();
  });

  it("does not call the provider when durable staging fails", async () => {
    const backend = new CapturingBackend();
    backend.failWrites = true;
    let sends = 0;
    const auth = buildAuth(
      {
        send: async () => {
          sends += 1;
          return { provider: "test" };
        },
      },
      backend,
    );

    await expect(
      auth.sendMagicLink("store-down@example.com", { tenantId: "tenant-a" }),
    ).rejects.toThrow("durable store unavailable");
    await expect(auth.sendOtp("store-down@example.com", { tenantId: "tenant-a" })).rejects.toThrow(
      "durable store unavailable",
    );
    expect(sends).toBe(0);
    auth.destroy();
  });

  it("keeps accepted magic-link and OTP credentials non-redeemable when activation storage fails", async () => {
    const magicBackend = new CapturingBackend();
    let magicText = "";
    const magicAuth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          magicText = body;
          magicBackend.failActiveWrites = true;
          return { provider: "test", id: "accepted-magic" };
        },
      },
      magicBackend,
    );
    await expect(
      magicAuth.sendMagicLink("activation@example.com", { tenantId: "tenant-a" }),
    ).rejects.toThrow(EmailDeliveryError);
    const token = magicText.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    const companionCode = magicText.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(
      await magicAuth.verifyMagicLink(token, "activation@example.com", "tenant-a"),
    ).toMatchObject({ valid: false });
    expect(
      await magicAuth.verifyEmailLoginCode("activation@example.com", companionCode, "tenant-a"),
    ).toMatchObject({ valid: false });

    const otpBackend = new CapturingBackend();
    let otpText = "";
    const otpAuth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          otpText = body;
          otpBackend.failActiveWrites = true;
          return { provider: "test", id: "accepted-otp" };
        },
      },
      otpBackend,
    );
    await expect(
      otpAuth.sendOtp("activation-otp@example.com", { tenantId: "tenant-a" }),
    ).rejects.toThrow(EmailDeliveryError);
    const otpCode = otpText.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(await otpAuth.verifyOtp("activation-otp@example.com", otpCode, "tenant-a")).toBe(false);

    magicAuth.destroy();
    otpAuth.destroy();
  });

  it("confirms a committed activation when the storage acknowledgement is lost", async () => {
    const backend = new CapturingBackend();
    let text = "";
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          backend.failActiveWritesAfterCommit = true;
          backend.failReadsAfterActiveCommit = true;
          return { provider: "test", id: "accepted-before-ack-loss" };
        },
      },
      backend,
    );

    await auth.sendMagicLink("ack-loss@example.com", { tenantId: "tenant-a" });
    backend.failReadsAfterActiveCommit = false;
    const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    expect(await auth.verifyMagicLink(token, "ack-loss@example.com", "tenant-a")).toMatchObject({
      valid: true,
    });
    auth.destroy();
  });

  it("keeps only the newest concurrently delivered challenge redeemable", async () => {
    const backend = new CapturingBackend();
    const messages: string[] = [];
    const accepts: Array<() => void> = [];
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          messages.push(body);
          await new Promise<void>((resolve) => accepts.push(resolve));
          return { provider: "test", id: `accepted-${messages.length}` };
        },
      },
      backend,
    );

    const firstSend = auth.sendMagicLink("supersede@example.com", { tenantId: "tenant-a" });
    while (messages.length < 1) await Bun.sleep(1);
    const secondSend = auth.sendMagicLink("supersede@example.com", { tenantId: "tenant-a" });
    while (messages.length < 2) await Bun.sleep(1);
    accepts[1]?.();
    await secondSend;
    accepts[0]?.();
    await expect(firstSend).rejects.toThrow(EmailDeliveryError);

    const firstToken = messages[0]?.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    const secondToken = messages[1]?.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    expect(
      await auth.verifyMagicLink(firstToken, "supersede@example.com", "tenant-a"),
    ).toMatchObject({ valid: false });
    expect(
      await auth.verifyMagicLink(secondToken, "supersede@example.com", "tenant-a"),
    ).toMatchObject({ valid: true });
    auth.destroy();
  });

  it("does not activate after the target is superseded at the commit boundary", async () => {
    const backend = new CapturingBackend();
    let text = "";
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          text = body;
          backend.replaceGuardBeforeTransition = true;
          return { provider: "test", id: "accepted-before-supersede" };
        },
      },
      backend,
    );

    await expect(
      auth.sendMagicLink("commit-race@example.com", { tenantId: "tenant-a" }),
    ).rejects.toThrow(EmailDeliveryError);
    const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    expect(await auth.verifyMagicLink(token, "commit-race@example.com", "tenant-a")).toMatchObject({
      valid: false,
    });
    auth.destroy();
  });

  it("supersedes an accepted OTP when the same target retries", async () => {
    const backend = new CapturingBackend();
    const messages: string[] = [];
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          messages.push(body);
          return { provider: "test", id: `accepted-${messages.length}` };
        },
      },
      backend,
    );

    await auth.sendOtp("otp-retry@example.com", { tenantId: "tenant-a" });
    await auth.sendOtp("otp-retry@example.com", { tenantId: "tenant-a" });
    const firstCode = messages[0]?.match(/\b(\d{6})\b/)?.[1] ?? "";
    const secondCode = messages[1]?.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(await auth.verifyOtp("otp-retry@example.com", firstCode, "tenant-a")).toBe(false);
    expect(await auth.verifyOtp("otp-retry@example.com", secondCode, "tenant-a")).toBe(true);
    auth.destroy();
  });

  it("redeems active wrapper records emitted before the rolling-format fix", async () => {
    const backend = new CapturingBackend();
    const messages: string[] = [];
    const auth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          messages.push(body);
          return { provider: "test", id: `accepted-${messages.length}` };
        },
      },
      backend,
    );

    await auth.sendMagicLink("active-wrapper@example.com", { tenantId: "tenant-a" });
    const magicRecord = [...backend.values.values()].find((entry) =>
      entry.value.includes('"purpose":"email-login"'),
    );
    expect(magicRecord).toBeDefined();
    if (magicRecord) {
      magicRecord.value = JSON.stringify({ ...JSON.parse(magicRecord.value), status: "active" });
    }
    const token = messages[0]?.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    expect(
      await auth.verifyMagicLink(token, "active-wrapper@example.com", "tenant-a"),
    ).toMatchObject({ valid: true });

    await auth.sendOtp("active-wrapper-otp@example.com", { tenantId: "tenant-a" });
    const otpRecord = [...backend.values.entries()].find(([key]) => key.length === 64);
    expect(otpRecord).toBeDefined();
    if (otpRecord) {
      otpRecord[1].value = JSON.stringify({
        status: "active",
        payload: { email: "active-wrapper-otp@example.com", tenantId: "tenant-a" },
      });
    }
    const otpCode = messages[1]?.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(await auth.verifyOtp("active-wrapper-otp@example.com", otpCode, "tenant-a")).toBe(true);

    auth.destroy();
  });

  it("rejects malformed active magic-link and OTP records", async () => {
    const magicBackend = new CapturingBackend();
    let magicText = "";
    const magicAuth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          magicText = body;
          return { provider: "test" };
        },
      },
      magicBackend,
    );
    await magicAuth.sendMagicLink("malformed@example.com", { tenantId: "tenant-a" });
    const magicRecord = [...magicBackend.values.entries()].find(([, entry]) =>
      entry.value.includes('"purpose":"email-login"'),
    );
    expect(magicRecord).toBeDefined();
    if (magicRecord) magicRecord[1].value = "{";
    const token = magicText.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    expect(
      await magicAuth.verifyMagicLink(token, "malformed@example.com", "tenant-a"),
    ).toMatchObject({ valid: false });

    const otpBackend = new CapturingBackend();
    let otpText = "";
    const otpAuth = buildAuth(
      {
        send: async (_to, _subject, body) => {
          otpText = body;
          return { provider: "test" };
        },
      },
      otpBackend,
    );
    await otpAuth.sendOtp("malformed-otp@example.com", { tenantId: "tenant-a" });
    const otpRecord = [...otpBackend.values.entries()].find(
      ([key, entry]) =>
        key.length === 64 && entry.value.includes('"email":"malformed-otp@example.com"'),
    );
    expect(otpRecord).toBeDefined();
    if (otpRecord) {
      otpRecord[1].value = JSON.stringify({
        status: "failed",
        email: "malformed-otp@example.com",
        tenantId: "tenant-a",
      });
    }
    const otpCode = otpText.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(await otpAuth.verifyOtp("malformed-otp@example.com", otpCode, "tenant-a")).toBe(false);

    magicAuth.destroy();
    otpAuth.destroy();
  });
});

describe("production requires a delivery-capable provider", () => {
  afterEach(() => {
    restoreEnv();
  });

  it("throws EmailDeliveryNotConfiguredError BEFORE storing any challenge state", async () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_EMAIL_CODE_SECRET = "prod-test-email-code-secret";
    const backend = new CapturingBackend();
    const auth = buildAuth(undefined, backend); // silent ConsoleProvider fallback

    await expect(auth.sendMagicLink("prod@example.com", { tenantId: "tenant-a" })).rejects.toThrow(
      EmailDeliveryNotConfiguredError,
    );
    await expect(auth.sendOtp("prod@example.com", { tenantId: "tenant-a" })).rejects.toThrow(
      EmailDeliveryNotConfiguredError,
    );
    await expect(
      auth.sendTenantInvitation("prod@example.com", {
        tenantId: "tenant-a",
        token: "b".repeat(64),
        expiresAt: new Date(Date.now() + 60_000),
      }),
    ).rejects.toThrow(EmailDeliveryNotConfiguredError);

    // No challenge was ever issued — nothing to invalidate, nothing to redeem.
    expect(backend.values.size).toBe(0);

    auth.destroy();
  });

  it("rejects an explicitly passed ConsoleProvider in production", async () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_EMAIL_CODE_SECRET = "prod-test-email-code-secret";
    const backend = new CapturingBackend();
    const auth = buildAuth(new ConsoleProvider(), backend);

    await expect(auth.sendMagicLink("console@example.com")).rejects.toThrow(
      EmailDeliveryNotConfiguredError,
    );
    expect(backend.values.size).toBe(0);

    auth.destroy();
  });

  it("still allows the ConsoleProvider fallback outside production", async () => {
    const backend = new CapturingBackend();
    const originalLog = console.log;
    console.log = () => {};
    try {
      const auth = buildAuth(undefined, backend);
      const issued = await auth.sendMagicLink("dev@example.com", { tenantId: "tenant-a" });
      expect(issued.challengeId).toMatch(/^[a-f0-9]{64}$/);
      auth.destroy();
    } finally {
      console.log = originalLog;
    }
  });
});

describe("email code verifier secret hardening", () => {
  afterEach(() => {
    restoreEnv();
  });

  it("rejects missing and weak verifier secrets in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_EMAIL_CODE_SECRET;
    expect(
      () =>
        new EmailAuth({
          from: "login@steward.fi",
          baseUrl: "https://steward.fi",
          provider: new MockEmailProvider(),
        }),
    ).toThrow("STEWARD_EMAIL_CODE_SECRET is required");

    expect(
      () =>
        new EmailAuth({
          from: "login@steward.fi",
          baseUrl: "https://steward.fi",
          provider: new MockEmailProvider(),
          codeVerifierSecret: "short-secret",
        }),
    ).toThrow("must be at least 32 characters");
  });

  it("requires explicit opt-in before using the deterministic development secret", () => {
    process.env.NODE_ENV = "development";
    delete process.env.STEWARD_EMAIL_CODE_SECRET;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    delete process.env.STEWARD_ALLOW_DEV_SECRET;
    const config = {
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider: new MockEmailProvider(),
    };

    expect(() => new EmailAuth(config)).toThrow("STEWARD_ALLOW_DEV_SECRETS=true");
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const allowed = new EmailAuth(config);
    allowed.destroy();
  });
});

describe("acceptance receipts per provider", () => {
  afterEach(() => {
    MockEmailInbox.clear();
  });

  it("ResendProvider returns {provider:'resend', id} on acceptance and throws on error", async () => {
    const provider = new ResendProvider({ apiKey: "test", from: "Steward <login@steward.fi>" });

    (provider as any).client = {
      emails: { send: async () => ({ data: { id: "resend-msg-1" }, error: null }) },
    };
    expect(await provider.send("a@example.com", "s", "t")).toEqual({
      provider: "resend",
      id: "resend-msg-1",
    });

    (provider as any).client = {
      emails: { send: async () => ({ data: null, error: null }) },
    };
    await expect(provider.send("a@example.com", "s", "t")).rejects.toThrow(
      "no delivery acceptance id",
    );

    (provider as any).client = {
      emails: { send: async () => ({ data: null, error: { message: "invalid api key" } }) },
    };
    expect(provider.send("a@example.com", "s", "t")).rejects.toThrow("Resend error");
  });

  it("ConsoleProvider and MockEmailProvider return redacted receipts", async () => {
    const originalLog = console.log;
    console.log = () => {};
    try {
      expect(await new ConsoleProvider().send("a@example.com", "s", "t")).toEqual({
        provider: "console",
      });
    } finally {
      console.log = originalLog;
    }

    const mockReceipt = await new MockEmailProvider().send("a@example.com", "s", "t");
    expect(mockReceipt.provider).toBe("mock");
    expect(mockReceipt.id).toBeTruthy();
    expect(MockEmailInbox.last("a@example.com")?.subject).toBe("s");
  });
});
