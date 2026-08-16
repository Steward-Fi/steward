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

import { EmailAuth } from "../email";
import {
  ConsoleProvider,
  EmailDeliveryError,
  EmailDeliveryNotConfiguredError,
  type EmailProvider,
  MockEmailInbox,
  MockEmailProvider,
  ResendProvider,
} from "../email-provider";
import type { StoreBackend } from "../store-backends";
import { TokenStore } from "../token-store";

class CapturingBackend implements StoreBackend {
  values = new Map<string, { value: string; expiresAt: number }>();

  async set(key: string, value: string, ttlMs: number): Promise<void> {
    this.values.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  async setIfNotExists(key: string, value: string, ttlMs: number): Promise<boolean> {
    if (await this.get(key)) return false;
    await this.set(key, value, ttlMs);
    return true;
  }

  async get(key: string): Promise<string | null> {
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

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
const ORIGINAL_CODE_SECRET = process.env.STEWARD_EMAIL_CODE_SECRET;

function restoreEnv(): void {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  if (ORIGINAL_CODE_SECRET === undefined) delete process.env.STEWARD_EMAIL_CODE_SECRET;
  else process.env.STEWARD_EMAIL_CODE_SECRET = ORIGINAL_CODE_SECRET;
}

function buildAuth(provider: EmailProvider | undefined, backend: CapturingBackend): EmailAuth {
  return new EmailAuth({
    from: "login@steward.fi",
    baseUrl: "https://steward.fi",
    ...(provider ? { provider } : {}),
    tokenStore: new TokenStore({ backend }),
    codeVerifierSecret: "fail-closed-test-secret",
  });
}

describe("fail-closed magic-link delivery", () => {
  afterEach(() => {
    restoreEnv();
  });

  it("invalidates the challenge and throws EmailDeliveryError when the provider rejects", async () => {
    const backend = new CapturingBackend();
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

    // The pre-fix false green: these credentials stayed redeemable. Now every
    // record of the challenge must be gone.
    const remaining = [...backend.values.keys()].filter((k) => k.startsWith("email-login:"));
    expect(remaining).toEqual([]);

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

  it("treats a missing acceptance receipt as delivery failure and invalidates", async () => {
    const backend = new CapturingBackend();
    // Legacy void-returning provider: resolves but produces NO receipt.
    const voidProvider = { send: async () => undefined } as unknown as EmailProvider;
    const auth = buildAuth(voidProvider, backend);

    await expect(auth.sendMagicLink("void@example.com", { tenantId: "tenant-a" })).rejects.toThrow(
      EmailDeliveryError,
    );

    const remaining = [...backend.values.keys()].filter((k) => k.startsWith("email-login:"));
    expect(remaining).toEqual([]);

    auth.destroy();
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

  it("deletes the stored OTP code when the provider rejects a sendOtp", async () => {
    const backend = new CapturingBackend();
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

    expect(backend.values.size).toBe(0);
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(code).not.toBe("");
    expect(await auth.verifyOtp("otp@example.com", code, "tenant-a")).toBe(false);

    auth.destroy();
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
    // Accepted but no id: still a receipt, id omitted.
    expect(await provider.send("a@example.com", "s", "t")).toEqual({ provider: "resend" });

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
