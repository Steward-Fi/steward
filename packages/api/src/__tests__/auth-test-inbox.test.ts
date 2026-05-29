import { afterEach, describe, expect, it } from "bun:test";
import { authRoutes } from "../routes/auth";

const originalEnv = {
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
  SMS_PROVIDER: process.env.SMS_PROVIDER,
  NODE_ENV: process.env.NODE_ENV,
  STEWARD_ENABLE_AUTH_TEST_INBOX: process.env.STEWARD_ENABLE_AUTH_TEST_INBOX,
};

function restoreEnv(name: keyof typeof originalEnv) {
  const value = originalEnv[name];
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

afterEach(() => {
  restoreEnv("EMAIL_PROVIDER");
  restoreEnv("SMS_PROVIDER");
  restoreEnv("NODE_ENV");
  restoreEnv("STEWARD_ENABLE_AUTH_TEST_INBOX");
});

describe("auth test inbox routes", () => {
  it("does not expose mock email or SMS inboxes in non-test environments by default", async () => {
    process.env.EMAIL_PROVIDER = "mock";
    process.env.SMS_PROVIDER = "mock";
    process.env.NODE_ENV = "development";
    delete process.env.STEWARD_ENABLE_AUTH_TEST_INBOX;

    const emailRes = await authRoutes.request("/test/inbox/victim@example.com");
    const smsRes = await authRoutes.request("/test/sms-inbox/%2B15555550123");

    expect(emailRes.status).toBe(404);
    expect(smsRes.status).toBe(404);
    await expect(emailRes.json()).resolves.toMatchObject({ error: "Not found" });
    await expect(smsRes.json()).resolves.toMatchObject({ error: "Not found" });
  });

  it("ignores explicit opt-in outside NODE_ENV=test", async () => {
    process.env.EMAIL_PROVIDER = "mock";
    process.env.SMS_PROVIDER = "mock";
    process.env.NODE_ENV = "development";
    process.env.STEWARD_ENABLE_AUTH_TEST_INBOX = "true";

    const emailRes = await authRoutes.request("/test/inbox/victim@example.com");
    const smsRes = await authRoutes.request("/test/sms-inbox/%2B15555550123");

    expect(emailRes.status).toBe(404);
    expect(smsRes.status).toBe(404);
    await expect(emailRes.json()).resolves.toMatchObject({ error: "Not found" });
    await expect(smsRes.json()).resolves.toMatchObject({ error: "Not found" });
  });
});
