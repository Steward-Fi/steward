import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";

const previousDatabaseUrl = process.env.DATABASE_URL;
process.env.DATABASE_URL ||= "postgres://unused:unused@localhost:5432/unused";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const USER_ID = "0x0000000000000000000000000000000000000001";

let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];
let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];

beforeAll(async () => {
  process.env.STEWARD_MASTER_PASSWORD = "user-wallet-export-master-password";
  process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
  process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT = "true";
  ({ createSessionToken } = await import("../routes/auth"));
  ({ userRoutes } = await import("../routes/user"));
});

beforeEach(() => {
  dispatchWebhookMock.mockClear();
});

afterAll(() => {
  if (previousDatabaseUrl === undefined) {
    delete process.env.DATABASE_URL;
  } else {
    process.env.DATABASE_URL = previousDatabaseUrl;
  }
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT;
  delete process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT;
});

describe("user wallet private key export hardening", () => {
  it("requires a recent MFA step-up before wallet transaction signing reaches vault setup", async () => {
    const token = await createSessionToken(USER_ID, "tenant");

    const res = await userRoutes.request("/me/wallet/sign", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        to: "0x1234567890123456789012345678901234567890",
        value: "1",
        chainId: 8453,
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Wallet transaction signing requires a recent MFA step-up");
  });

  it("requires a recent MFA step-up even when break-glass export flags are enabled", async () => {
    const token = await createSessionToken(USER_ID, "tenant");

    const res = await userRoutes.request("/me/wallet/export", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA step-up");
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });
});
