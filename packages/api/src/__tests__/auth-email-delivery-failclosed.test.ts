/**
 * Fail-closed email delivery at the route layer (elizaOS/eliza#18452).
 *
 * POST /auth/email/send (and /auth/email/otp/send) must never return ok:true
 * unless the provider ACCEPTED the message:
 *   - production with no delivery-capable provider  → 503, no challenge issued
 *   - tenant with partial/unsupported email config  → 503, no challenge issued
 *   - provider rejects the send                     → 502, challenge remains staged
 *   - provider returns an acceptance receipt        → 200, challenge live
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import type { EmailDeliveryReceipt, EmailProvider } from "@stwd/auth";
import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { Hono } from "hono";
import { createAuthorizationSignature } from "../middleware/authorization-signature";
import {
  authRoutes,
  clearEmailAuthTenantCacheForTests,
  getEmailAuthForTenant,
  initAuthStores,
  invalidateEmailAuthForTenant,
} from "../routes/auth";

const TENANT_PARTIAL = "tenant-email-partial-config";
const TENANT_LIVE = "tenant-email-live-provider";

const ORIGINAL_ENV = {
  NODE_ENV: process.env.NODE_ENV,
  RESEND_API_KEY: process.env.RESEND_API_KEY,
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
  EMAIL_FROM: process.env.EMAIL_FROM,
  APP_URL: process.env.APP_URL,
  REDIS_URL: process.env.REDIS_URL,
  STEWARD_EMAIL_CODE_SECRET: process.env.STEWARD_EMAIL_CODE_SECRET,
  STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL: process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL,
  STEWARD_REQUIRE_REQUEST_EXPIRY: process.env.STEWARD_REQUIRE_REQUEST_EXPIRY,
  STEWARD_REQUEST_SIGNING_SECRET: process.env.STEWARD_REQUEST_SIGNING_SECRET,
  STEWARD_REQUEST_SIGNING_SECRETS: process.env.STEWARD_REQUEST_SIGNING_SECRETS,
  STEWARD_PGLITE_MEMORY: process.env.STEWARD_PGLITE_MEMORY,
  STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD,
  STEWARD_JWT_SECRET: process.env.STEWARD_JWT_SECRET,
} as const;

function restoreEnv(): void {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

let app: Hono;
const REQUEST_SIGNING_SECRET = "email-delivery-fixture-request-signing-secret";
let requestSequence = 0;

describe("fail-closed email delivery routes (production)", () => {
  beforeAll(async () => {
    process.env.NODE_ENV = "production";
    delete process.env.RESEND_API_KEY;
    delete process.env.EMAIL_PROVIDER;
    delete process.env.REDIS_URL;
    process.env.EMAIL_FROM = "Steward <login@steward.fi>";
    process.env.APP_URL = "https://app.example.com";
    process.env.STEWARD_EMAIL_CODE_SECRET = "route-fail-closed-email-code-secret";
    process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
    process.env.STEWARD_REQUEST_SIGNING_SECRET = REQUEST_SIGNING_SECRET;
    delete process.env.STEWARD_REQUEST_SIGNING_SECRETS;
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "route-fail-closed-master-password";
    process.env.STEWARD_JWT_SECRET = "route-fail-closed-jwt-secret-32-chars!!";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await initAuthStores(false);
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.insert(tenants).values([
      { id: TENANT_PARTIAL, name: "Partial Email Config", apiKeyHash: "hash-1" },
      { id: TENANT_LIVE, name: "Live Provider", apiKeyHash: "hash-2" },
    ]);
    // Partial per-tenant config: an encrypted key blob but NO provider field.
    // This must not silently fall back to ConsoleProvider and return ok:true.
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TENANT_PARTIAL,
      emailConfig: { apiKeyEncrypted: '{"ciphertext":"x","iv":"x","tag":"x","salt":"x"}' },
    });

    const { createApp } = await import("../app");
    app = createApp();
    app.route("/auth", authRoutes);
  });

  afterAll(async () => {
    clearEmailAuthTenantCacheForTests();
    await closeDb();
    restoreEnv();
  });

  async function postJson(
    path: string,
    body: unknown,
    tenantId?: string,
    signed = true,
    fresh = signed,
  ): Promise<Response> {
    const encodedBody = JSON.stringify(body);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const idempotencyKey = `email-delivery-${++requestSequence}`;
    const signature = signed
      ? await createAuthorizationSignature(
          {
            method: "POST",
            url: path,
            tenantId,
            timestamp,
            idempotencyKey,
            body: encodedBody,
          },
          REQUEST_SIGNING_SECRET,
        )
      : undefined;
    return app.request(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(tenantId ? { "X-Steward-Tenant": tenantId } : {}),
        ...(fresh ? { "X-Steward-Request-Timestamp": timestamp } : {}),
        ...(signed
          ? {
              "X-Steward-Signature": signature as string,
              "Idempotency-Key": idempotencyKey,
            }
          : {}),
      },
      body: encodedBody,
    });
  }

  it("keeps production request-expiry enforcement load-bearing", async () => {
    const response = await postJson(
      "/auth/email/send",
      { email: "user@example.com" },
      undefined,
      false,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      ok: false,
      error: "Request expiry header required",
    });
  });

  it("allows fresh unsigned browser authentication in production", async () => {
    clearEmailAuthTenantCacheForTests();
    const response = await postJson(
      "/auth/email/send",
      { email: "browser@example.com" },
      undefined,
      false,
      true,
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      ok: false,
      error: "Email delivery is not configured",
    });
  });

  it("returns 503 (not a false ok:true) when no global provider is configured", async () => {
    clearEmailAuthTenantCacheForTests();

    const response = await postJson("/auth/email/send", { email: "user@example.com" });
    expect(response.status).toBe(503);
    const body = (await response.json()) as { ok: boolean; error: string; data?: unknown };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Email delivery is not configured");
    // No challenge escapes: nothing to poll, nothing to redeem.
    expect(body.data).toBeUndefined();
  });

  it("returns 503 for /email/otp/send when no global provider is configured", async () => {
    clearEmailAuthTenantCacheForTests();

    const response = await postJson("/auth/email/otp/send", { email: "user@example.com" });
    expect(response.status).toBe(503);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Email delivery is not configured");
  });

  it("returns 503 for a tenant with partial email config instead of silent ConsoleProvider", async () => {
    invalidateEmailAuthForTenant(TENANT_PARTIAL);

    const response = await postJson(
      "/auth/email/send",
      { email: "user@example.com" },
      TENANT_PARTIAL,
    );
    expect(response.status).toBe(503);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Email delivery is not configured");
  });

  it("returns 502, keeps the challenge staged, and redacts logs when the provider rejects", async () => {
    // Prime the tenant cache with a delivery-capable EmailAuth (Resend key
    // present), then swap in a rejecting provider — the seam a Resend outage
    // or invalid key hits in production.
    process.env.RESEND_API_KEY = "re_test_route_key";
    invalidateEmailAuthForTenant(TENANT_LIVE);
    const emailAuth = await getEmailAuthForTenant(TENANT_LIVE);
    delete process.env.RESEND_API_KEY;

    let text = "";
    (emailAuth as unknown as { provider: EmailProvider }).provider = {
      send: async (_to, _subject, body) => {
        text = body; // what WOULD have been delivered
        throw new Error("Resend error: unauthorized");
      },
    };

    const logged: string[] = [];
    const originalError = console.error;
    const originalLog = console.log;
    console.error = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
    console.log = (...args: unknown[]) => void logged.push(args.map(String).join(" "));
    let response: Response;
    try {
      response = await postJson(
        "/auth/email/send",
        { email: "outage-victim@example.com" },
        TENANT_LIVE,
      );
    } finally {
      console.error = originalError;
      console.log = originalLog;
    }

    expect(response.status).toBe(502);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Email could not be sent. Please try again later.");

    // The would-be credentials must not redeem while delivery remains staged.
    const token = text.match(/[?&]token=([a-f0-9]{64})/)?.[1] ?? "";
    const code = text.match(/\b(\d{6})\b/)?.[1] ?? "";
    expect(token).not.toBe("");
    expect(code).not.toBe("");
    const verifyResponse = await postJson(
      "/auth/email/verify",
      { token, email: "outage-victim@example.com", tenantId: TENANT_LIVE },
      TENANT_LIVE,
    );
    expect(verifyResponse.status).toBe(401);
    const codeResponse = await postJson(
      "/auth/email/code/verify",
      { email: "outage-victim@example.com", code, tenantId: TENANT_LIVE },
      TENANT_LIVE,
    );
    expect(codeResponse.status).toBe(401);

    // Nothing sensitive in server logs: no recipient, token, code, or raw
    // provider error text.
    const allLogs = logged.join("\n");
    expect(allLogs).not.toContain("outage-victim");
    expect(allLogs).not.toContain(token);
    expect(allLogs).not.toContain(code);
    expect(allLogs).not.toContain("unauthorized");
  });

  it("returns 200 with a live challenge only after an acceptance receipt", async () => {
    process.env.RESEND_API_KEY = "re_test_route_key";
    invalidateEmailAuthForTenant(TENANT_LIVE);
    const emailAuth = await getEmailAuthForTenant(TENANT_LIVE);
    delete process.env.RESEND_API_KEY;

    (emailAuth as unknown as { provider: EmailProvider }).provider = {
      send: async (): Promise<EmailDeliveryReceipt> => ({ provider: "test", id: "accepted-42" }),
    };

    const response = await postJson(
      "/auth/email/send",
      { email: "delivered@example.com" },
      TENANT_LIVE,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { expiresAt: string; challengeId: string; pollSecret: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.challengeId).toMatch(/^[a-f0-9]{64}$/);
    expect(body.data.pollSecret).toMatch(/^[a-f0-9]{64}$/);
    expect(new Date(body.data.expiresAt).getTime()).toBeGreaterThan(Date.now());

    // The challenge is genuinely live: polling reports pending.
    const statusResponse = await postJson(
      "/auth/email/status",
      { challengeId: body.data.challengeId, pollSecret: body.data.pollSecret },
      TENANT_LIVE,
    );
    expect(statusResponse.status).toBe(200);
    const statusBody = (await statusResponse.json()) as { ok: boolean; data: { status: string } };
    expect(statusBody.data.status).toBe("pending");
  });
});
