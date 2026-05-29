import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { TenantAuthAbuseConfig } from "@stwd/shared";
import {
  normalizeAuthAbuseConfig,
  validatePhoneAbusePolicy,
  validateWalletAbusePolicy,
} from "../services/auth-abuse";

let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
let tenantOwnerCounter = 1;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "auth-abuse-controls-master-password";
  process.env.STEWARD_JWT_SECRET = "auth-abuse-controls-jwt-secret-with-enough-entropy";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  ({ authRoutes } = await import("../routes/auth"));
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
});

async function createTenantWithAbuseConfig(
  tenantId: string,
  authAbuseConfig: TenantAuthAbuseConfig,
) {
  const db = getDb();
  await db
    .insert(tenants)
    .values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: "test-hash",
      ownerAddress: `0x${(tenantOwnerCounter++).toString(16).padStart(40, "0")}`,
    })
    .onConflictDoNothing();
  await db.insert(tenantConfigs).values({ tenantId, authAbuseConfig }).onConflictDoUpdate({
    target: tenantConfigs.tenantId,
    set: { authAbuseConfig },
  });
}

describe("auth abuse controls", () => {
  it("blocks disposable and plus-addressed magic-link emails before sending", async () => {
    const tenantId = `tenant-abuse-email-${Date.now()}`;
    await createTenantWithAbuseConfig(tenantId, {
      email: { blockDisposable: true, blockPlusAliases: true },
    });

    const disposable = await authRoutes.request("/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, email: "person@mailinator.com" }),
    });
    expect(disposable.status).toBe(400);
    expect(((await disposable.json()) as { error: string }).error).toContain("disposable");

    const plusAlias = await authRoutes.request("/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, email: "person+alias@example.com" }),
    });
    expect(plusAlias.status).toBe(400);
    expect(((await plusAlias.json()) as { error: string }).error).toContain("plus-addressed");
  });

  it("requires configured CAPTCHA tokens for public OTP sends", async () => {
    const tenantId = `tenant-abuse-captcha-${Date.now()}`;
    await createTenantWithAbuseConfig(tenantId, {
      captcha: {
        enabled: true,
        provider: "turnstile",
        siteKey: "site-key",
        requiredFor: ["email_otp", "sms_otp"],
      },
    });

    const email = await authRoutes.request("/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, email: "person@example.com" }),
    });
    expect(email.status).toBe(400);
    expect(((await email.json()) as { error: string }).error).toContain("captchaToken");

    const sms = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, phone: "+15555550123" }),
    });
    expect(sms.status).toBe(400);
    expect(((await sms.json()) as { error: string }).error).toContain("captchaToken");
  });

  it("rejects unknown explicit tenant hints before sending email or SMS", async () => {
    const tenantId = `tenant-does-not-exist-${Date.now()}`;

    const email = await authRoutes.request("/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, email: "person@example.com" }),
    });
    expect(email.status).toBe(404);
    expect(((await email.json()) as { error: string }).error).toContain("not found");

    const sms = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, phone: "+15555550123" }),
    });
    expect(sms.status).toBe(404);
    expect(((await sms.json()) as { error: string }).error).toContain("not found");
  });

  it("exposes public CAPTCHA metadata in provider discovery without the secret env name", async () => {
    const tenantId = `tenant-abuse-discovery-${Date.now()}`;
    await createTenantWithAbuseConfig(tenantId, {
      captcha: {
        enabled: true,
        provider: "hcaptcha",
        siteKey: "public-site-key",
        secretKeyEnv: "STEWARD_PRIVATE_HCAPTCHA_SECRET",
        requiredFor: ["email_otp"],
      },
    });

    const res = await authRoutes.request(`/providers?tenantId=${encodeURIComponent(tenantId)}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      captcha?: { provider?: string; siteKey?: string; secretKeyEnv?: string };
    };
    expect(body.captcha).toMatchObject({ provider: "hcaptcha", siteKey: "public-site-key" });
    expect(body.captcha?.secretKeyEnv).toBeUndefined();
  });

  it("rejects tenant-selected CAPTCHA secret env names outside the Steward CAPTCHA allowlist", () => {
    const unsafe = normalizeAuthAbuseConfig({
      captcha: {
        enabled: true,
        provider: "turnstile",
        siteKey: "site-key",
        secretKeyEnv: "DATABASE_URL",
      },
    });
    expect(unsafe).toBe(
      "captcha.secretKeyEnv must be a STEWARD_* CAPTCHA secret environment variable",
    );

    const safe = normalizeAuthAbuseConfig({
      captcha: {
        enabled: true,
        provider: "turnstile",
        siteKey: "site-key",
        secretKeyEnv: "STEWARD_TENANT_TURNSTILE_SECRET",
      },
    });
    expect(safe).toMatchObject({
      captcha: { secretKeyEnv: "STEWARD_TENANT_TURNSTILE_SECRET" },
    });
  });

  it("discovers additional OAuth-style social and custom providers", async () => {
    const original = {
      LINKEDIN_CLIENT_ID: process.env.LINKEDIN_CLIENT_ID,
      LINKEDIN_CLIENT_SECRET: process.env.LINKEDIN_CLIENT_SECRET,
      SPOTIFY_CLIENT_ID: process.env.SPOTIFY_CLIENT_ID,
      SPOTIFY_CLIENT_SECRET: process.env.SPOTIFY_CLIENT_SECRET,
      STEWARD_CUSTOM_OAUTH_PROVIDERS: process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS,
    };
    process.env.LINKEDIN_CLIENT_ID = "linkedin-id";
    process.env.LINKEDIN_CLIENT_SECRET = "linkedin-secret";
    process.env.SPOTIFY_CLIENT_ID = "spotify-id";
    process.env.SPOTIFY_CLIENT_SECRET = "spotify-secret";
    process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = JSON.stringify([
      {
        id: "acme",
        clientId: "custom-id",
        clientSecret: "custom-secret",
        authorizationUrl: "https://idp.example.com/auth",
        tokenUrl: "https://idp.example.com/token",
        userInfoUrl: "https://idp.example.com/userinfo",
        scopes: ["openid"],
      },
    ]);

    try {
      const res = await authRoutes.request("/providers");
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        linkedin?: boolean;
        spotify?: boolean;
        oauth?: string[];
      };
      expect(body.linkedin).toBe(true);
      expect(body.spotify).toBe(true);
      expect(body.oauth).toEqual(expect.arrayContaining(["linkedin", "spotify", "custom:acme"]));
    } finally {
      for (const [key, value] of Object.entries(original)) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    }
  });

  it("enforces exact email, wallet, and phone allowlist/denylist controls", async () => {
    const tenantId = `tenant-abuse-allowlist-${Date.now()}`;
    await createTenantWithAbuseConfig(tenantId, {
      email: {
        allowedEmails: ["allowed@example.com"],
        blockedEmails: ["blocked@example.com"],
      },
      wallet: {
        allowedWallets: ["0x1111111111111111111111111111111111111111"],
        blockedWallets: ["solana:Blocked111111111111111111111111111111111"],
      },
    });

    const notAllowed = await authRoutes.request("/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, email: "other@example.com" }),
    });
    expect(notAllowed.status).toBe(400);
    expect(((await notAllowed.json()) as { error: string }).error).toContain("not allowed");

    const blocked = await authRoutes.request("/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId, email: "blocked@example.com" }),
    });
    expect(blocked.status).toBe(400);
    expect(((await blocked.json()) as { error: string }).error).toContain("blocked");

    expect(
      validateWalletAbusePolicy("0x2222222222222222222222222222222222222222", "ethereum", {
        wallet: { allowedWallets: ["0x1111111111111111111111111111111111111111"] },
      }),
    ).toBe("wallet is not allowed");
    expect(
      validateWalletAbusePolicy("Blocked111111111111111111111111111111111", "solana", {
        wallet: { blockedWallets: ["solana:blocked111111111111111111111111111111111"] },
      }),
    ).toBe("wallet is blocked");
    expect(
      validatePhoneAbusePolicy("+15555550999", {
        phone: { allowedPhoneNumbers: ["+15555550123"] },
      }),
    ).toBe("phone number is not allowed");
    expect(
      validatePhoneAbusePolicy("+15555550123", {
        phone: { blockedPhoneNumbers: ["+15555550123"] },
      }),
    ).toBe("phone number is blocked");
  });

  it("normalizes exact phone allowlist and denylist controls", () => {
    const config = normalizeAuthAbuseConfig({
      phone: {
        allowedPhoneNumbers: [" +15555550123 ", "+15555550123"],
        blockedPhoneNumbers: ["+15555550456"],
      },
    });
    expect(config).toMatchObject({
      phone: {
        allowedPhoneNumbers: ["+15555550123"],
        blockedPhoneNumbers: ["+15555550456"],
      },
    });

    expect(
      normalizeAuthAbuseConfig({
        phone: { allowedPhoneNumbers: ["555-555-0123"] },
      }),
    ).toBe("phone.allowedPhoneNumbers must contain E.164 phone numbers");
  });
});
