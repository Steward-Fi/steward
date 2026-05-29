import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";

import { closeDb, getDb, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const PLATFORM_KEY = "auth-test-account-platform-key";
const TENANT_ID = "auth-test-account-tenant";
const ADMIN_TENANT_ID = "auth-test-account-admin-tenant";

describe("tenant test account credentials", () => {
  let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
  let app: Awaited<typeof import("../app")>["app"];
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "auth-test-account-master-password";
    process.env.STEWARD_JWT_SECRET = "auth-test-account-jwt-secret-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [PLATFORM_KEY]: ["platform:read", "platform:write", "platform:tenant-test-account:write"],
    });

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Auth Test Account Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(tenants).values({
      id: ADMIN_TENANT_ID,
      name: "Auth Test Account Admin Tenant",
      apiKeyHash: "hash-admin",
    });

    ({ authRoutes } = await import("../routes/auth"));
    ({ app } = await import("../app"));
    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  });

  function platformHeaders() {
    return {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": PLATFORM_KEY,
    };
  }

  it("requires platform auth to enable test credentials", async () => {
    const response = await platformRoutes.request(`/tenants/${TENANT_ID}/test-account`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(response.status).toBe(401);
  });

  it("enables, rotates, exchanges, and disables exact test credentials", async () => {
    const enableResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/test-account`, {
      method: "POST",
      headers: platformHeaders(),
    });
    expect(enableResponse.status).toBe(200);
    const enabled = (await enableResponse.json()) as {
      ok: boolean;
      data: {
        testAccount: {
          enabled: boolean;
          email: string;
          phone: string;
          otp: string;
        };
      };
    };
    expect(enabled.data.testAccount.email).toMatch(/^test-\d{6}@steward\.test$/);
    expect(enabled.data.testAccount.phone).toMatch(/^\+1555555\d{4}$/);
    expect(enabled.data.testAccount.otp).toMatch(/^\d{6}$/);

    const badOtp = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        email: enabled.data.testAccount.email,
        otp: "000000",
      }),
    });
    expect(badOtp.status).toBe(401);

    const tokenResponse = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        email: enabled.data.testAccount.email.toUpperCase(),
        otp: enabled.data.testAccount.otp,
      }),
    });
    expect(tokenResponse.status).toBe(200);
    const tokenBody = (await tokenResponse.json()) as {
      token: string;
      refreshToken: string;
      user: { id: string; email: string };
    };
    expect(tokenBody.token).toMatch(/\./);
    expect(tokenBody.refreshToken).toBeTruthy();
    expect(tokenBody.user.email).toBe(enabled.data.testAccount.email);

    const [user] = await getDb()
      .select({ id: users.id, emailVerified: users.emailVerified })
      .from(users)
      .where(eq(users.email, enabled.data.testAccount.email));
    expect(user?.emailVerified).toBe(true);
    const [membership] = await getDb()
      .select({ tenantId: userTenants.tenantId })
      .from(userTenants)
      .where(and(eq(userTenants.userId, user!.id), eq(userTenants.tenantId, TENANT_ID)));
    expect(membership?.tenantId).toBe(TENANT_ID);

    const disableResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/test-account`, {
      method: "DELETE",
      headers: platformHeaders(),
    });
    expect(disableResponse.status).toBe(200);

    const afterDisable = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        email: enabled.data.testAccount.email,
        otp: enabled.data.testAccount.otp,
      }),
    });
    expect(afterDisable.status).toBe(401);
  });

  it("lets tenant owners manage test credentials from dashboard auth", async () => {
    const adminUserId = crypto.randomUUID();
    await getDb()
      .insert(users)
      .values({
        id: adminUserId,
        email: "test-account-admin@example.test",
        emailVerified: true,
        walletAddress: `0x${"a".repeat(40)}`,
      });
    await getDb().insert(userTenants).values({
      userId: adminUserId,
      tenantId: ADMIN_TENANT_ID,
      role: "owner",
    });

    const { createSessionToken } = await import("../routes/auth");
    const token = await createSessionToken(`0x${"a".repeat(40)}`, ADMIN_TENANT_ID, {
      userId: adminUserId,
      email: "test-account-admin@example.test",
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const headers = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    };

    const enableResponse = await app.request(`/tenants/${ADMIN_TENANT_ID}/test-account`, {
      method: "POST",
      headers,
    });
    expect(enableResponse.status).toBe(200);
    const enabled = (await enableResponse.json()) as {
      data: { testAccount: { email: string; phone: string; otp: string } };
    };
    expect(enabled.data.testAccount.otp).toMatch(/^\d{6}$/);

    const getResponse = await app.request(`/tenants/${ADMIN_TENANT_ID}/test-account`, { headers });
    expect(getResponse.status).toBe(200);
    const current = (await getResponse.json()) as {
      data: { testAccount: { email: string; phone: string; otp?: string } };
    };
    expect(current.data.testAccount.email).toBe(enabled.data.testAccount.email);
    expect(current.data.testAccount.otp).toBeUndefined();

    const tokenResponse = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: ADMIN_TENANT_ID,
        phone: enabled.data.testAccount.phone,
        otp: enabled.data.testAccount.otp,
      }),
    });
    expect(tokenResponse.status).toBe(200);

    const disableResponse = await app.request(`/tenants/${ADMIN_TENANT_ID}/test-account`, {
      method: "DELETE",
      headers,
    });
    expect(disableResponse.status).toBe(200);
  });

  it("does not let test credentials bypass disabled email or sms login methods", async () => {
    const enableResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/test-account`, {
      method: "POST",
      headers: platformHeaders(),
    });
    expect(enableResponse.status).toBe(200);
    const enabled = (await enableResponse.json()) as {
      data: { testAccount: { email: string; phone: string; otp: string } };
    };

    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: { loginMethods: { email: false, sms: false } },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { authAbuseConfig: { loginMethods: { email: false, sms: false } } },
      });

    const emailResponse = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        email: enabled.data.testAccount.email,
        otp: enabled.data.testAccount.otp,
      }),
    });
    expect(emailResponse.status).toBe(403);

    const phoneResponse = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        phone: enabled.data.testAccount.phone,
        otp: enabled.data.testAccount.otp,
      }),
    });
    expect(phoneResponse.status).toBe(403);

    await getDb()
      .update(tenantConfigs)
      .set({ authAbuseConfig: {} })
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    const disableResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/test-account`, {
      method: "DELETE",
      headers: platformHeaders(),
    });
    expect(disableResponse.status).toBe(200);
  });

  it("lets tenant owners manage auth abuse controls without overwriting other config", async () => {
    const adminUserId = crypto.randomUUID();
    await getDb()
      .insert(users)
      .values({
        id: adminUserId,
        email: `auth-abuse-admin-${adminUserId}@example.test`,
        emailVerified: true,
        walletAddress: `0x${"b".repeat(40)}`,
      });
    await getDb().insert(userTenants).values({
      userId: adminUserId,
      tenantId: ADMIN_TENANT_ID,
      role: "owner",
    });

    const { createSessionToken } = await import("../routes/auth");
    const token = await createSessionToken(`0x${"b".repeat(40)}`, ADMIN_TENANT_ID, {
      userId: adminUserId,
      email: `auth-abuse-admin-${adminUserId}@example.test`,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const headers = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    };

    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: ADMIN_TENANT_ID,
        displayName: "Admin Test Tenant",
        policyTemplates: [
          {
            id: "existing-template",
            name: "Existing Template",
            policies: [],
            customizableFields: [],
          },
        ],
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: {
          displayName: "Admin Test Tenant",
          policyTemplates: [
            {
              id: "existing-template",
              name: "Existing Template",
              policies: [],
              customizableFields: [],
            },
          ],
        },
      });

    const response = await app.request(`/tenants/${ADMIN_TENANT_ID}/auth-abuse-config`, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        authAbuseConfig: {
          loginMethods: {
            email: false,
            sms: false,
            siwe: true,
            oauth: { google: false },
          },
          captcha: {
            enabled: true,
            provider: "turnstile",
            siteKey: "site-key",
            secretKeyEnv: "STEWARD_TENANT_TURNSTILE_SECRET",
            requiredFor: ["email_otp", "sms_otp"],
          },
          email: {
            blockDisposable: true,
            blockPlusAliases: true,
            allowedDomains: ["example.com"],
            blockedEmails: ["blocked@example.com"],
          },
          wallet: {
            blockedWallets: [`0x${"1".repeat(40)}`],
          },
          phone: {
            blockVoip: true,
            allowedCountryCodes: ["1"],
          },
        },
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        authAbuseConfig: {
          captcha?: { enabled?: boolean; secretKeyEnv?: string; requiredFor?: string[] };
          loginMethods?: {
            email?: boolean;
            sms?: boolean;
            siwe?: boolean;
            oauth?: Record<string, boolean>;
          };
          email?: { allowedDomains?: string[]; blockedEmails?: string[] };
          wallet?: { blockedWallets?: string[] };
          phone?: { allowedCountryCodes?: string[] };
        };
      };
    };
    expect(body.data.authAbuseConfig.captcha?.enabled).toBe(true);
    expect(body.data.authAbuseConfig.loginMethods).toMatchObject({
      email: false,
      sms: false,
      siwe: true,
      oauth: { google: false },
    });
    expect(body.data.authAbuseConfig.captcha?.secretKeyEnv).toBe("STEWARD_TENANT_TURNSTILE_SECRET");
    expect(body.data.authAbuseConfig.captcha?.requiredFor).toEqual(["email_otp", "sms_otp"]);
    expect(body.data.authAbuseConfig.email?.allowedDomains).toEqual(["example.com"]);
    expect(body.data.authAbuseConfig.wallet?.blockedWallets).toEqual([`0x${"1".repeat(40)}`]);
    expect(body.data.authAbuseConfig.phone?.allowedCountryCodes).toEqual(["1"]);

    const getResponse = await app.request(`/tenants/${ADMIN_TENANT_ID}/auth-abuse-config`, {
      headers,
    });
    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as typeof body;
    expect(getBody.data.authAbuseConfig.email?.blockedEmails).toEqual(["blocked@example.com"]);

    const providersResponse = await authRoutes.request(
      `/providers?tenantId=${encodeURIComponent(ADMIN_TENANT_ID)}`,
    );
    expect(providersResponse.status).toBe(200);
    const providers = (await providersResponse.json()) as {
      email: boolean;
      sms: boolean;
      siwe: boolean;
      google: boolean;
    };
    expect(providers.email).toBe(false);
    expect(providers.sms).toBe(false);
    expect(providers.siwe).toBe(true);
    expect(providers.google).toBe(false);

    const [stored] = await getDb()
      .select({
        displayName: tenantConfigs.displayName,
        policyTemplates: tenantConfigs.policyTemplates,
      })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, ADMIN_TENANT_ID));
    expect(stored?.displayName).toBe("Admin Test Tenant");
    expect(stored?.policyTemplates).toEqual([
      {
        id: "existing-template",
        name: "Existing Template",
        policies: [],
        customizableFields: [],
      },
    ]);

    const invalid = await app.request(`/tenants/${ADMIN_TENANT_ID}/auth-abuse-config`, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        authAbuseConfig: { email: { allowedDomains: ["not a domain"] } },
      }),
    });
    expect(invalid.status).toBe(400);
  });
});

describe("test account token exchange hardening", () => {
  it("does not enumerate tenant or test-account configuration and throttles credentials", () => {
    const source = readFileSync(new URL("../routes/auth.ts", import.meta.url), "utf8");
    const credentialSource = readFileSync(
      new URL("../services/test-account-credentials.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain("invalidTestAccountCredentials()");
    expect(source).toContain('"test-account-token-credential"');
    expect(source).toContain("credentialSubject");
    expect(source).toContain("testAccountOtpMatches(body?.otp, testAccount)");
    expect(credentialSource).toContain("otpHash: hashTestAccountOtp(otp)");
    expect(credentialSource).toContain("STEWARD_TEST_ACCOUNT_OTP_PEPPER");
  });
});
