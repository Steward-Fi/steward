import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { KeyStore } from "@stwd/vault";
import { eq } from "drizzle-orm";
import {
  clearEmailAuthTenantCacheForTests,
  getEmailAuthForTenant,
  initAuthStores,
  invalidateEmailAuthForTenant,
} from "../routes/auth";

const TEST_TENANT_ID = "tenant-email-config-test";
const MASTER_PASSWORD = "tenant-email-config-master-password";

describe("getEmailAuthForTenant", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
    process.env.APP_URL = "https://app.example.com";
    process.env.EMAIL_FROM = "Global <login@example.com>";
    process.env.RESEND_API_KEY = "global-resend-key";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await initAuthStores(false);

    const dbHandle = getDb();
    await dbHandle.insert(tenants).values({
      id: TEST_TENANT_ID,
      name: "Tenant Email Config Test",
      apiKeyHash: "hash",
    });
  });

  afterAll(async () => {
    clearEmailAuthTenantCacheForTests();
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.APP_URL;
    delete process.env.EMAIL_FROM;
    delete process.env.EMAIL_BRAND_NAME;
    delete process.env.EMAIL_MAGIC_LINK_BASE_URL;
    delete process.env.EMAIL_MAGIC_LINK_CALLBACK_PATH;
    delete process.env.RESEND_API_KEY;
  });

  it("falls back to the global env config when tenant emailConfig is unset", async () => {
    clearEmailAuthTenantCacheForTests();

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).from).toBe("Global <login@example.com>");
    expect((auth as any).templateId).toBeUndefined();
    expect((auth as any).baseUrl).toBe("https://app.example.com");
    expect((auth as any).callbackPath).toBe("/auth/callback/email");
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");
    expect(provider.replyTo).toBeUndefined();
  });

  it("keeps hosted branding and callback routing when tenant config is unavailable", async () => {
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    process.env.EMAIL_BRAND_NAME = "Eliza";
    process.env.EMAIL_MAGIC_LINK_BASE_URL = "https://cloud-staging.example";
    process.env.EMAIL_MAGIC_LINK_CALLBACK_PATH = "/auth/callback/email";
    clearEmailAuthTenantCacheForTests();

    try {
      const auth = await getEmailAuthForTenant(TEST_TENANT_ID);

      expect((auth as any).brandName).toBe("Eliza");
      expect((auth as any).baseUrl).toBe("https://cloud-staging.example");
      expect((auth as any).callbackPath).toBe("/auth/callback/email");

      const rendered = (auth as any).templateRenderer(undefined, {
        magicLink: "https://cloud-staging.example/auth/callback/email?token=fixture",
        email: "user@example.com",
        tenantName: (auth as any).brandName,
        expiresInMinutes: 10,
      });
      expect(rendered.subject).toBe("Sign in to Eliza");
      expect(rendered.text).toContain(
        "https://cloud-staging.example/auth/callback/email?token=fixture",
      );
      expect(rendered.html).not.toContain("steward.fi");
    } finally {
      delete process.env.EMAIL_BRAND_NAME;
      delete process.env.EMAIL_MAGIC_LINK_BASE_URL;
      delete process.env.EMAIL_MAGIC_LINK_CALLBACK_PATH;
      clearEmailAuthTenantCacheForTests();
    }
  });

  it("uses the tenant-specific config when emailConfig is set", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        provider: "resend",
        apiKeyEncrypted: JSON.stringify(encrypted),
        from: "Tenant <login@tenant.example.com>",
        replyTo: "help@tenant.example.com",
        templateId: "customer-template",
        subjectOverride: "Tenant Sign In",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).from).toBe("Tenant <login@tenant.example.com>");
    expect((auth as any).replyTo).toBe("help@tenant.example.com");
    expect((auth as any).templateId).toBe("customer-template");
    expect((auth as any).subjectOverride).toBe("Tenant Sign In");
    expect(provider.from).toBe("Tenant <login@tenant.example.com>");
    expect(provider.replyTo).toBe("help@tenant.example.com");
    // Without magicLinkBaseUrl set, baseUrl should fall back to APP_URL
    expect((auth as any).baseUrl).toBe("https://app.example.com");
    expect((auth as any).callbackPath).toBe("/auth/callback/email");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("uses tenant magicLinkBaseUrl when set, with default callback path", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        provider: "resend",
        apiKeyEncrypted: JSON.stringify(encrypted),
        from: "Waifu <noreply@waifu.fun>",
        magicLinkBaseUrl: "https://waifu.fun",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);

    expect((auth as any).baseUrl).toBe("https://waifu.fun");
    // Defaults to /auth/email/verify when magicLinkBaseUrl is set
    expect((auth as any).callbackPath).toBe("/auth/email/verify");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("uses tenant branding with its hosted magic-link callback", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        provider: "resend",
        apiKeyEncrypted: JSON.stringify(encrypted),
        from: "Customer <noreply@customer.example>",
        brandName: "Customer Cloud",
        magicLinkBaseUrl: "https://cloud.customer.example/",
        magicLinkCallbackPath: "/auth/callback/email",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);

    // Trailing slash gets stripped from baseUrl
    expect((auth as any).baseUrl).toBe("https://cloud.customer.example");
    expect((auth as any).callbackPath).toBe("/auth/callback/email");
    expect((auth as any).brandName).toBe("Customer Cloud");

    const rendered = (auth as any).templateRenderer(undefined, {
      magicLink: `${(auth as any).baseUrl}${(auth as any).callbackPath}?token=fixture`,
      email: "user@customer.example",
      tenantName: (auth as any).brandName,
      expiresInMinutes: 10,
    });
    expect(rendered.subject).toBe("Sign in to Customer Cloud");
    expect(rendered.text).toContain(
      "https://cloud.customer.example/auth/callback/email?token=fixture",
    );
    expect(rendered.html).not.toContain("steward.fi");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("uses global Resend creds + per-tenant magicLinkBaseUrl when no apiKeyEncrypted", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    // Magic-link-only tenant config (no per-tenant Resend key).
    // This is the waifu.fun shape: tenant doesn't bring its own Resend
    // account, just wants its own magic-link landing URL.
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        magicLinkBaseUrl: "https://waifu.fun",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    // Magic-link target overridden to the tenant's domain
    expect((auth as any).baseUrl).toBe("https://waifu.fun");
    expect((auth as any).callbackPath).toBe("/auth/email/verify");
    // Provider falls back to the global Resend key
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("honors templateId/subjectOverride/replyTo on the global provider when no apiKeyEncrypted", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    // Template-only tenant config: shared platform Resend account, but the
    // tenant wants its own branded email. This is the shared-provider branding shape —
    // This must not silently fall back to the Steward default template.
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        templateId: "customer-template",
        subjectOverride: "Sign in to Customer App",
        replyTo: "support@customer-template.ai",
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).templateId).toBe("customer-template");
    expect((auth as any).subjectOverride).toBe("Sign in to Customer App");
    expect((auth as any).replyTo).toBe("support@customer-template.ai");
    // Still the global provider + global sender
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });

  it("renders deployer-supplied raw templates from tenant config (global provider path)", async () => {
    clearEmailAuthTenantCacheForTests();

    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    // Custom-template tenant config: branded markup stored as instance
    // CONFIG, not repo code — the vendor-neutral mechanism for hosted
    // Steward deployments.
    await dbHandle.insert(tenantConfigs).values({
      tenantId: TEST_TENANT_ID,
      emailConfig: {
        templates: {
          magicLink: {
            subject: "Sign in to Customer App",
            text: "Link: {{magicLink}}",
            html: '<a href="{{magicLink}}">Sign in to Customer App</a>',
          },
          otp: {
            subject: "{{code}} is your Customer App code",
            text: "Code: {{code}}",
            html: "<b>{{code}}</b>",
          },
        },
      },
    });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);

    const magicRendered = (auth as any).templateRenderer(undefined, {
      magicLink: "https://app.example.com/auth/callback/email?token=t",
      email: "user@example.com",
      expiresInMinutes: 10,
      tenantName: undefined,
    });
    expect(magicRendered.subject).toBe("Sign in to Customer App");
    expect(magicRendered.text).toBe("Link: https://app.example.com/auth/callback/email?token=t");
    expect(magicRendered.html).toContain("Sign in to Customer App</a>");

    const otpRendered = (auth as any).otpTemplateRenderer(undefined, {
      email: "user@example.com",
      code: "654321",
      brandName: "Customer App",
      expiresInMinutes: 10,
    });
    expect(otpRendered.subject).toBe("654321 is your Customer App code");
    expect(otpRendered.html).toBe("<b>654321</b>");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });
});

describe("email magic-link verification hardening", () => {
  it("preflights tenant access before mutating email identity or wallet state", () => {
    const source = readFileSync(new URL("../routes/auth.ts", import.meta.url), "utf8");
    const completeStart = source.indexOf("async function completeEmailAuth");
    expect(completeStart).toBeGreaterThanOrEqual(0);
    const completeEnd = source.indexOf("function getEmailAuthRedirectBaseUrl", completeStart);
    const completeSource = source.slice(completeStart, completeEnd);

    const preflight = completeSource.indexOf("resolveEmailTenantBeforeMutation");
    expect(preflight).toBeGreaterThanOrEqual(0);
    expect(preflight).toBeLessThan(completeSource.indexOf("findOrCreateUserWithStatus(email)"));
    expect(preflight).toBeLessThan(completeSource.indexOf("emailVerified: true"));
    expect(preflight).toBeLessThan(completeSource.indexOf("provisionWalletForUser"));
  });

  it("rate limits both JSON verify and browser callback before token checks", () => {
    const source = readFileSync(new URL("../routes/auth.ts", import.meta.url), "utf8");
    const verifyStart = source.indexOf('auth.post("/email/verify"');
    const callbackStart = source.indexOf('auth.get("/callback/email"');
    expect(verifyStart).toBeGreaterThanOrEqual(0);
    expect(callbackStart).toBeGreaterThanOrEqual(0);
    expect(source.indexOf('"email-verify"', verifyStart)).toBeLessThan(
      source.indexOf("verifyMagicLink(body.token, email, resolvedTenantId)", verifyStart),
    );
    expect(source.indexOf('"email-verify-token"', verifyStart)).toBeLessThan(
      source.indexOf("verifyMagicLink(body.token, email, resolvedTenantId)", verifyStart),
    );
    expect(source.indexOf('"email-callback"', callbackStart)).toBeLessThan(
      source.indexOf("verifyMagicLink(token, email, resolvedTenantId)", callbackStart),
    );
    expect(source.indexOf('"email-callback-token"', callbackStart)).toBeLessThan(
      source.indexOf("verifyMagicLink(token, email, resolvedTenantId)", callbackStart),
    );
  });
});
