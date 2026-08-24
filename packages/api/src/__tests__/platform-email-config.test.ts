import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const PLATFORM_KEY = "platform-email-config-key";
const TENANT_ID = "platform-email-config-tenant";

describe("platform tenant email config routes", () => {
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "platform-email-config-master-password";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [PLATFORM_KEY]: [
        "platform:read",
        "platform:write",
        "platform:tenant-email-config:read",
        "platform:tenant-email-config:write",
        "platform:tenant-oidc:read",
        "platform:tenant-oidc:write",
      ],
    });

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const dbHandle = getDb();
    await dbHandle.insert(tenants).values({
      id: TENANT_ID,
      name: "Platform Email Config Tenant",
      apiKeyHash: "platform-email-config-hash",
    });

    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  });

  it("patches, reads, and deletes tenant email config", async () => {
    const patchResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        apiKey: "tenant-resend-api-key",
        from: "Tenant <login@tenant.example.com>",
        replyTo: "help@tenant.example.com",
        templateId: "customer-template",
        subjectOverride: "Tenant Sign In",
      }),
    });

    expect(patchResponse.status).toBe(200);
    const patchBody = (await patchResponse.json()) as {
      ok: boolean;
      data: {
        from: string;
        replyTo?: string;
        templateId?: string;
        subjectOverride?: string;
        hasApiKey: boolean;
      };
    };
    expect(patchBody.ok).toBe(true);
    expect(patchBody.data.hasApiKey).toBe(true);
    expect(patchBody.data.from).toBe("Tenant <login@tenant.example.com>");

    const dbHandle = getDb();
    const [storedConfig] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(storedConfig?.emailConfig?.apiKeyEncrypted).toBeDefined();
    expect(storedConfig?.emailConfig?.apiKeyEncrypted).not.toContain("tenant-resend-api-key");

    const getResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
    });

    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as {
      ok: boolean;
      data: {
        emailConfig: {
          from: string;
          replyTo?: string;
          templateId?: string;
          subjectOverride?: string;
        } | null;
        hasApiKey: boolean;
      };
    };
    expect(getBody.ok).toBe(true);
    expect(getBody.data.hasApiKey).toBe(true);
    expect(getBody.data.emailConfig).toEqual({
      provider: "resend",
      from: "Tenant <login@tenant.example.com>",
      replyTo: "help@tenant.example.com",
      templateId: "customer-template",
      subjectOverride: "Tenant Sign In",
    });

    const deleteResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "DELETE",
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
    });

    expect(deleteResponse.status).toBe(200);
    const deleteBody = (await deleteResponse.json()) as { ok: boolean };
    expect(deleteBody.ok).toBe(true);

    const [afterDelete] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(afterDelete?.emailConfig ?? null).toBeNull();
  });

  it("accepts a template-only PATCH (no apiKey) and merges over existing config", async () => {
    const dbHandle = getDb();
    // Seed existing config (upsert: earlier tests may have created the row).
    await dbHandle
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        emailConfig: {
          magicLinkBaseUrl: "https://app.customer.example",
          magicLinkCallbackPath: "/auth/email/verify",
        },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: {
          emailConfig: {
            magicLinkBaseUrl: "https://app.customer.example",
            magicLinkCallbackPath: "/auth/email/verify",
          },
        },
      });

    // Template-only branding config: tenant keeps the platform's global
    // Resend provider, only sets templateId (the shared-provider branding shape).
    const patchResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        brandName: "Customer App",
        templateId: "customer-template",
        subjectOverride: "Sign in to Customer App",
      }),
    });

    expect(patchResponse.status).toBe(200);
    const patchBody = (await patchResponse.json()) as {
      ok: boolean;
      data: {
        brandName?: string;
        templateId?: string;
        subjectOverride?: string;
        hasApiKey: boolean;
      };
    };
    expect(patchBody.ok).toBe(true);
    expect(patchBody.data.brandName).toBe("Customer App");
    expect(patchBody.data.templateId).toBe("customer-template");
    expect(patchBody.data.subjectOverride).toBe("Sign in to Customer App");
    expect(patchBody.data.hasApiKey).toBe(false);

    const [stored] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored?.emailConfig?.templateId).toBe("customer-template");
    expect(stored?.emailConfig?.brandName).toBe("Customer App");
    expect(stored?.emailConfig?.apiKeyEncrypted).toBeUndefined();
    expect(stored?.emailConfig?.magicLinkBaseUrl).toBe("https://app.customer.example");
    expect(stored?.emailConfig?.magicLinkCallbackPath).toBe("/auth/email/verify");

    const getResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
    });
    const getBody = (await getResponse.json()) as {
      data: { emailConfig: { brandName?: string } | null };
    };
    expect(getBody.data.emailConfig?.brandName).toBe("Customer App");

    // from without apiKey is rejected (provider config is all-or-nothing).
    const badResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({ from: "login@customer.example", templateId: "customer-template" }),
    });
    expect(badResponse.status).toBe(400);

    // Empty template-only body is rejected.
    const emptyResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({}),
    });
    expect(emptyResponse.status).toBe(400);

    for (const brandName of ["", "line one\nline two", "x".repeat(101)]) {
      const invalidBrandResponse = await platformRoutes.request(
        `/tenants/${TENANT_ID}/email-config`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "X-Steward-Platform-Key": PLATFORM_KEY,
          },
          body: JSON.stringify({ brandName }),
        },
      );
      expect(invalidBrandResponse.status).toBe(400);
    }

    // Cleanup so later tests see no residual config.
    await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "DELETE",
      headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
    });
  });

  it("patches magic-link routing without provider credentials or branding changes", async () => {
    const dbHandle = getDb();
    await dbHandle
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        emailConfig: { templateId: "customer-template" },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { emailConfig: { templateId: "customer-template" } },
      });

    const response = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        magicLinkBaseUrl: "https://app.customer.example/",
        magicLinkCallbackPath: "/auth/callback/email",
      }),
    });
    expect(response.status).toBe(200);

    const [stored] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored?.emailConfig).toMatchObject({
      templateId: "customer-template",
      magicLinkBaseUrl: "https://app.customer.example/",
      magicLinkCallbackPath: "/auth/callback/email",
    });

    for (const invalid of [
      { magicLinkBaseUrl: "javascript:alert(1)" },
      { magicLinkCallbackPath: "//evil.example/callback" },
    ]) {
      const invalidResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Platform-Key": PLATFORM_KEY,
        },
        body: JSON.stringify(invalid),
      });
      expect(invalidResponse.status).toBe(400);
    }
  });

  it("stores, returns, and clears deployer-supplied raw templates", async () => {
    const templates = {
      magicLink: {
        subject: "Sign in to Customer App",
        text: "Link: {{magicLink}}",
        html: '<a href="{{magicLink}}">Sign in</a>',
      },
      otp: {
        subject: "{{code}} is your Customer App code",
        text: "Code: {{code}}",
        html: "<b>{{code}}</b>",
      },
    };

    // Template-only PATCH carrying raw templates.
    const patchResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({ templates }),
    });
    expect(patchResponse.status).toBe(200);

    const dbHandle = getDb();
    const [stored] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored?.emailConfig?.templates).toEqual(templates);

    // GET exposes the stored templates.
    const getResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "GET",
      headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
    });
    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as {
      data: { emailConfig: { templates?: typeof templates } | null };
    };
    expect(getBody.data.emailConfig?.templates).toEqual(templates);

    // Malformed templates are rejected before persistence.
    const badResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({ templates: { magicLink: { subject: "only-subject" } } }),
    });
    expect(badResponse.status).toBe(400);

    // templates: null clears them without touching the rest of the config.
    const clearResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({ templates: null, templateId: "customer-template" }),
    });
    expect(clearResponse.status).toBe(200);
    const [afterClear] = await dbHandle
      .select({ emailConfig: tenantConfigs.emailConfig })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(afterClear?.emailConfig?.templates).toBeUndefined();
    expect(afterClear?.emailConfig?.templateId).toBe("customer-template");

    // Cleanup.
    await platformRoutes.request(`/tenants/${TENANT_ID}/email-config`, {
      method: "DELETE",
      headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
    });
  });

  it("puts and reads tenant OIDC provider config", async () => {
    const putResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/oidc-providers`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        providers: [
          {
            id: "auth0-prod",
            issuer: "https://tenant.example.com/",
            audience: ["steward-api"],
            jwksUri: "https://tenant.example.com/.well-known/jwks.json",
            allowedAlgs: ["RS256"],
            emailClaim: "email",
            allowJitProvisioning: false,
          },
        ],
      }),
    });

    expect(putResponse.status).toBe(200);
    const putBody = (await putResponse.json()) as {
      ok: boolean;
      data: {
        providers: Array<{
          id: string;
          enabled: boolean;
          issuer: string;
          audience: string[];
          jwksUri: string;
          subjectClaim: string;
          emailClaim: string;
          allowedAlgs: string[];
          allowJitProvisioning: boolean;
        }>;
      };
    };
    expect(putBody.ok).toBe(true);
    expect(putBody.data.providers).toEqual([
      expect.objectContaining({
        id: "auth0-prod",
        enabled: true,
        issuer: "https://tenant.example.com",
        audience: ["steward-api"],
        jwksUri: "https://tenant.example.com/.well-known/jwks.json",
        subjectClaim: "sub",
        emailClaim: "email",
        allowedAlgs: ["RS256"],
        allowJitProvisioning: false,
      }),
    ]);

    const [storedConfig] = await getDb()
      .select({ oidcProviders: tenantConfigs.oidcProviders })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(storedConfig?.oidcProviders).toHaveLength(1);
    expect(storedConfig?.oidcProviders[0]?.issuer).toBe("https://tenant.example.com");

    const getResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/oidc-providers`, {
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
    });

    expect(getResponse.status).toBe(200);
    const getBody = (await getResponse.json()) as typeof putBody;
    expect(getBody.data.providers[0]?.id).toBe("auth0-prod");
  });

  it("rejects unsafe tenant OIDC provider config", async () => {
    const response = await platformRoutes.request(`/tenants/${TENANT_ID}/oidc-providers`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        providers: [
          {
            id: "auth0-prod",
            issuer: "http://tenant.example.com",
            audience: ["steward-api"],
            jwksUri: "https://tenant.example.com/.well-known/jwks.json",
            allowedAlgs: ["HS256"],
          },
        ],
      }),
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("issuer for provider auth0-prod must be a public https URL");
  });

  it("rejects private OIDC JWKS URLs and duplicate audiences", async () => {
    const privateResponse = await platformRoutes.request(`/tenants/${TENANT_ID}/oidc-providers`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        providers: [
          {
            id: "private-jwks",
            issuer: "https://tenant.example.com",
            audience: ["steward-api"],
            jwksUri: "https://127.0.0.1/.well-known/jwks.json",
          },
        ],
      }),
    });

    expect(privateResponse.status).toBe(400);
    const privateBody = (await privateResponse.json()) as { error: string };
    expect(privateBody.error).toContain(
      "jwksUri for provider private-jwks must be a public https URL",
    );

    const duplicateAudienceResponse = await platformRoutes.request(
      `/tenants/${TENANT_ID}/oidc-providers`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Platform-Key": PLATFORM_KEY,
        },
        body: JSON.stringify({
          providers: [
            {
              id: "duplicate-aud",
              issuer: "https://tenant.example.com",
              audience: ["steward-api", "steward-api"],
              jwksUri: "https://tenant.example.com/.well-known/jwks.json",
            },
          ],
        }),
      },
    );

    expect(duplicateAudienceResponse.status).toBe(400);
    const duplicateAudienceBody = (await duplicateAudienceResponse.json()) as { error: string };
    expect(duplicateAudienceBody.error).toContain(
      "duplicate audience for provider duplicate-aud: steward-api",
    );
  });
});
