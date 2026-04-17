import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { KeyStore } from "@stwd/vault";
import {
  closeDb,
  createPGLiteDb,
  getDb,
  setPGLiteOverride,
  tenantConfigs,
  tenants,
} from "@stwd/db";
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
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.APP_URL;
    delete process.env.EMAIL_FROM;
    delete process.env.RESEND_API_KEY;
  });

  it("falls back to the global env config when tenant emailConfig is unset", async () => {
    clearEmailAuthTenantCacheForTests();

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).from).toBe("Global <login@example.com>");
    expect((auth as any).templateId).toBeUndefined();
    expect(provider.constructor.name).toBe("ResendProvider");
    expect(provider.from).toBe("Global <login@example.com>");
    expect(provider.replyTo).toBeUndefined();
  });

  it("uses the tenant-specific config when emailConfig is set", async () => {
    clearEmailAuthTenantCacheForTests();

    const encrypted = new KeyStore(MASTER_PASSWORD).encrypt("tenant-resend-key");
    const dbHandle = getDb();
    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    await dbHandle
      .insert(tenantConfigs)
      .values({
        tenantId: TEST_TENANT_ID,
        emailConfig: {
          provider: "resend",
          apiKeyEncrypted: JSON.stringify(encrypted),
          from: "Tenant <login@tenant.example.com>",
          replyTo: "help@tenant.example.com",
          templateId: "elizacloud",
          subjectOverride: "Tenant Sign In",
        },
      });
    invalidateEmailAuthForTenant(TEST_TENANT_ID);

    const auth = await getEmailAuthForTenant(TEST_TENANT_ID);
    const provider = (auth as any).provider;

    expect((auth as any).from).toBe("Tenant <login@tenant.example.com>");
    expect((auth as any).replyTo).toBe("help@tenant.example.com");
    expect((auth as any).templateId).toBe("elizacloud");
    expect((auth as any).subjectOverride).toBe("Tenant Sign In");
    expect(provider.from).toBe("Tenant <login@tenant.example.com>");
    expect(provider.replyTo).toBe("help@tenant.example.com");

    await dbHandle.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TEST_TENANT_ID));
    invalidateEmailAuthForTenant(TEST_TENANT_ID);
  });
});
