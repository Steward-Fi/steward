import { afterAll, beforeAll, describe, expect, it } from "bun:test";

// Skip all DB-dependent tests when DATABASE_URL is not configured
const SKIP = !process.env.DATABASE_URL;

import { generateApiKey } from "@stwd/auth";
import { agents, getDb, policies, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { eq } from "drizzle-orm";

// ─── Test Config ──────────────────────────────────────────────────────────

const TEST_PORT = 3299;
const BASE_URL = `http://localhost:${TEST_PORT}`;

const TENANT_ID = "test-tenant-config";
const AGENT_ID = "test-tenant-config-agent";
const DASHBOARD_USER_ID = crypto.randomUUID();
const OTHER_TENANT_ID = "test-tenant-config-other";
const OTHER_AGENT_ID = "test-tenant-config-other-agent";
const DASHBOARD_USER_EMAIL = `dashboard-${DASHBOARD_USER_ID}@example.test`;
let validApiKey: string;
// Owner session token with recent MFA. Config mutation routes now require
// requireRecentTenantAdminMfa (session-jwt + owner/admin + recent MFA), so
// API-key auth is correctly rejected for those; use this for legitimate updates.
let adminSessionToken: string;

// ─── Setup ────────────────────────────────────────────────────────────────

beforeAll(async () => {
  if (SKIP) return;
  const db = getDb();
  const apiKeyPair = generateApiKey();
  validApiKey = apiKeyPair.key;

  await db
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Config Test Tenant",
      apiKeyHash: apiKeyPair.hash,
    })
    .onConflictDoNothing();
  // apiKeyHash is unique-indexed. Reusing apiKeyPair.hash made this second
  // tenant insert silently no-op under onConflictDoNothing, which then tripped
  // the agents -> tenants FK below. Give the other tenant its own key hash.
  await db
    .insert(tenants)
    .values({
      id: OTHER_TENANT_ID,
      name: "Other Config Test Tenant",
      apiKeyHash: generateApiKey().hash,
    })
    .onConflictDoNothing();
  await db
    .insert(agents)
    .values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Config Test Agent",
      walletAddress: `0x${"1".repeat(40)}`,
    })
    .onConflictDoNothing();
  await db
    .insert(agents)
    .values({
      id: OTHER_AGENT_ID,
      tenantId: OTHER_TENANT_ID,
      name: "Other Tenant Agent",
      walletAddress: `0x${"2".repeat(40)}`,
    })
    .onConflictDoNothing();
  await db
    .insert(users)
    .values({ id: DASHBOARD_USER_ID, email: DASHBOARD_USER_EMAIL })
    .onConflictDoNothing();
  await db
    .insert(userTenants)
    .values({ userId: DASHBOARD_USER_ID, tenantId: TENANT_ID, role: "owner" })
    .onConflictDoNothing();

  const { createSessionToken } = await import("../routes/auth");
  adminSessionToken = await createSessionToken(
    "0x0000000000000000000000000000000000000000",
    TENANT_ID,
    {
      userId: DASHBOARD_USER_ID,
      email: DASHBOARD_USER_EMAIL,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    },
  );
});

afterAll(async () => {
  if (SKIP) return;
  const db = getDb();
  await db.delete(policies).where(eq(policies.agentId, AGENT_ID));
  await db.delete(policies).where(eq(policies.agentId, OTHER_AGENT_ID));
  await db.delete(userTenants).where(eq(userTenants.tenantId, TENANT_ID));
  await db.delete(users).where(eq(users.id, DASHBOARD_USER_ID));
  await db.delete(agents).where(eq(agents.id, AGENT_ID));
  await db.delete(agents).where(eq(agents.id, OTHER_AGENT_ID));
  await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
  await db.delete(tenants).where(eq(tenants.id, TENANT_ID));
  await db.delete(tenants).where(eq(tenants.id, OTHER_TENANT_ID));
});

const headers = () => ({
  "X-Steward-Tenant": TENANT_ID,
  "X-Steward-Key": validApiKey,
  "Content-Type": "application/json",
});

// Owner session + recent MFA, required by config mutation routes.
const adminHeaders = () => ({
  "X-Steward-Tenant": TENANT_ID,
  Authorization: `Bearer ${adminSessionToken}`,
  "Content-Type": "application/json",
});

// ─── Tests ────────────────────────────────────────────────────────────────

describe.skipIf(SKIP)("Tenant Config API", () => {
  describe("GET /tenants/:id/config", () => {
    it("returns empty config for tenant with no config set", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        headers: headers(),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.tenantId).toBe(TENANT_ID);
      expect(body.data.policyExposure).toEqual({});
      expect(body.data.policyTemplates).toEqual([]);
    });

    it("returns default config for milady-cloud tenant", async () => {
      // This tests the default fallback — milady-cloud has built-in defaults
      // We need a milady-cloud tenant to exist for auth to pass
      const db = getDb();
      const apiKeyPair = generateApiKey();
      await db
        .insert(tenants)
        .values({
          id: "milady-cloud",
          name: "Milady Cloud",
          apiKeyHash: apiKeyPair.hash,
        })
        .onConflictDoNothing();

      const res = await fetch(`${BASE_URL}/tenants/milady-cloud/config`, {
        headers: {
          "X-Steward-Tenant": "milady-cloud",
          "X-Steward-Key": apiKeyPair.key,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.tenantId).toBe("milady-cloud");
      expect(body.data.policyTemplates.length).toBeGreaterThan(0);
      expect(body.data.policyExposure["spending-limit"]).toBe("visible");

      // Cleanup
      await db.delete(tenants).where(eq(tenants.id, "milady-cloud"));
    });

    it("redacts admin-only auth configuration for tenant API key callers", async () => {
      const db = getDb();
      await db
        .insert(tenantConfigs)
        .values({
          tenantId: TENANT_ID,
          oidcProviders: [
            {
              id: "admin-only",
              issuer: "https://issuer.example.test",
              clientId: "client-id",
              audience: ["api://tenant"],
              jwksUri: "https://issuer.example.test/.well-known/jwks.json",
            },
          ],
          authAbuseConfig: {
            captcha: {
              enabled: true,
              provider: "turnstile",
              siteKey: "public-site-key",
              secretKeyEnv: "STEWARD_TENANT_TURNSTILE_SECRET",
              requiredFor: ["email_otp"],
            },
          },
        })
        .onConflictDoUpdate({
          target: tenantConfigs.tenantId,
          set: {
            oidcProviders: [
              {
                id: "admin-only",
                issuer: "https://issuer.example.test",
                clientId: "client-id",
                audience: ["api://tenant"],
                jwksUri: "https://issuer.example.test/.well-known/jwks.json",
              },
            ],
            authAbuseConfig: {
              captcha: {
                enabled: true,
                provider: "turnstile",
                siteKey: "public-site-key",
                secretKeyEnv: "STEWARD_TENANT_TURNSTILE_SECRET",
                requiredFor: ["email_otp"],
              },
            },
          },
        });

      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        headers: headers(),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.oidcProviders).toBeUndefined();
      expect(body.data.authAbuseConfig).toBeUndefined();
    });
  });

  describe("PUT /tenants/:id/config", () => {
    it("creates/updates tenant config", async () => {
      const config = {
        displayName: "Test Tenant Display",
        policyExposure: {
          "spending-limit": "visible",
          "rate-limit": "enforced",
        },
        policyTemplates: [
          {
            id: "test-template",
            name: "Test Template",
            description: "A test template",
            icon: "test",
            policies: [
              {
                id: "tpl-spend",
                type: "spending-limit",
                enabled: true,
                config: {
                  maxPerTx: "100",
                  maxPerDay: "1000",
                  maxPerWeek: "5000",
                },
              },
            ],
            customizableFields: [],
          },
        ],
        featureFlags: {
          showFundingQR: true,
          showTransactionHistory: true,
          showSpendDashboard: false,
          embeddedWallets: {
            createOnLogin: "users-without-wallets",
          },
        },
        approvalConfig: {
          autoExpireSeconds: 3600,
          approvers: { mode: "owner" },
        },
        theme: {
          primaryColor: "#FF0000",
          colorScheme: "dark",
        },
      };

      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify(config),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.tenantId).toBe(TENANT_ID);
      expect(body.data.displayName).toBe("Test Tenant Display");
      expect(body.data.policyExposure["spending-limit"]).toBe("visible");
      expect(body.data.policyTemplates).toHaveLength(1);
      expect(body.data.featureFlags.showFundingQR).toBe(true);
      expect(body.data.featureFlags.showSpendDashboard).toBe(false);
      expect(body.data.featureFlags.embeddedWallets.createOnLogin).toBe("users-without-wallets");
      expect(body.data.theme.primaryColor).toBe("#FF0000");
    });

    it("merges partial embedded wallet feature flag updates", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({
          featureFlags: {
            embeddedWallets: {
              createOnLogin: "all-users",
            },
          },
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.featureFlags.showFundingQR).toBe(true);
      expect(body.data.featureFlags.showSpendDashboard).toBe(false);
      expect(body.data.featureFlags.embeddedWallets.createOnLogin).toBe("all-users");
    });

    it("rejects invalid embedded wallet create-on-login feature flags", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({
          featureFlags: {
            embeddedWallets: {
              createOnLogin: "sometimes",
            },
          },
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.ok).toBe(false);
      expect(body.error).toContain("featureFlags.embeddedWallets.createOnLogin");

      const saved = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        headers: headers(),
      });
      const savedBody = await saved.json();
      expect(savedBody.data.featureFlags.embeddedWallets.createOnLogin).toBe("all-users");
    });

    it("persists app-client embedded wallet create-on-login overrides", async () => {
      const appClients = [
        {
          id: "web-prod",
          name: "Production Web",
          environment: "production",
          enabled: true,
          isDefault: true,
          allowedOrigins: ["https://app.example.test"],
          allowedRedirectUrls: ["https://app.example.test/auth/callback"],
          embeddedWallets: { createOnLogin: "off" },
        },
      ];

      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({ appClients }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.appClients[0].embeddedWallets.createOnLogin).toBe("off");

      const saved = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        headers: adminHeaders(),
      });
      const savedBody = await saved.json();
      expect(savedBody.data.appClients[0].embeddedWallets.createOnLogin).toBe("off");
    });

    it("preserves app-client embedded wallet inheritance when no override is supplied", async () => {
      const appClients = [
        {
          id: "web-inherit",
          name: "Inherited Web",
          environment: "preview",
          enabled: true,
          isDefault: false,
          allowedOrigins: ["https://inherit.example.test"],
          allowedRedirectUrls: ["https://inherit.example.test/auth/callback"],
        },
      ];

      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({ appClients }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.appClients[0].embeddedWallets).toBeUndefined();

      const saved = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        headers: adminHeaders(),
      });
      const savedBody = await saved.json();
      expect(savedBody.data.appClients[0].embeddedWallets).toBeUndefined();
    });

    it("rejects invalid app-client embedded wallet create-on-login overrides", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({
          appClients: [
            {
              id: "web-bad",
              name: "Bad Web",
              environment: "production",
              embeddedWallets: { createOnLogin: "sometimes" },
            },
          ],
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.ok).toBe(false);
      expect(body.error).toContain('app client "web-bad" embeddedWallets.createOnLogin');
    });

    it("GET returns the saved config", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        headers: headers(),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.displayName).toBe("Test Tenant Display");
      expect(body.data.policyTemplates).toHaveLength(1);
    });

    it("rejects invalid JSON", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: {
          ...adminHeaders(),
          "Content-Type": "text/plain",
        },
        body: "not json",
      });
      expect(res.status).toBe(400);
    });

    it("rejects tenant API-key updates to security-sensitive config fields", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: headers(), // intentional: API-key must be rejected
        body: JSON.stringify({
          allowedOrigins: ["https://attacker.example"],
          authAbuseConfig: {},
        }),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      // The top-level admin-session+MFA gate rejects API-key callers before the
      // field-specific check; either way it is a 403 owner/admin-session rejection.
      expect(body.error).toContain("owner or admin session");
    });

    it("rejects templates with unsupported persisted policy types", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({
          policyTemplates: [
            {
              id: "bad-template",
              name: "Bad Template",
              description: "Unsupported policy should not be stored",
              icon: "test",
              policies: [
                {
                  id: "bad-policy",
                  type: "unsupported-policy",
                  enabled: true,
                  config: {},
                },
              ],
              customizableFields: [],
            },
          ],
        }),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.ok).toBe(false);
      expect(body.error).toContain("Unknown policy type");
    });
  });

  describe("GET /tenants/:id/config/templates", () => {
    it("returns saved templates", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config/templates`, {
        headers: headers(),
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data).toHaveLength(1);
      expect(body.data[0].id).toBe("test-template");
    });
  });

  describe("POST /tenants/:id/config/templates/:name/apply", () => {
    it("rejects without agentId", async () => {
      const res = await fetch(
        `${BASE_URL}/tenants/${TENANT_ID}/config/templates/test-template/apply`,
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({}),
        },
      );
      expect(res.status).toBe(400);
    });

    it("returns 404 for non-existent template", async () => {
      const res = await fetch(
        `${BASE_URL}/tenants/${TENANT_ID}/config/templates/nonexistent/apply`,
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({ agentId: "some-agent" }),
        },
      );
      expect(res.status).toBe(404);
    });

    it("rejects applying a template to an agent owned by another tenant", async () => {
      const res = await fetch(
        `${BASE_URL}/tenants/${TENANT_ID}/config/templates/test-template/apply`,
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({ agentId: OTHER_AGENT_ID }),
        },
      );

      expect(res.status).toBe(404);

      const db = getDb();
      const otherPolicies = await db
        .select()
        .from(policies)
        .where(eq(policies.agentId, OTHER_AGENT_ID));
      expect(otherPolicies).toHaveLength(0);
    });

    it("rejects undeclared overrides without deleting existing policies", async () => {
      const db = getDb();
      await db.delete(policies).where(eq(policies.agentId, AGENT_ID));
      await db.insert(policies).values({
        id: `${AGENT_ID}-existing`,
        agentId: AGENT_ID,
        type: "rate-limit",
        enabled: true,
        config: { maxTxPerDay: 1 },
      });

      const res = await fetch(
        `${BASE_URL}/tenants/${TENANT_ID}/config/templates/test-template/apply`,
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({
            agentId: AGENT_ID,
            overrides: { "spending-limit.maxPerDay": "999999999999999999999999" },
          }),
        },
      );

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.ok).toBe(false);
      expect(body.error).toContain("Override not allowed");

      const existingPolicies = await db
        .select()
        .from(policies)
        .where(eq(policies.agentId, AGENT_ID));
      expect(existingPolicies).toHaveLength(1);
      expect(existingPolicies[0]?.id).toBe(`${AGENT_ID}-existing`);
    });

    it("rejects malformed stored templates before deleting existing policies", async () => {
      const db = getDb();
      await db
        .update(tenantConfigs)
        .set({
          policyTemplates: [
            {
              id: "bad-template",
              name: "Bad Template",
              description: "Unsupported policy from storage",
              icon: "test",
              policies: [
                {
                  id: "bad-policy",
                  type: "unsupported-policy",
                  enabled: true,
                  config: {},
                },
              ],
              customizableFields: [],
            },
          ],
        })
        .where(eq(tenantConfigs.tenantId, TENANT_ID));

      const res = await fetch(
        `${BASE_URL}/tenants/${TENANT_ID}/config/templates/bad-template/apply`,
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({ agentId: AGENT_ID }),
        },
      );

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.ok).toBe(false);
      expect(body.error).toContain("Unknown policy type");

      const existingPolicies = await db
        .select()
        .from(policies)
        .where(eq(policies.agentId, AGENT_ID));
      expect(existingPolicies).toHaveLength(1);
      expect(existingPolicies[0]?.id).toBe(`${AGENT_ID}-existing`);
    });
  });

  describe("Auth", () => {
    it("rejects access without auth", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`);
      expect(res.status).toBe(403);
    });

    it("rejects cross-tenant access", async () => {
      const res = await fetch(`${BASE_URL}/tenants/other-tenant/config`, {
        headers: headers(),
      });
      expect(res.status).toBe(403);
    });
  });
});

describe.skipIf(SKIP)("Dashboard API", () => {
  it("returns 404 for non-existent agent", async () => {
    const { createSessionToken } = await import("../routes/auth");
    // dashboardAuthMiddleware requires a userId on session tokens, so we
    // mint a session that includes one. The dashboard route also now requires
    // recent session MFA, so include mfaVerifiedAt. The route itself only
    // cares about the agent lookup result, hence the synthetic userId.
    const token = await createSessionToken(
      "0x0000000000000000000000000000000000000000",
      TENANT_ID,
      { userId: DASHBOARD_USER_ID, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
    );
    const res = await fetch(`${BASE_URL}/dashboard/nonexistent-agent`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(404);
  });
});
