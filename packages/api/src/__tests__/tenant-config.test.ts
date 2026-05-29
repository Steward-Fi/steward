import { afterAll, beforeAll, describe, expect, it } from "bun:test";

// Skip all DB-dependent tests when DATABASE_URL is not configured
const SKIP = !process.env.DATABASE_URL;

import { generateApiKey } from "@stwd/auth";
import { agents, getDb, policies, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { eq } from "drizzle-orm";

// ─── Test Config ──────────────────────────────────────────────────────────

const TEST_PORT = parseInt(process.env.PORT || "3299", 10);
const BASE_URL = `http://localhost:${TEST_PORT}`;

const TENANT_ID = "test-tenant-config";
const AGENT_ID = "test-tenant-config-agent";
const DASHBOARD_USER_ID = crypto.randomUUID();
const OTHER_TENANT_ID = "test-tenant-config-other";
const OTHER_AGENT_ID = "test-tenant-config-other-agent";
const DASHBOARD_USER_EMAIL = `dashboard-${DASHBOARD_USER_ID}@example.test`;
let validApiKey: string;
// PUT /config and template-apply were hardened to require an owner/admin session
// with recent MFA. `sessionHeaders()` authenticates those; `headers()` keeps a
// tenant API key for GET-redaction and security-boundary rejection assertions.
let sessionToken: string;

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
  await db
    .insert(tenants)
    .values({
      id: OTHER_TENANT_ID,
      name: "Other Config Test Tenant",
      // Distinct hash: apiKeyHash is unique, so reusing the primary tenant's hash
      // would make this insert no-op via onConflictDoNothing and break the agent FK.
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
    .values({ id: DASHBOARD_USER_ID, email: DASHBOARD_USER_EMAIL, emailVerified: true })
    .onConflictDoNothing();
  await db
    .insert(userTenants)
    .values({ userId: DASHBOARD_USER_ID, tenantId: TENANT_ID, role: "owner" })
    .onConflictDoNothing();

  const { createSessionToken } = await import("../routes/auth");
  sessionToken = await createSessionToken(
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

// Owner session with recent MFA — required by PUT /config and template apply.
const sessionHeaders = () => ({
  "X-Steward-Tenant": TENANT_ID,
  Authorization: `Bearer ${sessionToken}`,
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
        // Upsert the hash so a leftover milady-cloud row (e.g. from an interrupted
        // run) still matches the freshly generated key instead of returning 403.
        .onConflictDoUpdate({
          target: tenants.id,
          set: { apiKeyHash: apiKeyPair.hash },
        });

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
        headers: sessionHeaders(),
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
      expect(body.data.theme.primaryColor).toBe("#FF0000");
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
          ...sessionHeaders(),
          "Content-Type": "text/plain",
        },
        body: "not json",
      });
      expect(res.status).toBe(400);
    });

    it("rejects tenant API-key updates to security-sensitive config fields", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: headers(),
        body: JSON.stringify({
          allowedOrigins: ["https://attacker.example"],
          authAbuseConfig: {},
        }),
      });

      // API-key callers are rejected before any mutation: PUT /config now requires
      // an owner/admin session, so the request never reaches the security-field check.
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin session");
    });

    it("rejects templates with unsupported persisted policy types", async () => {
      const res = await fetch(`${BASE_URL}/tenants/${TENANT_ID}/config`, {
        method: "PUT",
        headers: sessionHeaders(),
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
      // Route now rejects unsupported persisted policy types with this message.
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
          headers: sessionHeaders(),
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
          headers: sessionHeaders(),
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
          headers: sessionHeaders(),
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
          headers: sessionHeaders(),
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
          headers: sessionHeaders(),
          body: JSON.stringify({ agentId: AGENT_ID }),
        },
      );

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.ok).toBe(false);
      // Route now rejects unsupported persisted policy types with this message.
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
    // dashboardAuthMiddleware requires a userId on session tokens, and the
    // dashboard route now also requires recent MFA verification — so we mint a
    // session that includes both. The route then reaches the agent lookup,
    // which 404s for the non-existent agent.
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
