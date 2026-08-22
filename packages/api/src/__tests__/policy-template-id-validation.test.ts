import { describe, expect, it } from "bun:test";
import { auditEvents, getDb, policyTemplates } from "@stwd/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = "policy-template-id-boundary";
const VALID_MISSING_ID = "11111111-1111-4111-8111-111111111111";

async function makeApp(options: { mfa?: boolean; role?: "admin" | "member" } = {}) {
  const { policiesStandaloneRoutes } = await import("../routes/policies-standalone");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", options.role ?? "admin");
    c.set("userId", "22222222-2222-4222-8222-222222222222");
    if (options.mfa !== false) c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/policies", policiesStandaloneRoutes);
  return app;
}

const malformedIds = [
  "not-a-uuid",
  "00000000-0000-0000-0000-000000000000",
  `11111111-1111-4111-8111-111111111111${"x".repeat(256)}`,
  "11111111-1111-4111-8111-111111111111\u0000suffix",
  "11111111-1111-4111-8111-111111111111\nsuffix",
];

const routes = [
  { method: "GET", suffix: "", body: undefined },
  { method: "PUT", suffix: "", body: { name: "must-not-update" } },
  { method: "DELETE", suffix: "", body: undefined },
  { method: "POST", suffix: "/assign", body: { agentIds: ["must-not-assign"] } },
] as const;

describe("mounted policy-template id boundary", () => {
  it("uniformly rejects malformed IDs before lookup, mutation, or audit", async () => {
    const app = await makeApp();
    const beforeTemplates = await getDb()
      .select({ id: policyTemplates.id })
      .from(policyTemplates)
      .where(eq(policyTemplates.tenantId, TENANT_ID));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));

    for (const id of malformedIds) {
      for (const route of routes) {
        const response = await app.request(`/policies/${encodeURIComponent(id)}${route.suffix}`, {
          method: route.method,
          headers: { "content-type": "application/json" },
          body: route.body === undefined ? undefined : JSON.stringify(route.body),
        });
        expect(response.status, `${route.method} ${JSON.stringify(id)}`).toBe(400);
        await expect(response.json()).resolves.toEqual({
          ok: false,
          error: "Invalid policy template id format",
        });
      }
    }

    expect(
      await getDb()
        .select({ id: policyTemplates.id })
        .from(policyTemplates)
        .where(eq(policyTemplates.tenantId, TENANT_ID)),
    ).toEqual(beforeTemplates);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
  });

  it("distinguishes a valid missing UUID from malformed input", async () => {
    const app = await makeApp();
    for (const route of routes) {
      const response = await app.request(`/policies/${VALID_MISSING_ID}${route.suffix}`, {
        method: route.method,
        headers: { "content-type": "application/json" },
        body: route.body === undefined ? undefined : JSON.stringify(route.body),
      });
      expect(response.status, route.method).toBe(404);
      await expect(response.json()).resolves.toMatchObject({
        ok: false,
        error: expect.stringMatching(/not found/i),
      });
    }
  });

  it("preserves adjacent admin and recent-MFA boundaries", async () => {
    const noMfa = await makeApp({ mfa: false });
    const member = await makeApp({ role: "member" });
    const noMfaResponse = await noMfa.request(`/policies/${VALID_MISSING_ID}`);
    const memberResponse = await member.request(`/policies/${VALID_MISSING_ID}`, {
      method: "DELETE",
    });
    expect(noMfaResponse.status).toBe(403);
    expect(memberResponse.status).toBe(403);
  });
});
