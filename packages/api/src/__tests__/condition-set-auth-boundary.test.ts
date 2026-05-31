import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `condition-set-auth-${Date.now()}`;

async function makeApp() {
  const { conditionSetRoutes } = await import("../routes/condition-sets");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    const mode = c.req.header("x-test-auth-mode") ?? "api-key";
    c.set("tenantId", TENANT_ID);
    c.set(
      "authType",
      mode === "agent" ? "agent-token" : mode === "api-key" ? "api-key" : "session-jwt",
    );
    if (mode === "admin" || mode === "admin-no-mfa") {
      c.set("tenantRole", "admin");
      c.set("sessionUserId", "condition-set-admin");
    }
    if (mode === "admin") {
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("sessionMfaMethod", "totp");
    }
    await next();
  });
  app.route("/condition-sets", conditionSetRoutes);
  return app;
}

describe("condition set executable auth boundary", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "condition-set-auth-master-password";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Condition Set Auth Tenant",
      apiKeyHash: "hash",
    });
    app = await makeApp();
  });

  afterAll(async () => {
    const { tenantConfigs } = await import("../services/context");
    tenantConfigs.delete(TENANT_ID);
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
  });

  it("blocks API keys, agent tokens, and admin sessions without recent MFA", async () => {
    for (const mode of ["api-key", "agent", "admin-no-mfa"]) {
      const response = await app.request("/condition-sets", {
        headers: { "x-test-auth-mode": mode },
      });
      expect(response.status).toBe(403);
    }
  });

  it("allows owner/admin sessions with recent MFA to manage condition sets", async () => {
    const createResponse = await app.request("/condition-sets", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-test-auth-mode": "admin",
      },
      body: JSON.stringify({
        name: "Executable auth allowlist",
        ownerId: "dashboard",
      }),
    });
    expect(createResponse.status).toBe(201);
    const createBody = (await createResponse.json()) as {
      ok: boolean;
      data: { id: string; name: string };
    };
    expect(createBody.ok).toBe(true);
    expect(createBody.data.name).toBe("Executable auth allowlist");

    const listResponse = await app.request("/condition-sets", {
      headers: { "x-test-auth-mode": "admin" },
    });
    expect(listResponse.status).toBe(200);
    const listBody = (await listResponse.json()) as {
      ok: boolean;
      data: { conditionSets: Array<{ id: string; name: string }> };
    };
    expect(listBody.ok).toBe(true);
    expect(listBody.data.conditionSets.map((set) => set.id)).toContain(createBody.data.id);
  });
});
