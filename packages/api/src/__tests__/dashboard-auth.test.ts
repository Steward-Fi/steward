import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAccessToken, signAgentToken } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

setDefaultTimeout(30000);

const TENANT_ID = "dashboard-auth-tenant";
let app: typeof import("../app")["app"];

beforeAll(async () => {
  process.env.DATABASE_URL = "pglite://embedded";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "dashboard-auth-master-password";
  process.env.STEWARD_JWT_SECRET = "dashboard-auth-jwt-secret-with-enough-bytes";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ app } = await import("../app"));

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Dashboard Auth Tenant",
    apiKeyHash: "hash",
  });
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
});

describe("dashboardAuthMiddleware", () => {
  it("explicitly rejects agent tokens", async () => {
    const token = await signAgentToken({ agentId: "agent-1", tenantId: TENANT_ID }, "1h");

    const res = await app.request("/dashboard/nonexistent-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("agent tokens");
  });

  it("still allows user session tokens to reach the dashboard route", async () => {
    const token = await signAccessToken(
      {
        address: `0x${"1".repeat(40)}`,
        tenantId: TENANT_ID,
        userId: "user-1",
      },
      "1h",
    );

    const res = await app.request("/dashboard/nonexistent-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(res.status).toBe(404);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Agent not found");
  });
});
