import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { tenantCors } from "../middleware/tenant-cors";

const ALLOWED_ORIGIN = "https://console.example.com";
const originalNodeEnv = process.env.NODE_ENV;
const originalPgliteMemory = process.env.STEWARD_PGLITE_MEMORY;

describe("tenant CORS preflight", () => {
  beforeAll(async () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb();
    setPGLiteOverride(db as never, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: "cors-patch-tenant",
      name: "CORS PATCH tenant",
      apiKeyHash: "cors-patch-tenant-hash",
    });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: "cors-patch-tenant",
        allowedOrigins: [ALLOWED_ORIGIN],
      });
  });

  afterAll(async () => {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    if (originalPgliteMemory === undefined) delete process.env.STEWARD_PGLITE_MEMORY;
    else process.env.STEWARD_PGLITE_MEMORY = originalPgliteMemory;
    await closeDb();
  });

  test("advertises PATCH to an allowed browser preflight", async () => {
    const app = new Hono();
    app.use("*", tenantCors);
    app.patch("/resource", (c) => c.json({ ok: true }));

    const response = await app.request("/resource", {
      method: "OPTIONS",
      headers: {
        Origin: ALLOWED_ORIGIN,
        "Access-Control-Request-Method": "PATCH",
        "Access-Control-Request-Headers": "Authorization, X-Steward-Tenant",
      },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(ALLOWED_ORIGIN);
    expect(response.headers.get("access-control-allow-methods")?.split(/,\s*/)).toContain("PATCH");
    expect(response.headers.get("access-control-allow-headers")?.split(/,\s*/)).toEqual(
      expect.arrayContaining(["Authorization", "X-Steward-Tenant"]),
    );
    expect(response.headers.get("access-control-allow-credentials")).toBeNull();
    expect(response.headers.get("vary")).toBe("Origin, X-Steward-Tenant");
  });

  test("keeps disallowed origins fail closed", async () => {
    const app = new Hono();
    app.use("*", tenantCors);

    const response = await app.request("/resource", {
      method: "OPTIONS",
      headers: {
        Origin: "https://attacker.example",
        "Access-Control-Request-Method": "PATCH",
      },
    });

    expect(response.status).toBe(403);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("access-control-allow-credentials")).toBeNull();
    expect(response.headers.get("vary")).toBe("Origin, X-Steward-Tenant");
  });
});
