import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { hashApiKey } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const TENANT_ID = `adapter-app-mount-${Date.now()}`;
const API_KEY = `stw_adapter_mount_${Date.now()}`;

describe("adapter app mount", () => {
  let app: Awaited<typeof import("../app")>["app"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "adapter-app-mount-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "adapter-app-mount-audit-hmac-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Adapter App Mount Tenant",
        apiKeyHash: hashApiKey(API_KEY),
      });
    ({ app } = await import("../app"));
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("exposes adapter routes through the real app only after tenant auth", async () => {
    const unauthenticated = await app.request("/adapters");
    expect(unauthenticated.status).toBe(403);
    await expect(unauthenticated.json()).resolves.toMatchObject({
      ok: false,
      error: "Forbidden",
    });

    for (const path of ["/adapters", "/v1/adapters"]) {
      const response = await app.request(path, {
        headers: {
          "X-Steward-Tenant": TENANT_ID,
          "X-Steward-Key": API_KEY,
        },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data: { adapters: Record<string, unknown> };
      };
      expect(body.ok).toBe(true);
      expect(body.data.adapters).toHaveProperty("swap");
      expect(body.data.adapters).toHaveProperty("earn");
      expect(body.data.adapters).toHaveProperty("bridge");
      expect(body.data.adapters).toHaveProperty("spark");
    }
  });
});
