import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { AppVariables } from "@stwd/shared";
import { Hono } from "hono";

const PLATFORM_KEY = "operator-middleware-platform-key-with-enough-entropy";
const TENANT_ID = "operator-middleware-tenant";
const KEY_HASH = createHash("sha256").update(PLATFORM_KEY).digest("hex");

describe("operatorAuth platform authority", () => {
  let app: Hono<{ Variables: AppVariables }>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Operator middleware tenant",
        apiKeyHash: "0".repeat(64),
      });
    const { operatorAuth } = await import("../middleware/operator-auth");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("/operator", operatorAuth);
    app.get("/operator", (c) =>
      c.json({
        authType: c.get("authType"),
        tenantId: c.get("tenantId"),
        platformKeyHash: c.get("platformKeyHash"),
        platformScopes: c.get("platformScopes"),
      }),
    );
  }, 30_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  });

  it("denies a valid legacy platform key until operator authority is explicitly granted", async () => {
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
    const response = await app.request("/operator", {
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": TENANT_ID,
      },
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ ok: false, error: "Forbidden" });
  });

  it("propagates the authenticated key identity and narrow operator scope", async () => {
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [KEY_HASH]: ["platform:trade:operator"],
    });
    const response = await app.request("/operator", {
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": TENANT_ID,
      },
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      authType: "platform",
      tenantId: TENANT_ID,
      platformKeyHash: KEY_HASH,
      platformScopes: ["platform:trade:operator"],
    });
  });

  it("fails closed without exposing malformed scope configuration", async () => {
    process.env.STEWARD_PLATFORM_KEY_SCOPES = "not-json";
    const response = await app.request("/operator", {
      headers: {
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": TENANT_ID,
      },
    });
    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      error: "Platform key scope configuration is invalid",
    });
  });
});
