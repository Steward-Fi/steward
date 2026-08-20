import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { closeDb, getDb, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";

const ROOT = join(import.meta.dir, "../../../..");
const TENANT_ID = "tenant-theme-hardening";
const USER_ID = crypto.randomUUID();
let token = "";
let app: Hono;

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("tenant theme hardening", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "tenant-theme-hardening-master";
    process.env.STEWARD_JWT_SECRET = "tenant-theme-hardening-jwt-secret-value";
    process.env.STEWARD_AUDIT_HMAC_KEY = "tenant-theme-hardening-audit-key-value";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Tenant Theme Hardening",
      apiKeyHash: "tenant-theme-hardening-key-hash",
    });
    await getDb()
      .insert(users)
      .values({ id: USER_ID, email: `${USER_ID}@example.test` });
    await getDb()
      .insert(userTenants)
      .values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        theme: { primaryColor: "#112233", colorScheme: "system" },
      });
    const { createSessionToken } = await import("../routes/auth");
    token = await createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
      userId: USER_ID,
      tenantId: TENANT_ID,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const { tenantConfigRoutes } = await import("../routes/tenant-config");
    app = new Hono();
    app.use("*", correlationId);
    app.route("/tenants", tenantConfigRoutes);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  const updateTheme = (theme: unknown) =>
    app.request(`/tenants/${TENANT_ID}/config`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ theme }),
    });

  it("rejects invalid appearance tokens without mutating the mounted tenant config", async () => {
    const invalidThemes = [
      [{ primaryColor: "#12345" }, "theme.primaryColor must be a 6-digit hex color"],
      [{ borderRadius: 33 }, "theme.borderRadius must be a number between 0 and 32"],
      [
        { fontFamily: "Inter; url(javascript:evil)" },
        "theme.fontFamily contains unsupported characters",
      ],
      [{ colorScheme: "sepia" }, "theme.colorScheme must be light, dark, or system"],
    ] as const;

    for (const [theme, error] of invalidThemes) {
      const response = await updateTheme(theme);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ ok: false, error });
      const [stored] = await getDb()
        .select({ theme: tenantConfigs.theme })
        .from(tenantConfigs)
        .where(eq(tenantConfigs.tenantId, TENANT_ID));
      expect(stored?.theme).toEqual({ primaryColor: "#112233", colorScheme: "system" });
    }
  });

  it("normalizes and persists exact appearance tokens through the mounted route", async () => {
    const response = await updateTheme({
      primaryColor: " #a1b2c3 ",
      accentColor: "#00ffAA",
      borderRadius: "12",
      fontFamily: "  Inter, sans-serif  ",
      colorScheme: "dark",
    });
    expect(response.status).toBe(200);
    const normalized = {
      primaryColor: "#A1B2C3",
      accentColor: "#00FFAA",
      borderRadius: 12,
      fontFamily: "Inter, sans-serif",
      colorScheme: "dark",
    };
    expect(await response.json()).toMatchObject({ ok: true, data: { theme: normalized } });
    const [stored] = await getDb()
      .select({ theme: tenantConfigs.theme })
      .from(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    expect(stored?.theme).toEqual(normalized);
  });

  it("documents and exposes appearance controls through dashboard settings", () => {
    const settings = read("web/src/app/dashboard/settings/page.tsx");
    const docs = read("docs/api-reference/tenant-config.mdx");

    expect(settings).toContain("Save Appearance");
    expect(settings).toContain('data-testid="appearance-preview"');
    expect(settings).toContain("themePayloadFromForm");
    expect(settings).toContain("themeFormFromConfig(data.data.theme)");
    expect(docs).toContain("## Theme Config");
  });
});
