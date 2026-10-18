import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { generateApiKey, hashSha256Hex } from "@stwd/auth";
import {
  auditEvents,
  closeDb,
  getDb,
  tenantAppClientSecrets,
  tenantAppClients,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { Hono } from "hono";

const ROOT = join(import.meta.dir, "../../../..");
const TENANT_ID = "tenant-app-client-behavior";
const CLIENT = {
  id: "web-prod",
  name: "Web Production",
  environment: "production",
  enabled: true,
  isDefault: true,
  allowedOrigins: ["https://app.example.test"],
  allowedRedirectUrls: ["https://app.example.test/callback"],
  allowedBundleIds: ["com.example.steward"],
  allowedPackageNames: ["com.example.steward"],
};

function allMigrations(): string {
  const dir = join(ROOT, "packages/db/drizzle");
  return readdirSync(dir)
    .filter((file) => file.endsWith(".sql"))
    .map((file) => readFileSync(join(dir, file), "utf8"))
    .join("\n");
}

describe("tenant app-client mounted behavior", () => {
  let tenantConfigRoutes: typeof import("../routes/tenant-config").tenantConfigRoutes;
  let authRoutes: typeof import("../routes/auth").authRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let tenantCors: typeof import("../middleware/tenant-cors").tenantCors;
  let ownerId = "";
  let memberId = "";
  let apiKey = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "tenant-app-client-master-password";
    process.env.STEWARD_JWT_SECRET = "tenant-app-client-jwt-secret-with-enough-bytes";
    process.env.STEWARD_AUDIT_HMAC_KEY = "tenant-app-client-audit-hmac-key";
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    const generated = generateApiKey();
    apiKey = generated.key;
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Tenant App Client Behavior",
      apiKeyHash: generated.hash,
    });
    const [owner, member] = await getDb()
      .insert(users)
      .values([
        { email: "app-client-owner@example.test", emailVerified: true },
        { email: "app-client-member@example.test", emailVerified: true },
      ])
      .returning({ id: users.id });
    ownerId = owner.id;
    memberId = member.id;
    await getDb()
      .insert(userTenants)
      .values([
        { userId: ownerId, tenantId: TENANT_ID, role: "owner" },
        { userId: memberId, tenantId: TENANT_ID, role: "member" },
      ]);

    ({ tenantConfigRoutes } = await import("../routes/tenant-config"));
    ({ authRoutes, createSessionToken } = await import("../routes/auth"));
    ({ tenantCors } = await import("../middleware/tenant-cors"));
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    for (const name of [
      "STEWARD_PGLITE_MEMORY",
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_JWT_SECRET",
      "STEWARD_AUDIT_HMAC_KEY",
      "APP_URL",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
    ])
      delete process.env[name];
  });

  async function tokenFor(userId: string, mfaVerifiedAt = Date.now()): Promise<string> {
    return createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
      userId,
      tenantId: TENANT_ID,
      mfaVerifiedAt,
      mfaMethod: "totp",
    });
  }

  function request(path: string, token: string, method = "GET", body?: unknown) {
    return tenantConfigRoutes.request(`/${TENANT_ID}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  it("retains only narrow schema and migration inventory assertions", () => {
    const schema = readFileSync(join(ROOT, "packages/db/src/schema.ts"), "utf8");
    const migrations = allMigrations();
    expect(schema).toContain("export const tenantAppClients");
    expect(schema).toContain("export const tenantAppClientSecrets");
    expect(migrations).toContain('CREATE TABLE IF NOT EXISTS "tenant_app_clients"');
    expect(migrations).toContain('CREATE TABLE IF NOT EXISTS "tenant_app_client_secrets"');
    expect(migrations).toContain('"secret_hash" text NOT NULL');
  });

  it("enforces API-key, membership, and recent-MFA authorization on mounted routes", async () => {
    const apiKeyResponse = await tenantConfigRoutes.request(`/${TENANT_ID}/app-clients`, {
      headers: { "X-Steward-Key": apiKey, "X-Steward-Tenant": TENANT_ID },
    });
    expect(apiKeyResponse.status).toBe(403);
    expect((await request("/app-clients", await tokenFor(memberId))).status).toBe(403);
    const stale = await request("/app-clients", await tokenFor(ownerId, Date.now() - 60 * 60_000));
    expect(stale.status).toBe(403);
    expect(await stale.json()).toEqual(
      expect.objectContaining({ error: expect.stringContaining("recent MFA") }),
    );
    const fresh = await request("/app-clients", await tokenFor(ownerId));
    expect(fresh.status).toBe(200);
    expect(fresh.headers.get("cache-control")).toContain("no-store");
  });

  it("creates, normalizes, lists, replaces, and deletes clients through mounted routes", async () => {
    const token = await tokenFor(ownerId);
    const create = await request("/app-clients", token, "POST", {
      client: { ...CLIENT, id: " Web-Prod ", allowedOrigins: ["https://app.example.test/"] },
    });
    expect(create.status).toBe(201);
    const created = (await create.json()) as { data: { client: typeof CLIENT } };
    expect(created.data.client).toEqual(
      expect.objectContaining({ id: "web-prod", allowedOrigins: ["https://app.example.test"] }),
    );
    expect(
      (
        await request("/app-clients", token, "POST", {
          client: { ...CLIENT, id: "wildcard", allowedOrigins: ["*"] },
        })
      ).status,
    ).toBe(400);

    const replace = await request("/app-clients", token, "PUT", {
      clients: [
        { ...CLIENT, name: "Renamed" },
        {
          ...CLIENT,
          id: "native-app",
          name: "Native",
          isDefault: false,
          allowedOrigins: [],
          allowedRedirectUrls: [],
        },
      ],
    });
    expect(replace.status).toBe(200);
    const listed = (await (await request("/app-clients", token)).json()) as {
      data: { clients: Array<{ id: string }> };
    };
    expect(listed.data.clients.map((client) => client.id)).toEqual(["web-prod", "native-app"]);
    expect((await request("/app-clients/native-app", token, "DELETE")).status).toBe(200);
    expect(await getDb().select().from(tenantAppClients)).toHaveLength(1);
  });

  it("rolls client and secret mutations back when their required audit append fails", async () => {
    const token = await tokenFor(ownerId);
    const installFailure = async (action: string) => {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_app_client_completion_audit()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action = '${action}' THEN
            RAISE EXCEPTION 'forced app-client completion audit failure';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
      `),
      );
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS app_client_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER app_client_completion_audit_failure
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_app_client_completion_audit();
      `),
      );
    };
    const clearFailure = async () => {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS app_client_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(sql.raw("DROP FUNCTION IF EXISTS fail_app_client_completion_audit()"));
    };

    await installFailure("tenant.app_client.replace");
    const failedReplace = await request("/app-clients", token, "PUT", {
      clients: [{ ...CLIENT, name: "Must Roll Back" }],
    });
    expect(failedReplace.status).toBe(500);
    expect((await getDb().select().from(tenantAppClients))[0]?.name).toBe("Renamed");
    await clearFailure();

    await installFailure("tenant.app_client_secret.rotate");
    const failedRotate = await request("/app-clients/web-prod/secrets", token, "POST", {});
    expect(failedRotate.status).toBe(500);
    expect(await getDb().select().from(tenantAppClientSecrets)).toHaveLength(0);
    await clearFailure();
  });

  it("returns a secret once, persists only its hash, and preserves it on replacement", async () => {
    const token = await tokenFor(ownerId);
    const rotate = await request("/app-clients/web-prod/secrets", token, "POST", {});
    expect(rotate.status).toBe(201);
    expect(rotate.headers.get("cache-control")).toContain("no-store");
    expect(rotate.headers.get("pragma")).toBe("no-cache");
    const rotated = (await rotate.json()) as {
      data: { appSecret: string; secret: { id: string } };
    };
    expect(rotated.data.appSecret).toStartWith("stw_app_");
    const [stored] = await getDb().select().from(tenantAppClientSecrets);
    expect(stored.secretHash).toBe(hashSha256Hex(rotated.data.appSecret));
    expect(JSON.stringify(stored)).not.toContain(rotated.data.appSecret);

    expect(
      (
        await request("/app-clients", token, "PUT", {
          clients: [{ ...CLIENT, name: "Still here" }],
        })
      ).status,
    ).toBe(200);
    expect(await getDb().select().from(tenantAppClientSecrets)).toHaveLength(1);
    const listed = (await (await request("/app-clients/web-prod/secrets", token)).json()) as {
      data: { secrets: unknown[] };
    };
    expect(JSON.stringify(listed)).not.toContain(rotated.data.appSecret);
    expect(listed.data.secrets).toHaveLength(1);
    expect(
      (await request(`/app-clients/web-prod/secrets/${rotated.data.secret.id}`, token, "DELETE"))
        .status,
    ).toBe(200);
    expect((await getDb().select().from(tenantAppClientSecrets))[0]?.status).toBe("revoked");
  });

  it("uses enabled client allowlists at CORS and OAuth runtime", async () => {
    const token = await tokenFor(ownerId);
    await request("/app-clients", token, "PUT", {
      clients: [
        CLIENT,
        {
          ...CLIENT,
          id: "disabled",
          name: "Disabled",
          enabled: false,
          isDefault: false,
          allowedOrigins: ["https://disabled.example.test"],
          allowedRedirectUrls: ["https://disabled.example.test/callback"],
        },
      ],
    });
    const corsApp = new Hono();
    corsApp.use("*", tenantCors);
    corsApp.get("/resource", (c) => c.json({ ok: true }));
    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    const allowedCors = await corsApp.request("/resource", {
      headers: { Origin: "https://app.example.test", "X-Steward-Tenant": TENANT_ID },
    });
    expect(allowedCors.headers.get("access-control-allow-origin")).toBe("https://app.example.test");
    const disabledCors = await corsApp.request("/resource", {
      headers: { Origin: "https://disabled.example.test", "X-Steward-Tenant": TENANT_ID },
    });
    expect(disabledCors.headers.get("access-control-allow-origin")).toBeNull();
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;

    const pkce =
      "&response_type=code&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256";
    expect(
      (
        await authRoutes.request(
          `/oauth/google/authorize?tenant_id=${TENANT_ID}&client_id=web-prod&redirect_uri=${encodeURIComponent("https://app.example.test/callback")}${pkce}`,
        )
      ).status,
    ).toBe(302);
    for (const [clientId, redirect] of [
      ["disabled", "https://app.example.test/callback"],
      ["disabled", "https://disabled.example.test/callback"],
    ]) {
      expect(
        (
          await authRoutes.request(
            `/oauth/google/authorize?tenant_id=${TENANT_ID}&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}${pkce}`,
          )
        ).status,
      ).toBe(400);
    }

    const deviceCode = (clientId: string, bundleId: string, packageName: string) =>
      authRoutes.request("/device/code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenantId: TENANT_ID,
          client_id: clientId,
          native_bundle_id: bundleId,
          native_package_name: packageName,
        }),
      });
    expect(
      (await deviceCode("web-prod", "com.example.steward", "com.example.steward")).status,
    ).toBe(200);
    expect(
      (await deviceCode("web-prod", "com.disabled.steward", "com.example.steward")).status,
    ).toBe(400);
    expect(
      (await deviceCode("web-prod", "com.example.steward", "com.disabled.steward")).status,
    ).toBe(400);
    expect(
      (await deviceCode("disabled", "com.example.steward", "com.example.steward")).status,
    ).toBe(404);
  });

  it("records mounted completion audits for client and secret mutations", async () => {
    const actions = (
      await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID))
    ).map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        "tenant.app_client.create",
        "tenant.app_client.replace",
        "tenant.app_client.delete",
        "tenant.app_client_secret.rotate",
        "tenant.app_client_secret.revoke",
      ]),
    );
  });
});
