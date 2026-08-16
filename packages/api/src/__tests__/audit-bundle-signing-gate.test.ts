import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import { resetCheckpointSignerCache } from "../services/audit-checkpoint";
import type { AppVariables } from "../services/context";

const TENANT_ID = "audit-bundle-gate-tenant";
let auditRoutesModule: Awaited<typeof import("../routes/audit")>;
let priorNodeEnv: string | undefined;

describe("audit bundle signing-key gate", () => {
  beforeAll(async () => {
    priorNodeEnv = process.env.NODE_ENV;
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-bundle-gate-hmac-key-0123456789abcdef";
    process.env.STEWARD_MASTER_PASSWORD = "audit-bundle-gate-master-password";
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
    resetCheckpointSignerCache();

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    auditRoutesModule = await import("../routes/audit");
    await getDb()
      .insert(tenants)
      .values([{ id: TENANT_ID, name: "Audit Bundle Gate", apiKeyHash: "audit-bundle-gate" }]);
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      action: "wallet.action.1",
      metadata: {},
    });
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    if (priorNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = priorNodeEnv;
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    resetCheckpointSignerCache();
  });

  function app() {
    const a = new Hono<{ Variables: AppVariables }>();
    a.use("*", async (c, next) => {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("tenantId", TENANT_ID);
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    a.route("/audit", auditRoutesModule.auditRoutes);
    return a;
  }

  it("returns 503 with a hard error in production when signing key is unset", async () => {
    process.env.NODE_ENV = "production";
    const res = await app().request("/audit/bundle");
    expect(res.status).toBe(503);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("STEWARD_AUDIT_SIGNING_KEY");
  });

  it("returns 503 disabled-with-warning in development when signing key is unset", async () => {
    process.env.NODE_ENV = "development";
    const res = await app().request("/audit/bundle");
    expect(res.status).toBe(503);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error.toLowerCase()).toContain("disabled");
  });
});
