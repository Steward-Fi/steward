import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditEvents,
  closeDb,
  getDb,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { verifyAuditChain } from "../services/audit";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30_000);

const TENANT_ID = `secret-route-validation-${Date.now()}`;
const AGENT_ID = `secret-route-agent-${Date.now()}`;
const SECRET_ID = "00000000-0000-4000-8000-000000000733";
const EXISTING_ROUTE_ID = "00000000-0000-4000-8000-000000000734";
const OWNER_USER_ID = "00000000-0000-4000-8000-000000000735";
const MEMBER_USER_ID = "00000000-0000-4000-8000-000000000736";
const VALID_SECRET_VALUE = "mounted-pglite-secret-value";
const MUTATED_ENV = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_JWT_SECRET",
] as const;
const originalEnv = new Map(MUTATED_ENV.map((name) => [name, process.env[name]]));

let app: Hono<{ Variables: AppVariables }>;
let ownerToken = "";
let memberToken = "";
let staleMfaToken = "";

type Snapshot = {
  audits: (typeof auditEvents.$inferSelect)[];
  routes: (typeof secretRoutes.$inferSelect)[];
  secrets: (typeof secrets.$inferSelect)[];
};

async function snapshot(): Promise<Snapshot> {
  const db = getDb();
  return {
    audits: await db.select().from(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID)),
    routes: await db.select().from(secretRoutes).where(eq(secretRoutes.tenantId, TENANT_ID)),
    secrets: await db.select().from(secrets).where(eq(secrets.tenantId, TENANT_ID)),
  };
}

async function jsonRequest(
  method: "POST" | "PUT",
  path: string,
  body: unknown,
  token: string | null = ownerToken,
) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-steward-tenant": TENANT_ID,
  };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await app.request(path, {
    method,
    headers,
    body: JSON.stringify(body),
  });
  const json = (await response.json()) as { ok: boolean; error?: string; data?: unknown };
  return { response, json };
}

async function auditActionsSince(count: number): Promise<string[]> {
  const rows = await getDb()
    .select({ action: auditEvents.action, actorId: auditEvents.actorId })
    .from(auditEvents)
    .where(eq(auditEvents.tenantId, TENANT_ID))
    .orderBy(asc(auditEvents.seq));
  const appended = rows.slice(count);
  expect(appended.every((row) => row.actorId === OWNER_USER_ID)).toBe(true);
  return appended.map((row) => row.action);
}

async function expectValidAuditChain(): Promise<void> {
  expect(await verifyAuditChain(TENANT_ID, { requireHead: true })).toMatchObject({ valid: true });
}

const validRouteCreate = {
  secretId: SECRET_ID,
  agentId: AGENT_ID,
  hostPattern: "api.openai.com",
  pathPattern: "/v1/responses",
  method: "POST",
  injectAs: "header",
  injectKey: "Authorization",
  injectFormat: "Bearer {value}",
  priority: 7,
  enabled: true,
};

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "secret-route-validation-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "secret-route-validation-audit-hmac-key-with-entropy";
  process.env.STEWARD_JWT_SECRET =
    "secret-route-validation-jwt-secret-with-at-least-thirty-two-bytes";
  __resetAuditHmacKeyCacheForTests();

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb()
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Secret Route Validation Tenant",
      apiKeyHash: `hash-${TENANT_ID}`,
    });
  await getDb().insert(agents).values({
    id: AGENT_ID,
    tenantId: TENANT_ID,
    name: "Secret Route Validation Agent",
    walletAddress: "0x0000000000000000000000000000000000000733",
  });
  await getDb()
    .insert(users)
    .values([
      {
        id: OWNER_USER_ID,
        email: "secret-route-owner@example.test",
        emailVerified: true,
      },
      {
        id: MEMBER_USER_ID,
        email: "secret-route-member@example.test",
        emailVerified: true,
      },
    ]);
  await getDb()
    .insert(userTenants)
    .values([
      { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
    ]);
  await getDb().insert(secrets).values({
    id: SECRET_ID,
    tenantId: TENANT_ID,
    name: "mounted-secret",
    ciphertext: "fixture-ciphertext",
    iv: "fixture-iv",
    authTag: "fixture-tag",
    salt: "fixture-salt",
  });
  await getDb().insert(secretRoutes).values({
    id: EXISTING_ROUTE_ID,
    tenantId: TENANT_ID,
    agentId: AGENT_ID,
    secretId: SECRET_ID,
    hostPattern: "api.openai.com",
    pathPattern: "/v1/responses",
    method: "POST",
    injectAs: "header",
    injectKey: "Authorization",
    injectFormat: "Bearer {value}",
  });

  const { signAccessToken } = await import("@stwd/auth");
  ownerToken = await signAccessToken({
    address: "0x0000000000000000000000000000000000000735",
    tenantId: TENANT_ID,
    userId: OWNER_USER_ID,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  memberToken = await signAccessToken({
    address: "0x0000000000000000000000000000000000000736",
    tenantId: TENANT_ID,
    userId: MEMBER_USER_ID,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  staleMfaToken = await signAccessToken({
    address: "0x0000000000000000000000000000000000000735",
    tenantId: TENANT_ID,
    userId: OWNER_USER_ID,
    mfaVerifiedAt: Date.now() - 10 * 60_000,
    mfaMethod: "totp",
  });

  const { createApp, mountCoreIdempotencyAndRoutes } = await import("../app");
  app = mountCoreIdempotencyAndRoutes(createApp());
});

afterAll(async () => {
  await closeDb();
  for (const name of MUTATED_ENV) {
    const original = originalEnv.get(name);
    if (original === undefined) delete process.env[name];
    else process.env[name] = original;
  }
  __resetAuditHmacKeyCacheForTests();
});

describe("mounted secret route validation", () => {
  it("uses the production app tenantAuth and MFA boundary before secret persistence", async () => {
    const body = { name: "must-not-persist", value: VALID_SECRET_VALUE };
    for (const testCase of [
      // tenantAuth falls through to the tenant API-key boundary when no bearer
      // is present; an empty key is forbidden before the router is reached.
      { name: "unauthenticated", token: null, status: 403 },
      { name: "non-admin member", token: memberToken, status: 403 },
      { name: "stale owner MFA", token: staleMfaToken, status: 403 },
    ]) {
      const before = await snapshot();
      const { response, json } = await jsonRequest("POST", "/secrets", body, testCase.token);
      expect(response.status, testCase.name).toBe(testCase.status);
      expect(json.ok, testCase.name).toBe(false);
      expect(await snapshot(), testCase.name).toEqual(before);
    }
  });

  it("creates, updates, and rotates a secret through the production app with exact audit pairs", async () => {
    const beforeCreate = await snapshot();
    const createResult = await jsonRequest("POST", "/secrets", {
      name: "production-mounted-secret",
      value: `${VALID_SECRET_VALUE}-created`,
    });
    expect(createResult.response.status).toBe(201);
    const createdId = (createResult.json.data as { id?: string })?.id;
    expect(createdId).toBeString();
    expect(await auditActionsSince(beforeCreate.audits.length)).toEqual([
      "secret.create.authorized",
      "secret.create",
    ]);
    await expectValidAuditChain();

    const beforeUpdate = await snapshot();
    const updateResult = await jsonRequest("PUT", `/secrets/${createdId}`, {
      value: `${VALID_SECRET_VALUE}-updated`,
    });
    expect(updateResult.response.status).toBe(200);
    const updatedId = (updateResult.json.data as { id?: string })?.id;
    expect(updatedId).toBeString();
    expect(updatedId).not.toBe(createdId);
    expect(await auditActionsSince(beforeUpdate.audits.length)).toEqual([
      "secret.rotate.authorized",
      "secret.rotate",
    ]);
    await expectValidAuditChain();

    const beforeRotate = await snapshot();
    const rotateResult = await jsonRequest("POST", `/secrets/${updatedId}/rotate`, {
      value: `${VALID_SECRET_VALUE}-rotated`,
    });
    expect(rotateResult.response.status).toBe(200);
    const rotatedId = (rotateResult.json.data as { id?: string })?.id;
    expect(rotatedId).toBeString();
    expect(rotatedId).not.toBe(updatedId);
    expect(await auditActionsSince(beforeRotate.audits.length)).toEqual([
      "secret.rotate.authorized",
      "secret.rotate",
    ]);
    await expectValidAuditChain();

    const active = (await snapshot()).secrets.filter(
      (row) => row.name === "production-mounted-secret" && row.deletedAt === null,
    );
    expect(active).toHaveLength(1);
    expect(active[0]?.id).toBe(rotatedId);
  });

  it("rejects every invalid create shape before route, audit, or vault persistence", async () => {
    const invalidCases: Array<{ name: string; patch: Record<string, unknown> }> = [
      { name: "query injection", patch: { injectAs: "query" } },
      { name: "body injection", patch: { injectAs: "body" } },
      { name: "oversized injection format", patch: { injectFormat: `{value}${"x".repeat(249)}` } },
      { name: "invalid header name", patch: { injectKey: "X Secret: Value" } },
      { name: "non-integer priority", patch: { priority: 1.5 } },
      { name: "string priority", patch: { priority: "7" } },
      { name: "non-boolean enabled", patch: { enabled: "true" } },
      { name: "CR injection format", patch: { injectFormat: "Bearer {value}\rX-Evil: yes" } },
      { name: "LF injection format", patch: { injectFormat: "Bearer {value}\nX-Evil: yes" } },
    ];
    for (const testCase of invalidCases) {
      const before = await snapshot();
      const { response, json } = await jsonRequest("POST", "/secrets/routes", {
        ...validRouteCreate,
        ...testCase.patch,
      });
      expect(response.status, testCase.name).toBe(400);
      expect(json, testCase.name).toMatchObject({ ok: false, error: expect.any(String) });
      expect(await snapshot(), testCase.name).toEqual(before);
    }
  });

  it("rejects every invalid update shape before route, audit, or vault persistence", async () => {
    const invalidCases: Array<{ name: string; patch: Record<string, unknown> }> = [
      { name: "query injection", patch: { injectAs: "query" } },
      { name: "body injection", patch: { injectAs: "body" } },
      { name: "oversized injection format", patch: { injectFormat: `{value}${"x".repeat(249)}` } },
      { name: "invalid header name", patch: { injectKey: "Bad Header" } },
      { name: "non-integer priority", patch: { priority: 2.25 } },
      { name: "string priority", patch: { priority: "2" } },
      { name: "non-boolean enabled", patch: { enabled: 1 } },
      { name: "CR injection format", patch: { injectFormat: "{value}\rX-Evil: yes" } },
      { name: "LF injection format", patch: { injectFormat: "{value}\nX-Evil: yes" } },
    ];
    for (const testCase of invalidCases) {
      const before = await snapshot();
      const { response, json } = await jsonRequest(
        "PUT",
        `/secrets/routes/${EXISTING_ROUTE_ID}`,
        testCase.patch,
      );
      expect(response.status, testCase.name).toBe(400);
      expect(json, testCase.name).toMatchObject({ ok: false, error: expect.any(String) });
      expect(await snapshot(), testCase.name).toEqual(before);
    }
  });

  it("rejects CR/LF secret values on create and update with zero persistence", async () => {
    const cases = [
      {
        method: "POST" as const,
        path: "/secrets",
        body: { name: "cr-secret", value: `${VALID_SECRET_VALUE}\rattack` },
      },
      {
        method: "POST" as const,
        path: "/secrets",
        body: { name: "lf-secret", value: `${VALID_SECRET_VALUE}\nattack` },
      },
      {
        method: "PUT" as const,
        path: `/secrets/${SECRET_ID}`,
        body: { value: `${VALID_SECRET_VALUE}\rattack` },
      },
      {
        method: "PUT" as const,
        path: `/secrets/${SECRET_ID}`,
        body: { value: `${VALID_SECRET_VALUE}\nattack` },
      },
      {
        method: "POST" as const,
        path: `/secrets/${SECRET_ID}/rotate`,
        body: { value: `${VALID_SECRET_VALUE}\rattack` },
      },
      {
        method: "POST" as const,
        path: `/secrets/${SECRET_ID}/rotate`,
        body: { value: `${VALID_SECRET_VALUE}\nattack` },
      },
    ];
    for (const testCase of cases) {
      const before = await snapshot();
      const { response, json } = await jsonRequest(testCase.method, testCase.path, testCase.body);
      expect(response.status, `${testCase.method} ${testCase.path}`).toBe(400);
      expect(json).toEqual({ ok: false, error: "secret value must not contain line breaks" });
      expect(await snapshot()).toEqual(before);
    }
  });

  it("persists one normalized header route on create and normalizes its mounted update", async () => {
    const before = await snapshot();
    const { response, json } = await jsonRequest("POST", "/secrets/routes", {
      ...validRouteCreate,
      hostPattern: "  API.OPENAI.COM  ",
      method: " post ",
      injectKey: "  X-Steward-Token  ",
    });
    expect(response.status).toBe(201);
    expect(json.ok).toBe(true);
    const afterCreate = await snapshot();
    expect(afterCreate.routes).toHaveLength(before.routes.length + 1);
    expect(afterCreate.audits).toHaveLength(before.audits.length + 2);
    expect(await auditActionsSince(before.audits.length)).toEqual([
      "secret_route.create.authorized",
      "secret_route.create",
    ]);
    await expectValidAuditChain();
    expect(afterCreate.secrets).toEqual(before.secrets);
    const created = afterCreate.routes.find((route) => route.id !== EXISTING_ROUTE_ID);
    expect(created).toMatchObject({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      secretId: SECRET_ID,
      hostPattern: "api.openai.com",
      pathPattern: "/v1/responses",
      method: "POST",
      injectAs: "header",
      injectKey: "X-Steward-Token",
      injectFormat: "Bearer {value}",
      priority: 7,
      enabled: true,
    });

    const updateBefore = await snapshot();
    const updateResult = await jsonRequest("PUT", `/secrets/routes/${created?.id}`, {
      hostPattern: " API.ANTHROPIC.COM ",
      pathPattern: " /v1/messages ",
      method: " post ",
      injectKey: " X-Api-Key ",
    });
    expect(updateResult.response.status).toBe(200);
    const updateAfter = await snapshot();
    expect(updateAfter.routes).toHaveLength(updateBefore.routes.length);
    expect(updateAfter.audits).toHaveLength(updateBefore.audits.length + 2);
    expect(await auditActionsSince(updateBefore.audits.length)).toEqual([
      "secret_route.update.authorized",
      "secret_route.update",
    ]);
    await expectValidAuditChain();
    expect(updateAfter.secrets).toEqual(updateBefore.secrets);
    expect(updateAfter.routes.find((route) => route.id === created?.id)).toMatchObject({
      hostPattern: "api.anthropic.com",
      pathPattern: "/v1/messages",
      method: "POST",
      injectKey: "X-Api-Key",
    });
  });

  it("marks secret inventory and route topology responses fully non-cacheable", async () => {
    for (const path of ["/secrets", "/secrets/routes"]) {
      const response = await app.request(path);
      expect(response.status, path).toBe(200);
      expect(response.headers.get("cache-control"), path).toBe("no-store, max-age=0");
      expect(response.headers.get("pragma"), path).toBe("no-cache");
      expect(response.headers.get("expires"), path).toBe("0");
      const body = await response.text();
      expect(body, path).not.toContain(VALID_SECRET_VALUE);
      expect(body, path).not.toContain("fixture-ciphertext");
    }
  });
});
