import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  getDb,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, asc, eq, isNull } from "drizzle-orm";
import type { Hono } from "hono";
import { verifyAuditChain } from "../services/audit";
import type { AppVariables } from "../services/context";

setDefaultTimeout(120_000);

const hasDatabaseUrl = Boolean(process.env.DATABASE_URL?.trim());
const describeWithPostgres = hasDatabaseUrl ? describe : describe.skip;
const SUFFIX = crypto.randomUUID();
const TENANT_ID = `secret-production-${SUFFIX}`;
const AGENT_ID = `secret-production-agent-${SUFFIX}`;
const OWNER_USER_ID = crypto.randomUUID();
const MEMBER_USER_ID = crypto.randomUUID();
const SECRET_VALUE = `production-secret-${SUFFIX}`;
const ENV_NAMES = [
  "NODE_ENV",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_JWT_SECRET",
] as const;
const originalEnv = new Map(ENV_NAMES.map((name) => [name, process.env[name]]));

let app: Hono<{ Variables: AppVariables }>;
let ownerToken = "";
let memberToken = "";
let staleMfaToken = "";

async function cleanupFixture(): Promise<void> {
  const db = getDb();
  await db.transaction(async (tx) => {
    await tx.delete(secretRoutes).where(eq(secretRoutes.tenantId, TENANT_ID));
    await tx.delete(secrets).where(eq(secrets.tenantId, TENANT_ID));
    await tx.delete(agents).where(eq(agents.tenantId, TENANT_ID));
    await tx.delete(userTenants).where(eq(userTenants.tenantId, TENANT_ID));
    await tx.delete(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID));
    await tx.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, TENANT_ID));
    await tx.delete(users).where(eq(users.id, OWNER_USER_ID));
    await tx.delete(users).where(eq(users.id, MEMBER_USER_ID));
    await tx.delete(tenants).where(eq(tenants.id, TENANT_ID));
  });
}

async function request(
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
  return {
    response,
    body: (await response.json()) as { ok: boolean; error?: string; data?: unknown },
  };
}

async function fixtureCounts() {
  const db = getDb();
  const [secretRows, routeRows, auditRows] = await Promise.all([
    db.select({ id: secrets.id }).from(secrets).where(eq(secrets.tenantId, TENANT_ID)),
    db
      .select({ id: secretRoutes.id })
      .from(secretRoutes)
      .where(eq(secretRoutes.tenantId, TENANT_ID)),
    db.select({ id: auditEvents.id }).from(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID)),
  ]);
  return { secrets: secretRows.length, routes: routeRows.length, audits: auditRows.length };
}

describeWithPostgres(
  "secret routes through the production app and PostgreSQL tenant transaction",
  () => {
    beforeAll(async () => {
      process.env.NODE_ENV = "test";
      process.env.STEWARD_MASTER_PASSWORD ||= "secret-production-postgres-master-password";
      process.env.STEWARD_AUDIT_HMAC_KEY ||= "c".repeat(64);
      process.env.STEWARD_JWT_SECRET ||=
        "secret-production-postgres-jwt-secret-with-at-least-thirty-two-bytes";
      __resetAuditHmacKeyCacheForTests();

      await cleanupFixture();
      const db = getDb();
      await db.insert(tenants).values({
        id: TENANT_ID,
        name: "Secret production boundary",
        apiKeyHash: `unused-${SUFFIX}`,
      });
      await db.insert(users).values([
        { id: OWNER_USER_ID, email: `owner-${SUFFIX}@example.test`, emailVerified: true },
        { id: MEMBER_USER_ID, email: `member-${SUFFIX}@example.test`, emailVerified: true },
      ]);
      await db.insert(userTenants).values([
        { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
        { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
      ]);
      await db.insert(agents).values({
        id: AGENT_ID,
        tenantId: TENANT_ID,
        name: "Secret production agent",
        walletAddress: `0x${SUFFIX.replaceAll("-", "").slice(0, 40).padEnd(40, "0")}`,
      });

      const { signAccessToken } = await import("@stwd/auth");
      ownerToken = await signAccessToken({
        address: "0x0000000000000000000000000000000000000816",
        tenantId: TENANT_ID,
        userId: OWNER_USER_ID,
        mfaVerifiedAt: Date.now(),
        mfaMethod: "totp",
      });
      memberToken = await signAccessToken({
        address: "0x0000000000000000000000000000000000000817",
        tenantId: TENANT_ID,
        userId: MEMBER_USER_ID,
        mfaVerifiedAt: Date.now(),
        mfaMethod: "totp",
      });
      staleMfaToken = await signAccessToken({
        address: "0x0000000000000000000000000000000000000816",
        tenantId: TENANT_ID,
        userId: OWNER_USER_ID,
        mfaVerifiedAt: Date.now() - 10 * 60_000,
        mfaMethod: "totp",
      });

      const { createApp, mountCoreIdempotencyAndRoutes } = await import("../app");
      app = mountCoreIdempotencyAndRoutes(createApp());
    });

    afterAll(async () => {
      await cleanupFixture();
      for (const name of ENV_NAMES) {
        const value = originalEnv.get(name);
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      __resetAuditHmacKeyCacheForTests();
    });

    it("enforces real JWT authority and persists create/update/rotate with exact chained audits", async () => {
      for (const testCase of [
        { name: "unauthenticated", token: null },
        { name: "member", token: memberToken },
        { name: "stale MFA", token: staleMfaToken },
      ]) {
        const before = await fixtureCounts();
        const denied = await request(
          "POST",
          "/secrets",
          { name: `denied-${testCase.name}`, value: SECRET_VALUE },
          testCase.token,
        );
        expect(denied.response.status, testCase.name).toBe(403);
        expect(denied.body.ok, testCase.name).toBe(false);
        expect(await fixtureCounts(), testCase.name).toEqual(before);
      }

      const created = await request("POST", "/secrets", {
        name: `mounted-${SUFFIX}`,
        value: `${SECRET_VALUE}-created`,
      });
      expect(created.response.status).toBe(201);
      expect(created.response.headers.get("cache-control")).toBe("no-store, max-age=0");
      expect(JSON.stringify(created.body)).not.toContain(`${SECRET_VALUE}-created`);
      const createdId = (created.body.data as { id?: string })?.id;
      expect(createdId).toBeString();

      for (const [method, path] of [
        ["PUT", `/secrets/${createdId}`],
        ["POST", `/secrets/${createdId}/rotate`],
      ] as const) {
        for (const lineBreak of ["\r", "\n"]) {
          const before = await fixtureCounts();
          const invalid = await request(method, path, {
            value: `${SECRET_VALUE}${lineBreak}attack`,
          });
          expect(invalid.response.status).toBe(400);
          expect(invalid.body).toEqual({
            ok: false,
            error: "secret value must not contain line breaks",
          });
          expect(await fixtureCounts()).toEqual(before);
        }
      }

      const updated = await request("PUT", `/secrets/${createdId}`, {
        value: `${SECRET_VALUE}-updated`,
      });
      expect(updated.response.status).toBe(200);
      const updatedId = (updated.body.data as { id?: string })?.id;
      expect(updatedId).toBeString();
      expect(updatedId).not.toBe(createdId);

      const rotated = await request("POST", `/secrets/${updatedId}/rotate`, {
        value: `${SECRET_VALUE}-rotated`,
      });
      expect(rotated.response.status).toBe(200);
      const rotatedId = (rotated.body.data as { id?: string })?.id;
      expect(rotatedId).toBeString();
      expect(rotatedId).not.toBe(updatedId);

      const routeCreated = await request("POST", "/secrets/routes", {
        secretId: rotatedId,
        agentId: AGENT_ID,
        hostPattern: " API.OPENAI.COM ",
        pathPattern: "/v1/responses",
        method: " post ",
        injectAs: "header",
        injectKey: " X-Steward-Token ",
        injectFormat: "Bearer {value}",
      });
      expect(routeCreated.response.status).toBe(201);
      const routeId = (routeCreated.body.data as { id?: string })?.id;
      expect(routeId).toBeString();

      const routeUpdated = await request("PUT", `/secrets/routes/${routeId}`, {
        hostPattern: " API.ANTHROPIC.COM ",
        pathPattern: "/v1/messages",
        method: " POST ",
        injectKey: " X-Api-Key ",
      });
      expect(routeUpdated.response.status).toBe(200);

      const events = await getDb()
        .select({ action: auditEvents.action, actorId: auditEvents.actorId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID))
        .orderBy(asc(auditEvents.seq));
      expect(events.map((event) => event.action)).toEqual([
        "secret.create.authorized",
        "secret.create",
        "secret.rotate.authorized",
        "secret.rotate",
        "secret.rotate.authorized",
        "secret.rotate",
        "secret_route.create.authorized",
        "secret_route.create",
        "secret_route.update.authorized",
        "secret_route.update",
      ]);
      expect(events.every((event) => event.actorId === OWNER_USER_ID)).toBe(true);
      expect(await verifyAuditChain(TENANT_ID, { requireHead: true })).toMatchObject({
        valid: true,
        count: 10,
      });

      const [active] = await getDb()
        .select({ id: secrets.id })
        .from(secrets)
        .where(
          and(
            eq(secrets.tenantId, TENANT_ID),
            eq(secrets.name, `mounted-${SUFFIX}`),
            isNull(secrets.deletedAt),
          ),
        );
      expect(active?.id).toBe(rotatedId);
    });
  },
);
