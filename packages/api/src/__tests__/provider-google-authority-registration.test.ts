import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  providerOperations,
  secretRoutes,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { ProviderAuthorityStore } from "../services/provider-authority-store";

setDefaultTimeout(120_000);

const TENANT = "tenant-google-authority";
const OWNER = "10000000-0000-4000-8000-000000000092";
const WORKSPACE = "20000000-0000-4000-8000-000000000092";
const AGENT = "agent-google-authority";
const MASTER = "google-authority-registration-test-master";

describe("Google provider authority registration", () => {
  const store = new ProviderAuthorityStore();
  let secretId: string;
  let gmailRouteId: string;
  let calendarListRouteId: string;
  let calendarInsertRouteId: string;
  let wrongRouteId: string;
  let wrongInjectionRouteId: string;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = MASTER;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await db.insert(tenants).values({ id: TENANT, name: TENANT, apiKeyHash: `hash-${TENANT}` });
    await db.insert(users).values({ id: OWNER, email: "google-authority@example.test" });
    await db.insert(userTenants).values({ userId: OWNER, tenantId: TENANT, role: "owner" });
    await db.insert(agents).values({
      id: AGENT,
      tenantId: TENANT,
      name: "Google authority agent",
      walletAddress: `0x${"8".repeat(40)}`,
    });
    await db.insert(workspaces).values({
      id: WORKSPACE,
      tenantId: TENANT,
      key: "google-authority",
      name: "Google Authority",
      environment: "production",
      createdBy: OWNER,
    });
    const vault = new SecretVault(MASTER);
    const secret = await vault.createSecret(
      TENANT,
      "google-authority-token",
      JSON.stringify({
        schemaVersion: "steward.provider-google.credential.v1",
        accessToken: "stale-access",
        refreshToken: "server-refresh",
        scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      }),
    );
    secretId = secret.id;
    const createRoute = (
      hostPattern: string,
      pathPattern: string,
      method: string,
      injectKey = "authorization",
    ) =>
      vault.createRoute(TENANT, secret.id, {
        agentId: AGENT,
        hostPattern,
        pathPattern,
        method,
        injectAs: "header",
        injectKey,
        injectFormat: "Bearer {value}",
      });
    gmailRouteId = (
      await createRoute("gmail.googleapis.com", "/gmail/v1/users/me/messages/send", "POST")
    ).id;
    calendarListRouteId = (
      await createRoute("www.googleapis.com", "/calendar/v3/calendars/primary/events", "GET")
    ).id;
    calendarInsertRouteId = (
      await createRoute("www.googleapis.com", "/calendar/v3/calendars/primary/events", "POST")
    ).id;
    wrongRouteId = (
      await createRoute("www.googleapis.com", "/drive/v3/files/attacker/export", "POST")
    ).id;
    wrongInjectionRouteId = (
      await createRoute(
        "gmail.googleapis.com",
        "/gmail/v1/users/me/messages/send",
        "POST",
        "x-api-key",
      )
    ).id;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  test("registers only fixed Google host/path/method/injection tuples without risk downgrade", async () => {
    const context = (expectedRevision: number) => ({
      tenantId: TENANT,
      actorUserId: OWNER,
      tenantRole: "owner",
      mfaVerifiedAt: Date.now(),
      idempotencyKey: `idem-${crypto.randomUUID()}`,
      expectedRevision,
      reason: "Google authority regression",
      audit: async () => {},
    });
    const account = await store.createProviderAccount(context(1), {
      workspaceId: WORKSPACE,
      adapterKey: "google",
      externalRef: "google-user-123",
      displayName: "Google user",
      credentialSecretId: secretId,
      credentialVersion: 1,
    });
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "google.gmail.messages.send",
        riskClass: "read",
        secretRouteId: gmailRouteId,
      }),
    ).rejects.toMatchObject({ code: "bad_request", status: 400 });
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "google.gmail.messages.send",
        riskClass: "write",
        secretRouteId: gmailRouteId,
      }),
    ).rejects.toMatchObject({ code: "bad_request", status: 400 });
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "google.gmail.messages.send",
        riskClass: "consequential",
        secretRouteId: wrongRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "google.gmail.messages.send",
        riskClass: "consequential",
        secretRouteId: wrongInjectionRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });
    const [rejectedRoute] = await getDb()
      .select({
        authorityMode: secretRoutes.authorityMode,
        providerOperationId: secretRoutes.providerOperationId,
      })
      .from(secretRoutes)
      .where(eq(secretRoutes.id, wrongInjectionRouteId));
    expect(rejectedRoute.authorityMode).toBe("legacy");
    expect(rejectedRoute.providerOperationId).toBeNull();
    await getDb()
      .update(secretRoutes)
      .set({ enabled: false })
      .where(eq(secretRoutes.id, wrongInjectionRouteId));

    const gmail = await store.registerOperation(context(1), account.id, {
      operationKey: "google.gmail.messages.send",
      riskClass: "consequential",
      secretRouteId: gmailRouteId,
    });
    const list = await store.registerOperation(context(2), account.id, {
      operationKey: "google.calendar.events.list",
      riskClass: "read",
      secretRouteId: calendarListRouteId,
    });
    const insert = await store.registerOperation(context(3), account.id, {
      operationKey: "google.calendar.events.insert",
      riskClass: "consequential",
      secretRouteId: calendarInsertRouteId,
    });
    expect([gmail.operationKey, list.operationKey, insert.operationKey]).toEqual([
      "google.gmail.messages.send",
      "google.calendar.events.list",
      "google.calendar.events.insert",
    ]);
    expect(await getDb().select().from(providerOperations)).toHaveLength(3);
  });
});
