import { randomUUID } from "node:crypto";
import { generateApiKey, signAccessToken } from "@stwd/auth";
import {
  assertRlsDeploymentSafety,
  auditEvents,
  closeDb,
  getDb,
  refreshTokens,
  tenantConfigs,
  tenantSamlAuthnRequests,
  tenantSamlSsoConfigs,
  tenants,
  userTenants,
} from "@stwd/db";
import { eq, sql } from "drizzle-orm";
import app from "../../app";
import { runRetentionSweep } from "../../services/retention";
import { runInternalJobForEachTenant, runInternalJobForTenant } from "../../services/tenant-job";

const platformKey = process.env.STEWARD_PLATFORM_KEYS ?? "";
const tenantId = process.env.STEWARD_RLS_TEST_TENANT ?? "";
const suffix = process.env.STEWARD_RLS_TEST_SUFFIX ?? randomUUID();

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function requestJson(
  path: string,
  init: RequestInit,
  expectedStatus: number,
): Promise<Record<string, unknown>> {
  const response = await app.request(`http://steward.test${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": platformKey,
      ...(init.headers ?? {}),
    },
  });
  const body = (await response.json()) as Record<string, unknown>;
  assert(
    response.status === expectedStatus,
    `${init.method ?? "GET"} ${path} returned ${response.status}: ${JSON.stringify(body)}`,
  );
  return body;
}

try {
  assert(platformKey.length > 0, "STEWARD_PLATFORM_KEYS is required");
  assert(tenantId.length > 0, "STEWARD_RLS_TEST_TENANT is required");
  const expectedAppRole = process.env.STEWARD_APP_DATABASE_ROLE ?? "";
  assert(expectedAppRole.length > 0, "STEWARD_APP_DATABASE_ROLE is required");
  await assertRlsDeploymentSafety(getDb(), { expectedRole: expectedAppRole });

  const email = `rls-app-role-${suffix}@example.test`;
  const created = await requestJson(
    "/platform/users",
    { method: "POST", body: JSON.stringify({ email, name: "RLS app role" }) },
    201,
  );
  const createdData = created.data as { userId?: string } | undefined;
  const userId = createdData?.userId ?? "";
  assert(/^[0-9a-f-]{36}$/i.test(userId), "global platform user route did not return a UUID");

  await requestJson(
    `/platform/tenants/${tenantId}/members`,
    { method: "POST", body: JSON.stringify({ email, role: "member" }) },
    201,
  );
  const identity = await requestJson(`/platform/users/${userId}`, { method: "GET" }, 200);
  const identityData = identity.data as { tenantIds?: string[] } | undefined;
  assert(
    identityData?.tenantIds?.includes(tenantId),
    "global identity route did not recover tenant membership through its fixed bootstrap shape",
  );

  const tenantApiKey = generateApiKey();
  await runInternalJobForTenant(tenantId, "rls-tenant-key-fixture", async () => {
    await getDb()
      .update(tenants)
      .set({ apiKeyHash: tenantApiKey.hash })
      .where(eq(tenants.id, tenantId));
  });
  const agentList = await app.request("http://steward.test/agents", {
    headers: { "X-Steward-Tenant": tenantId, "X-Steward-Key": tenantApiKey.key },
  });
  assert(agentList.status === 200, `tenant API-key route returned ${agentList.status}`);

  const personalTenantId = `personal-${userId}`;
  await runInternalJobForTenant(personalTenantId, "rls-user-session-fixture", async () => {
    await getDb()
      .insert(tenants)
      .values({ id: personalTenantId, name: "RLS personal", apiKeyHash: "disabled" })
      .onConflictDoNothing();
    await getDb()
      .insert(userTenants)
      .values({ userId, tenantId: personalTenantId, role: "owner" })
      .onConflictDoNothing();
  });
  const userToken = await signAccessToken({ address: "", tenantId: personalTenantId, userId });
  const pushSubscriptions = await app.request("http://steward.test/user/me/push-subscriptions", {
    headers: { Authorization: `Bearer ${userToken}` },
  });
  assert(
    pushSubscriptions.status === 200,
    `user-identity RLS route returned ${pushSubscriptions.status}`,
  );

  const samlRedirect = "https://client.example/callback";
  await runInternalJobForTenant(tenantId, "rls-saml-fixture-seed", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({ tenantId, allowedRedirectUrls: [samlRedirect] })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { allowedRedirectUrls: [samlRedirect] },
      });
    await getDb()
      .insert(tenantSamlSsoConfigs)
      .values({
        tenantId,
        enabled: true,
        status: "active",
        idpEntityId: "https://idp.example.test/saml",
        idpSsoUrl: "https://idp.example.test/sso",
        idpCertPems: ["fixture-certificate"],
        spEntityId: `https://steward.test/auth/saml/${tenantId}/metadata`,
        acsUrl: `https://steward.test/auth/saml/${tenantId}/acs`,
      })
      .onConflictDoNothing();
  });
  const metadataResponse = await app.request(`http://steward.test/auth/saml/${tenantId}/metadata`);
  assert(metadataResponse.status === 200, "SAML metadata pre-auth RLS read failed");
  const samlLogin = new URL(`http://steward.test/auth/saml/${tenantId}/login`);
  samlLogin.searchParams.set("redirect_uri", samlRedirect);
  samlLogin.searchParams.set("code_challenge", "A".repeat(43));
  const loginResponse = await app.request(samlLogin.toString());
  assert(loginResponse.status === 302, `SAML login returned ${loginResponse.status}`);
  const samlRequests = await runInternalJobForTenant(
    tenantId,
    "rls-saml-fixture-verify",
    async () => getDb().select({ id: tenantSamlAuthnRequests.id }).from(tenantSamlAuthnRequests),
  );
  assert(samlRequests.length === 1, "SAML pre-auth request was not persisted under tenant RLS");

  await runInternalJobForTenant(tenantId, "rls-route-fixture-seed", async () => {
    await getDb()
      .insert(refreshTokens)
      .values({
        id: `rls-route-${suffix}`,
        userId,
        tenantId,
        tokenHash: `rls-route-hash-${suffix}`,
        expiresAt: new Date(Date.now() + 60_000),
      });
  });

  await requestJson(
    `/platform/users/${userId}/deactivate`,
    { method: "PATCH", body: JSON.stringify({ deactivated: true }) },
    200,
  );
  const remainingRefreshTokens = await runInternalJobForTenant(
    tenantId,
    "rls-route-fixture-verify",
    async () =>
      getDb()
        .select({ id: refreshTokens.id })
        .from(refreshTokens)
        .where(eq(refreshTokens.userId, userId)),
  );
  assert(
    remainingRefreshTokens.length === 0,
    "global lifecycle route did not revoke tenant refresh sessions",
  );

  const platformAudits = await runInternalJobForTenant(
    "platform",
    "rls-platform-audit-verify",
    async () =>
      getDb()
        .select({ seq: auditEvents.seq, action: auditEvents.action })
        .from(auditEvents)
        .where(eq(auditEvents.resourceId, userId)),
  );
  assert(
    platformAudits.filter((row) => row.action === "user.deactivate.authorized").length === 1 &&
      platformAudits.filter((row) => row.action === "user.deactivate").length === 1,
    "global platform lifecycle did not write exactly one authorization and completion audit",
  );
  const authorizedAudit = platformAudits.find((row) => row.action === "user.deactivate.authorized");
  const completionAudit = platformAudits.find((row) => row.action === "user.deactivate");
  assert(
    authorizedAudit !== undefined &&
      completionAudit !== undefined &&
      authorizedAudit.seq < completionAudit.seq,
    "global platform lifecycle audit authorization did not precede completion",
  );

  const tenantRuns = await runInternalJobForEachTenant(
    "rls-app-role-inventory",
    async (current) => {
      const rows = await getDb().execute(sql`SELECT id FROM tenants ORDER BY id`);
      const visible = (
        Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? [])
      ) as Array<{
        id: string;
      }>;
      assert(
        visible.length === 1 && visible[0]?.id === current,
        `background tenant ${current} saw ${visible.map((row) => row.id).join(",")}`,
      );
      return visible[0]?.id;
    },
  );
  assert(
    tenantRuns.some((run) => run.tenantId === tenantId),
    "tenant job omitted fixture tenant",
  );

  const authKvId = randomUUID();
  await getDb().execute(sql`
    INSERT INTO auth_kv_store(id, namespace, value, expires_at)
    VALUES (${authKvId}, ${`rls-retention-${suffix}`}, '{}', now() - interval '1 day')
  `);
  const retention = await runRetentionSweep({ auditWriter: async () => undefined });
  assert(
    retention.some((result) => result.table === "auth_kv_store" && result.deleted >= 1),
    "global auth KV retention did not execute through the app role",
  );
  const expiredKv = await getDb().execute(sql`SELECT id FROM auth_kv_store WHERE id = ${authKvId}`);
  assert(
    (Array.isArray(expiredKv) ? expiredKv : ((expiredKv as { rows?: unknown[] }).rows ?? []))
      .length === 0,
    "expired auth KV row survived retention",
  );

  console.log(
    JSON.stringify({
      ok: true,
      userId,
      tenantRuns: tenantRuns.length,
      platformAuditActions: platformAudits.map((row) => row.action).sort(),
    }),
  );
} finally {
  await closeDb();
}

// Importing the API intentionally installs process-lifetime maintenance timers.
// This fixture is a one-shot child process, so terminate after all assertions
// and database cleanup instead of waiting for the server timers.
process.exit(0);
