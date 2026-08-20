import { closeDb, createDb } from "@stwd/db";

const adminUrl = process.env.TEST_ADMIN_DATABASE_URL as string;
const sharedTenantId = process.env.TEST_SHARED_TENANT_ID as string;
const sharedOwnerId = process.env.TEST_SHARED_OWNER_ID as string;
const personalDeleteTenantId = process.env.TEST_PERSONAL_DELETE_TENANT_ID as string;
const personalDeleteUserId = process.env.TEST_PERSONAL_DELETE_USER_ID as string;
const platformKey = process.env.TEST_PLATFORM_KEY as string;

const { platformRoutes } = await import("../../routes/platform");
const { userRoutes } = await import("../../routes/user");
const { createSessionToken } = await import("../../routes/auth");

const token = await createSessionToken(
  "0x0000000000000000000000000000000000000000",
  sharedTenantId,
  {
    userId: sharedOwnerId,
    tenantId: sharedTenantId,
    mfaVerifiedAt: Date.now(),
  },
);
const { client: admin } = createDb(adminUrl);
let releaseOwnerLock = () => {};
let signalOwnerLock = () => {};
const ownerLockAcquired = new Promise<void>((resolve) => {
  signalOwnerLock = resolve;
});
const ownerLockRelease = new Promise<void>((resolve) => {
  releaseOwnerLock = resolve;
});
const blocker = admin.begin(async (tx) => {
  await tx`SELECT pg_advisory_xact_lock(
    hashtextextended(${`tenant_owner_lifecycle_${sharedTenantId}`}, 0)
  )`;
  signalOwnerLock();
  await ownerLockRelease;
});
await ownerLockAcquired;

const dashboardDeactivate = userRoutes.request(
  `/me/tenants/${sharedTenantId}/users/${sharedOwnerId}/deactivate`,
  {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ deactivated: true }),
  },
);

let dashboardOwnsUserLock = false;
for (let attempt = 0; attempt < 100 && !dashboardOwnsUserLock; attempt += 1) {
  dashboardOwnsUserLock = !(await admin.begin(async (tx) => {
    const [row] = await tx<{ acquired: boolean }[]>`
      SELECT pg_try_advisory_xact_lock(
        hashtextextended(${`platform_user_account_${sharedOwnerId}`}, 0)
      ) AS acquired
    `;
    return row?.acquired ?? false;
  }));
  if (!dashboardOwnsUserLock) await Bun.sleep(20);
}
if (!dashboardOwnsUserLock) throw new Error("mounted dashboard route never acquired user lock");

const platformDeactivate = platformRoutes.request(`/users/${sharedOwnerId}/deactivate`, {
  method: "PATCH",
  headers: {
    "X-Steward-Platform-Key": platformKey,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ deactivated: true }),
});
releaseOwnerLock();
await blocker;
const [dashboardResponse, platformResponse] = await Promise.all([
  dashboardDeactivate,
  platformDeactivate,
]);
if (dashboardResponse.status !== 200 || platformResponse.status !== 200) {
  const dashboardBody = await dashboardResponse.text();
  const platformBody = await platformResponse.text();
  throw new Error(
    `inverse lifecycle routes failed: dashboard=${dashboardResponse.status}:${dashboardBody} platform=${platformResponse.status}:${platformBody}`,
  );
}

const nestedPersonalDelete = await platformRoutes.request(
  `/tenants/${personalDeleteTenantId}/email-config`,
  {
    method: "DELETE",
    headers: { "X-Steward-Platform-Key": platformKey },
  },
);
if (nestedPersonalDelete.status !== 200) {
  throw new Error(`mounted nested personal deletion failed: ${nestedPersonalDelete.status}`);
}
const [nestedPersonalState] = await admin<{ email_config_cleared: boolean; audit_count: number }[]>`
  SELECT
    (SELECT email_config IS NULL FROM tenant_configs
      WHERE tenant_id = ${personalDeleteTenantId}) AS email_config_cleared,
    (SELECT count(*)::int FROM audit_events
      WHERE tenant_id = ${personalDeleteTenantId}
        AND resource_id = ${personalDeleteTenantId}
        AND action IN (
          'tenant.email_config.delete.authorized',
          'tenant.email_config.delete'
        )) AS audit_count
`;
if (!nestedPersonalState?.email_config_cleared || nestedPersonalState.audit_count !== 2) {
  throw new Error(
    `mounted nested personal deletion context mismatch: ${JSON.stringify(nestedPersonalState)}`,
  );
}

const tenantDelete = await platformRoutes.request(`/tenants/${personalDeleteTenantId}`, {
  method: "DELETE",
  headers: { "X-Steward-Platform-Key": platformKey },
});
if (tenantDelete.status !== 200) {
  throw new Error(`mounted personal tenant deletion failed: ${tenantDelete.status}`);
}
const personalDeleteAudits = await admin<
  { tenant_id: string; action: string; resource_id: string; target_tenant_id: string | null }[]
>`
  SELECT tenant_id, action, resource_id, metadata->>'targetTenantId' AS target_tenant_id
  FROM audit_events
  WHERE resource_type = 'tenant'
    AND resource_id = ${personalDeleteTenantId}
    AND action IN (
      'tenant.delete.authorized',
      'tenant.delete.token_revocation_completed',
      'tenant.delete'
    )
  ORDER BY seq
`;
const expectedPersonalDeleteActions = [
  "tenant.delete.authorized",
  "tenant.delete.token_revocation_completed",
  "tenant.delete",
];
if (
  personalDeleteAudits.length !== expectedPersonalDeleteActions.length ||
  personalDeleteAudits.some(
    (row, index) =>
      row.tenant_id !== "platform" ||
      row.action !== expectedPersonalDeleteActions[index] ||
      row.resource_id !== personalDeleteTenantId ||
      row.target_tenant_id !== personalDeleteTenantId,
  )
) {
  throw new Error(
    `mounted personal tenant deletion audit mismatch: ${JSON.stringify(personalDeleteAudits)}`,
  );
}
const userDelete = await platformRoutes.request(`/users/${personalDeleteUserId}`, {
  method: "DELETE",
  headers: { "X-Steward-Platform-Key": platformKey },
});
if (userDelete.status !== 200) {
  throw new Error(`mounted post-tenant user deletion failed: ${userDelete.status}`);
}

const remaining = await admin<{ tenants: number; users: number }[]>`
  SELECT
    (SELECT count(*)::int FROM tenants WHERE id = ${personalDeleteTenantId}) AS tenants,
    (SELECT count(*)::int FROM users WHERE id = ${personalDeleteUserId}::uuid) AS users
`;
if (remaining[0]?.tenants !== 0 || remaining[0]?.users !== 0) {
  throw new Error(`mounted deletion left rows: ${JSON.stringify(remaining[0])}`);
}

await admin.end();
await closeDb();
console.log("mounted split-role lifecycle routes passed");
process.exit(0);
