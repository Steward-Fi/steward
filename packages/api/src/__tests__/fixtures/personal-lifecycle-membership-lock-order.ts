import { closeDb, createDb } from "@stwd/db";

const adminUrl = process.env.TEST_ADMIN_DATABASE_URL as string;
const tenantId = process.env.TEST_SHARED_TENANT_ID as string;
const targetUserId = process.env.TEST_SHARED_OWNER_ID as string;
const platformKey = process.env.TEST_PLATFORM_KEY as string;

const { platformRoutes } = await import("../../routes/platform");
const { client: admin } = createDb(adminUrl);
let releaseTenantLock = () => {};
let signalTenantLock = () => {};
const tenantLockAcquired = new Promise<void>((resolve) => {
  signalTenantLock = resolve;
});
const tenantLockRelease = new Promise<void>((resolve) => {
  releaseTenantLock = resolve;
});

const blocker = admin.begin(async (tx) => {
  await tx`SELECT pg_advisory_xact_lock(
    hashtextextended(${`tenant_owner_lifecycle_${tenantId}`}, 0)
  )`;
  signalTenantLock();
  await tenantLockRelease;
});
await tenantLockAcquired;

const membership = platformRoutes.request(`/tenants/${tenantId}/members/${targetUserId}`, {
  method: "PATCH",
  headers: {
    "X-Steward-Platform-Key": platformKey,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ role: "admin" }),
});

await Bun.sleep(100);
const userLockRemainsAvailable = await admin.begin(async (tx) => {
  const [row] = await tx<{ acquired: boolean }[]>`
    SELECT pg_try_advisory_xact_lock(
      hashtextextended(${`platform_user_account_${targetUserId}`}, 0)
    ) AS acquired
  `;
  return row?.acquired ?? false;
});
if (!userLockRemainsAvailable) {
  releaseTenantLock();
  await blocker;
  const response = await membership;
  throw new Error(
    `mounted membership route acquired the user lock before the tenant lock: ${response.status}:${await response.text()}`,
  );
}

releaseTenantLock();
await blocker;
const membershipResponse = await membership;
if (membershipResponse.status !== 200) {
  throw new Error(
    `mounted lock-order route failed: membership=${membershipResponse.status}:${await membershipResponse.text()}`,
  );
}

await admin.end();
await closeDb();
console.log("mounted tenant-before-user membership/lifecycle lock order passed");
process.exit(0);
