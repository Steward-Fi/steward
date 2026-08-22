import { closeDb, createDb } from "@stwd/db";

const adminUrl = process.env.TEST_ADMIN_DATABASE_URL as string;
const tenantId = process.env.TEST_SHARED_TENANT_ID as string;
const targetUserId = process.env.TEST_SHARED_OWNER_ID as string;
const platformKey = process.env.TEST_PLATFORM_KEY as string;

const { platformRoutes } = await import("../../routes/platform");
const { client: admin } = createDb(adminUrl);
let releaseUserLock = () => {};
let signalUserLock = () => {};
const userLockAcquired = new Promise<void>((resolve) => {
  signalUserLock = resolve;
});
const userLockRelease = new Promise<void>((resolve) => {
  releaseUserLock = resolve;
});

const blocker = admin.begin(async (tx) => {
  await tx`SELECT pg_advisory_xact_lock(
    hashtextextended(${`platform_user_account_${targetUserId}`}, 0)
  )`;
  signalUserLock();
  await userLockRelease;
});
await userLockAcquired;

const membership = platformRoutes.request(`/tenants/${tenantId}/members/${targetUserId}`, {
  method: "PATCH",
  headers: {
    "X-Steward-Platform-Key": platformKey,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ role: "admin" }),
});

await Bun.sleep(100);
const tenantLockRemainsAvailable = await admin.begin(async (tx) => {
  const [row] = await tx<{ acquired: boolean }[]>`
    SELECT pg_try_advisory_xact_lock(
      hashtextextended(${`tenant_owner_lifecycle_${tenantId}`}, 0)
    ) AS acquired
  `;
  return row?.acquired ?? false;
});
if (!tenantLockRemainsAvailable) {
  releaseUserLock();
  await blocker;
  const response = await membership;
  throw new Error(
    `mounted membership route acquired the tenant lock before the user lock: ${response.status}:${await response.text()}`,
  );
}

releaseUserLock();
await blocker;
const membershipResponse = await membership;
if (membershipResponse.status !== 200) {
  throw new Error(
    `mounted lock-order route failed: membership=${membershipResponse.status}:${await membershipResponse.text()}`,
  );
}

await admin.end();
await closeDb();
console.log("mounted user-before-tenant membership/lifecycle lock order passed");
process.exit(0);
