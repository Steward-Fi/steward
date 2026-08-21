import { revocationStore, signAccessToken } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";
import app from "../../app";
import { verifySessionToken } from "../../services/context";

const platformKey = process.env.STEWARD_PLATFORM_KEYS ?? "";
const tenantId = process.env.STEWARD_PERSONAL_LIFECYCLE_TEST_TENANT ?? "";
const userId = process.env.STEWARD_PERSONAL_LIFECYCLE_TEST_USER ?? "";
const teamTenantId = process.env.STEWARD_PERSONAL_LIFECYCLE_TEAM_TENANT ?? "";
const teamAdminId = process.env.STEWARD_PERSONAL_LIFECYCLE_TEAM_ADMIN ?? "";
const teamTargetId = process.env.STEWARD_PERSONAL_LIFECYCLE_TEAM_TARGET ?? "";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const originalRevokeUserTokens = revocationStore.revokeUserTokens.bind(revocationStore);
let cacheOverrideInstalled = false;
try {
  assert(platformKey.length > 0, "STEWARD_PLATFORM_KEYS is required");
  assert(tenantId.startsWith("personal-"), "personal lifecycle tenant is required");
  assert(userId.length > 0, "personal lifecycle user is required");
  assert(teamTenantId.length > 0, "team lifecycle tenant is required");
  assert(teamAdminId.length > 0 && teamTargetId.length > 0, "team lifecycle users are required");

  const oldToken = await signAccessToken({ address: "", tenantId, userId });
  assert(
    (await verifySessionToken(oldToken))?.userId === userId,
    "old token was not initially valid",
  );
  let failNextCacheRefresh = true;
  revocationStore.revokeUserTokens = async (...args) => {
    if (failNextCacheRefresh) {
      failNextCacheRefresh = false;
      throw new Error("injected token-cache refresh failure");
    }
    return originalRevokeUserTokens(...args);
  };
  cacheOverrideInstalled = true;

  const deactivate = await app.request(`http://steward.test/platform/users/${userId}/deactivate`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": platformKey,
    },
    body: JSON.stringify({ deactivated: true }),
  });
  assert(
    deactivate.status === 200,
    `mounted failed-cache deactivation returned ${deactivate.status}`,
  );
  assert(
    (await verifySessionToken(oldToken)) === null,
    "deactivation did not invalidate old token",
  );
  // Mint while the database identity is inactive. This token is newer than the
  // successful deactivation cache line, so only the durable reactivation line
  // can keep it invalid after deactivated_at is cleared.
  await Bun.sleep(1_100);
  const betweenToken = await signAccessToken({ address: "", tenantId, userId });
  failNextCacheRefresh = true;

  const reactivate = await app.request(`http://steward.test/platform/users/${userId}/deactivate`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": platformKey,
    },
    body: JSON.stringify({ deactivated: false }),
  });
  assert(
    reactivate.status === 200,
    `mounted failed-cache reactivation returned ${reactivate.status}`,
  );
  assert(
    (await verifySessionToken(betweenToken)) === null,
    "reactivation restored a token newer than the stale cache but older than the durable boundary",
  );
  await Bun.sleep(1_100);
  const freshToken = await signAccessToken({ address: "", tenantId, userId });
  assert(
    (await verifySessionToken(freshToken))?.userId === userId,
    "fresh post-reactivation token was not accepted",
  );

  const adminToken = await signAccessToken({
    address: "",
    tenantId: teamTenantId,
    userId: teamAdminId,
    mfaVerifiedAt: Date.now(),
  });
  for (const deactivated of [true, false]) {
    const tenantLifecycle = await app.request(
      `http://steward.test/user/me/tenants/${teamTenantId}/users/${teamTargetId}/deactivate`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ deactivated }),
      },
    );
    assert(
      tenantLifecycle.status === 200,
      `mounted tenant-admin lifecycle (${deactivated}) returned ${tenantLifecycle.status}: ${await tenantLifecycle.text()}`,
    );
  }

  const response = await app.request(`http://steward.test/platform/tenants/${tenantId}`, {
    method: "DELETE",
    headers: { "X-Steward-Platform-Key": platformKey },
  });
  const body = (await response.json()) as { ok?: boolean; error?: string };
  assert(
    response.status === 200 && body.ok === true,
    `mounted personal tenant deletion returned ${response.status}: ${JSON.stringify(body)}`,
  );

  const deleted =
    (await getDb().select({ id: tenants.id }).from(tenants).where(eq(tenants.id, tenantId)))
      .length === 0;
  assert(deleted, "mounted personal tenant deletion did not commit through the app login");
  console.log(JSON.stringify({ ok: true, deleted, lifecycle: true }));
} finally {
  if (cacheOverrideInstalled) revocationStore.revokeUserTokens = originalRevokeUserTokens;
  await closeDb();
}

// Production route imports install process-lifetime maintenance handles. This
// is a one-shot role-bound fixture, so exit after the mounted request settles.
process.exit(0);
