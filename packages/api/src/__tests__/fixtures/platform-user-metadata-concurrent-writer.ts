import {
  __resetAuditHmacKeyCacheForTests,
  createDb,
  users,
  withTenantAuditedTransactionOnDb,
} from "@stwd/db";
import { eq, sql } from "drizzle-orm";

const databaseUrl = process.env.DATABASE_URL;
const userId = process.env.TEST_USER_ID;
const requestId = process.env.TEST_REQUEST_ID;
const expectedRole = process.env.TEST_EXPECTED_DATABASE_ROLE;
if (!databaseUrl || !userId || !requestId || !expectedRole) {
  throw new Error("platform metadata concurrent-writer environment is incomplete");
}

__resetAuditHmacKeyCacheForTests();
const handle = createDb(databaseUrl);
try {
  const [role] = await handle.client<
    { current_user: string; session_user: string; rolsuper: boolean; rolbypassrls: boolean }[]
  >`SELECT current_user::text, session_user::text, role.rolsuper, role.rolbypassrls
    FROM pg_roles role WHERE role.rolname = current_user`;
  if (
    !role ||
    role.current_user !== expectedRole ||
    role.session_user !== expectedRole ||
    role.rolsuper ||
    role.rolbypassrls
  ) {
    throw new Error("concurrent writer did not use the restricted platform role");
  }
  await withTenantAuditedTransactionOnDb(handle.db, "platform", async (txRaw, appendAudit) => {
    const tx = txRaw as typeof handle.db;
    await tx.execute(sql`SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`);
    await tx.update(users).set({
      customMetadata: { owner: "concurrent-winner" },
      updatedAt: new Date(),
    }).where(eq(users.id, userId));
    await appendAudit({
      tenantId: "platform",
      actorType: "platform",
      action: "user.metadata.update",
      resourceType: "user",
      resourceId: userId,
      metadata: { updatedGlobal: true, source: "concurrent-writer" },
      requestId,
    });
  });
} finally {
  await handle.client.end();
}
