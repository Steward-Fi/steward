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
if (!databaseUrl || !userId || !requestId) {
  throw new Error("platform metadata concurrent-writer environment is incomplete");
}

__resetAuditHmacKeyCacheForTests();
const handle = createDb(databaseUrl);
try {
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
