import { createDb, tenantConfigs, withTenantAuditedTransactionOnDb } from "@stwd/db";
import { eq } from "drizzle-orm";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const requestId = process.env.TEST_REQUEST_ID;
const redirectUrl = process.env.TEST_REDIRECT_URL;
if (!databaseUrl || !tenantId || !requestId || !redirectUrl) {
  throw new Error("concurrent tenant-config writer environment is incomplete");
}

const connection = createDb(databaseUrl);
try {
  await withTenantAuditedTransactionOnDb(
    connection.db,
    tenantId,
    async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof connection.db;
      await tx
        .update(tenantConfigs)
        .set({ allowedRedirectUrls: [redirectUrl], updatedAt: new Date() })
        .where(eq(tenantConfigs.tenantId, tenantId));
      await appendRequiredAudit({
        tenantId,
        actorType: "system",
        actorId: "concurrent-test-writer",
        action: "tenant.redirect_url.concurrent_success",
        resourceType: "tenant_config",
        resourceId: tenantId,
        metadata: { url: redirectUrl },
        requestId,
      });
    },
  );
} finally {
  await connection.client.end();
}
