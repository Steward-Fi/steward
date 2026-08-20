import { createDb, tenantConfigs, withTenantAuditedTransactionOnDb } from "@stwd/db";
import { eq } from "drizzle-orm";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const requestId = process.env.TEST_REQUEST_ID;
const mode = process.env.TEST_WRITER_MODE;

if (!databaseUrl || !tenantId || !requestId || !["same", "unrelated"].includes(mode ?? "")) {
  throw new Error("platform tenant-config concurrent-writer environment is incomplete");
}

const handle = createDb(databaseUrl);
try {
  await withTenantAuditedTransactionOnDb(
    handle.db,
    tenantId,
    async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof handle.db;
      if (mode === "same") {
        await tx
          .update(tenantConfigs)
          .set({ joinMode: "open", updatedAt: new Date() })
          .where(eq(tenantConfigs.tenantId, tenantId));
      } else {
        await tx
          .update(tenantConfigs)
          .set({ allowedOrigins: ["https://concurrent.example"], updatedAt: new Date() })
          .where(eq(tenantConfigs.tenantId, tenantId));
      }
      await appendRequiredAudit({
        tenantId,
        actorType: "platform",
        action: `tenant.platform_config.concurrent_${mode}`,
        resourceType: "tenant",
        resourceId: tenantId,
        requestId,
      });
    },
  );
} finally {
  await handle.client.end();
}
