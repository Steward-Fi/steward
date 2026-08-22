import { closeDb, createDb, tenantConfigs } from "@stwd/db";
import { eq } from "drizzle-orm";
import { writeAuditEvent } from "../../services/audit";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const requestId = process.env.TEST_REQUEST_ID;
const mode = process.env.TEST_WRITER_MODE;

if (!databaseUrl || !tenantId || !requestId || !["same", "unrelated"].includes(mode ?? "")) {
  throw new Error("platform tenant-config concurrent-writer environment is incomplete");
}

const writerUrl = new URL(databaseUrl);
writerUrl.searchParams.set("application_name", `platform-config-writer-${requestId}`);
const handle = createDb(writerUrl.toString());
try {
  // Deliberately commit the config write before entering the tenant audit
  // serialization path. Under the retired snapshot/restore implementation this
  // write could land while the failed completion audit was blocked, then be
  // overwritten by compensation. The fixed route retains the row lock through
  // its required audit, so this UPDATE must block until that transaction rolls
  // back. The follow-up audit makes the successful concurrent mutation visible.
  if (mode === "same") {
    await handle.db
      .update(tenantConfigs)
      .set({ joinMode: "open", updatedAt: new Date() })
      .where(eq(tenantConfigs.tenantId, tenantId));
  } else {
    await handle.db
      .update(tenantConfigs)
      .set({ allowedOrigins: ["https://concurrent.example"], updatedAt: new Date() })
      .where(eq(tenantConfigs.tenantId, tenantId));
  }
  await writeAuditEvent({
    tenantId,
    actorType: "platform",
    action: `tenant.platform_config.concurrent_${mode}`,
    resourceType: "tenant",
    resourceId: tenantId,
    requestId,
  });
} finally {
  await handle.client.end();
  await closeDb();
}
