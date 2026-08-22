import {
  agents,
  createDb,
  policies,
  policyTemplates,
  withTenantAuditedTransactionOnDb,
} from "@stwd/db";
import { and, eq, sql } from "drizzle-orm";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const templateId = process.env.TEST_TEMPLATE_ID;
const agentId = process.env.TEST_AGENT_ID;
const requestId = process.env.TEST_REQUEST_ID;
const mode = process.env.TEST_WRITER_MODE as "create" | "update" | "delete" | "assign" | undefined;
if (!databaseUrl || !tenantId || !templateId || !agentId || !requestId || !mode) {
  throw new Error("concurrent policy-template writer environment is incomplete");
}

const connection = createDb(databaseUrl);
try {
  await withTenantAuditedTransactionOnDb(
    connection.db,
    tenantId,
    async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof connection.db;
      if (mode === "create") {
        await tx.insert(policyTemplates).values({
          id: templateId,
          tenantId,
          name: "concurrent-winner",
          rules: [],
        });
      } else if (mode === "update") {
        await tx
          .update(policyTemplates)
          .set({ name: "concurrent-winner", updatedAt: new Date() })
          .where(and(eq(policyTemplates.id, templateId), eq(policyTemplates.tenantId, tenantId)));
      } else if (mode === "delete") {
        await tx
          .delete(policyTemplates)
          .where(and(eq(policyTemplates.id, templateId), eq(policyTemplates.tenantId, tenantId)));
      } else {
        await tx.execute(
          sql`select pg_advisory_xact_lock(hashtextextended(${`steward_agent_authority_${tenantId}:${agentId}`}, 0))`,
        );
        await tx
          .select({ id: agents.id })
          .from(agents)
          .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)))
          .for("update");
        await tx.delete(policies).where(eq(policies.agentId, agentId));
        await tx.insert(policies).values({
          id: `concurrent-${crypto.randomUUID()}`,
          agentId,
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "777" },
        });
      }
      await appendRequiredAudit({
        tenantId,
        actorType: "system",
        actorId: "concurrent-test-writer",
        action: `policy.template.concurrent_${mode}`,
        resourceType: "policy_template",
        resourceId: templateId,
        metadata: { mode },
        requestId,
      });
    },
  );
} finally {
  await connection.client.end();
}
