import {
  __resetAuditHmacKeyCacheForTests,
  agentRegistrations,
  createDb,
  withTenantAuditedTransactionOnDb,
} from "@stwd/db";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const agentId = process.env.TEST_AGENT_ID;
const requestId = process.env.TEST_REQUEST_ID;
const apiUrl = process.env.TEST_API_URL;

if (!databaseUrl || !tenantId || !agentId || !requestId || !apiUrl) {
  throw new Error("ERC-8004 concurrent writer fixture is missing required environment");
}

__resetAuditHmacKeyCacheForTests();
const handle = createDb(databaseUrl);

try {
  await withTenantAuditedTransactionOnDb(
    handle.db,
    tenantId,
    async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof handle.db;
      await tx
        .insert(agentRegistrations)
        .values({
          tenantId,
          agentId,
          chainId: 8453,
          registryAddress: "0x0000000000000000000000000000000000008004",
          agentCardJson: { name: agentId, apiUrl, capabilities: ["concurrent-winner"] },
          status: "pending",
        })
        .onConflictDoUpdate({
          target: [
            agentRegistrations.tenantId,
            agentRegistrations.agentId,
            agentRegistrations.chainId,
          ],
          set: {
            agentCardJson: { name: agentId, apiUrl, capabilities: ["concurrent-winner"] },
            status: "pending",
            updatedAt: new Date(),
          },
        });
      await appendRequiredAudit({
        tenantId,
        actorType: "user",
        actorId: "concurrent-writer",
        action: "erc8004.register",
        resourceType: "agent",
        resourceId: agentId,
        metadata: {
          chainId: 8453,
          registryAddress: "0x0000000000000000000000000000000000008004",
          source: "concurrent-writer",
        },
        requestId,
      });
    },
  );
} finally {
  await handle.client.end();
}
