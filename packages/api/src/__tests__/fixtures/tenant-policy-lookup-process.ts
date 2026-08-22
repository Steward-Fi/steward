import { closeDb } from "@stwd/db";
import {
  getPolicySet,
  policyEngine,
  withAuthenticatedTenantDatabase,
} from "../../services/context";

const tenantId = process.env.TEST_TENANT_ID;
const ownAgentId = process.env.TEST_OWN_AGENT_ID;
const foreignAgentId = process.env.TEST_FOREIGN_AGENT_ID;

if (!tenantId || !ownAgentId || !foreignAgentId) {
  throw new Error("tenant policy lookup fixture environment is incomplete");
}

try {
  const result = await withAuthenticatedTenantDatabase(
    tenantId,
    "tenant-policy-restart-proof",
    `fixture:${tenantId}`,
    async () => {
      const own = await getPolicySet(tenantId, ownAgentId);
      const foreign = await getPolicySet(tenantId, foreignAgentId);
      const missing = await getPolicySet(tenantId, `missing-${ownAgentId}`);
      const emptyEvaluation = await policyEngine.evaluate(missing, {
        request: {
          agentId: ownAgentId,
          tenantId,
          to: "0x0000000000000000000000000000000000000001",
          value: "0",
          chainId: 1,
        },
        recentTxCount24h: 0,
        recentTxCount1h: 0,
        spentToday: 0n,
        spentThisWeek: 0n,
      });
      return {
        ownPolicyIds: own.map((policy) => policy.id),
        foreignPolicyIds: foreign.map((policy) => policy.id),
        emptyEvaluation,
      };
    },
  );
  console.log(JSON.stringify(result));
} finally {
  await closeDb();
}
