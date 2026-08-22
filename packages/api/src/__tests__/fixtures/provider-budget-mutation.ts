import { closeDb } from "@stwd/db";
import {
  ProviderAuthorityError,
  providerAuthorityStore,
} from "../../services/provider-authority-store";

const required = (name: string): string => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const action = required("TEST_ACTION") as "create" | "update" | "delete";
const expectedRevision = Number(required("TEST_EXPECTED_REVISION"));
const context = {
  tenantId: required("TEST_TENANT_ID"),
  actorUserId: required("TEST_USER_ID"),
  tenantRole: "owner" as const,
  mfaVerifiedAt: Date.now(),
  idempotencyKey: required("TEST_IDEMPOTENCY_KEY"),
  expectedRevision,
  reason: `real race ${action}`,
  requestId: `budget-race-${action}`,
  audit: async () => undefined,
};

try {
  const row =
    action === "create"
      ? await providerAuthorityStore.createAgentBudget(context, {
          agentId: required("TEST_AGENT_ID"),
          dimension: "count",
          windowSeconds: 3600,
          max: Number(required("TEST_MAX")),
          autoFreeze: false,
        })
      : action === "update"
        ? await providerAuthorityStore.updateAgentBudget(context, required("TEST_BUDGET_ID"), {
            dimension: "count",
            windowSeconds: 3600,
            max: Number(required("TEST_MAX")),
            enabled: process.env.TEST_ENABLED !== "false",
            autoFreeze: false,
          })
        : await providerAuthorityStore.deleteAgentBudget(context, required("TEST_BUDGET_ID"));
  console.log(JSON.stringify({ ok: true, row }));
} catch (error) {
  if (error instanceof ProviderAuthorityError) {
    console.log(
      JSON.stringify({
        ok: false,
        error: { code: error.code, message: error.message, status: error.status },
      }),
    );
  } else {
    console.log(
      JSON.stringify({
        ok: false,
        error: { code: "internal", message: "authority mutation failed", status: 500 },
      }),
    );
  }
} finally {
  await closeDb();
}
