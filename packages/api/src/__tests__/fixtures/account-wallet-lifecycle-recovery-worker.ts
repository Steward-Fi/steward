import { closeDb } from "@stwd/db";
import { recoverStaleAccountWalletLifecyclesForTenant } from "../../services/account-wallet-lifecycle";

const tenantId = process.env.TEST_TENANT_ID;
if (!tenantId) throw new Error("TEST_TENANT_ID is required");

try {
  const result = await recoverStaleAccountWalletLifecyclesForTenant(tenantId);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} finally {
  await closeDb();
}
