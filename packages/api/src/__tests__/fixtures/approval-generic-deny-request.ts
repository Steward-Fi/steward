import { closeDb } from "@stwd/db";
import { Hono } from "hono";
import { correlationId } from "../../middleware/correlation";
import type { AppVariables } from "../../services/context";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const tenantId = required("TEST_TENANT_ID");
const userId = required("TEST_USER_ID");
const txId = required("TEST_TX_ID");

const [{ createSessionToken }, { tenantAuth }, { approvalRoutes }] = await Promise.all([
  import("../../routes/auth"),
  import("../../services/context"),
  import("../../routes/approvals"),
]);

const token = await createSessionToken("0x0000000000000000000000000000000000000737", tenantId, {
  userId,
  tenantId,
  mfaVerifiedAt: Date.now(),
  mfaMethod: "totp",
});
const app = new Hono<{ Variables: AppVariables }>();
app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
app.use("*", correlationId);
app.use("*", tenantAuth);
app.route("/approvals", approvalRoutes);

const response = await app.request(`/approvals/${txId}/deny`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-Request-Id": required("TEST_REQUEST_ID"),
  },
  body: JSON.stringify({ reason: required("TEST_DENY_REASON") }),
});
const body = await response.json();
await closeDb();
process.stdout.write(JSON.stringify({ status: response.status, body }));
process.exit(0);
