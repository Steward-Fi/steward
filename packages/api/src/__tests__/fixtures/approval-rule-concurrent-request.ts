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
const requestId = required("TEST_REQUEST_ID");
const requestBody = JSON.parse(required("TEST_REQUEST_BODY")) as Record<string, unknown>;

const [{ createSessionToken }, { tenantAuth }, { approvalRoutes }] = await Promise.all([
  import("../../routes/auth"),
  import("../../services/context"),
  import("../../routes/approvals"),
]);

const token = await createSessionToken("0x0000000000000000000000000000000000000720", tenantId, {
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

const response = await app.request("/approvals/rules", {
  method: "PUT",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-Request-Id": requestId,
  },
  body: JSON.stringify(requestBody),
});
const body = await response.json();
await closeDb();
process.stdout.write(JSON.stringify({ status: response.status, body }));
// postgres.js keeps its pool timer alive after this single-purpose process has
// returned the mounted response. The request transaction is already committed;
// force a clean helper exit so Bun's test runner never has to reap it.
process.exit(0);
