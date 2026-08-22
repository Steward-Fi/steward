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
const method = required("TEST_REQUEST_METHOD");
const path = required("TEST_REQUEST_PATH");
const requestBody = process.env.TEST_REQUEST_BODY;

const [{ createSessionToken }, { tenantAuth }, { webhookRoutes }] = await Promise.all([
  import("../../routes/auth"),
  import("../../services/context"),
  import("../../routes/webhooks"),
]);

const token = await createSessionToken("0x0000000000000000000000000000000000000719", tenantId, {
  userId,
  tenantId,
  mfaVerifiedAt: Date.now(),
  mfaMethod: "totp",
});
const app = new Hono<{ Variables: AppVariables }>();
app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
app.use("*", correlationId);
app.use("*", tenantAuth);
app.route("/webhooks", webhookRoutes);

const response = await app.request(path, {
  method,
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-Request-Id": requestId,
  },
  ...(requestBody === undefined ? {} : { body: requestBody }),
});
const body = await response.json();
await closeDb();
process.stdout.write(JSON.stringify({ status: response.status, body }));
process.exit(0);
