import { closeDb } from "@stwd/db";
import { Hono } from "hono";
import { tenantConfigRoutes } from "../../routes/tenant-config";

const tenantId = process.env.TEST_TENANT_ID;
const token = process.env.TEST_SESSION_TOKEN;
const method = process.env.TEST_METHOD;
const path = process.env.TEST_PATH;
if (!tenantId || !token || !method || !path) {
  throw new Error("tenant app-client request fixture is missing required environment");
}

const app = new Hono();
app.route("/tenants", tenantConfigRoutes);
app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
const body = process.env.TEST_BODY;
const response = await app.request(`/tenants/${tenantId}${path}`, {
  method,
  headers: {
    Authorization: `Bearer ${token}`,
    ...(body === undefined ? {} : { "Content-Type": "application/json" }),
  },
  body,
});
process.stdout.write(JSON.stringify({ status: response.status, body: await response.text() }));
await closeDb();
process.exit(0);
