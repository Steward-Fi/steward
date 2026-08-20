import { closeDb } from "@stwd/db";
import { Hono } from "hono";
import { conditionSetRoutes } from "../../routes/condition-sets";
import type { AppVariables } from "../../services/context";

const tenantId = process.env.TEST_TENANT_ID;
const path = process.env.TEST_PATH;
const method = process.env.TEST_METHOD;
if (!tenantId || !path || !method) throw new Error("condition-set writer input is incomplete");

const app = new Hono<{ Variables: AppVariables }>();
app.use("*", async (c, next) => {
  c.set("tenantId", tenantId);
  c.set("authType", "session-jwt");
  c.set("tenantRole", "admin");
  c.set("userId", "condition-set-postgres-writer");
  c.set("sessionMfaVerifiedAt", Date.now());
  c.set("requestId", process.env.TEST_REQUEST_ID);
  await next();
});
app.route("/condition-sets", conditionSetRoutes);

const response = await app.request(path, {
  method,
  headers: process.env.TEST_BODY ? { "Content-Type": "application/json" } : undefined,
  body: process.env.TEST_BODY,
});
const body = await response.json();
await closeDb();
await new Promise<void>((resolve, reject) => {
  process.stdout.write(`${JSON.stringify({ body, status: response.status })}\n`, (error) => {
    if (error) reject(error);
    else resolve();
  });
});
process.exit(0);
