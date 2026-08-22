import { Hono } from "hono";
import { correlationId } from "../../middleware/correlation";
import type { AppVariables } from "../../services/context";

const tenantId = process.env.TEST_TENANT_ID;
const path = process.env.TEST_PATH;
const method = process.env.TEST_METHOD;
if (!tenantId || !path || !method) throw new Error("secret route writer input incomplete");

const { secretsRoutes } = await import("../../routes/secrets");
const app = new Hono<{ Variables: AppVariables }>();
app.use("*", correlationId);
app.use("*", async (c, next) => {
  c.set("tenantId", tenantId);
  c.set("authType", "session-jwt");
  c.set("tenantRole", "owner");
  c.set("userId", process.env.TEST_USER_ID ?? crypto.randomUUID());
  c.set("sessionMfaVerifiedAt", Date.now());
  await next();
});
app.route("/secrets", secretsRoutes);
app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
const response = await app.request(path, {
  method,
  headers: {
    ...(process.env.TEST_BODY ? { "content-type": "application/json" } : {}),
    ...(process.env.TEST_REQUEST_ID ? { "x-request-id": process.env.TEST_REQUEST_ID } : {}),
  },
  body: process.env.TEST_BODY,
});
await Bun.write(
  Bun.stdout,
  `${JSON.stringify({ status: response.status, body: await response.text() })}\n`,
);
process.exit(0);
