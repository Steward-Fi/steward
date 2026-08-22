import { createDb, sql, withTenantTransactionDatabase } from "@stwd/db";
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

async function writeFrame(frame: unknown) {
  await new Promise<void>((resolve, reject) => {
    globalThis.process.stdout.write(`${JSON.stringify(frame)}\n`, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

const database = createDb();
let result: { body: unknown; status: number } | undefined;
try {
  await database.db.transaction(async (tx) => {
    const rows = (await tx.execute(sql`select pg_backend_pid()::integer as pid`)) as unknown as {
      pid: number;
    }[];
    const backend = rows[0];
    if (!backend) throw new Error("condition-set writer could not resolve its backend PID");
    await writeFrame({ type: "backend", pid: backend.pid });

    const response = await withTenantTransactionDatabase(tx as never, { tenantId }, () =>
      app.request(path, {
        method,
        headers: globalThis.process.env.TEST_BODY
          ? { "Content-Type": "application/json" }
          : undefined,
        body: globalThis.process.env.TEST_BODY,
      }),
    );
    result = { body: await response.json(), status: response.status };
  });
} finally {
  await database.client.end();
}
if (!result) throw new Error("condition-set writer produced no route result");
await writeFrame({ type: "result", ...result });
await new Promise<void>((resolve, reject) => {
  globalThis.process.stdout.write("", (error) => {
    if (error) reject(error);
    else resolve();
  });
});
globalThis.process.exit(0);
