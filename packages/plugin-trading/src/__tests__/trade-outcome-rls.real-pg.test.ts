import { afterAll, beforeAll, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createDb, runPluginMigrations } from "@stwd/db";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresTest = databaseUrl ? test : test.skip;
const suffix = randomUUID().replaceAll("-", "");
const roleName = `trading_outcome_app_${suffix}`;
const rolePassword = randomUUID().replaceAll("-", "");
let admin: ReturnType<typeof createDb>;
let restricted: ReturnType<typeof createDb>;

setDefaultTimeout(30_000);

beforeAll(async () => {
  if (!databaseUrl) return;
  admin = createDb(databaseUrl);
  await runPluginMigrations(
    {
      id: "trading",
      migrationsFolder: fileURLToPath(new URL("../../drizzle", import.meta.url)),
    },
    { client: admin.client },
  );
  await admin.client.unsafe(
    `CREATE ROLE ${roleName} LOGIN PASSWORD '${rolePassword}' ` +
      "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
  );
  await admin.client.unsafe(`GRANT USAGE ON SCHEMA public, steward_rls TO ${roleName}`);
  await admin.client.unsafe(`GRANT EXECUTE ON FUNCTION steward_rls.tenant_id() TO ${roleName}`);
  await admin.client.unsafe(`GRANT SELECT, INSERT ON TABLE trading_order_outcomes TO ${roleName}`);
  const restrictedUrl = new URL(databaseUrl);
  restrictedUrl.username = roleName;
  restrictedUrl.password = rolePassword;
  restricted = createDb(restrictedUrl.toString());
});

afterAll(async () => {
  if (!databaseUrl) return;
  await restricted?.client.end();
  await admin?.client.unsafe(`DROP OWNED BY ${roleName}`);
  await admin?.client.unsafe(`DROP ROLE IF EXISTS ${roleName}`);
  await admin?.client.end();
});

realPostgresTest(
  "restricted app role replays its tenant outcome and cannot observe or insert across tenants",
  async () => {
    const id = randomUUID().replaceAll("-", "");
    const tenantA = `tenant-a-${suffix}`;
    const tenantB = `tenant-b-${suffix}`;
    const agentId = `agent-${suffix}`;
    const keyHash = "a".repeat(64);
    const requestHash = "b".repeat(64);
    const response = { status: 200, body: { ok: true, data: { orderId: "order-1" } } };

    await restricted.client.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', ${tenantA}, true)`;
      await tx`
        INSERT INTO trading_order_outcomes
          (id, tenant_id, agent_id, venue, idempotency_key_hash, request_hash, http_status, response)
        VALUES
          (${id}, ${tenantA}, ${agentId}, 'hyperliquid', ${keyHash}, ${requestHash}, 200,
           ${JSON.stringify(response)}::jsonb)
      `;
      const replay = await tx<{ response: typeof response }[]>`
        SELECT response FROM trading_order_outcomes
        WHERE tenant_id = ${tenantA} AND agent_id = ${agentId}
          AND venue = 'hyperliquid' AND idempotency_key_hash = ${keyHash}
      `;
      expect(replay).toEqual([{ response }]);

      await tx`SELECT set_config('steward.tenant_id', ${tenantB}, true)`;
      const hidden = await tx<{ count: string }[]>`
        SELECT count(*)::text AS count FROM trading_order_outcomes WHERE id = ${id}
      `;
      expect(hidden[0]?.count).toBe("0");
    });

    try {
      await restricted.client.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', ${tenantB}, true)`;
        await tx`
          INSERT INTO trading_order_outcomes
            (id, tenant_id, agent_id, venue, idempotency_key_hash, request_hash, http_status, response)
          VALUES
            (${"c".repeat(64)}, ${tenantA}, ${agentId}, 'hyperliquid', ${"d".repeat(64)},
             ${requestHash}, 200, ${JSON.stringify(response)}::jsonb)
        `;
      });
      throw new Error("expected cross-tenant insert to be denied");
    } catch (error) {
      expect((error as { code?: string }).code).toBe("42501");
    }
  },
);
