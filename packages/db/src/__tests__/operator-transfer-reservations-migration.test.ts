import { describe, expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

const migrations = new URL("../../drizzle", import.meta.url).pathname;

describe("0108 operator transfer durable replay migration", () => {
  test("enforces durable replay records and permits retry after release", async () => {
    const client = new PGlite("memory://");
    for (const file of (await readdir(migrations)).filter((name) => name.endsWith(".sql")).sort()) {
      const migration = await readFile(join(migrations, file), "utf8");
      for (const statement of migration.split("--> statement-breakpoint")) {
        if (statement.trim()) await client.exec(statement);
      }
      if (file === "0094_operator_transfer_reservations.sql") {
        await client.exec(`
          INSERT INTO tenants(id,name,api_key_hash) VALUES ('transfer-t','Transfer','hash');
          INSERT INTO agents(id,tenant_id,name,wallet_address)
            VALUES ('transfer-a','transfer-t','Agent','0x1111111111111111111111111111111111111111');
          INSERT INTO operator_transfer_reservations(
            tenant_id,agent_id,rail,idempotency_key,destination,amount_base_units,status
          ) VALUES (
            'transfer-t','transfer-a','withdraw','legacy-key',
            '0x2222222222222222222222222222222222222222','1000000','pending'
          );
        `);
      }
    }
    const idempotencyKey = "transfer-key";
    const requestDigest = "b".repeat(64);
    await client.exec(`
      INSERT INTO operator_transfer_reservations(
        tenant_id,agent_id,rail,idempotency_key,request_digest,destination,
        amount_base_units,status,finalized_at
      ) VALUES (
        'transfer-t','transfer-a','withdraw','${idempotencyKey}','${requestDigest}',
        '0x2222222222222222222222222222222222222222','1000000','released',now()
      );
      INSERT INTO operator_transfer_reservations(
        tenant_id,agent_id,rail,idempotency_key,request_digest,destination,
        amount_base_units,status,response_status,response_body,finalized_at
      ) VALUES (
        'transfer-t','transfer-a','withdraw','${idempotencyKey}','${requestDigest}',
        '0x2222222222222222222222222222222222222222','1000000','final',200,
        '{"ok":true,"data":{"transfer":"accepted"}}',now()
      );
    `);
    await expect(
      client.exec(`
        INSERT INTO operator_transfer_reservations(
          tenant_id,agent_id,rail,idempotency_key,request_digest,destination,
          amount_base_units,status
        ) VALUES (
          'transfer-t','transfer-a','withdraw','${idempotencyKey}','${"c".repeat(64)}',
          '0x2222222222222222222222222222222222222222','1000000','pending'
        );
      `),
    ).rejects.toThrow();
    await expect(
      client.exec(`
        UPDATE operator_transfer_reservations
        SET response_status=201,response_body='{"ok":true}'
        WHERE status='final'
      `),
    ).rejects.toThrow();
    await expect(
      client.exec(`
        UPDATE operator_transfer_reservations
        SET response_status=NULL,response_body=NULL
        WHERE status='final'
      `),
    ).rejects.toThrow();
    const rows = await client.query<{
      status: string;
      response_status: number | null;
      response_body: unknown;
    }>(`
      SELECT status,response_status,response_body
      FROM operator_transfer_reservations
      WHERE idempotency_key='${idempotencyKey}'
      ORDER BY status DESC
    `);
    expect(rows.rows).toEqual([
      { status: "released", response_status: null, response_body: null },
      {
        status: "final",
        response_status: 200,
        response_body: { ok: true, data: { transfer: "accepted" } },
      },
    ]);
    const legacy = await client.query<{
      request_digest: string;
      response_status: number;
      response_body: unknown;
    }>(`
      SELECT request_digest,response_status,response_body
      FROM operator_transfer_reservations
      WHERE idempotency_key='legacy-key'
    `);
    expect(legacy.rows).toEqual([
      {
        request_digest: "0".repeat(64),
        response_status: 502,
        response_body: {
          ok: false,
          error: "Operator transfer outcome requires reconciliation",
        },
      },
    ]);
    await client.close();
  });
});
