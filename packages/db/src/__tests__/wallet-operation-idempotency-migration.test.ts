import { describe, expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

const migrations = new URL("../../drizzle", import.meta.url).pathname;

describe("0107 wallet operation idempotency migration", () => {
  test("enforces one durable operation key and valid terminal states", async () => {
    const client = new PGlite("memory://");
    for (const file of (await readdir(migrations)).filter((name) => name.endsWith(".sql")).sort()) {
      const migration = await readFile(join(migrations, file), "utf8");
      for (const statement of migration.split("--> statement-breakpoint")) {
        if (statement.trim()) await client.exec(statement);
      }
    }
    await client.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('wallet-t','Wallet','hash');
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('wallet-other','Other','other-hash');
      INSERT INTO agents(id,tenant_id,name,wallet_address)
        VALUES ('wallet-a','wallet-t','Agent','0x1111111111111111111111111111111111111111');
      INSERT INTO wallet_operation_idempotency(
        tenant_id,agent_id,operation,idempotency_key_hash,request_digest,status,tx_id
      ) VALUES (
        'wallet-t','wallet-a','vault.sign.broadcast','${"a".repeat(64)}','${"b".repeat(64)}',
        'submission_unknown','wallet-tx'
      );
    `);
    await expect(
      client.exec(`
        INSERT INTO wallet_operation_idempotency(
          tenant_id,agent_id,operation,idempotency_key_hash,request_digest,status,tx_id
        ) VALUES (
          'wallet-t','wallet-a','vault.sign.broadcast','${"a".repeat(64)}','${"c".repeat(64)}',
          'processing','wallet-tx-2'
        );
      `),
    ).rejects.toThrow();
    await expect(
      client.exec(
        `UPDATE wallet_operation_idempotency SET status='failed' WHERE tx_id='wallet-tx'`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(`
        INSERT INTO wallet_operation_idempotency(
          tenant_id,agent_id,operation,idempotency_key_hash,request_digest,status,tx_id
        ) VALUES (
          'wallet-other','wallet-a','vault.sign.broadcast','${"d".repeat(64)}','${"e".repeat(64)}',
          'processing','wallet-cross-tenant'
        );
      `),
    ).rejects.toThrow();
    const row = await client.query<{ status: string }>(
      "SELECT status FROM wallet_operation_idempotency WHERE tx_id='wallet-tx'",
    );
    expect(row.rows).toEqual([{ status: "submission_unknown" }]);
    await client.close();
  });
});
