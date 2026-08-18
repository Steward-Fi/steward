import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;

async function applyAll(client: PGlite) {
  const files = (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort();
  for (const file of files) {
    await applyMigration(client, file);
  }
}

async function applyMigration(client: PGlite, file: string) {
  const migration = await readFile(join(migrations, file), "utf8");
  for (const statement of migration.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

async function expectRejected(client: PGlite, statement: string) {
  await expect(client.exec(statement)).rejects.toBeDefined();
}

describe("0101 operator transfer reservation integrity", () => {
  test("follows the SigV4 migration without reusing its journal index", async () => {
    const journal = JSON.parse(
      await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
    ) as { entries: Array<{ idx: number; tag: string }> };
    expect(journal.entries.slice(-2).map(({ idx, tag }) => ({ idx, tag }))).toEqual([
      { idx: 100, tag: "0100_sigv4_injection" },
      { idx: 101, tag: "0101_operator_transfer_integrity" },
    ]);
  });

  test("binds tenant/agent identity, rail, and terminal timestamp shape", async () => {
    const client = new PGlite("memory://");
    try {
      await applyAll(client);
      await client.exec(`
        INSERT INTO tenants(id,name,api_key_hash) VALUES
          ('operator-integrity-a','A','operator-integrity-hash-a'),
          ('operator-integrity-b','B','operator-integrity-hash-b');
        INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES
          ('operator-integrity-agent-a','operator-integrity-a','A','0x1111111111111111111111111111111111111111'),
          ('operator-integrity-agent-b','operator-integrity-b','B','0x2222222222222222222222222222222222222222');
      `);

      const values = (
        id: string,
        tenantId: string,
        agentId: string,
        rail: string,
        tail: string,
      ) => `
        INSERT INTO operator_transfer_reservations
          (id,tenant_id,agent_id,rail,idempotency_key,destination,amount_base_units,status,finalized_at)
        VALUES ('${id}','${tenantId}','${agentId}','${rail}','${id}',
          '0x3333333333333333333333333333333333333333','1',${tail})
      `;

      await client.exec(
        values(
          "10000000-0000-4000-8000-000000000001",
          "operator-integrity-a",
          "operator-integrity-agent-a",
          "withdraw",
          "'pending',NULL",
        ),
      );
      await client.exec(
        values(
          "10000000-0000-4000-8000-000000000002",
          "operator-integrity-a",
          "operator-integrity-agent-a",
          "usd-send",
          "'final',now()",
        ),
      );
      await expectRejected(
        client,
        values(
          "10000000-0000-4000-8000-000000000003",
          "operator-integrity-a",
          "operator-integrity-agent-b",
          "withdraw",
          "'pending',NULL",
        ),
      );
      await expectRejected(
        client,
        values(
          "10000000-0000-4000-8000-000000000004",
          "operator-integrity-a",
          "operator-integrity-agent-a",
          "withdraw ",
          "'pending',NULL",
        ),
      );
      await expectRejected(
        client,
        values(
          "10000000-0000-4000-8000-000000000005",
          "operator-integrity-a",
          "operator-integrity-agent-a",
          "withdraw",
          "'final',NULL",
        ),
      );
      await expectRejected(
        client,
        values(
          "10000000-0000-4000-8000-000000000006",
          "operator-integrity-a",
          "operator-integrity-agent-a",
          "withdraw",
          "'pending',now()",
        ),
      );
      await expectRejected(
        client,
        `UPDATE operator_transfer_reservations
         SET status = 'final'
         WHERE id = '10000000-0000-4000-8000-000000000001'`,
      );
    } finally {
      await client.close();
    }
  });

  test("normalizes legacy lifecycle timestamps before enforcing the shape", async () => {
    const client = new PGlite("memory://");
    try {
      const files = (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort();
      for (const file of files) {
        if (file === "0101_operator_transfer_integrity.sql") break;
        await applyMigration(client, file);
      }
      await client.exec(`
        INSERT INTO tenants(id,name,api_key_hash)
        VALUES ('operator-normalize','Normalize','operator-normalize-hash');
        INSERT INTO agents(id,tenant_id,name,wallet_address)
        VALUES ('operator-normalize-agent','operator-normalize','Agent',
          '0x4444444444444444444444444444444444444444');
        INSERT INTO operator_transfer_reservations
          (id,tenant_id,agent_id,rail,idempotency_key,destination,amount_base_units,status,finalized_at)
        VALUES
          ('10000000-0000-4000-8000-000000000010','operator-normalize',
           'operator-normalize-agent','withdraw','legacy-final',
           '0x5555555555555555555555555555555555555555','1','final',NULL),
          ('10000000-0000-4000-8000-000000000011','operator-normalize',
           'operator-normalize-agent','usd-send','legacy-pending',
           '0x5555555555555555555555555555555555555555','1','pending',now());
      `);

      await applyMigration(client, "0101_operator_transfer_integrity.sql");
      const rows = await client.query<{ id: string; finalized: boolean }>(`
        SELECT id, finalized_at IS NOT NULL AS finalized
        FROM operator_transfer_reservations
        WHERE tenant_id = 'operator-normalize'
        ORDER BY id
      `);
      expect(rows.rows).toEqual([
        { id: "10000000-0000-4000-8000-000000000010", finalized: true },
        { id: "10000000-0000-4000-8000-000000000011", finalized: false },
      ]);
    } finally {
      await client.close();
    }
  });
});
