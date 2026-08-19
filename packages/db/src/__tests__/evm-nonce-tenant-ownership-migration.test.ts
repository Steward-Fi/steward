import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const migrationUnderTest = "0108_evm_nonce_tenant_ownership.sql";

async function applyMigration(client: PGlite, file: string) {
  const migration = await readFile(join(migrations, file), "utf8");
  for (const statement of migration.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

async function applyBeforeMigration(client: PGlite) {
  const files = (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort();
  for (const file of files) {
    if (file === migrationUnderTest) break;
    await applyMigration(client, file);
  }
}

describe("0108 EVM nonce tenant ownership", () => {
  test("is journal-contiguous after X disconnect recovery", async () => {
    const journal = JSON.parse(
      await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
    ) as { entries: Array<{ idx: number; tag: string }> };
    expect(journal.entries.slice(-2).map(({ idx, tag }) => ({ idx, tag }))).toEqual([
      { idx: 107, tag: "0107_x_disconnect_route_recovery" },
      { idx: 108, tag: "0108_evm_nonce_tenant_ownership" },
    ]);
  });

  test("backfills an unambiguous owner and enforces the cross-tenant claim", async () => {
    const client = new PGlite("memory://");
    try {
      await applyBeforeMigration(client);
      await client.exec(`
        INSERT INTO tenants(id,name,api_key_hash) VALUES
          ('nonce-owner-a','A','nonce-owner-a-hash'),
          ('nonce-owner-b','B','nonce-owner-b-hash');
        INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES
          ('nonce-agent-a','nonce-owner-a','A','0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        INSERT INTO evm_wallet_nonces(wallet_address,chain_id,next_nonce)
          VALUES ('0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',8453,12);
        INSERT INTO evm_wallet_nonce_inflight(wallet_address,chain_id,nonce,state)
          VALUES ('0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',8453,11,'allocated');
      `);

      await applyMigration(client, migrationUnderTest);
      const rows = await client.query<{ tenant_id: string; wallet_address: string }>(`
        SELECT tenant_id,wallet_address FROM evm_wallet_nonces
      `);
      expect(rows.rows).toEqual([
        {
          tenant_id: "nonce-owner-a",
          wallet_address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      ]);

      await expect(
        client.exec(`
          INSERT INTO evm_wallet_nonce_owners(tenant_id,wallet_address,chain_id)
          VALUES ('nonce-owner-b','0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',8453)
        `),
      ).rejects.toBeDefined();
      await expect(
        client.exec(`
          INSERT INTO evm_wallet_nonces(tenant_id,wallet_address,chain_id,next_nonce)
          VALUES ('nonce-owner-b','0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',8453,13)
        `),
      ).rejects.toBeDefined();
    } finally {
      await client.close();
    }
  });

  test("fails closed when legacy ownership is ambiguous or missing", async () => {
    for (const scenario of ["ambiguous", "missing"] as const) {
      const client = new PGlite("memory://");
      try {
        await applyBeforeMigration(client);
        await client.exec(`
          INSERT INTO tenants(id,name,api_key_hash) VALUES
            ('nonce-${scenario}-a','A','nonce-${scenario}-a-hash'),
            ('nonce-${scenario}-b','B','nonce-${scenario}-b-hash');
        `);
        if (scenario === "ambiguous") {
          await client.exec(`
            INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES
              ('nonce-ambiguous-agent-a','nonce-ambiguous-a','A',
               '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
              ('nonce-ambiguous-agent-b','nonce-ambiguous-b','B',
               '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
          `);
        }
        await client.exec(`
          INSERT INTO evm_wallet_nonces(wallet_address,chain_id,next_nonce)
          VALUES ('0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1,2)
        `);

        await expect(applyMigration(client, migrationUnderTest)).rejects.toThrow(
          "requires exactly one tenant owner",
        );
      } finally {
        await client.close();
      }
    }
  });
});
