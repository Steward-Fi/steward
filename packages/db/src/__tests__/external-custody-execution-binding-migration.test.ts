import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const IDENTITY = "a".repeat(64);

async function applyAll(client: PGlite) {
  const files = (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort();
  for (const file of files) {
    const sql = await readFile(join(migrations, file), "utf8");
    for (const statement of sql.split("--> statement-breakpoint")) {
      if (statement.trim()) await client.exec(statement);
    }
  }
}

async function expectRejected(client: PGlite, sql: string) {
  let rejected = false;
  try {
    await client.exec(sql);
  } catch {
    rejected = true;
  }
  expect(rejected).toBe(true);
}

describe("0087 external custody execution binding migration", () => {
  test("enforces exact backend and identity pairings", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await client.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('custody-t','Custody','hash');
      INSERT INTO agents(id,tenant_id,name,wallet_address)
        VALUES ('custody-a','custody-t','Agent','0x1111111111111111111111111111111111111111');
    `);

    const transaction = (id: string, backend: string, identity: string) => `
      INSERT INTO transactions(
        id,agent_id,status,to_address,value,chain_id,execution_backend,execution_backend_identity_digest
      ) VALUES (
        '${id}','custody-a','pending','0x2222222222222222222222222222222222222222','1',8453,
        ${backend},${identity}
      );
    `;
    await client.exec(transaction("tx-local", "'local-vault'", "NULL"));
    await client.exec(transaction("tx-external", "'external-custody'", `'${IDENTITY}'`));
    await client.exec(transaction("tx-legacy", "NULL", "NULL"));
    await expectRejected(client, transaction("tx-null-smuggle", "NULL", `'${IDENTITY}'`));
    await expectRejected(client, transaction("tx-unknown", "'unknown'", "NULL"));
    await expectRejected(client, transaction("tx-external-null", "'external-custody'", "NULL"));

    const constraint = await client.query<{ definition: string }>(`
      SELECT pg_get_constraintdef(oid) AS definition
      FROM pg_constraint
      WHERE conname = 'execution_auth_external_identity_chk'
    `);
    expect(constraint.rows[0]?.definition).toContain("credential-proxy");
    expect(constraint.rows[0]?.definition).toContain("local-vault");
    expect(constraint.rows[0]?.definition).toContain("external-custody");
    await client.close();
  });
});
