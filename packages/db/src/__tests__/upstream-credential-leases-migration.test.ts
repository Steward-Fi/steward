import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const migrationUnderTest = "0093_upstream_credential_leases.sql";

async function applyFile(client: PGlite, file: string) {
  const contents = await readFile(join(migrations, file), "utf8");
  for (const statement of contents.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

async function applyBefore0093(client: PGlite) {
  const files = (await readdir(migrations))
    .filter((file) => file.endsWith(".sql") && file < migrationUnderTest)
    .sort();
  for (const file of files) await applyFile(client, file);
}

async function seedParentRows(client: PGlite) {
  await client.exec(`
    INSERT INTO tenants(id,name,api_key_hash) VALUES ('ta','A','ha'),('tb','B','hb');
    INSERT INTO users(id,email,created_at,updated_at) VALUES
      ('00000000-0000-4000-8000-000000000001','owner@example.test',now(),now());
    INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES ('agent-a','ta','A','0xa');
    INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES
      ('00000000-0000-4000-8000-000000000101','ta','client-a','Client A','production','00000000-0000-4000-8000-000000000001');
  `);
}

describe("0093 upstream credential lease evidence integrity", () => {
  test("upgrades 0092 and enforces a tenant-matched immutable event parent", async () => {
    const client = new PGlite("memory://");
    await applyBefore0093(client);
    await seedParentRows(client);
    await applyFile(client, migrationUnderTest);

    const leaseId = "00000000-0000-4000-8000-000000000201";
    await client.exec(`
      INSERT INTO upstream_credential_leases(
        id,tenant_id,workspace_id,agent_id,grant_id,capability_id,issuer,resource,
        resource_hash,authority_digest,idempotency_key_hash
      ) VALUES (
        '${leaseId}','ta','00000000-0000-4000-8000-000000000101','agent-a',
        '00000000-0000-4000-8000-000000000301','00000000-0000-4000-8000-000000000401',
        'github-app-installation','{}','${"a".repeat(64)}','${"b".repeat(64)}','${"c".repeat(64)}'
      );
      INSERT INTO upstream_credential_lease_events(lease_id,tenant_id,action,decision)
      VALUES ('${leaseId}','ta','lease.issue','allow');
    `);

    await expect(
      client.exec(
        `INSERT INTO upstream_credential_lease_events(lease_id,tenant_id,action,decision) VALUES ('${leaseId}','tb','lease.issue','allow')`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(
        "INSERT INTO upstream_credential_lease_events(lease_id,tenant_id,action,decision) VALUES ('00000000-0000-4000-8000-000000000999','ta','lease.issue','allow')",
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(`DELETE FROM upstream_credential_lease_events WHERE lease_id='${leaseId}'`),
    ).rejects.toThrow(/append-only/);
    await expect(
      client.exec(`DELETE FROM upstream_credential_leases WHERE id='${leaseId}'`),
    ).rejects.toThrow(/append-only/);

    const tenant = await client.query<{ name: string }>("SELECT name FROM tenants WHERE id='ta'");
    expect(tenant.rows[0]?.name).toBe("A");
    await client.close();
  });
});
