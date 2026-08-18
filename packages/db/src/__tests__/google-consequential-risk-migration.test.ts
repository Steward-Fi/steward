import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const migrationUnderTest = "0102_google_consequential_write_risk.sql";

async function applyFile(client: PGlite, file: string): Promise<void> {
  const sql = await readFile(join(migrations, file), "utf8");
  for (const statement of sql.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

async function applyBeforeMigration(client: PGlite): Promise<void> {
  const files = (await readdir(migrations))
    .filter((file) => file.endsWith(".sql") && file < migrationUnderTest)
    .sort();
  for (const file of files) await applyFile(client, file);
}

describe("Google consequential write risk migration (0102)", () => {
  test("upgrades existing write rows, stales commitments, and is idempotent", async () => {
    const client = new PGlite("memory://");
    await applyBeforeMigration(client);
    await client.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('tg','Google','hg');
      INSERT INTO users(id,email,created_at,updated_at) VALUES
        ('00000000-0000-4000-8000-000000000001','owner@example.test',now(),now());
      INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES
        ('00000000-0000-4000-8000-000000000101','tg','google','Google','production',
         '00000000-0000-4000-8000-000000000001');
      INSERT INTO provider_accounts(
        id,tenant_id,workspace_id,adapter_key,external_ref,display_name
      ) VALUES
        ('00000000-0000-4000-8000-000000000201','tg',
         '00000000-0000-4000-8000-000000000101','google','google-1','Google'),
        ('00000000-0000-4000-8000-000000000202','tg',
         '00000000-0000-4000-8000-000000000101','github','github-1','GitHub');
      INSERT INTO provider_operations(
        id,tenant_id,workspace_id,provider_account_id,operation_key,risk_class,revision
      ) VALUES
        ('00000000-0000-4000-8000-000000000301','tg',
         '00000000-0000-4000-8000-000000000101',
         '00000000-0000-4000-8000-000000000201','google.gmail.messages.send','write',7),
        ('00000000-0000-4000-8000-000000000302','tg',
         '00000000-0000-4000-8000-000000000101',
         '00000000-0000-4000-8000-000000000201','google.calendar.events.insert','read',9),
        ('00000000-0000-4000-8000-000000000303','tg',
         '00000000-0000-4000-8000-000000000101',
         '00000000-0000-4000-8000-000000000201','google.calendar.events.list','read',11),
        ('00000000-0000-4000-8000-000000000304','tg',
         '00000000-0000-4000-8000-000000000101',
         '00000000-0000-4000-8000-000000000202','github.pr.comment.create','write',13);
    `);

    await applyFile(client, migrationUnderTest);
    const first = await client.query<{
      operation_key: string;
      risk_class: string;
      revision: number;
    }>(`
      SELECT operation_key,risk_class,revision
      FROM provider_operations ORDER BY operation_key
    `);
    expect(first.rows).toEqual([
      { operation_key: "github.pr.comment.create", risk_class: "write", revision: 13 },
      { operation_key: "google.calendar.events.insert", risk_class: "consequential", revision: 10 },
      { operation_key: "google.calendar.events.list", risk_class: "read", revision: 11 },
      { operation_key: "google.gmail.messages.send", risk_class: "consequential", revision: 8 },
    ]);

    await applyFile(client, migrationUnderTest);
    const second = await client.query<{ revision: number }>(`
      SELECT revision FROM provider_operations
      WHERE operation_key='google.gmail.messages.send'
    `);
    expect(second.rows[0]?.revision).toBe(8);
    await client.close();
  });
});
