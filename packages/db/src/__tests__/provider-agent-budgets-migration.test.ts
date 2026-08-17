import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);

let client: PGlite;

const IDS = {
  owner: "00000000-0000-4000-8000-000000000001",
  workspaceA: "00000000-0000-4000-8000-000000000101",
  workspaceB: "00000000-0000-4000-8000-000000000102",
  countBudget: "00000000-0000-4000-8000-000000000201",
} as const;

describe("provider agent budgets migration (0088)", () => {
  beforeAll(async () => {
    ({ client } = await createPGLiteDb("memory://"));
    await client.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('ta','A','ha'),('tb','B','hb');
      INSERT INTO users(id,email,created_at,updated_at) VALUES
        ('${IDS.owner}','owner@example.test',now(),now());
      INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES
        ('agent-a','ta','A','0xa'),('agent-b','tb','B','0xb');
      INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES
        ('${IDS.workspaceA}','ta','a','A','production','${IDS.owner}'),
        ('${IDS.workspaceB}','tb','b','B','production','${IDS.owner}');
    `);
  });

  afterAll(async () => {
    await client.close();
  });

  test("creates count and notional budget objects with bounded windows", async () => {
    await client.exec(`
      INSERT INTO provider_agent_budgets
        (id,tenant_id,agent_id,dimension,window_seconds,max,auto_freeze)
      VALUES ('${IDS.countBudget}','ta','agent-a','count',86400,500,true);
      INSERT INTO provider_agent_budgets
        (tenant_id,workspace_id,agent_id,dimension,window_seconds,max,currency)
      VALUES ('ta','${IDS.workspaceA}','agent-a','notional',604800,10000,'USD');
    `);
    const rows = await client.query<{ dimension: string; currency: string | null }>(
      `SELECT dimension,currency FROM provider_agent_budgets ORDER BY dimension`,
    );
    expect(rows.rows).toEqual([
      { dimension: "count", currency: null },
      { dimension: "notional", currency: "USD" },
    ]);
    await expect(
      client.exec(
        `INSERT INTO provider_agent_budgets (tenant_id,agent_id,dimension,window_seconds,max,currency) VALUES ('ta','agent-a','count',0,1,NULL)`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(
        `INSERT INTO provider_agent_budgets (tenant_id,agent_id,dimension,window_seconds,max,currency) VALUES ('ta','agent-a','notional',60,1,NULL)`,
      ),
    ).rejects.toThrow();
  });

  test("enforces tenant ownership and one budget per scope/dimension/window", async () => {
    await expect(
      client.exec(
        `INSERT INTO provider_agent_budgets (tenant_id,workspace_id,agent_id,dimension,window_seconds,max) VALUES ('ta','${IDS.workspaceB}','agent-a','count',60,1)`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(
        `INSERT INTO provider_agent_budgets (tenant_id,agent_id,dimension,window_seconds,max) VALUES ('ta','agent-b','count',60,1)`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(
        `INSERT INTO provider_agent_budgets (tenant_id,agent_id,dimension,window_seconds,max) VALUES ('ta','agent-a','count',86400,999)`,
      ),
    ).rejects.toThrow();
  });

  test("configuration changes atomically bump revision and reject naked revisions", async () => {
    await client.exec(`UPDATE provider_agent_budgets SET max=501 WHERE id='${IDS.countBudget}'`);
    const changed = await client.query<{ max: bigint; revision: number }>(
      `SELECT max,revision FROM provider_agent_budgets WHERE id='${IDS.countBudget}'`,
    );
    expect(Number(changed.rows[0]?.max)).toBe(501);
    expect(changed.rows[0]?.revision).toBe(2);
    await expect(
      client.exec(`UPDATE provider_agent_budgets SET revision=99 WHERE id='${IDS.countBudget}'`),
    ).rejects.toThrow(/revision changed/);
  });
});
