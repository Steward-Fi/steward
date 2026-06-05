import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { sql } from "drizzle-orm";
import type { AuditEventInput } from "../services/audit";

const TENANT_ID = "retention-audit-gate";
const AGENT_ID = "retention-audit-gate-agent";

async function proxyPaths(): Promise<string[]> {
  const result = (await getDb().execute(
    sql`SELECT target_path FROM proxy_audit_log WHERE tenant_id = ${TENANT_ID} ORDER BY target_path`,
  )) as Array<{ target_path: string }> | { rows?: Array<{ target_path: string }> };
  const rows = Array.isArray(result) ? result : (result.rows ?? []);
  return rows.map((row) => row.target_path);
}

describe("retention audit gate", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_RETENTION_DISABLED = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_RETENTION_DISABLED;
  });

  it("skips destructive deletes when the authorization audit write fails", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    await getDb().execute(sql`DELETE FROM proxy_audit_log WHERE tenant_id = ${TENANT_ID}`);
    await getDb().execute(sql`
      INSERT INTO proxy_audit_log
        (agent_id, tenant_id, target_host, target_path, method, status_code, latency_ms, created_at)
      VALUES
        (${AGENT_ID}, ${TENANT_ID}, 'example.test', '/must-remain', 'GET', 200, 5, now() - interval '200 days')
    `);

    const results = await runRetentionSweep({
      auditWriter: async (event: AuditEventInput) => {
        if (
          event.action === "system.retention.sweep.authorized" &&
          event.resourceId === "proxy_audit_log"
        ) {
          throw new Error("simulated audit outage");
        }
      },
    });

    expect(results.find((result) => result.table === "proxy_audit_log")).toMatchObject({
      deleted: 0,
      auditFailed: true,
    });
    expect(await proxyPaths()).toContain("/must-remain");
  });

  it("records authorization before deleting and completion after rows are removed", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    await getDb().execute(sql`DELETE FROM proxy_audit_log WHERE tenant_id = ${TENANT_ID}`);
    await getDb().execute(sql`
      INSERT INTO proxy_audit_log
        (agent_id, tenant_id, target_host, target_path, method, status_code, latency_ms, created_at)
      VALUES
        (${AGENT_ID}, ${TENANT_ID}, 'example.test', '/old', 'GET', 200, 5, now() - interval '200 days'),
        (${AGENT_ID}, ${TENANT_ID}, 'example.test', '/fresh', 'GET', 200, 5, now())
    `);
    const proxyAuditActions: string[] = [];

    const results = await runRetentionSweep({
      auditWriter: async (event: AuditEventInput) => {
        if (event.resourceId === "proxy_audit_log") {
          proxyAuditActions.push(event.action);
        }
      },
    });

    expect(results.find((result) => result.table === "proxy_audit_log")?.deleted).toBe(1);
    expect(proxyAuditActions).toEqual([
      "system.retention.sweep.authorized",
      "system.retention.sweep",
    ]);
    expect(await proxyPaths()).toEqual(["/fresh"]);
  });
});
