import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(30_000);

let client: Awaited<ReturnType<typeof createPGLiteDb>>["client"] | undefined;

beforeAll(async () => {
  ({ client } = await createPGLiteDb("memory://"));
});

afterAll(async () => {
  await client?.close();
});

describe("approval queue pagination index", () => {
  test("is journaled with the exact filtering and raw-order columns", async () => {
    const result = await client!.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes
       WHERE tablename = 'approval_queue'
         AND indexname = 'approval_queue_agent_status_requested_idx'`,
    );
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]?.indexdef).toContain("(agent_id, status, requested_at DESC, id DESC)");
  });

  test("the filtered keyset query can use the composite index prefix", async () => {
    await client!.exec("SET enable_seqscan = off");
    const plan = await client!.query<{ "QUERY PLAN": string }>(`
      EXPLAIN SELECT id
      FROM approval_queue
      WHERE agent_id = 'agent-index-probe' AND status = 'pending'
      ORDER BY date_trunc('milliseconds', requested_at) DESC, id DESC
      LIMIT 200
    `);
    expect(plan.rows.map((row) => row["QUERY PLAN"]).join("\n")).toContain(
      "approval_queue_agent_status_requested_idx",
    );
  });
});
