/**
 * #205 migration 0083 schema-invariant tests. Asserts the raw-SQL invariants
 * that drizzle-kit cannot express survive migration, so accidental removal fails
 * CI:
 *   - approval_queue quorum columns exist (threshold nullable, count NOT NULL
 *     default 0, eligible-set array NOT NULL default '{}')
 *   - the fail-closed quorum-shape CHECK rejects malformed rows AND permits the
 *     single-approver (NULL threshold) shape
 *   - provider_action_approvals table + its distinctness / idempotency unique
 *     indexes + decision CHECK exist and enforce
 *
 * A single migrated PGLite instance is shared across cases (fresh WASM instances
 * per case race the pglite runtime under bun parallel execution).
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);

let client: PGlite;
const migrationsDir = new URL("../../drizzle", import.meta.url).pathname;

async function applyFile(c: PGlite, file: string) {
  const sql = await readFile(join(migrationsDir, file), "utf8");
  for (const stmt of sql.split("--> statement-breakpoint")) {
    if (stmt.trim()) await c.exec(stmt);
  }
}

describe("#205 quorum migration (0083)", () => {
  beforeAll(async () => {
    ({ client } = await createPGLiteDb("memory://"));
  });
  afterAll(async () => {
    await client.close();
  });

  test("approval_queue quorum columns exist with the right nullability/defaults", async () => {
    const cols = await client.query<{
      column_name: string;
      is_nullable: string;
      column_default: string | null;
    }>(
      `SELECT column_name, is_nullable, column_default FROM information_schema.columns
       WHERE table_name='approval_queue' AND column_name LIKE 'quorum%' ORDER BY column_name`,
    );
    const byName = Object.fromEntries(cols.rows.map((r) => [r.column_name, r]));
    expect(byName.quorum_threshold?.is_nullable).toBe("YES");
    expect(byName.quorum_approvals_count?.is_nullable).toBe("NO");
    expect(byName.quorum_eligible_user_ids?.is_nullable).toBe("NO");
    expect(byName.quorum_approvals_count?.column_default).toContain("0");
  });

  // A provider_action approval_queue row must satisfy the 0081 arm CHECK
  // (intent_id/tenant_id/workspace_id/hashes/commitment/expires_at). This helper
  // builds a legal row and lets the caller vary only the quorum columns.
  const H = `sha256:${"a".repeat(64)}`;
  // Each queue row needs its own intent (approval_queue has a UNIQUE(intent_id)).
  async function armRow(id: string, quorumCols: string): Promise<void> {
    const intentId = `int_${id}`;
    await client.exec(
      `INSERT INTO intents (id, tenant_id, intent_type, status) VALUES ('${intentId}','t205','provider-action','pending')`,
    );
    await client.exec(`INSERT INTO approval_queue
      (id, agent_id, status, approval_kind, intent_id, tenant_id, workspace_id,
       request_hash, action_digest, approval_commitment, approval_commitment_hash,
       expected_binding_revision, expires_at ${quorumCols ? ", " + quorumCols.split("::VALUES::")[0] : ""})
      VALUES ('${id}','ag205','pending','provider_action','${intentId}','t205',
              '20000000-0000-4000-8000-000000000009', '${H}', '${H}', '{}'::jsonb, '${H}',
              1, now() + interval '5 minutes'
              ${quorumCols ? ", " + quorumCols.split("::VALUES::")[1] : ""})`);
  }

  test("quorum-shape CHECK permits single-approver (NULL) and a valid quorum, rejects malformed", async () => {
    // Minimal parent rows for a legal approval_queue insert.
    await client.exec(`INSERT INTO tenants (id, name, api_key_hash) VALUES ('t205','t','h')`);
    await client.exec(
      `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES ('ag205','t205','a','0x1')`,
    );

    // NULL threshold (single-approver) is permitted.
    await armRow("aq_single", "");

    // A valid 2-of-3 quorum is permitted.
    await armRow(
      "aq_quorum",
      "quorum_threshold, quorum_eligible_user_ids, quorum_approvals_count::VALUES::2, ARRAY['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000003']::uuid[], 1",
    );

    // threshold 0 rejected.
    let rejected0 = false;
    try {
      await armRow(
        "aq_bad0",
        "quorum_threshold, quorum_eligible_user_ids::VALUES::0, ARRAY['00000000-0000-4000-8000-000000000001']::uuid[]",
      );
    } catch {
      rejected0 = true;
    }
    expect(rejected0).toBe(true);

    // threshold > eligible set size rejected.
    let rejectedBig = false;
    try {
      await armRow(
        "aq_bad_big",
        "quorum_threshold, quorum_eligible_user_ids::VALUES::3, ARRAY['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002']::uuid[]",
      );
    } catch {
      rejectedBig = true;
    }
    expect(rejectedBig).toBe(true);

    // tally > threshold rejected.
    let rejectedTally = false;
    try {
      await armRow(
        "aq_bad_tally",
        "quorum_threshold, quorum_eligible_user_ids, quorum_approvals_count::VALUES::2, ARRAY['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002']::uuid[], 3",
      );
    } catch {
      rejectedTally = true;
    }
    expect(rejectedTally).toBe(true);

    // NULL threshold with a non-empty eligible set rejected (shape must be clean).
    let rejectedDirtyNull = false;
    try {
      await armRow(
        "aq_dirty_null",
        "quorum_eligible_user_ids::VALUES::ARRAY['00000000-0000-4000-8000-000000000001']::uuid[]",
      );
    } catch {
      rejectedDirtyNull = true;
    }
    expect(rejectedDirtyNull).toBe(true);
  });

  test("provider_action_approvals distinctness + idempotency unique indexes enforce", async () => {
    const idx = await client.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes WHERE tablename='provider_action_approvals' ORDER BY indexname`,
    );
    const names = idx.rows.map((r) => r.indexname);
    expect(names).toContain("provider_action_approvals_approver_uniq");
    expect(names).toContain("provider_action_approvals_idem_uniq");

    // Seed a legal provider_action queue to reference.
    await armRow(
      "aq_paa",
      "quorum_threshold, quorum_eligible_user_ids::VALUES::2, ARRAY['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002']::uuid[]",
    );
    // A second legal queue so the per-approver cross-ACTION idem guard can be
    // exercised (same approver + same key on a DIFFERENT queue).
    await armRow(
      "aq_paa2",
      "quorum_threshold, quorum_eligible_user_ids::VALUES::2, ARRAY['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002']::uuid[]",
    );

    const row = (queueId: string, approverIdx: number, idemDigit: string) =>
      `INSERT INTO provider_action_approvals
        (approval_queue_id, intent_id, tenant_id, workspace_id, approver_user_id, decision,
         binding_revision_at_decision, request_hash, action_digest, approval_commitment_hash,
         decision_idempotency_key_hash, decision_request_hash)
       VALUES ('${queueId}','int_${queueId}','t205','20000000-0000-4000-8000-000000000009',
               '00000000-0000-4000-8000-00000000000${approverIdx}','approve', 1,
               'sha256:${"a".repeat(64)}','sha256:${"b".repeat(64)}','sha256:${"c".repeat(64)}',
               'sha256:${idemDigit.repeat(64)}','sha256:${"e".repeat(64)}')`;

    await client.exec(row("aq_paa", 1, "1"));

    // Same approver on the same queue => distinctness violation (different key).
    let dupApprover = false;
    try {
      await client.exec(row("aq_paa", 1, "2"));
    } catch {
      dupApprover = true;
    }
    expect(dupApprover).toBe(true);

    // Same approver reusing the SAME idempotency key on a DIFFERENT queue/action
    // => per-approver cross-action idem violation.
    let dupIdem = false;
    try {
      await client.exec(row("aq_paa2", 1, "1"));
    } catch {
      dupIdem = true;
    }
    expect(dupIdem).toBe(true);

    // A DIFFERENT approver reusing the same key string is fine (distinct people):
    // the idem guard is scoped per-approver, so this must SUCCEED.
    await client.exec(row("aq_paa2", 2, "1"));

    // Invalid decision value rejected by the CHECK.
    let badDecision = false;
    try {
      await client.exec(
        `INSERT INTO provider_action_approvals
          (approval_queue_id, intent_id, tenant_id, workspace_id, approver_user_id, decision,
           binding_revision_at_decision, request_hash, action_digest, approval_commitment_hash,
           decision_idempotency_key_hash, decision_request_hash)
         VALUES ('aq_paa','int_aq_paa','t205','20000000-0000-4000-8000-000000000009',
                 '00000000-0000-4000-8000-000000000003','maybe', 1,
                 'sha256:${"a".repeat(64)}','sha256:${"b".repeat(64)}','sha256:${"c".repeat(64)}',
                 'sha256:${"f".repeat(64)}','sha256:${"9".repeat(64)}')`,
      );
    } catch {
      badDecision = true;
    }
    expect(badDecision).toBe(true);
  });
});
