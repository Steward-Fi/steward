/**
 * SEC-031 regression tests for 0090_provider_action_approval_evidence_write_once.
 *
 * The binding guard's `mutable` list includes the approval evidence columns
 * (approval_actor_user_id, approval_queue_id, approval_commitment_hash,
 * approved_at); before 0090 a same-status UPDATE could rewrite who approved an
 * action and what request was approved, post-hoc, without the app-level audit
 * chain ever seeing it. Approval evidence is now write-once: NULL -> value
 * only, and only on the pending_approval decision transitions.
 */

import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;

async function applyFile(client: PGlite, file: string) {
  const sql = await readFile(join(migrations, file), "utf8");
  for (const statement of sql.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

async function applyAll(client: PGlite) {
  const files = (await readdir(migrations)).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) await applyFile(client, file);
}

const IDS = {
  wsA: "00000000-0000-4000-8000-000000000101",
  acctA: "00000000-0000-4000-8000-000000000201",
  opA: "00000000-0000-4000-8000-000000000301",
  owner: "00000000-0000-4000-8000-000000000001",
  accessDecision: "00000000-0000-4000-8000-000000000401",
  policyDecision: "00000000-0000-4000-8000-000000000402",
  queue: "00000000-0000-4000-8000-000000000501",
};

const DIGEST = "sha256:effa84639ed9c9b0b2c01b65bd716342a25a846d9209818b194ab3d151276f3a";
const REQHASH = "sha256:8c0d3d5761ad6ad8ea017d3d36bd57157a7d2f5767acce8ede417d4556b377e3";
const IDEMHASH = "sha256:36c27d7668cf64a4354635a421f14d74410e9cd54bf1002bffa82421145c7a57";
const ACCESSHASH = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const COMMITMENT = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const REWRITTEN_COMMITMENT =
  "sha256:3333333333333333333333333333333333333333333333333333333333333333";

async function seed(client: PGlite) {
  // PGlite's multi-statement exec mis-parses mixed batches once the
  // dollar-quoted trigger function is installed; run each statement alone.
  const stmts = [
    `INSERT INTO tenants(id,name,api_key_hash) VALUES ('ta','A','ha')`,
    `INSERT INTO users(id,email,created_at,updated_at) VALUES ('${IDS.owner}','owner@example.test',now(),now())`,
    `INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES ('agent-a','ta','A','0xa')`,
    `INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES ('${IDS.wsA}','ta','client-a','Client A','production','${IDS.owner}')`,
    `INSERT INTO provider_accounts(id,tenant_id,workspace_id,adapter_key,external_ref,display_name) VALUES ('${IDS.acctA}','ta','${IDS.wsA}','github','a','A')`,
    `INSERT INTO provider_operations(id,tenant_id,workspace_id,provider_account_id,operation_key,risk_class) VALUES ('${IDS.opA}','ta','${IDS.wsA}','${IDS.acctA}','github.issue.list','read')`,
    `INSERT INTO intents(id,tenant_id,agent_id,intent_type,status) VALUES ('intent-1','ta','agent-a','provider.action','pending')`,
  ];
  for (const s of stmts) await client.exec(`${s};`);
}

/** Insert an approval_required binding in pending_approval (revision 1). */
async function insertPendingApprovalBinding(client: PGlite) {
  await client.exec(`
    INSERT INTO provider_action_bindings(
      intent_id, tenant_id, workspace_id, actor_agent_id, provider_account_id,
      operation_id, operation_revision, canonical_profile, canonical_action_bytes,
      action_digest, request_envelope, request_hash, idempotency_key_hash, safe_summary,
      access_decision_id, access_effect, access_reason_code, dependency_revisions,
      access_decision, access_decision_hash,
      policy_decision_id, policy_effect, policy_revision_hash, policy_decision, policy_decision_hash,
      status, binding_revision, approval_queue_id, approval_commitment_hash
    ) VALUES (
      'intent-1','ta','${IDS.wsA}','agent-a','${IDS.acctA}',
      '${IDS.opA}',7,'github.provider-action.v1', decode('7b7d','hex'),
      '${DIGEST}','{}'::jsonb,'${REQHASH}','${IDEMHASH}','{}'::jsonb,
      '${IDS.accessDecision}','allow','provider_access_allowed','{}'::jsonb,
      '{}'::jsonb,'${ACCESSHASH}',
      '${IDS.policyDecision}','approval_required','${ACCESSHASH}','{}'::jsonb,'${ACCESSHASH}',
      'pending_approval',1,'${IDS.queue}','${COMMITMENT}'
    );
  `);
}

async function approveBinding(client: PGlite) {
  await client.exec(`
    UPDATE provider_action_bindings
    SET status='approved', binding_revision=2,
        approval_actor_user_id='${IDS.owner}', approved_at=now(), updated_at=now()
    WHERE intent_id='intent-1'
  `);
}

async function freshApprovedClient(): Promise<PGlite> {
  const client = new PGlite("memory://");
  await applyAll(client);
  await seed(client);
  await insertPendingApprovalBinding(client);
  await approveBinding(client);
  return client;
}

describe("0090 approval evidence write-once guard (SEC-031)", () => {
  test("legit approve: pending_approval -> approved may populate actor + approved_at", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await insertPendingApprovalBinding(client);
    await approveBinding(client);
    const rows = await client.query<{
      status: string;
      approval_actor_user_id: string;
      approved_at: Date | null;
    }>(
      `SELECT status, approval_actor_user_id, approved_at FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(rows.rows[0].status).toBe("approved");
    expect(rows.rows[0].approval_actor_user_id).toBe(IDS.owner);
    expect(rows.rows[0].approved_at).not.toBeNull();
    await client.close();
  });

  test("legit deny: pending_approval -> approval_denied may record the deciding actor", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await insertPendingApprovalBinding(client);
    await client.exec(`
      UPDATE provider_action_bindings
      SET status='approval_denied', binding_revision=2,
          approval_actor_user_id='${IDS.owner}', denied_at=now(), updated_at=now()
      WHERE intent_id='intent-1'
    `);
    const rows = await client.query<{ status: string; approval_actor_user_id: string }>(
      `SELECT status, approval_actor_user_id FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(rows.rows[0].status).toBe("approval_denied");
    expect(rows.rows[0].approval_actor_user_id).toBe(IDS.owner);
    await client.close();
  });

  test("same-status rewrite of approval_actor_user_id is rejected", async () => {
    const client = await freshApprovedClient();
    await expect(
      client.exec(`
        UPDATE provider_action_bindings
        SET approval_actor_user_id='00000000-0000-4000-8000-000000000666', updated_at=now()
        WHERE intent_id='intent-1'
      `),
    ).rejects.toThrow(/approval evidence/);
    await client.close();
  });

  test("post-hoc rewrite of approval_commitment_hash is rejected", async () => {
    const client = await freshApprovedClient();
    await expect(
      client.exec(`
        UPDATE provider_action_bindings
        SET approval_commitment_hash='${REWRITTEN_COMMITMENT}', updated_at=now()
        WHERE intent_id='intent-1'
      `),
    ).rejects.toThrow(/approval evidence/);
    await client.close();
  });

  test("rewrite during a later transition (approved -> approval_expired) is rejected", async () => {
    const client = await freshApprovedClient();
    await expect(
      client.exec(`
        UPDATE provider_action_bindings
        SET status='approval_expired', binding_revision=3, expired_at=now(),
            approval_actor_user_id='00000000-0000-4000-8000-000000000666', updated_at=now()
        WHERE intent_id='intent-1'
      `),
    ).rejects.toThrow(/approval evidence/);
    await client.close();
  });

  test("later transitions succeed while evidence is carried unchanged", async () => {
    const client = await freshApprovedClient();
    await client.exec(`
      UPDATE provider_action_bindings
      SET status='approval_expired', binding_revision=3, expired_at=now(), updated_at=now()
      WHERE intent_id='intent-1'
    `);
    const rows = await client.query<{ status: string; approval_actor_user_id: string }>(
      `SELECT status, approval_actor_user_id FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(rows.rows[0].status).toBe("approval_expired");
    expect(rows.rows[0].approval_actor_user_id).toBe(IDS.owner);
    await client.close();
  });

  test("execution-policy evidence gate still permits approved -> execution_ready", async () => {
    const client = await freshApprovedClient();
    await client.exec(`
      UPDATE provider_action_bindings
      SET status='execution_ready', binding_revision=3,
          resume_actor='steward-system',
          resume_attempt_id='00000000-0000-4000-8000-000000000502',
          resume_validated_at=now(),
          execution_policy_decision_id='00000000-0000-4000-8000-000000000503',
          execution_policy_revision_hash='${ACCESSHASH}',
          execution_policy_decision='{}'::jsonb,
          execution_policy_decision_hash='${ACCESSHASH}',
          execution_policy_evaluated_at=now(),
          updated_at=now()
      WHERE intent_id='intent-1'
    `);
    const rows = await client.query<{ status: string }>(
      `SELECT status FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(rows.rows[0].status).toBe("execution_ready");
    await client.close();
  });
});
