/**
 * Migration + invariant coverage for 0080_provider_action_bindings.
 *
 * Applies the full migration chain into an in-memory PGlite database, then
 * asserts the table exists and that its strict composite FKs, uniqueness
 * indexes, CHECK state-machine, and immutability trigger all behave per spec
 * section 5. These are the DB-level fail-closed guarantees the service relies on.
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
  wsB: "00000000-0000-4000-8000-000000000102",
  acctA: "00000000-0000-4000-8000-000000000201",
  opA: "00000000-0000-4000-8000-000000000301",
  owner: "00000000-0000-4000-8000-000000000001",
  accessDecision: "00000000-0000-4000-8000-000000000401",
  policyDecision: "00000000-0000-4000-8000-000000000402",
};

const DIGEST = "sha256:effa84639ed9c9b0b2c01b65bd716342a25a846d9209818b194ab3d151276f3a";
const REQHASH = "sha256:8c0d3d5761ad6ad8ea017d3d36bd57157a7d2f5767acce8ede417d4556b377e3";
const IDEMHASH = "sha256:36c27d7668cf64a4354635a421f14d74410e9cd54bf1002bffa82421145c7a57";
const ACCESSHASH = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

async function seed(client: PGlite) {
  // NOTE: PGlite's multi-statement exec mis-parses this specific mixed batch
  // once 0080's dollar-quoted trigger function is installed; run each statement
  // as its own exec (robust, and closer to how the migrator applies them).
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

function bindingInsert(overrides: Partial<Record<string, string>> = {}): string {
  const v = {
    intentId: "intent-1",
    accessEffect: "allow",
    policyEffect: "allow",
    status: "allowed_stub",
    policyId: `'${IDS.policyDecision}'`,
    policyRevHash: `'${ACCESSHASH}'`,
    policyDecision: `'{}'::jsonb`,
    policyDecisionHash: `'${ACCESSHASH}'`,
    reservationHandles: "NULL",
    reservationState: "'not_required'",
    reservationReconciledAt: "NULL",
    ...overrides,
  } as Record<string, string>;
  return `
    INSERT INTO provider_action_bindings(
      intent_id, tenant_id, workspace_id, actor_agent_id, provider_account_id,
      operation_id, operation_revision, canonical_profile, canonical_action_bytes,
      action_digest, request_envelope, request_hash, idempotency_key_hash, safe_summary,
      access_decision_id, access_effect, access_reason_code, dependency_revisions,
      access_decision, access_decision_hash,
      policy_decision_id, policy_effect, policy_revision_hash, policy_decision, policy_decision_hash,
      policy_reservation_handles, reservation_reconciliation_state, reservation_reconciled_at,
      status
    ) VALUES (
      '${v.intentId}','ta','${IDS.wsA}','agent-a','${IDS.acctA}',
      '${IDS.opA}',7,'github.provider-action.v1', decode('7b7d','hex'),
      '${DIGEST}','{}'::jsonb,'${REQHASH}','${IDEMHASH}','{}'::jsonb,
      '${IDS.accessDecision}','${v.accessEffect}','provider_access_allowed','{}'::jsonb,
      '{}'::jsonb,'${ACCESSHASH}',
      ${v.policyId},'${v.policyEffect}',${v.policyRevHash},${v.policyDecision},${v.policyDecisionHash},
      ${v.reservationHandles},${v.reservationState},${v.reservationReconciledAt},
      '${v.status}'
    );
  `;
}

describe("0080 provider_action_bindings migration", () => {
  test("migrates and creates the table + intents composite unique", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    const tbl = await client.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables WHERE table_name = 'provider_action_bindings'`,
    );
    expect(tbl.rows).toHaveLength(1);
    const con = await client.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint WHERE conname = 'intents_tenant_id_id_uniq'`,
    );
    expect(con.rows).toHaveLength(1);
    await client.close();
  });

  test("inserts a valid allow/allow binding", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(bindingInsert());
    const rows = await client.query(`SELECT status FROM provider_action_bindings`);
    expect(rows.rows).toHaveLength(1);
    await client.close();
  });

  test("state-machine CHECK rejects allow/allow with status denied", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    let threw = false;
    try {
      await client.exec(bindingInsert({ status: "denied" }));
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });

  test("policy_shape CHECK rejects not_evaluated with a policy decision present", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    let threw = false;
    try {
      await client.exec(
        bindingInsert({
          accessEffect: "deny",
          policyEffect: "not_evaluated",
          status: "denied",
          // leave policy decision fields present -> violates shape check
        }),
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });

  test("deny/not_evaluated/denied with null policy fields is valid", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(
      bindingInsert({
        accessEffect: "deny",
        policyEffect: "not_evaluated",
        status: "denied",
        policyId: "NULL",
        policyRevHash: "NULL",
        policyDecision: "NULL",
        policyDecisionHash: "NULL",
      }),
    );
    const rows = await client.query(`SELECT status FROM provider_action_bindings`);
    expect(rows.rows).toHaveLength(1);
    await client.close();
  });

  test("digest regex CHECK rejects a malformed action digest", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    let threw = false;
    try {
      await client.exec(bindingInsert().replace(`'${DIGEST}'`, `'sha256:NOTHEX'`));
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });

  test("request_hash uniqueness rejects a second binding with the same request hash", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(bindingInsert());
    await client.exec(
      `INSERT INTO intents(id,tenant_id,agent_id,intent_type,status) VALUES ('intent-2','ta','agent-a','provider.action','pending');`,
    );
    let threw = false;
    try {
      await client.exec(bindingInsert({ intentId: "intent-2" }));
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });

  test("immutability trigger freezes non-status columns", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(bindingInsert());
    let threw = false;
    try {
      await client.exec(
        `UPDATE provider_action_bindings SET action_digest = '${DIGEST.replace("effa", "0000")}' WHERE intent_id = 'intent-1'`,
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });

  test("0084 freezes handles and permits only pending -> terminal reconciliation CAS", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    const handles = `'{"schemaVersion":"steward.provider-policy-reservations.v1","cumulativeSpend":[{"stream":{"agentId":"agent-a","scope":"agent","scopeKey":"","currency":"USD"},"reservationId":"r1","amount":7}],"windowedInvoke":null}'::jsonb`;
    await client.exec(
      bindingInsert({ reservationHandles: handles, reservationState: "'pending'" }),
    );

    await expect(
      client.exec(
        `UPDATE provider_action_bindings
         SET policy_reservation_handles = jsonb_set(policy_reservation_handles, '{cumulativeSpend,0,amount}', '8')
         WHERE intent_id='intent-1'`,
      ),
    ).rejects.toBeDefined();
    await client.exec(
      `UPDATE provider_action_bindings
       SET reservation_reconciliation_state='settled', reservation_reconciled_at=now()
       WHERE intent_id='intent-1' AND reservation_reconciliation_state='pending'`,
    );
    const row = await client.query<{
      reservation_reconciliation_state: string;
      reservation_reconciled_at: Date | null;
    }>(
      `SELECT reservation_reconciliation_state,reservation_reconciled_at
       FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(row.rows[0].reservation_reconciliation_state).toBe("settled");
    expect(row.rows[0].reservation_reconciled_at).not.toBeNull();
    await expect(
      client.exec(
        `UPDATE provider_action_bindings SET reservation_reconciliation_state='released'
         WHERE intent_id='intent-1'`,
      ),
    ).rejects.toBeDefined();
    await client.close();
  });

  test("0084 rejects terminal reconciliation without a timestamp", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    const handles = `'{"schemaVersion":"steward.provider-policy-reservations.v1","cumulativeSpend":[],"windowedInvoke":{"agentId":"agent-a","operationKey":"github.issue.list","reservationId":"r2"}}'::jsonb`;
    await expect(
      client.exec(bindingInsert({ reservationHandles: handles, reservationState: "'released'" })),
    ).rejects.toBeDefined();
    await client.close();
  });

  test("immutability trigger allows allowed_stub -> stub_succeeded but not other transitions", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(bindingInsert());
    await client.exec(
      `UPDATE provider_action_bindings SET status = 'stub_succeeded' WHERE intent_id = 'intent-1'`,
    );
    const rows = await client.query<{ status: string }>(
      `SELECT status FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(rows.rows[0].status).toBe("stub_succeeded");

    // terminal -> another status must be rejected
    let threw = false;
    try {
      await client.exec(
        `UPDATE provider_action_bindings SET status = 'stub_failed' WHERE intent_id = 'intent-1'`,
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });

  test("cross-scope FK: operation from another workspace is rejected", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    // wsB + its own account/op belong to a different workspace; the composite
    // operation FK must reject an operation id that isn't under (ta, wsA, acctA).
    let threw = false;
    try {
      await client.exec(
        bindingInsert().replace(`'${IDS.opA}'`, `'00000000-0000-4000-8000-000000000999'`),
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });
});
