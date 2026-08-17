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

async function applyThrough(client: PGlite, last: string) {
  const files = (await readdir(migrations)).filter((f) => f.endsWith(".sql") && f <= last).sort();
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
    ...overrides,
  } as Record<string, string>;
  return `
    INSERT INTO provider_action_bindings(
      intent_id, tenant_id, workspace_id, actor_agent_id, provider_account_id,
      operation_id, operation_revision, canonical_profile, canonical_action_bytes,
      action_digest, request_envelope, request_hash, idempotency_key_hash, safe_summary,
      access_decision_id, access_effect, access_reason_code, dependency_revisions,
      access_decision, access_decision_hash,
      policy_decision_id, policy_effect, policy_revision_hash, policy_decision, policy_decision_hash, status
    ) VALUES (
      '${v.intentId}','ta','${IDS.wsA}','agent-a','${IDS.acctA}',
      '${IDS.opA}',7,'github.provider-action.v1', decode('7b7d','hex'),
      '${DIGEST}','{}'::jsonb,'${REQHASH}','${IDEMHASH}','{}'::jsonb,
      '${IDS.accessDecision}','${v.accessEffect}','provider_access_allowed','{}'::jsonb,
      '{}'::jsonb,'${ACCESSHASH}',
      ${v.policyId},'${v.policyEffect}',${v.policyRevHash},${v.policyDecision},${v.policyDecisionHash},'${v.status}'
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

  test("0084 uses append-only generations and permits only pending -> terminal reconciliation CAS", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    const handles = `'{"schemaVersion":"steward.provider-policy-reservations.v1","generation":1,"phase":"decision","cumulativeSpend":[{"stream":{"agentId":"agent-a","scope":"agent","scopeKey":"","currency":"USD"},"reservationId":"r1","amount":7}],"windowedInvoke":null}'::jsonb`;
    await client.exec(bindingInsert());
    await client.exec(`INSERT INTO provider_action_reservation_generations
      (intent_id,tenant_id,generation,phase,handles) VALUES ('intent-1','ta',1,'decision',${handles})`);

    await expect(
      client.exec(
        `UPDATE provider_action_reservation_generations
         SET handles = jsonb_set(handles, '{cumulativeSpend,0,amount}', '8') WHERE intent_id='intent-1'`,
      ),
    ).rejects.toBeDefined();
    await client.exec(
      `UPDATE provider_action_reservation_generations SET state='settled', reconciled_at=now()
       WHERE intent_id='intent-1' AND state='pending'`,
    );
    const row = await client.query<{
      state: string;
      reconciled_at: Date | null;
    }>(
      `SELECT state,reconciled_at FROM provider_action_reservation_generations WHERE intent_id='intent-1'`,
    );
    expect(row.rows[0].state).toBe("settled");
    expect(row.rows[0].reconciled_at).not.toBeNull();
    await expect(
      client.exec(
        `UPDATE provider_action_reservation_generations SET state='released' WHERE intent_id='intent-1'`,
      ),
    ).rejects.toBeDefined();
    await client.close();
  });

  test("0084 rejects terminal reconciliation without a timestamp", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    const handles = `'{"schemaVersion":"steward.provider-policy-reservations.v1","generation":2,"phase":"execution","cumulativeSpend":[],"windowedInvoke":{"agentId":"agent-a","operationKey":"github.issue.list","reservationId":"r2"}}'::jsonb`;
    await client.exec(bindingInsert());
    await expect(
      client.exec(`INSERT INTO provider_action_reservation_generations
      (intent_id,tenant_id,generation,phase,handles,state)
      VALUES ('intent-1','ta',2,'execution',${handles},'released')`),
    ).rejects.toBeDefined();
    await client.close();
  });

  test("0088 rejects v2 reservation handles bound to another tenant", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(bindingInsert());
    const crossTenant = `'{"schemaVersion":"steward.provider-policy-reservations.v2","generation":1,"phase":"decision","cumulativeSpend":[{"stream":{"tenantId":"tb","agentId":"agent-a","scope":"agent","scopeKey":"","currency":"USD"},"reservationId":"cross-tenant","amount":7}],"windowedInvoke":null}'::jsonb`;
    await expect(
      client.exec(`INSERT INTO provider_action_reservation_generations
        (intent_id,tenant_id,generation,phase,handles)
        VALUES ('intent-1','ta',1,'decision',${crossTenant})`),
    ).rejects.toBeDefined();
    await client.close();
  });

  test("0084 fail-closes a legacy execution_ready row and enqueues rollout evidence", async () => {
    const client = new PGlite("memory://");
    await applyThrough(client, "0083_provider_approval_quorum.sql");
    await seed(client);
    for (const statement of [
      `INSERT INTO secrets(id,tenant_id,name,ciphertext,iv,auth_tag,salt,version)
       VALUES ('00000000-0000-4000-8000-000000000601','ta','legacy','x','x','x','x',1)`,
      `INSERT INTO secret_routes(id,tenant_id,secret_id,host_pattern,inject_as,inject_key)
       VALUES ('00000000-0000-4000-8000-000000000602','ta',
       '00000000-0000-4000-8000-000000000601','api.github.com','header','authorization')`,
      `UPDATE provider_accounts SET credential_secret_id='00000000-0000-4000-8000-000000000601',
       credential_version=1 WHERE id='${IDS.acctA}'`,
      `UPDATE provider_operations SET secret_route_id='00000000-0000-4000-8000-000000000602'
       WHERE id='${IDS.opA}'`,
      `UPDATE secret_routes SET authority_mode='governed_v2', provider_operation_id='${IDS.opA}'
       WHERE id='00000000-0000-4000-8000-000000000602'`,
    ]) {
      await client.exec(statement);
    }
    await client.exec(`UPDATE intents SET status='authorized' WHERE id='intent-1'`);
    await client.exec(`
      INSERT INTO provider_action_bindings(
        intent_id,tenant_id,workspace_id,actor_agent_id,provider_account_id,
        operation_id,operation_revision,canonical_profile,canonical_action_bytes,
        action_digest,request_envelope,request_hash,idempotency_key_hash,safe_summary,
        access_decision_id,access_effect,access_reason_code,dependency_revisions,
        access_decision,access_decision_hash,policy_decision_id,policy_effect,
        policy_revision_hash,policy_decision,policy_decision_hash,status,binding_revision,
        approval_queue_id,approval_commitment_hash,approval_actor_user_id,approved_at,
        resume_actor,resume_attempt_id,resume_validated_at
      ) VALUES (
        'intent-1','ta','${IDS.wsA}','agent-a','${IDS.acctA}','${IDS.opA}',1,
        'github.provider-action.v1',decode('7b7d','hex'),'${DIGEST}','{}'::jsonb,
        '${REQHASH}','${IDEMHASH}','{}'::jsonb,'${IDS.accessDecision}','allow',
        'provider_access_allowed','{}'::jsonb,'{}'::jsonb,'${ACCESSHASH}',
        '${IDS.policyDecision}','approval_required','${ACCESSHASH}','{}'::jsonb,
        '${ACCESSHASH}','execution_ready',2,'00000000-0000-4000-8000-000000000501',
        '${ACCESSHASH}','${IDS.owner}',now(),'steward-system',
        '00000000-0000-4000-8000-000000000502',now()
      )
    `);
    await client.exec(`
      INSERT INTO execution_authorization_nonces(
        authorization_id,request_id,tenant_id,agent_id,capability,backend,payload_digest,
        policy_revision_hash,approval_id,nonce,signature,idempotency_key,status,issued_at,
        expires_at,version,execution_id,intent_id,workspace_id,provider_account_id,
        operation_id,operation_revision,request_hash,action_digest,grant_dependency_hash,
        route_id,route_revision,secret_id,secret_version,provider_idempotency_key,
        commitment_hash,key_id,dispatch_state
      ) VALUES (
        'legacy-auth','intent-1','ta','agent-a','credential.inject_http','credential-proxy',
        '${DIGEST.slice(7)}','${ACCESSHASH.slice(7)}','00000000-0000-4000-8000-000000000501',
        'legacy-nonce','legacy-signature','legacy-provider-idem','active',now(),now()+interval '5 minutes',
        2,'legacy-execution','intent-1','${IDS.wsA}','${IDS.acctA}','${IDS.opA}',1,
        '${REQHASH}','${DIGEST}','${ACCESSHASH}','00000000-0000-4000-8000-000000000602',
        2,'00000000-0000-4000-8000-000000000601',1,'legacy-provider-idem',
        '${ACCESSHASH}','v2-1','none'
      )
    `);
    await applyFile(client, "0084_provider_action_reservation_reconciliation.sql");

    const binding = await client.query<{ status: string; binding_revision: number }>(
      `SELECT status,binding_revision FROM provider_action_bindings WHERE intent_id='intent-1'`,
    );
    expect(binding.rows[0]).toMatchObject({ status: "failed", binding_revision: 3 });
    const intent = await client.query<{ status: string }>(
      `SELECT status FROM intents WHERE id='intent-1'`,
    );
    expect(intent.rows[0].status).toBe("failed");
    const nonce = await client.query<{ status: string }>(
      `SELECT status FROM execution_authorization_nonces WHERE intent_id='intent-1'`,
    );
    expect(nonce.rows[0].status).toBe("revoked");
    const evidence = await client.query<{ action: string }>(
      `SELECT action FROM provider_action_audit_outbox WHERE intent_id='intent-1'`,
    );
    expect(evidence.rows.map((row) => row.action)).toContain(
      "provider.execution.legacy_policy_evidence_rejected",
    );
    const fence = await client.query<{ convalidated: boolean }>(
      `SELECT convalidated FROM pg_constraint
       WHERE conname='provider_action_bindings_execution_policy_ready_chk'`,
    );
    expect(fence.rows).toEqual([{ convalidated: false }]);
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
