/**
 * Migration 0082 schema-invariant tests. Mirrors
 * exact-approval-migration.test.ts: asserts the raw-SQL-only invariants that
 * drizzle-kit cannot express survive migration, so accidental removal fails CI.
 *
 *   - execution_authorization_nonces v2 columns + version/arm/dispatch CHECKs
 *   - the three partial-unique v2 indexes (intent, execution, provider idem)
 *   - the four v2 composite FKs
 *   - secret_routes.authority_mode enum + provider_operation_id + governed CHECK
 *   - the 0081 bump trigger EXTENDED to bump on authority_mode / operation change
 *
 * A single migrated PGLite instance is shared across the read-only cases; the
 * trigger-behavior case uses disposable rows.
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);

let client: PGlite;

// `createPGLiteDb` runs the FULL migration set (including 0082) on init, so we
// assert against the already-migrated schema — no manual re-apply (that would
// double-create the enums/tables). This mirrors the sibling migration tests.
describe("execution-authorization-v2 migration (0082)", () => {
  beforeAll(async () => {
    ({ client } = await createPGLiteDb("memory://"));
  });
  afterAll(async () => {
    await client.close();
  });

  test("execution_authorization_nonces carries the v2 columns", async () => {
    const cols = await client.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name='execution_authorization_nonces'
       AND column_name IN ('version','execution_id','intent_id','workspace_id',
         'provider_account_id','operation_id','operation_revision','request_hash',
         'action_digest','grant_dependency_hash','route_id','route_revision',
         'secret_id','secret_version','provider_idempotency_key','commitment_hash',
         'key_id','dispatch_state','dispatched_at','outcome_recorded_at')
       ORDER BY 1`,
    );
    expect(cols.rows.length).toBe(20);
  });

  test("version defaults to 1 and dispatch_state defaults to none", async () => {
    const col = await client.query<{ column_default: string | null }>(
      `SELECT column_default FROM information_schema.columns
       WHERE table_name='execution_authorization_nonces' AND column_name='version'`,
    );
    expect(col.rows[0].column_default).toContain("1");
    const ds = await client.query<{ column_default: string | null }>(
      `SELECT column_default FROM information_schema.columns
       WHERE table_name='execution_authorization_nonces' AND column_name='dispatch_state'`,
    );
    expect(ds.rows[0].column_default).toContain("none");
  });

  test("the v2 CHECK constraints exist", async () => {
    const cons = await client.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint
       WHERE conname IN ('exec_auth_nonces_version_chk','exec_auth_nonces_v2_arm_chk',
         'exec_auth_nonces_dispatch_state_chk','exec_auth_nonces_dispatch_shape_chk')
       ORDER BY 1`,
    );
    expect(cons.rows.map((r) => r.conname)).toEqual([
      "exec_auth_nonces_dispatch_shape_chk",
      "exec_auth_nonces_dispatch_state_chk",
      "exec_auth_nonces_v2_arm_chk",
      "exec_auth_nonces_version_chk",
    ]);
  });

  test("the three partial-unique v2 indexes exist", async () => {
    const idx = await client.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes
       WHERE indexname IN ('exec_auth_nonces_intent_uniq','exec_auth_nonces_execution_uniq',
         'exec_auth_nonces_provider_idem_uniq')
       ORDER BY 1`,
    );
    expect(idx.rows.map((r) => r.indexname)).toEqual([
      "exec_auth_nonces_execution_uniq",
      "exec_auth_nonces_intent_uniq",
      "exec_auth_nonces_provider_idem_uniq",
    ]);
  });

  test("the four v2 composite FKs exist", async () => {
    const fks = await client.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint
       WHERE conname IN ('exec_auth_nonces_intent_fk','exec_auth_nonces_operation_fk',
         'exec_auth_nonces_route_fk','exec_auth_nonces_secret_fk')
       AND contype='f' ORDER BY 1`,
    );
    expect(fks.rows.map((r) => r.conname)).toEqual([
      "exec_auth_nonces_intent_fk",
      "exec_auth_nonces_operation_fk",
      "exec_auth_nonces_route_fk",
      "exec_auth_nonces_secret_fk",
    ]);
  });

  test("secret_routes.authority_mode enum + provider_operation_id + governed CHECK", async () => {
    const cols = await client.query<{ column_name: string; data_type: string }>(
      `SELECT column_name, data_type FROM information_schema.columns
       WHERE table_name='secret_routes'
       AND column_name IN ('authority_mode','provider_operation_id') ORDER BY 1`,
    );
    expect(cols.rows.map((r) => r.column_name)).toEqual([
      "authority_mode",
      "provider_operation_id",
    ]);
    const en = await client.query<{ enumlabel: string }>(
      `SELECT enumlabel FROM pg_enum e JOIN pg_type t ON e.enumtypid=t.oid
       WHERE t.typname='secret_route_authority_mode' ORDER BY 1`,
    );
    expect(en.rows.map((r) => r.enumlabel)).toEqual(["governed_v2", "legacy"]);
    const chk = await client.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint
       WHERE conname IN ('secret_routes_governed_operation_chk','secret_routes_provider_operation_fk')
       ORDER BY 1`,
    );
    expect(chk.rows.map((r) => r.conname)).toEqual([
      "secret_routes_governed_operation_chk",
      "secret_routes_provider_operation_fk",
    ]);
  });

  test("version=1 rows insert with null v2 fields (legacy unaffected)", async () => {
    await client.exec(
      `INSERT INTO tenants(id,name,api_key_hash) VALUES ('t0082','T','h') ON CONFLICT DO NOTHING`,
    );
    await client.exec(
      `INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES ('ag0082','t0082','A','0xabc') ON CONFLICT DO NOTHING`,
    );
    await client.exec(
      `INSERT INTO execution_authorization_nonces
        (authorization_id, request_id, tenant_id, agent_id, capability, backend,
         payload_digest, nonce, signature, issued_at, expires_at)
        VALUES ('auth-v1-0082','req','t0082','ag0082','wallet.sign_transaction',
         'local-vault','deadbeef','nonce-v1-0082','sig', now(), now())`,
    );
    const row = await client.query<{ version: number; dispatch_state: string }>(
      `SELECT version, dispatch_state FROM execution_authorization_nonces
       WHERE authorization_id='auth-v1-0082'`,
    );
    expect(Number(row.rows[0].version)).toBe(1);
    expect(row.rows[0].dispatch_state).toBe("none");
  });

  test("the arm CHECK rejects a version=2 row missing v2 fields", async () => {
    let threw = false;
    try {
      await client.exec(
        `INSERT INTO execution_authorization_nonces
          (authorization_id, request_id, tenant_id, agent_id, capability, backend,
           payload_digest, nonce, signature, issued_at, expires_at, version)
          VALUES ('auth-bad-v2','req','t0082','ag0082','credential.inject_http',
           'credential-proxy','deadbeef','nonce-bad-v2','sig', now(), now(), 2)`,
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  test("the dispatch_shape CHECK rejects dispatched with null dispatched_at", async () => {
    // A version=1 row with dispatch_state='dispatched' but no dispatched_at must
    // fail the shape CHECK (the shape CHECK is version-independent).
    let threw = false;
    try {
      await client.exec(
        `UPDATE execution_authorization_nonces SET dispatch_state='dispatched'
         WHERE authorization_id='auth-v1-0082'`,
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  test("the bump trigger now bumps on authority_mode / provider_operation_id change", async () => {
    // Seed a legacy route, an operation to point at, then flip to governed_v2.
    for (const stmt of [
      `INSERT INTO users(id) VALUES ('00000000-0000-4000-8000-0000000000f1') ON CONFLICT DO NOTHING`,
      `INSERT INTO workspaces(id,tenant_id,key,name,environment,status,created_by)
        VALUES ('00000000-0000-4000-8000-0000000000c1','t0082','wsk','WS','production','active','00000000-0000-4000-8000-0000000000f1')
        ON CONFLICT DO NOTHING`,
      `INSERT INTO secrets(id,tenant_id,name,ciphertext,iv,auth_tag,salt,version)
        VALUES ('00000000-0000-4000-8000-0000000000a2','t0082','s2','x','x','x','x',1)
        ON CONFLICT DO NOTHING`,
      `INSERT INTO provider_accounts(id,tenant_id,workspace_id,adapter_key,external_ref,display_name,status,credential_secret_id,credential_version)
        VALUES ('00000000-0000-4000-8000-0000000000d1','t0082','00000000-0000-4000-8000-0000000000c1','github','ext','acct','active','00000000-0000-4000-8000-0000000000a2',1)
        ON CONFLICT DO NOTHING`,
      `INSERT INTO secret_routes(id,tenant_id,secret_id,host_pattern,inject_as,inject_key)
        VALUES ('00000000-0000-4000-8000-0000000000b2','t0082','00000000-0000-4000-8000-0000000000a2','api.github.com','header','authorization')
        ON CONFLICT DO NOTHING`,
      `INSERT INTO provider_operations(id,tenant_id,workspace_id,provider_account_id,operation_key,risk_class,secret_route_id,request_profile,status,revision)
        VALUES ('00000000-0000-4000-8000-0000000000e1','t0082','00000000-0000-4000-8000-0000000000c1','00000000-0000-4000-8000-0000000000d1','github.issue.list','read','00000000-0000-4000-8000-0000000000b2','{}'::jsonb,'active',1)
        ON CONFLICT DO NOTHING`,
    ]) {
      await client.exec(stmt);
    }
    await client.exec(
      `UPDATE secret_routes SET authority_mode='governed_v2',
         provider_operation_id='00000000-0000-4000-8000-0000000000e1'
       WHERE id='00000000-0000-4000-8000-0000000000b2'`,
    );
    const rev = await client.query<{ authority_revision: number; authority_mode: string }>(
      `SELECT authority_revision, authority_mode FROM secret_routes
       WHERE id='00000000-0000-4000-8000-0000000000b2'`,
    );
    expect(rev.rows[0].authority_mode).toBe("governed_v2");
    expect(Number(rev.rows[0].authority_revision)).toBe(2);
  });

  test("the governed CHECK rejects governed_v2 without an operation", async () => {
    let threw = false;
    try {
      await client.exec(
        `INSERT INTO secret_routes(id,tenant_id,secret_id,host_pattern,inject_as,inject_key,authority_mode)
          VALUES ('00000000-0000-4000-8000-0000000000b9','t0082','00000000-0000-4000-8000-0000000000a2','api.github.com','header','authorization','governed_v2')`,
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});
