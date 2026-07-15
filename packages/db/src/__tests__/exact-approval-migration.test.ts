/**
 * PR3 migration 0081 schema-invariant tests. Mirrors
 * provider-authority-migration.test.ts: asserts the raw-SQL-only invariants that
 * drizzle-kit cannot express survive migration, so accidental removal fails CI.
 *
 *   - secret_routes.authority_revision column + bump trigger (G1 adjudication)
 *   - the PR3 provider_action_bindings transition trigger (replaces the PR2
 *     immutability trigger)
 *   - the approval_queue provider-action arm CHECK + decision-shape CHECK
 *
 * A single migrated PGLite instance is shared across the cases (fresh WASM
 * instances per case race the pglite WASM runtime under bun's parallel test
 * execution). The schema is read-only for all but the trigger-behavior case,
 * which uses disposable rows.
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);

let client: PGlite;

const migrationsDir = new URL("../../drizzle", import.meta.url).pathname;
const MIG_0081 = "0081_exact_approval_binding.sql";

async function applyFile(c: PGlite, file: string) {
  const sql = await readFile(join(migrationsDir, file), "utf8");
  for (const stmt of sql.split("--> statement-breakpoint")) {
    if (stmt.trim()) await c.exec(stmt);
  }
}

async function applyThrough(c: PGlite, upToExclusive: string) {
  const files = (await readdir(migrationsDir))
    .filter((f) => f.endsWith(".sql") && f < upToExclusive)
    .sort();
  for (const f of files) await applyFile(c, f);
}

describe("PR3 exact-approval migration (0081)", () => {
  beforeAll(async () => {
    ({ client } = await createPGLiteDb("memory://"));
  });
  afterAll(async () => {
    await client.close();
  });

  test("secret_routes.authority_revision exists with the bump trigger (G1)", async () => {
    const col = await client.query<{ column_name: string; is_nullable: string }>(
      `SELECT column_name, is_nullable FROM information_schema.columns
       WHERE table_name='secret_routes' AND column_name='authority_revision'`,
    );
    expect(col.rows.length).toBe(1);
    expect(col.rows[0].is_nullable).toBe("NO");

    const trg = await client.query<{ tgname: string }>(
      `SELECT tgname FROM pg_trigger WHERE NOT tgisinternal
       AND tgname='secret_routes_bump_authority_revision'`,
    );
    expect(trg.rows.map((r) => r.tgname)).toEqual(["secret_routes_bump_authority_revision"]);

    const fn = await client.query<{ p: string | null }>(
      `SELECT to_regprocedure('steward_bump_secret_route_authority_revision()')::text AS p`,
    );
    expect(fn.rows[0].p).toBe("steward_bump_secret_route_authority_revision()");
  });

  test("the authority_revision bump trigger increments on a bound-field change", async () => {
    await client.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('t','T','h');
      INSERT INTO secrets(id,tenant_id,name,ciphertext,iv,auth_tag,salt,version)
        VALUES ('00000000-0000-4000-8000-0000000000a1','t','s','x','x','x','x',1);
      INSERT INTO secret_routes(id,tenant_id,secret_id,host_pattern,inject_as,inject_key)
        VALUES ('00000000-0000-4000-8000-0000000000b1','t','00000000-0000-4000-8000-0000000000a1','api.github.com','header','authorization');
    `);
    await client.exec(
      `UPDATE secret_routes SET path_pattern='/changed' WHERE id='00000000-0000-4000-8000-0000000000b1'`,
    );
    let rev = await client.query<{ authority_revision: number }>(
      `SELECT authority_revision FROM secret_routes WHERE id='00000000-0000-4000-8000-0000000000b1'`,
    );
    expect(Number(rev.rows[0].authority_revision)).toBe(2);
    // A non-bound field change (priority) does NOT bump.
    await client.exec(
      `UPDATE secret_routes SET priority=5 WHERE id='00000000-0000-4000-8000-0000000000b1'`,
    );
    rev = await client.query<{ authority_revision: number }>(
      `SELECT authority_revision FROM secret_routes WHERE id='00000000-0000-4000-8000-0000000000b1'`,
    );
    expect(Number(rev.rows[0].authority_revision)).toBe(2);
  });

  test("the PR3 provider_action_bindings transition trigger replaces the PR2 one", async () => {
    const trg = await client.query<{ tgname: string }>(
      `SELECT tgname FROM pg_trigger WHERE NOT tgisinternal
       AND tgname='provider_action_bindings_immutable'`,
    );
    expect(trg.rows.map((r) => r.tgname)).toEqual(["provider_action_bindings_immutable"]);
    const fn = await client.query<{ p: string | null }>(
      `SELECT to_regprocedure('steward_provider_action_binding_guard()')::text AS p`,
    );
    expect(fn.rows[0].p).toBe("steward_provider_action_binding_guard()");
  });

  test("approval_queue carries the provider-action arm columns + constraints", async () => {
    const cols = await client.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name='approval_queue'
       AND column_name IN ('approval_kind','intent_id','approval_commitment_hash','expected_binding_revision','consumed_by')
       ORDER BY 1`,
    );
    expect(cols.rows.map((r) => r.column_name)).toEqual([
      "approval_commitment_hash",
      "approval_kind",
      "consumed_by",
      "expected_binding_revision",
      "intent_id",
    ]);
    const chk = await client.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint
       WHERE conname IN ('approval_queue_arm_chk','approval_queue_decision_shape_chk')
       ORDER BY 1`,
    );
    expect(chk.rows.map((r) => r.conname)).toEqual([
      "approval_queue_arm_chk",
      "approval_queue_decision_shape_chk",
    ]);
    const txcol = await client.query<{ is_nullable: string }>(
      `SELECT is_nullable FROM information_schema.columns
       WHERE table_name='approval_queue' AND column_name='tx_id'`,
    );
    expect(txcol.rows[0].is_nullable).toBe("YES");
  });

  test("backfill: a legacy PR2 pending_approval binding migrates to approval_stale without failing the shape CHECK (P1 codex)", async () => {
    // Build the pre-0081 schema, insert a pending_approval binding (as PR2 would
    // leave it), THEN apply 0081 and assert the migration succeeds + reclassifies.
    const c = new PGlite("memory://");
    await applyThrough(c, MIG_0081);
    await c.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('t','T','h');
      INSERT INTO users(id,email,created_at,updated_at) VALUES
        ('00000000-0000-4000-8000-000000000001','o@e.test',now(),now());
      INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES ('ag','t','A','0x1');
      INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES
        ('00000000-0000-4000-8000-000000000101','t','w','W','production','00000000-0000-4000-8000-000000000001');
      INSERT INTO provider_accounts(id,tenant_id,workspace_id,adapter_key,external_ref,display_name) VALUES
        ('00000000-0000-4000-8000-000000000201','t','00000000-0000-4000-8000-000000000101','github','a','A');
      INSERT INTO provider_operations(id,tenant_id,workspace_id,provider_account_id,operation_key,risk_class) VALUES
        ('00000000-0000-4000-8000-000000000301','t','00000000-0000-4000-8000-000000000101','00000000-0000-4000-8000-000000000201','github.pr.comment.create','consequential');
      INSERT INTO intents(id,tenant_id,agent_id,intent_type,status,resource_type,resource_id,created_by_type,created_by_id)
        VALUES ('pa_legacy','t','ag','provider-action','pending','provider-action','x','agent','ag');
      INSERT INTO provider_action_bindings(
        intent_id,tenant_id,workspace_id,actor_agent_id,provider_account_id,operation_id,operation_revision,
        canonical_profile,canonical_action_bytes,action_digest,request_envelope,request_hash,idempotency_key_hash,
        safe_summary,access_decision_id,access_effect,access_reason_code,dependency_revisions,access_decision,
        access_decision_hash,policy_decision_id,policy_effect,policy_revision_hash,policy_decision,policy_decision_hash,status)
      VALUES (
        'pa_legacy','t','00000000-0000-4000-8000-000000000101','ag','00000000-0000-4000-8000-000000000201',
        '00000000-0000-4000-8000-000000000301',1,'github.provider-action.v1',decode('7b7d','hex'),
        'sha256:${"a".repeat(64)}','{}'::jsonb,'sha256:${"b".repeat(64)}','sha256:${"c".repeat(64)}','{}'::jsonb,
        '00000000-0000-4000-8000-000000000401','allow','ok','{}'::jsonb,'{}'::jsonb,'sha256:${"d".repeat(64)}',
        '00000000-0000-4000-8000-000000000501','approval_required','sha256:${"e".repeat(64)}','{}'::jsonb,
        'sha256:${"f".repeat(64)}','pending_approval');
    `);
    // Apply 0081 — must NOT fail on the shape CHECK.
    await applyFile(c, MIG_0081);
    const b = await c.query<{ status: string; stale_reason_code: string | null }>(
      `SELECT status, stale_reason_code FROM provider_action_bindings WHERE intent_id='pa_legacy'`,
    );
    expect(b.rows[0].status).toBe("approval_stale");
    expect(b.rows[0].stale_reason_code).toBe("APPROVAL_MIGRATED_PR3");
    const i = await c.query<{ status: string }>(`SELECT status FROM intents WHERE id='pa_legacy'`);
    expect(i.rows[0].status).toBe("canceled");
    await c.close();
  });

  test("the enum carries the PR3 provider lifecycle statuses", async () => {
    const vals = await client.query<{ enumlabel: string }>(
      `SELECT enumlabel FROM pg_enum e
       JOIN pg_type t ON t.oid = e.enumtypid
       WHERE t.typname = 'approval_queue_status' ORDER BY enumlabel`,
    );
    const labels = vals.rows.map((r) => r.enumlabel);
    for (const s of ["expired", "stale", "consumed"]) {
      expect(labels).toContain(s);
    }
  });
});
