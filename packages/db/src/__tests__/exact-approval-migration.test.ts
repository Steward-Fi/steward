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
import type { PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);

let client: PGlite;

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
