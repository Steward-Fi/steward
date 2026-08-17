/**
 * #201 generic-http profile migration (0085).
 *
 * Applies the full migration chain into an in-memory PGlite database and proves
 * the widened `provider_action_bindings_profile_chk`:
 *   - ADMITS a binding with canonical_profile = 'generic-http.provider-action.v1'
 *     (the new profile can persist through the identical pipeline);
 *   - STILL ADMITS the pre-existing github + x profiles (no regression);
 *   - STILL REJECTS an unknown profile via the SAME named CHECK (exact allowlist
 *     extension, not a blanket relaxation).
 *
 * This is the storage-layer backstop; the code-side profile registry rejects an
 * unregistered profile earlier and fail-closed at every consumption site.
 */

import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { REGISTERED_PROFILES } from "@stwd/shared";

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
  wsA: "00000000-0000-4000-8000-000000000901",
  acctA: "00000000-0000-4000-8000-000000000902",
  opA: "00000000-0000-4000-8000-000000000903",
  owner: "00000000-0000-4000-8000-000000000904",
  accessDecision: "00000000-0000-4000-8000-000000000905",
  policyDecision: "00000000-0000-4000-8000-000000000906",
};

const DIGEST = "sha256:effa84639ed9c9b0b2c01b65bd716342a25a846d9209818b194ab3d151276f3a";
const REQHASH = "sha256:8c0d3d5761ad6ad8ea017d3d36bd57157a7d2f5767acce8ede417d4556b377e3";
const IDEMHASH = "sha256:36c27d7668cf64a4354635a421f14d74410e9cd54bf1002bffa82421145c7a57";
const HASH = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

async function seed(client: PGlite) {
  const stmts = [
    `INSERT INTO tenants(id,name,api_key_hash) VALUES ('t201','A','h201')`,
    `INSERT INTO users(id,email,created_at,updated_at) VALUES ('${IDS.owner}','o201@example.test',now(),now())`,
    `INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES ('agent-201','t201','A','0xa201')`,
    `INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES ('${IDS.wsA}','t201','client-201','Client 201','production','${IDS.owner}')`,
    `INSERT INTO provider_accounts(id,tenant_id,workspace_id,adapter_key,external_ref,display_name) VALUES ('${IDS.acctA}','t201','${IDS.wsA}','generic-http','a201','A')`,
    `INSERT INTO provider_operations(id,tenant_id,workspace_id,provider_account_id,operation_key,risk_class) VALUES ('${IDS.opA}','t201','${IDS.wsA}','${IDS.acctA}','acme.item.list','read')`,
    `INSERT INTO intents(id,tenant_id,agent_id,intent_type,status) VALUES ('intent-201','t201','agent-201','provider.action','pending')`,
  ];
  for (const s of stmts) await client.exec(`${s};`);
}

function bindingInsert(profile: string): string {
  return `
    INSERT INTO provider_action_bindings(
      intent_id, tenant_id, workspace_id, actor_agent_id, provider_account_id,
      operation_id, operation_revision, canonical_profile, canonical_action_bytes,
      action_digest, request_envelope, request_hash, idempotency_key_hash, safe_summary,
      access_decision_id, access_effect, access_reason_code, dependency_revisions,
      access_decision, access_decision_hash,
      policy_decision_id, policy_effect, policy_revision_hash, policy_decision, policy_decision_hash,
      status
    ) VALUES (
      'intent-201','t201','${IDS.wsA}','agent-201','${IDS.acctA}',
      '${IDS.opA}',7,'${profile}', decode('7b7d','hex'),
      '${DIGEST}','{}'::jsonb,'${REQHASH}','${IDEMHASH}','{}'::jsonb,
      '${IDS.accessDecision}','allow','provider_access_allowed','{}'::jsonb,
      '{}'::jsonb,'${HASH}',
      '${IDS.policyDecision}','allow','${HASH}','{}'::jsonb,'${HASH}',
      'allowed_stub'
    );
  `;
}

describe("#201 generic-http profile migration (0085)", () => {
  test("profile CHECK is present and named", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    const con = await client.query<{ conname: string; def: string }>(
      `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
       WHERE conname = 'provider_action_bindings_profile_chk'`,
    );
    expect(con.rows).toHaveLength(1);
    const storedProfiles = [...con.rows[0].def.matchAll(/'([^']+\.provider-action\.v1)'/g)]
      .map((match) => match[1])
      .sort();
    expect(storedProfiles).toEqual([...REGISTERED_PROFILES].sort());
    await client.close();
  });

  test("admits a generic-http binding", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    await client.exec(bindingInsert("generic-http.provider-action.v1"));
    const rows = await client.query(
      `SELECT canonical_profile FROM provider_action_bindings WHERE intent_id='intent-201'`,
    );
    expect(rows.rows).toHaveLength(1);
    await client.close();
  });

  test("admits and reloads every registered profile (registry-driven)", async () => {
    for (const profile of REGISTERED_PROFILES) {
      const client = new PGlite("memory://");
      await applyAll(client);
      await seed(client);
      await client.exec(bindingInsert(profile));
      const rows = await client.query<{ canonical_profile: string; action: string }>(
        `SELECT canonical_profile, encode(canonical_action_bytes, 'hex') AS action
         FROM provider_action_bindings WHERE intent_id='intent-201'`,
      );
      expect(rows.rows).toHaveLength(1);
      expect(rows.rows[0]).toEqual({ canonical_profile: profile, action: "7b7d" });
      await client.close();
    }
  });

  test("still rejects an unknown profile via the same CHECK", async () => {
    const client = new PGlite("memory://");
    await applyAll(client);
    await seed(client);
    let threw = false;
    try {
      await client.exec(bindingInsert("evil.provider-action.v1"));
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    await client.close();
  });
});
