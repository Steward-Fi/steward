/**
 * PGLite adapter tests.
 *
 * Verifies that the PGLite adapter:
 *   1. Initializes and runs all migrations
 *   2. Supports basic CRUD via Drizzle (tenants, agents, policies)
 *   3. Persists data across close/reopen cycles
 */

import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";

import { createPGLiteDb } from "../pglite";
import { agents, encryptedKeys, policies, policyTypeEnum, tenants, transactions } from "../schema";

setDefaultTimeout(120000);

// Shared temp dir for persistence tests
let tempDir: string;

async function freshDb(dir?: string) {
  return createPGLiteDb(dir ?? "memory://");
}

function readCountRow(rows: unknown[]): number {
  const firstRow = rows[0];
  if (!firstRow || typeof firstRow !== "object" || !("cnt" in firstRow)) {
    throw new Error("Expected count row");
  }

  return Number(firstRow.cnt);
}

function readStringRows(rows: unknown[], key: string): string[] {
  return rows
    .map((row) => {
      if (!row || typeof row !== "object" || !(key in row)) {
        throw new Error(`Expected ${key} row`);
      }
      return String(row[key as keyof typeof row]);
    })
    .sort();
}

describe("PGLite Adapter", () => {
  afterAll(async () => {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  // ─── Initialization & Migrations ──────────────────────────────────────

  test("initializes in-memory and runs migrations", async () => {
    const { db, client } = await freshDb();

    // Check that core tables exist by querying them
    const tenantRows = await db.select().from(tenants);
    expect(tenantRows).toEqual([]);

    const agentRows = await db.select().from(agents);
    expect(agentRows).toEqual([]);

    const policyRows = await db.select().from(policies);
    expect(policyRows).toEqual([]);

    await client.close();
  });

  test("migration tracking table exists", async () => {
    const { client } = await freshDb();

    const result = await client.query("SELECT tag FROM __steward_migrations ORDER BY tag");
    expect(result.rows.length).toBeGreaterThan(0);
    // Should have at least the initial migration
    const tags = result.rows.map((r: any) => r.tag);
    expect(tags).toContain("0000_black_klaw");

    await client.close();
  });

  test("migrations create ERC-8004 and policy template tables", async () => {
    const { client } = await freshDb();
    const expectedTables = [
      "agent_registrations",
      "reputation_cache",
      "registry_index",
      "policy_templates",
    ];

    const result = await client.query<{ table_name: string }>(
      `SELECT table_name
       FROM information_schema.tables
       WHERE table_schema = 'public'
         AND table_name IN (
           'agent_registrations',
           'reputation_cache',
           'registry_index',
           'policy_templates'
         )
       ORDER BY table_name`,
    );

    expect(result.rows.map((row) => row.table_name).sort()).toEqual(expectedTables.sort());

    await client.close();
  });

  test("migrations match Drizzle schema for Privy-parity auth and app tables", async () => {
    const { client } = await freshDb();

    const tableResult = await client.query<{ table_name: string }>(
      `SELECT table_name
       FROM information_schema.tables
       WHERE table_schema = 'public'
         AND table_name IN (
           'tenant_app_clients',
           'tenant_app_client_secrets',
           'tenant_request_signing_keys',
           'tenant_invitations',
           'user_push_subscriptions',
           'user_wallet_app_consents',
           'global_wallet_action_confirmations'
         )
       ORDER BY table_name`,
    );
    expect(readStringRows(tableResult.rows, "table_name")).toEqual([
      "global_wallet_action_confirmations",
      "tenant_app_client_secrets",
      "tenant_app_clients",
      "tenant_invitations",
      "tenant_request_signing_keys",
      "user_push_subscriptions",
      "user_wallet_app_consents",
    ]);

    const columnResult = await client.query<{ table_name: string; column_name: string }>(
      `SELECT table_name, column_name
       FROM information_schema.columns
       WHERE table_schema = 'public'
         AND (
           (table_name = 'tenant_app_clients' AND column_name IN (
             'id', 'tenant_id', 'allowed_origins', 'allowed_redirect_urls',
             'login_methods', 'global_wallet_enabled', 'global_wallet_allowed_scopes'
           ))
           OR (table_name = 'tenant_app_client_secrets' AND column_name IN (
             'tenant_id', 'client_id', 'secret_hash', 'secret_prefix', 'status',
             'expires_at', 'revoked_at'
           ))
           OR (table_name = 'tenant_request_signing_keys' AND column_name IN (
             'tenant_id', 'name', 'secret_ciphertext', 'secret_iv', 'secret_auth_tag',
             'secret_salt', 'secret_prefix', 'status', 'expires_at', 'revoked_at'
           ))
           OR (table_name = 'tenant_invitations' AND column_name IN (
             'tenant_id', 'email', 'role', 'token_hash', 'status', 'invited_by_user_id',
             'accepted_by_user_id', 'accepted_at', 'revoked_at', 'expires_at'
           ))
           OR (table_name = 'users' AND column_name IN ('is_guest', 'guest_expires_at'))
           OR (table_name = 'user_push_subscriptions' AND column_name IN (
             'user_id', 'tenant_id', 'provider', 'token', 'platform', 'device_id',
             'app_id', 'locale', 'timezone', 'metadata', 'status', 'last_seen_at',
             'revoked_at'
           ))
           OR (table_name = 'user_wallet_app_consents' AND column_name IN (
             'tenant_id', 'client_id', 'user_id', 'wallet_agent_id', 'wallet_address',
             'origin', 'redirect_uri', 'scopes', 'status', 'granted_at', 'last_used_at',
             'expires_at', 'revoked_at'
           ))
           OR (table_name = 'global_wallet_action_confirmations' AND column_name IN (
             'consent_id', 'tenant_id', 'client_id', 'user_id', 'origin', 'method',
             'request_hash', 'status', 'expires_at', 'approved_at', 'consumed_at'
           ))
         )
       ORDER BY table_name, column_name`,
    );
    const columns = new Set(columnResult.rows.map((row) => `${row.table_name}.${row.column_name}`));
    for (const expected of [
      "tenant_app_clients.global_wallet_enabled",
      "tenant_app_clients.global_wallet_allowed_scopes",
      "tenant_app_client_secrets.secret_hash",
      "tenant_request_signing_keys.secret_ciphertext",
      "tenant_invitations.accepted_by_user_id",
      "users.is_guest",
      "users.guest_expires_at",
      "user_push_subscriptions.revoked_at",
      "user_wallet_app_consents.scopes",
      "global_wallet_action_confirmations.request_hash",
    ]) {
      expect(columns.has(expected)).toBe(true);
    }

    const constraintResult = await client.query<{ conname: string }>(
      `SELECT conname
       FROM pg_constraint
       WHERE conname IN (
         'tenant_app_client_secrets_client_fk',
         'user_wallet_app_consents_app_client_fk',
         'tenant_invitations_status_check',
         'tenant_invitations_role_check',
         'tenant_invitations_terminal_state_check',
         'user_push_subscriptions_provider_check',
         'user_push_subscriptions_platform_check',
         'user_push_subscriptions_status_check',
         'user_push_subscriptions_revoked_state_check'
       )
       ORDER BY conname`,
    );
    expect(readStringRows(constraintResult.rows, "conname")).toEqual([
      "tenant_app_client_secrets_client_fk",
      "tenant_invitations_role_check",
      "tenant_invitations_status_check",
      "tenant_invitations_terminal_state_check",
      "user_push_subscriptions_platform_check",
      "user_push_subscriptions_provider_check",
      "user_push_subscriptions_revoked_state_check",
      "user_push_subscriptions_status_check",
      "user_wallet_app_consents_app_client_fk",
    ]);

    const indexResult = await client.query<{ indexname: string }>(
      `SELECT indexname
       FROM pg_indexes
       WHERE schemaname = 'public'
         AND indexname IN (
           'tenant_app_clients_tenant_id_id_idx',
           'tenant_app_client_secrets_tenant_client_idx',
           'tenant_request_signing_keys_tenant_status_idx',
           'tenant_invitations_pending_email_idx',
           'users_guest_expires_at_idx',
           'user_push_subscriptions_active_token_idx',
           'user_wallet_app_consents_active_unique_idx',
           'global_wallet_action_confirmations_user_status_idx'
         )
       ORDER BY indexname`,
    );
    expect(readStringRows(indexResult.rows, "indexname")).toEqual([
      "global_wallet_action_confirmations_user_status_idx",
      "tenant_app_client_secrets_tenant_client_idx",
      "tenant_app_clients_tenant_id_id_idx",
      "tenant_invitations_pending_email_idx",
      "tenant_request_signing_keys_tenant_status_idx",
      "user_push_subscriptions_active_token_idx",
      "user_wallet_app_consents_active_unique_idx",
      "users_guest_expires_at_idx",
    ]);

    await client.close();
  });

  test("migrations include all policy enum values modeled by Drizzle schema", async () => {
    const { client } = await freshDb();

    const result = await client.query<{ enumlabel: string }>(
      `SELECT enumlabel
       FROM pg_enum
       WHERE enumtypid = 'policy_type'::regtype
       ORDER BY enumlabel`,
    );

    expect(readStringRows(result.rows, "enumlabel")).toEqual([...policyTypeEnum.enumValues].sort());

    await client.close();
  });

  // ─── Basic CRUD ────────────────────────────────────────────────────────

  test("create and read tenant", async () => {
    const { db, client } = await freshDb();

    await db.insert(tenants).values({
      id: "test-tenant-1",
      name: "Test Tenant",
      apiKeyHash: "hash123",
    });

    const rows = await db.select().from(tenants).where(eq(tenants.id, "test-tenant-1"));

    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe("Test Tenant");
    expect(rows[0].apiKeyHash).toBe("hash123");

    await client.close();
  });

  test("create agent with tenant FK", async () => {
    const { db, client } = await freshDb();

    // Create tenant first
    await db.insert(tenants).values({
      id: "t1",
      name: "Tenant",
      apiKeyHash: "h",
    });

    // Create agent
    await db.insert(agents).values({
      id: "agent-1",
      tenantId: "t1",
      name: "Test Agent",
      walletAddress: "0x1234567890abcdef",
    });

    const rows = await db.select().from(agents).where(eq(agents.id, "agent-1"));

    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe("Test Agent");
    expect(rows[0].tenantId).toBe("t1");
    expect(rows[0].walletAddress).toBe("0x1234567890abcdef");

    await client.close();
  });

  test("create and query policies", async () => {
    const { db, client } = await freshDb();

    await db.insert(tenants).values({ id: "t1", name: "T", apiKeyHash: "h" });
    await db.insert(agents).values({
      id: "a1",
      tenantId: "t1",
      name: "Agent",
      walletAddress: "0xabc",
    });

    await db.insert(policies).values({
      id: "pol-1",
      agentId: "a1",
      type: "spending-limit",
      enabled: true,
      config: { maxAmount: "1000", period: "daily" },
    });

    const rows = await db.select().from(policies).where(eq(policies.agentId, "a1"));

    expect(rows).toHaveLength(1);
    expect(rows[0].type).toBe("spending-limit");
    expect(rows[0].config).toEqual({ maxAmount: "1000", period: "daily" });

    await client.close();
  });

  test("create transaction and update status", async () => {
    const { db, client } = await freshDb();

    await db.insert(tenants).values({ id: "t1", name: "T", apiKeyHash: "h" });
    await db.insert(agents).values({
      id: "a1",
      tenantId: "t1",
      name: "Agent",
      walletAddress: "0xabc",
    });

    await db.insert(transactions).values({
      id: "tx-1",
      agentId: "a1",
      status: "pending",
      toAddress: "0xdef",
      value: "1000000",
      chainId: 1,
    });

    // Update status
    await db.update(transactions).set({ status: "approved" }).where(eq(transactions.id, "tx-1"));

    const rows = await db.select().from(transactions).where(eq(transactions.id, "tx-1"));

    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("approved");

    await client.close();
  });

  test("encrypted keys CRUD", async () => {
    const { db, client } = await freshDb();

    await db.insert(tenants).values({ id: "t1", name: "T", apiKeyHash: "h" });
    await db.insert(agents).values({
      id: "a1",
      tenantId: "t1",
      name: "Agent",
      walletAddress: "0xabc",
    });

    await db.insert(encryptedKeys).values({
      agentId: "a1",
      ciphertext: "encrypted_data",
      iv: "init_vector",
      tag: "auth_tag",
      salt: "salt_value",
    });

    const rows = await db.select().from(encryptedKeys).where(eq(encryptedKeys.agentId, "a1"));

    expect(rows).toHaveLength(1);
    expect(rows[0].ciphertext).toBe("encrypted_data");

    await client.close();
  });

  // ─── Persistence ───────────────────────────────────────────────────────

  test("data persists across close/reopen", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "steward-pglite-test-"));

    // First session: write data
    {
      const { db, client } = await createPGLiteDb(tempDir);

      await db.insert(tenants).values({
        id: "persist-tenant",
        name: "Persistent Tenant",
        apiKeyHash: "persist-hash",
      });

      await db.insert(agents).values({
        id: "persist-agent",
        tenantId: "persist-tenant",
        name: "Persistent Agent",
        walletAddress: "0xpersist",
      });

      await client.close();
    }

    // Second session: read data back
    {
      const { db, client } = await createPGLiteDb(tempDir);

      const tenantRows = await db.select().from(tenants).where(eq(tenants.id, "persist-tenant"));

      expect(tenantRows).toHaveLength(1);
      expect(tenantRows[0].name).toBe("Persistent Tenant");

      const agentRows = await db.select().from(agents).where(eq(agents.id, "persist-agent"));

      expect(agentRows).toHaveLength(1);
      expect(agentRows[0].name).toBe("Persistent Agent");

      await client.close();
    }
  });

  test("migrations don't re-run on persistent DB", async () => {
    const dir = await mkdtemp(join(tmpdir(), "steward-pglite-mig-"));

    // First init
    const { client: c1 } = await createPGLiteDb(dir);
    const r1 = await c1.query("SELECT COUNT(*) as cnt FROM __steward_migrations");
    const count1 = readCountRow(r1.rows);
    await c1.close();

    // Second init — same dir
    const { client: c2 } = await createPGLiteDb(dir);
    const r2 = await c2.query("SELECT COUNT(*) as cnt FROM __steward_migrations");
    const count2 = readCountRow(r2.rows);
    await c2.close();

    // Same number of migrations applied
    expect(count2).toBe(count1);

    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("security invariants reject cross-tenant agent ownership rows", async () => {
    const { client } = await freshDb();

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('tenant-a', 'Tenant A', 'hash-a'), ('tenant-b', 'Tenant B', 'hash-b')
    `);
    await client.query(`
      INSERT INTO agents (id, tenant_id, name, wallet_address)
      VALUES ('agent-a', 'tenant-a', 'Agent A', '0xa'), ('agent-b', 'tenant-b', 'Agent B', '0xb')
    `);

    await expect(
      client.query(`
        INSERT INTO agent_signers (
          tenant_id, agent_id, signer_type, subject_type, subject_id, permissions
        ) VALUES (
          'tenant-a', 'agent-b', 'service', 'user', 'user-a', ARRAY[]::text[]
        )
      `),
    ).rejects.toThrow();
    await expect(
      client.query(`
        INSERT INTO agent_key_quorums (
          tenant_id, agent_id, name, threshold, member_signer_ids, permissions
        ) VALUES (
          'tenant-a', 'agent-b', 'bad quorum', 1, ARRAY[]::text[], ARRAY[]::text[]
        )
      `),
    ).rejects.toThrow();
    await expect(
      client.query(`
        INSERT INTO intents (id, tenant_id, agent_id, intent_type)
        VALUES ('intent-bad', 'tenant-a', 'agent-b', 'vault.sign')
      `),
    ).rejects.toThrow();

    await client.close();
  });

  test("security invariants enforce unique tenant API key hashes", async () => {
    const { client } = await freshDb();

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('tenant-a', 'Tenant A', 'shared-hash')
    `);

    await expect(
      client.query(`
        INSERT INTO tenants (id, name, api_key_hash)
        VALUES ('tenant-b', 'Tenant B', 'shared-hash')
      `),
    ).rejects.toThrow();

    await client.close();
  });

  test("security invariants enforce canonical verified SSO domain ownership", async () => {
    const { client } = await freshDb();

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('tenant-a', 'Tenant A', 'hash-a'), ('tenant-b', 'Tenant B', 'hash-b')
    `);
    await client.query(`
      INSERT INTO tenant_sso_domains (
        tenant_id, domain, verification_token, status, verified_at
      ) VALUES (
        'tenant-a', 'example.com', 'token-a', 'verified', now()
      )
    `);
    await client.query(`
      INSERT INTO tenant_sso_domains (
        tenant_id, domain, verification_token, status
      ) VALUES (
        'tenant-b', 'Example.com.', 'token-b', 'pending'
      )
    `);

    await expect(
      client.query(`
        UPDATE tenant_sso_domains
        SET status = 'verified', verified_at = now()
        WHERE tenant_id = 'tenant-b'
      `),
    ).rejects.toThrow();
    await expect(
      client.query(`
        INSERT INTO tenant_sso_domains (
          tenant_id, domain, verification_token, status
        ) VALUES (
          'tenant-a', 'EXAMPLE.com.', 'token-c', 'pending'
        )
      `),
    ).rejects.toThrow();

    await client.close();
  });

  test("security invariants enforce refresh token uniqueness and ownership FKs", async () => {
    const { client } = await freshDb();
    const userId = "11111111-1111-4111-8111-111111111111";

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('tenant-a', 'Tenant A', 'hash-a')
    `);
    await client.query(`
      INSERT INTO users (id, email)
      VALUES ('${userId}', 'user@example.com')
    `);
    await client.query(`
      INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at)
      VALUES ('rt-a', '${userId}', 'tenant-a', 'duplicate-token-hash', now() + interval '1 day')
    `);

    await expect(
      client.query(`
        INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at)
        VALUES ('rt-b', '${userId}', 'tenant-a', 'duplicate-token-hash', now() + interval '1 day')
      `),
    ).rejects.toThrow();
    await expect(
      client.query(`
        INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at)
        VALUES (
          'rt-orphan',
          '22222222-2222-4222-8222-222222222222',
          'tenant-a',
          'orphan-token-hash',
          now() + interval '1 day'
        )
      `),
    ).rejects.toThrow();

    await client.query(`DELETE FROM users WHERE id = '${userId}'`);
    const remaining = await client.query(
      "SELECT COUNT(*)::int AS cnt FROM refresh_tokens WHERE id = 'rt-a'",
    );
    expect(readCountRow(remaining.rows)).toBe(0);

    await client.close();
  });

  test("security invariants enforce SAML SSO config bounds and tenant cascade", async () => {
    const { client } = await freshDb();
    const cert = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUU3Rld2FyZC1TQU1MLUlkUC1maXh0dXJlLWNlcnQwDQYJ
KoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN0ZXdhcmQgVGVz
dDElMCMGA1UEAwwcU3Rld2FyZCBTQU1MIElkUCBGaXh0dXJlMB4XDTI2MDEwMTAw
MDAwMFoXDTM2MDEwMTAwMDAwMFowSDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN0
ZXdhcmQgVGVzdDElMCMGA1UEAwwcU3Rld2FyZCBTQU1MIElkUCBGaXh0dXJlMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AQIDAQAB
-----END CERTIFICATE-----`;

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('tenant-saml', 'Tenant SAML', 'hash-saml')
    `);
    await client.query(
      `
        INSERT INTO tenant_saml_sso_configs (
          tenant_id, enabled, status, idp_entity_id, idp_sso_url, idp_cert_pems,
          sp_entity_id, acs_url
        ) VALUES (
          'tenant-saml', true, 'active', 'https://idp.example.com/saml',
          'https://idp.example.com/sso', ARRAY[$1]::text[],
          'https://api.example.com/auth/saml/tenant-saml/metadata',
          'https://api.example.com/auth/saml/tenant-saml/acs'
        )
      `,
      [cert],
    );

    await expect(
      client.query(`
        UPDATE tenant_saml_sso_configs
        SET jit_default_role = 'admin'
        WHERE tenant_id = 'tenant-saml'
      `),
    ).rejects.toThrow();

    await expect(
      client.query(`
        UPDATE tenant_saml_sso_configs
        SET idp_cert_pems = ARRAY[]::text[]
        WHERE tenant_id = 'tenant-saml'
      `),
    ).rejects.toThrow();

    await client.query(`
      UPDATE tenant_saml_sso_configs
      SET group_role_mappings = '[{"group":"Engineering","role":"developer"}]'::jsonb
      WHERE tenant_id = 'tenant-saml'
    `);
    await expect(
      client.query(`
        UPDATE tenant_saml_sso_configs
        SET group_role_mappings = '{"group":"Engineering","role":"developer"}'::jsonb
        WHERE tenant_id = 'tenant-saml'
      `),
    ).rejects.toThrow();

    await client.query(`
      INSERT INTO tenant_saml_authn_requests (
        tenant_id, request_id, relay_state, redirect_uri, code_challenge, expires_at
      ) VALUES (
        'tenant-saml', 'saml-request-1', 'relay-1', 'https://app.example.com/callback',
        'code-challenge-1', now() + interval '5 minutes'
      )
    `);
    await expect(
      client.query(`
        INSERT INTO tenant_saml_authn_requests (
          tenant_id, request_id, relay_state, redirect_uri, code_challenge, expires_at
        ) VALUES (
          'tenant-saml', 'saml-request-2', 'relay-1', 'https://app.example.com/callback',
          'code-challenge-2', now() + interval '5 minutes'
        )
      `),
    ).rejects.toThrow();
    await expect(
      client.query(`
        UPDATE tenant_saml_authn_requests
        SET code_challenge_method = 'plain'
        WHERE relay_state = 'relay-1'
      `),
    ).rejects.toThrow();

    await client.query(`
      INSERT INTO tenant_saml_assertion_replays (
        tenant_id, assertion_id, response_id, expires_at
      ) VALUES (
        'tenant-saml', 'assertion-1', 'response-1', now() + interval '5 minutes'
      )
    `);
    await expect(
      client.query(`
        INSERT INTO tenant_saml_assertion_replays (
          tenant_id, assertion_id, response_id, expires_at
        ) VALUES (
          'tenant-saml', 'assertion-1', 'response-2', now() + interval '5 minutes'
        )
      `),
    ).rejects.toThrow();

    await client.query("DELETE FROM tenants WHERE id = 'tenant-saml'");
    for (const tableName of [
      "tenant_saml_sso_configs",
      "tenant_saml_authn_requests",
      "tenant_saml_assertion_replays",
    ]) {
      const remaining = await client.query(
        `SELECT COUNT(*)::int AS cnt FROM ${tableName} WHERE tenant_id = 'tenant-saml'`,
      );
      expect(readCountRow(remaining.rows)).toBe(0);
    }

    await client.close();
  });

  test("security invariants enforce tenant invitation lifecycle", async () => {
    const { client } = await freshDb();

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('tenant-invite', 'Tenant Invite', 'hash-invite')
    `);
    const userId = "00000000-0000-4000-8000-000000000054";
    await client.query(`
      INSERT INTO users (id, email, email_verified)
      VALUES ('${userId}', 'alice@example.com', true)
    `);

    await client.query(`
      INSERT INTO tenant_invitations (
        tenant_id, email, role, token_hash, status, expires_at
      ) VALUES (
        'tenant-invite', 'alice@example.com', 'developer', 'token-hash-1',
        'pending', now() + interval '7 days'
      )
    `);

    await expect(
      client.query(`
        INSERT INTO tenant_invitations (
          tenant_id, email, role, token_hash, status, expires_at
        ) VALUES (
          'tenant-invite', 'ALICE@example.com', 'viewer', 'token-hash-2',
          'pending', now() + interval '7 days'
        )
      `),
    ).rejects.toThrow();

    await expect(
      client.query(`
        INSERT INTO tenant_invitations (
          tenant_id, email, role, token_hash, status, expires_at
        ) VALUES (
          'tenant-invite', 'owner@example.com', 'owner', 'token-hash-3',
          'pending', now() + interval '7 days'
        )
      `),
    ).rejects.toThrow();

    await client.query(`
      UPDATE tenant_invitations
      SET status = 'accepted',
          accepted_by_user_id = '${userId}',
          accepted_at = now()
      WHERE token_hash = 'token-hash-1'
    `);

    await client.query(`
      INSERT INTO tenant_invitations (
        tenant_id, email, role, token_hash, status, expires_at
      ) VALUES (
        'tenant-invite', 'alice@example.com', 'viewer', 'token-hash-4',
        'pending', now() + interval '7 days'
      )
    `);

    await expect(
      client.query(`
        UPDATE tenant_invitations
        SET status = 'accepted'
        WHERE token_hash = 'token-hash-4'
      `),
    ).rejects.toThrow();

    await client.query("DELETE FROM tenants WHERE id = 'tenant-invite'");
    const remaining = await client.query(
      "SELECT COUNT(*)::int AS cnt FROM tenant_invitations WHERE tenant_id = 'tenant-invite'",
    );
    expect(readCountRow(remaining.rows)).toBe(0);

    await client.close();
  });
});
