/**
 * PGLite adapter tests.
 *
 * Verifies that the PGLite adapter:
 *   1. Initializes and runs all migrations
 *   2. Supports basic CRUD via Drizzle (tenants, agents, policies)
 *   3. Persists data across close/reopen cycles
 */

import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";

import { createPGLiteDb } from "../pglite";
import { agents, encryptedKeys, policies, tenants, transactions } from "../schema";

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

  // ─── Data directory permissions (SEC-090) ──────────────────────────────

  test.skipIf(process.platform === "win32")(
    "data directory is created owner-only (SEC-090)",
    async () => {
      const parent = await mkdtemp(join(tmpdir(), "steward-pglite-perms-"));
      const dir = join(parent, "data");

      const { client } = await createPGLiteDb(dir);
      await client.close();

      expect((await stat(dir)).mode & 0o777).toBe(0o700);
      await rm(parent, { recursive: true, force: true }).catch(() => {});
    },
  );

  test.skipIf(process.platform === "win32")(
    "pre-existing permissive data directory is tightened to owner-only (SEC-090)",
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "steward-pglite-perms-existing-"));
      await chmod(dir, 0o755);

      const { client } = await createPGLiteDb(dir);
      await client.close();

      expect((await stat(dir)).mode & 0o777).toBe(0o700);
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    },
  );

  test.skipIf(process.platform === "win32")(
    "symbolic-link data directory is rejected before chmod (SEC-090)",
    async () => {
      const parent = await mkdtemp(join(tmpdir(), "steward-pglite-symlink-"));
      const target = join(parent, "target");
      const link = join(parent, "data");
      await mkdir(target, { mode: 0o755 });
      await symlink(target, link, "dir");

      await expect(createPGLiteDb(link)).rejects.toThrow("Refusing symbolic-link data directory");
      expect((await stat(target)).mode & 0o777).toBe(0o755);
      await rm(parent, { recursive: true, force: true }).catch(() => {});
    },
  );
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

  test("personal tenant authority rejects every non-canonical membership writer", async () => {
    const { client } = await freshDb();
    const ownerId = "00000000-0000-4000-8000-000000000061";
    const otherId = "00000000-0000-4000-8000-000000000062";
    const tenantId = `personal-${ownerId}`;

    await client.query(`
      INSERT INTO users (id, email, email_verified) VALUES
        ('${ownerId}', 'personal-owner@example.test', true),
        ('${otherId}', 'personal-other@example.test', true)
    `);
    await client.query("BEGIN");
    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('${tenantId}', 'Canonical personal', 'personal-authority-hash')
    `);
    await client.query(`
      INSERT INTO user_tenants (user_id, tenant_id, role)
      VALUES ('${ownerId}', '${tenantId}', 'owner')
    `);
    await client.query("COMMIT");

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('solana:AbCdEf123', 'Case-sensitive Solana payload', 'solana-payload-hash')
    `);
    await expect(
      client.query(`
        INSERT INTO tenants (id, name, api_key_hash)
        VALUES ('Solana:AbCdEf456', 'Hostile Solana prefix', 'solana-prefix-hash')
      `),
    ).rejects.toThrow("Reserved tenant id must use canonical lowercase form");
    await expect(
      client.query(`
        INSERT INTO tenants (id, name, api_key_hash)
        VALUES ('Personal-${otherId}', 'Hostile personal prefix', 'personal-prefix-hash')
      `),
    ).rejects.toThrow("Reserved tenant id must use canonical lowercase form");
    await expect(
      client.query(`
        INSERT INTO tenants (id, name, api_key_hash)
        VALUES ('personal-${otherId}', 'Ownerless personal', 'ownerless-personal-hash')
      `),
    ).rejects.toThrow("Personal tenant requires exactly one canonical owner");
    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('ordinary-reserved-update', 'Ordinary update source', 'ordinary-update-hash')
    `);
    await expect(
      client.query(`
        UPDATE tenants SET id = 'Personal-${otherId}'
        WHERE id = 'ordinary-reserved-update'
      `),
    ).rejects.toThrow("Reserved tenant id must use canonical lowercase form");
    await expect(
      client.query(`
        UPDATE tenants SET id = 'personal-${otherId}'
        WHERE id = 'ordinary-reserved-update'
      `),
    ).rejects.toThrow("Personal tenant requires exactly one canonical owner");
    await expect(
      client.query(`
        UPDATE tenants SET id = 'escaped-personal-tenant'
        WHERE id = 'solana:AbCdEf123'
      `),
    ).rejects.toThrow("Reserved tenant id is immutable");
    await expect(
      client.query(`
        UPDATE tenants SET id = 'eth:0x1111111111111111111111111111111111111111'
        WHERE id = 'solana:AbCdEf123'
      `),
    ).rejects.toThrow("Reserved tenant id is immutable");

    await expect(
      client.query(`
        INSERT INTO user_tenants (user_id, tenant_id, role)
        VALUES ('${otherId}', '${tenantId}', 'member')
      `),
    ).rejects.toThrow("Reserved tenant membership is immutable");
    await expect(
      client.query(`
        UPDATE user_tenants SET role = 'member'
        WHERE user_id = '${ownerId}' AND tenant_id = '${tenantId}'
      `),
    ).rejects.toThrow("Reserved tenant membership is immutable");
    await expect(
      client.query(`
        INSERT INTO tenant_invitations (
          tenant_id, email, role, token_hash, status, expires_at
        ) VALUES (
          '${tenantId}', 'blocked@example.test', 'member',
          'personal-invitation-hash', 'pending', now() + interval '1 day'
        )
      `),
    ).rejects.toThrow("Reserved tenant invitations are forbidden");
    await expect(
      client.query(`
        DELETE FROM user_tenants
        WHERE user_id = '${ownerId}' AND tenant_id = '${tenantId}'
      `),
    ).rejects.toThrow("Reserved tenant membership is immutable");

    await client.query(`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES ('default', 'Default tenant', 'default-authority-hash')
      ON CONFLICT (id) DO NOTHING
    `);
    await expect(
      client.query(`INSERT INTO user_tenants (user_id, tenant_id, role)
        VALUES ('${otherId}', 'default', 'member')`),
    ).rejects.toThrow("Reserved tenant membership is immutable");
    await client.query(`SELECT set_config('steward.tenant_id', 'default', false)`);
    await client.query(`SELECT set_config('steward.user_id', '${otherId}', false)`);
    await client.query(
      `SELECT steward_bootstrap.ensure_default_membership('${otherId}'::uuid, 'member')`,
    );
    await expect(
      client.query(`SELECT steward_bootstrap.ensure_default_membership(
        '${ownerId}'::uuid, 'member'
      )`),
    ).rejects.toThrow("default membership authority denied");

    await client.query(`DELETE FROM tenants WHERE id = '${tenantId}'`);
    expect(
      readCountRow(
        (
          await client.query(
            `SELECT COUNT(*)::int AS cnt FROM user_tenants WHERE tenant_id = '${tenantId}'`,
          )
        ).rows,
      ),
    ).toBe(0);
    await client.close();
  });
});
