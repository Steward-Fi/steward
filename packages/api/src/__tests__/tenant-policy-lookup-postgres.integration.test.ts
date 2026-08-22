import { expect, it } from "bun:test";
import { randomUUID } from "node:crypto";
import { createDb } from "@stwd/db";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && process.env.STEWARD_PGLITE_MEMORY !== "true" ? it : it.skip;

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function databaseUrlFor(
  base: string,
  database: string,
  username?: string,
  password?: string,
): string {
  const url = new URL(base);
  url.pathname = `/${database}`;
  if (username) url.username = username;
  if (password) url.password = password;
  return url.toString();
}

async function run(command: string[], env: Record<string, string>): Promise<string> {
  const child = Bun.spawn(command, {
    cwd: new URL("../../../..", import.meta.url).pathname,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(stderr || stdout || `command exited ${exitCode}`);
  return stdout;
}

realPostgresIt(
  "denies empty policy sets and keeps durable policy lookup tenant-bound across process restarts",
  async () => {
    const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
    const databaseName = `steward_policy_${suffix}`;
    const appRole = `steward_policy_app_${suffix}`;
    const appPassword = randomUUID().replaceAll("-", "");
    const tenantA = `policy-a-${suffix}`;
    const tenantB = `policy-b-${suffix}`;
    const agentA = `agent-a-${suffix}`;
    const agentB = `agent-b-${suffix}`;
    const policyA = `policy-a-${suffix}`;
    const policyB = `policy-b-${suffix}`;
    const admin = createDb(databaseUrl!);

    try {
      const [authority] = await admin.client<{ rolsuper: boolean }[]>`
        SELECT rolsuper FROM pg_roles WHERE rolname = current_user
      `;
      expect(authority?.rolsuper).toBe(true);
      await admin.client.unsafe(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
      await admin.client.unsafe(
        `CREATE ROLE ${quoteIdentifier(appRole)} LOGIN PASSWORD '${appPassword}' ` +
          "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
      );

      const isolatedAdminUrl = databaseUrlFor(databaseUrl!, databaseName);
      const isolated = createDb(isolatedAdminUrl);
      try {
        await isolated.client.unsafe(`
          CREATE SCHEMA steward_rls;
          CREATE SCHEMA steward_bootstrap;
          CREATE FUNCTION steward_rls.tenant_id() RETURNS text
            LANGUAGE sql STABLE
            AS $$ SELECT NULLIF(current_setting('steward.tenant_id', true), '') $$;
          CREATE FUNCTION steward_bootstrap.ensure_default_tenant(text) RETURNS void
            LANGUAGE sql SECURITY DEFINER
            AS $$ SELECT NULL::void $$;
          CREATE TABLE public.tenants (
            id varchar(64) PRIMARY KEY,
            name varchar(255) NOT NULL,
            api_key_hash varchar(255) NOT NULL
          );
          CREATE TABLE public.agents (
            id varchar(64) PRIMARY KEY,
            tenant_id varchar(64) NOT NULL REFERENCES public.tenants(id),
            name varchar(255) NOT NULL,
            wallet_address varchar(128) NOT NULL
          );
          CREATE TABLE public.policies (
            id varchar(64) PRIMARY KEY,
            agent_id varchar(64) NOT NULL REFERENCES public.agents(id),
            type text NOT NULL,
            enabled boolean NOT NULL DEFAULT true,
            config jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
          );
          CREATE POLICY steward_tenant_isolation ON public.agents
            USING (tenant_id = steward_rls.tenant_id())
            WITH CHECK (tenant_id = steward_rls.tenant_id());
          CREATE POLICY steward_tenant_isolation ON public.policies
            USING (EXISTS (
              SELECT 1 FROM public.agents parent
              WHERE parent.id = policies.agent_id
                AND parent.tenant_id = steward_rls.tenant_id()
            ))
            WITH CHECK (EXISTS (
              SELECT 1 FROM public.agents parent
              WHERE parent.id = policies.agent_id
                AND parent.tenant_id = steward_rls.tenant_id()
            ));
          GRANT CONNECT ON DATABASE ${quoteIdentifier(databaseName)} TO ${quoteIdentifier(appRole)};
          GRANT USAGE ON SCHEMA public, steward_rls, steward_bootstrap TO ${quoteIdentifier(appRole)};
          GRANT SELECT ON TABLE public.agents, public.policies TO ${quoteIdentifier(appRole)};
          GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA steward_rls, steward_bootstrap TO ${quoteIdentifier(appRole)};
          ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;
          ALTER TABLE public.agents FORCE ROW LEVEL SECURITY;
          ALTER TABLE public.policies ENABLE ROW LEVEL SECURITY;
          ALTER TABLE public.policies FORCE ROW LEVEL SECURITY;
        `);
        await isolated.client`
          INSERT INTO tenants(id, name, api_key_hash) VALUES
            (${tenantA}, 'Policy tenant A', ${`hash-${tenantA}`}),
            (${tenantB}, 'Policy tenant B', ${`hash-${tenantB}`})
        `;
        await isolated.client`
          INSERT INTO agents(id, tenant_id, name, wallet_address) VALUES
            (${agentA}, ${tenantA}, 'Agent A', '0x0000000000000000000000000000000000000001'),
            (${agentB}, ${tenantB}, 'Agent B', '0x0000000000000000000000000000000000000002')
        `;
        await isolated.client`
          INSERT INTO policies(id, agent_id, type, enabled, config) VALUES
            (${policyA}, ${agentA}, 'spending-limit', true, ${JSON.stringify({ maxPerTx: "1" })}::jsonb),
            (${policyB}, ${agentB}, 'spending-limit', true, ${JSON.stringify({ maxPerTx: "2" })}::jsonb)
        `;
      } finally {
        await isolated.client.end();
      }

      const fixture = new URL("./fixtures/tenant-policy-lookup-process.ts", import.meta.url)
        .pathname;
      const restrictedUrl = databaseUrlFor(databaseUrl!, databaseName, appRole, appPassword);
      const childEnv = {
        DATABASE_URL: restrictedUrl,
        STEWARD_MASTER_PASSWORD: `policy-master-${suffix}-at-least-32-bytes`,
        STEWARD_JWT_SECRET: `policy-jwt-${suffix}-at-least-32-bytes`,
        STEWARD_AUDIT_HMAC_KEY: `policy-audit-${suffix}-at-least-32-bytes`,
        TEST_TENANT_ID: tenantA,
        TEST_OWN_AGENT_ID: agentA,
        TEST_FOREIGN_AGENT_ID: agentB,
      };
      // The owner connection bypasses RLS, so this first lookup proves the SQL
      // predicate itself binds tenant identity instead of relying on ambient
      // row visibility. The following two fresh restricted-role processes
      // separately prove production RLS isolation and restart durability.
      const ownerLookup = JSON.parse(
        (
          await run([process.execPath, fixture], {
            ...childEnv,
            DATABASE_URL: isolatedAdminUrl,
          })
        ).trim(),
      );
      const firstRestricted = JSON.parse((await run([process.execPath, fixture], childEnv)).trim());
      const restartedRestricted = JSON.parse(
        (await run([process.execPath, fixture], childEnv)).trim(),
      );

      for (const result of [ownerLookup, firstRestricted, restartedRestricted]) {
        expect(result).toEqual({
          ownPolicyIds: [policyA],
          foreignPolicyIds: [],
          emptyEvaluation: {
            approved: false,
            results: [],
            requiresManualApproval: false,
          },
        });
      }
    } finally {
      await admin.client.unsafe(
        `DROP DATABASE IF EXISTS ${quoteIdentifier(databaseName)} WITH (FORCE)`,
      );
      await admin.client.unsafe(`DROP ROLE IF EXISTS ${quoteIdentifier(appRole)}`);
      await admin.client.end();
    }
  },
  180_000,
);
