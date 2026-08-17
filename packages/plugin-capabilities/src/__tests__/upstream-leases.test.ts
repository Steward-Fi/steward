import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { eq, upstreamCredentialLeaseEvents, upstreamCredentialLeases } from "@stwd/db";
import { sql } from "drizzle-orm";
import {
  expireUpstreamCredentialLeases,
  GITHUB_APP_LEASE_ISSUER,
  issueUpstreamCredentialLease,
  revokeUpstreamCredentialLease,
  type UpstreamTokenIssuer,
} from "../upstream-leases";
import { ensureAgent, ensureTenant, type Harness, makeHarness } from "./_harness";

const TENANT = "lease-tenant";
const OTHER_TENANT = "lease-other";
const AGENT = "lease-agent";
const CAPABILITY = "10000000-0000-4000-8000-000000000001";
const GRANT = "20000000-0000-4000-8000-000000000001";
const TOKEN = "github_installation_token_CANARY_must_not_be_stored";
const NOW = new Date("2026-08-16T12:00:00.000Z");

let harness: Harness;
let workspaceId: string;

class FakeIssuer implements UpstreamTokenIssuer {
  issueCalls = 0;
  revokeCalls = 0;
  failIssue = false;
  failRevoke = false;
  expiryOffsetMs = 3_590_000;

  async issue() {
    this.issueCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 10));
    if (this.failIssue) throw new Error("issuer down");
    return { token: TOKEN, expiresAt: new Date(NOW.getTime() + this.expiryOffsetMs) };
  }

  async revoke(token: string) {
    this.revokeCalls += 1;
    expect(token).toBe(TOKEN);
    if (this.failRevoke) throw new Error("revoker down");
  }
}

async function createWorkspace(db: any, tenantId: string): Promise<string> {
  const email = `${tenantId}@lease.test`;
  const user = await db.execute(sql`INSERT INTO users (email) VALUES (${email}) RETURNING id`);
  const userId = (user.rows ?? user)[0].id as string;
  const result = await db.execute(sql`
    INSERT INTO workspaces (tenant_id, key, name, environment, created_by)
    VALUES (${tenantId}, 'lease', 'Lease', 'production', ${userId}) RETURNING id
  `);
  return (result.rows ?? result)[0].id as string;
}

function resolved(overrides: { tenantId?: string; agentId?: string; workspaceId?: string } = {}) {
  const tenantId = overrides.tenantId ?? TENANT;
  return {
    capability: {
      id: CAPABILITY,
      tenantId,
      secretId: "30000000-0000-4000-8000-000000000001",
      constraints: {
        manifest: "github:app:org",
        upstreamLease: {
          issuer: GITHUB_APP_LEASE_ISSUER,
          workspaceId: overrides.workspaceId ?? workspaceId,
          appId: "12345",
          installationId: "67890",
          allowedRepositories: ["steward", "docs"],
          allowedPermissions: { contents: "read", issues: "write" },
          maxTtlSeconds: 3600,
        },
      },
    },
    grant: {
      id: GRANT,
      tenantId,
      agentId: overrides.agentId ?? AGENT,
      capabilityId: CAPABILITY,
    },
  };
}

function issueArgs(issuer: FakeIssuer, key = "idempotency-key-0001") {
  return {
    db: harness.db,
    tenantId: TENANT,
    agentId: AGENT,
    workspaceId,
    idempotencyKey: key,
    ttlSeconds: 3600,
    resource: { repositories: ["steward"], permissions: { issues: "write" as const } },
    resolved: resolved(),
    exerciseSecret: async <T>(
      _tenantId: string,
      _secretId: string,
      use: (value: string) => Promise<T>,
    ) => use("FAKE PRIVATE KEY"),
    issuer,
    now: NOW,
  };
}

beforeEach(async () => {
  harness = await makeHarness();
  await ensureTenant(harness.db, TENANT);
  await ensureTenant(harness.db, OTHER_TENANT);
  await ensureAgent(harness.db, TENANT, AGENT);
  workspaceId = await createWorkspace(harness.db, TENANT);
});

afterEach(async () => {
  await harness.close();
});

describe("upstream credential leases", () => {
  test("concurrent issuance calls upstream once and never replays or persists plaintext", async () => {
    const issuer = new FakeIssuer();
    const results = await Promise.all(
      Array.from({ length: 8 }, () => issueUpstreamCredentialLease(issueArgs(issuer))),
    );
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok && result.code === "lease_replay")).toHaveLength(
      7,
    );
    expect(issuer.issueCalls).toBe(1);
    const success = results.find((result) => result.ok);
    if (!success?.ok) throw new Error("expected one delivery");
    expect(success.token).toBe(TOKEN);

    const rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      tenantId: TENANT,
      workspaceId,
      agentId: AGENT,
      grantId: GRANT,
      capabilityId: CAPABILITY,
      status: "active",
    });
    expect(JSON.stringify(rows[0])).not.toContain(TOKEN);
    expect(rows[0].tokenHash).toMatch(/^[a-f0-9]{64}$/);
  });

  test("cross-tenant, cross-agent, workspace and over-broad scopes deny before issuer", async () => {
    const issuer = new FakeIssuer();
    const crossTenant = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-cross-tenant"),
      resolved: resolved({ tenantId: OTHER_TENANT }),
    });
    expect(crossTenant).toMatchObject({ ok: false, code: "binding_denied" });
    const crossAgent = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-cross-agent-1"),
      resolved: resolved({ agentId: "other-agent" }),
    });
    expect(crossAgent).toMatchObject({ ok: false, code: "binding_denied" });
    const crossWorkspace = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-cross-workspace"),
      workspaceId: "40000000-0000-4000-8000-000000000001",
    });
    expect(crossWorkspace).toMatchObject({ ok: false, code: "lease_not_configured" });
    const broad = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-broad-scope"),
      resource: { repositories: ["unconfigured"], permissions: { issues: "admin" } },
    });
    expect(broad).toMatchObject({ ok: false, code: "scope_denied" });
    expect(issuer.issueCalls).toBe(0);
  });

  test("revocation needs token proof, is single-claim, and records durable audit", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(issueArgs(issuer));
    if (!issued.ok) throw new Error("expected issuance");
    const wrong = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: "wrong",
      issuer,
      now: NOW,
    });
    expect(wrong).toMatchObject({ ok: false, status: 403 });
    expect(issuer.revokeCalls).toBe(0);
    const results = await Promise.all([
      revokeUpstreamCredentialLease({
        db: harness.db,
        tenantId: TENANT,
        agentId: AGENT,
        leaseId: issued.leaseId,
        token: TOKEN,
        issuer,
        now: NOW,
      }),
      revokeUpstreamCredentialLease({
        db: harness.db,
        tenantId: TENANT,
        agentId: AGENT,
        leaseId: issued.leaseId,
        token: TOKEN,
        issuer,
        now: NOW,
      }),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(issuer.revokeCalls).toBe(1);
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
    const events = await harness.db
      .select()
      .from(upstreamCredentialLeaseEvents)
      .where(eq(upstreamCredentialLeaseEvents.leaseId, issued.leaseId));
    expect(
      events.map(
        (event: { action: string; decision: string }) => `${event.action}:${event.decision}`,
      ),
    ).toEqual(["lease.issue:allow", "lease.revoke:allow"]);
  });

  test("issuer and revoker failures fail closed with durable status and evidence", async () => {
    const issuer = new FakeIssuer();
    issuer.failIssue = true;
    const denied = await issueUpstreamCredentialLease(issueArgs(issuer));
    expect(denied).toMatchObject({ ok: false, status: 503, code: "issuer_unavailable" });
    let rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0].status).toBe("failed");

    issuer.failIssue = false;
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-revoker-fail"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    issuer.failRevoke = true;
    const revoke = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: TOKEN,
      issuer,
      now: NOW,
    });
    expect(revoke).toMatchObject({ ok: false, status: 503 });
    rows = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(rows[0].status).toBe("active");
    const events = await harness.db
      .select()
      .from(upstreamCredentialLeaseEvents)
      .where(eq(upstreamCredentialLeaseEvents.leaseId, issued.leaseId));
    expect(
      events.some(
        (event: { action: string; decision: string }) =>
          event.action === "lease.revoke" && event.decision === "deny",
      ),
    ).toBe(true);
  });

  test("bounded expiry changes durable status and appends evidence", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(issueArgs(issuer));
    if (!issued.ok) throw new Error("expected issuance");
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ expiresAt: new Date(NOW.getTime() - 1) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(
      await expireUpstreamCredentialLeases({ db: harness.db, tenantId: TENANT, now: NOW }),
    ).toBe(1);
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("expired");
    const events = await harness.db
      .select()
      .from(upstreamCredentialLeaseEvents)
      .where(eq(upstreamCredentialLeaseEvents.leaseId, issued.leaseId));
    expect(events.at(-1)).toMatchObject({ action: "lease.expire", decision: "allow" });
  });

  test("an overlong upstream token is revoked or durably flagged for attention", async () => {
    const issuer = new FakeIssuer();
    issuer.expiryOffsetMs = 4_000_000;
    issuer.failRevoke = true;
    const denied = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-expiry-contract"),
    );
    expect(denied).toMatchObject({ ok: false, code: "issuer_contract_violation" });
    expect(issuer.revokeCalls).toBe(1);
    const rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0].status).toBe("needs_attention");
    expect(JSON.stringify(rows[0])).not.toContain(TOKEN);
  });
});
