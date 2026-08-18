import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  eq,
  tenants,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
  workspaces,
} from "@stwd/db";
import { sql } from "drizzle-orm";
import { capabilities, capabilityGrants } from "../schema";
import {
  __setBeforeUpstreamLeaseRecoveryClaimForTests,
  acknowledgeUpstreamCredentialLease,
  canonicalGitHubLeaseResource,
  DELIVERY_ACK_TIMEOUT_MS,
  expireUpstreamCredentialLeases,
  GITHUB_APP_LEASE_ISSUER,
  issueUpstreamCredentialLease,
  recoverAllInterruptedUpstreamCredentialLeases,
  recoverInterruptedUpstreamCredentialLeases,
  revokeUpstreamCredentialLease,
  revokeUpstreamLeasesForAuthority,
  sha256,
  UPSTREAM_LEASE_AUTHORITY_RECHECK_INTERVAL_MS,
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

setDefaultTimeout(120_000);

let harness: Harness;
let workspaceId: string;

class FakeIssuer implements UpstreamTokenIssuer {
  issueCalls = 0;
  revokeCalls = 0;
  failIssue = false;
  failRevoke = false;
  revokeFailuresRemaining = 0;
  expiryOffsetMs = 3_590_000;
  token = TOKEN;
  issueStarted?: () => void;
  issueBarrier?: Promise<void>;
  beforeRevoke?: () => Promise<void>;

  async issue() {
    this.issueCalls += 1;
    this.issueStarted?.();
    if (this.issueBarrier) await this.issueBarrier;
    await new Promise((resolve) => setTimeout(resolve, 10));
    if (this.failIssue) throw new Error("issuer down");
    return { token: this.token, expiresAt: new Date(NOW.getTime() + this.expiryOffsetMs) };
  }

  async revoke(token: string) {
    this.revokeCalls += 1;
    expect(token).toBe(this.token);
    await this.beforeRevoke?.();
    if (this.failRevoke) throw new Error("revoker down");
    if (this.revokeFailuresRemaining > 0) {
      this.revokeFailuresRemaining -= 1;
      throw new Error("revoker down");
    }
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
    sealToken: async (_tenantId: string, _leaseId: string, token: string) => ({
      ciphertext: Buffer.from(token).toString("base64"),
      iv: "iv",
      tag: "tag",
      salt: "salt",
    }),
    auditedTransaction: auditedTransaction(),
    issuer,
    now: NOW,
  };
}

const audit = async () => {};
function auditedTransaction(auditWriter: (event: any) => Promise<void> = audit) {
  return <T>(
    _tenantId: string,
    fn: (tx: any, appendRequiredAudit: (event: any) => Promise<void>) => Promise<T>,
  ) => harness.db.transaction((tx: any) => fn(tx, auditWriter));
}
const exerciseToken = async <T>(
  _tenantId: string,
  _leaseId: string,
  sealed: { ciphertext: string },
  use: (token: string) => Promise<T>,
) => use(Buffer.from(sealed.ciphertext, "base64").toString());

async function acknowledge(issued: { leaseId: string; token: string }) {
  return acknowledgeUpstreamCredentialLease({
    db: harness.db,
    tenantId: TENANT,
    agentId: AGENT,
    leaseId: issued.leaseId,
    token: issued.token,
    auditedTransaction: auditedTransaction(),
    now: NOW,
  });
}

beforeEach(async () => {
  harness = await makeHarness();
  await ensureTenant(harness.db, TENANT);
  await ensureTenant(harness.db, OTHER_TENANT);
  await ensureAgent(harness.db, TENANT, AGENT);
  workspaceId = await createWorkspace(harness.db, TENANT);
  await harness.db.insert(capabilities).values({
    id: CAPABILITY,
    tenantId: TENANT,
    name: "github:app:org",
    secretId: "30000000-0000-4000-8000-000000000001",
    host: "api.github.com",
    pathPattern: "/",
    method: "POST",
    injectAs: "header",
    injectKey: "authorization",
    constraints: resolved().capability.constraints,
    enabled: true,
  });
  await harness.db.insert(capabilityGrants).values({
    id: GRANT,
    tenantId: TENANT,
    agentId: AGENT,
    capabilityId: CAPABILITY,
    status: "active",
  });
});

afterEach(async () => {
  __setBeforeUpstreamLeaseRecoveryClaimForTests();
  await harness.close();
});

describe("upstream credential leases", () => {
  test("only advertises GitHub's actual one-hour installation-token lifetime", async () => {
    const issuer = new FakeIssuer();
    for (const ttlSeconds of [60, 300, 900, 3599, 3601]) {
      const result = await issueUpstreamCredentialLease({
        ...issueArgs(issuer, `idempotency-unsupported-ttl-${ttlSeconds}`),
        ttlSeconds,
      });
      expect(result).toMatchObject({
        ok: false,
        status: 400,
        code: "ttl_out_of_range",
      });
    }
    expect(issuer.issueCalls).toBe(0);
  });

  test("denies and revokes when the fixed provider token would outlive its grant", async () => {
    const issuer = new FakeIssuer();
    await harness.db
      .update(capabilityGrants)
      .set({ expiresAt: new Date(NOW.getTime() + 30 * 60_000) })
      .where(eq(capabilityGrants.id, GRANT));
    const denied = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-grant-expiry-containment"),
    );
    expect(denied).toMatchObject({ ok: false, code: "lease_authority_changed" });
    expect(issuer.revokeCalls).toBe(1);
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(
        eq(
          upstreamCredentialLeases.idempotencyKeyHash,
          sha256("idempotency-grant-expiry-containment"),
        ),
      );
    expect(row.status).toBe("failed");
  });

  test("canonical resource hashing uses deterministic code-unit ordering", () => {
    expect(
      Object.keys(
        canonicalGitHubLeaseResource({
          repositories: ["steward"],
          permissions: { zeta: "read", Alpha: "write", beta: "read" },
        }).permissions,
      ),
    ).toEqual(["Alpha", "beta", "zeta"]);
  });

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
      status: "delivery_pending",
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
    const inheritedPermission = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-prototype-permission"),
      resource: {
        repositories: ["steward"],
        permissions: { toString: "admin" } as never,
      },
    });
    expect(inheritedPermission).toMatchObject({ ok: false, code: "scope_denied" });
    const unknownLevel = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-unknown-permission-level"),
      resource: {
        repositories: ["steward"],
        permissions: { issues: "owner" } as never,
      },
    });
    expect(unknownLevel).toMatchObject({ ok: false, code: "scope_denied" });
    expect(issuer.issueCalls).toBe(0);
  });

  for (const mutation of ["revoke", "disable", "delete", "narrow"] as const) {
    test(`a concurrent ${mutation} after the upstream claim revokes the token and delivers nothing`, async () => {
      const issuer = new FakeIssuer();
      let releaseIssue!: () => void;
      issuer.issueBarrier = new Promise<void>((resolve) => {
        releaseIssue = resolve;
      });
      let markStarted!: () => void;
      const started = new Promise<void>((resolve) => {
        markStarted = resolve;
      });
      issuer.issueStarted = markStarted;

      const pending = issueUpstreamCredentialLease(
        issueArgs(issuer, `idempotency-authority-race-${mutation}`),
      );
      await started;
      if (mutation === "revoke") {
        await harness.db
          .update(capabilityGrants)
          .set({ status: "revoked" })
          .where(eq(capabilityGrants.id, GRANT));
      } else if (mutation === "disable") {
        await harness.db
          .update(capabilities)
          .set({ enabled: false })
          .where(eq(capabilities.id, CAPABILITY));
      } else if (mutation === "delete") {
        await harness.db.delete(capabilityGrants).where(eq(capabilityGrants.id, GRANT));
        await harness.db.delete(capabilities).where(eq(capabilities.id, CAPABILITY));
      } else {
        const narrowed = resolved().capability.constraints as Record<string, unknown>;
        await harness.db
          .update(capabilities)
          .set({
            constraints: {
              ...narrowed,
              upstreamLease: {
                ...(narrowed.upstreamLease as Record<string, unknown>),
                allowedPermissions: { issues: "read" },
              },
            },
          })
          .where(eq(capabilities.id, CAPABILITY));
      }
      releaseIssue();

      const result = await pending;
      expect(result).toMatchObject({
        ok: false,
        status: 409,
        code: "lease_authority_changed",
      });
      expect("token" in result).toBe(false);
      expect(issuer.issueCalls).toBe(1);
      expect(issuer.revokeCalls).toBe(1);
      const [lease] = await harness.db
        .select()
        .from(upstreamCredentialLeases)
        .where(
          eq(
            upstreamCredentialLeases.idempotencyKeyHash,
            sha256(`idempotency-authority-race-${mutation}`),
          ),
        );
      expect(lease.status).toBe("failed");
      expect(lease.deliveredAt).toBeNull();
      expect(lease.tokenHash).toBeNull();
    });
  }

  test("revocation needs token proof, is single-claim, and records durable audit", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(issueArgs(issuer));
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    const wrong = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: "wrong",
      issuer,
      auditedTransaction: auditedTransaction(),
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
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
      revokeUpstreamCredentialLease({
        db: harness.db,
        tenantId: TENANT,
        agentId: AGENT,
        leaseId: issued.leaseId,
        token: TOKEN,
        issuer,
        auditedTransaction: auditedTransaction(),
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
    ).toEqual(["lease.delivery_pending:allow", "lease.issue:allow", "lease.revoke:allow"]);
  });

  test("acknowledgement audit commits atomically with the active transition", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-ack-ordering"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    let observedAction = "";
    const result = await acknowledgeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: issued.token,
      now: NOW,
      auditedTransaction: auditedTransaction(async (event) => {
        observedAction = event.action;
      }),
    });
    expect(result).toEqual({ ok: true });
    expect(observedAction).toBe("upstream_credential_lease.activated");
    const [active] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(active.status).toBe("active");
  });

  test("issuer and revoker failures fail closed with durable status and evidence", async () => {
    const issuer = new FakeIssuer();
    issuer.failIssue = true;
    const denied = await issueUpstreamCredentialLease(issueArgs(issuer));
    expect(denied).toMatchObject({ ok: false, status: 503, code: "issuer_unavailable" });
    let rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0].status).toBe("needs_attention");

    issuer.failIssue = false;
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-revoker-fail"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    issuer.failRevoke = true;
    const revoke = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: TOKEN,
      issuer,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(revoke).toMatchObject({ ok: false, status: 503 });
    rows = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(rows[0].status).toBe("needs_attention");
    expect(rows[0].lastError).toContain("outcome unknown");
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
    issuer.failRevoke = false;
    expect(
      await revokeUpstreamCredentialLease({
        db: harness.db,
        tenantId: TENANT,
        agentId: AGENT,
        leaseId: issued.leaseId,
        token: TOKEN,
        issuer,
        auditedTransaction: auditedTransaction(),
        now: new Date(NOW.getTime() + 1_000),
      }),
    ).toEqual({ ok: true });
  });

  test("a stale revocation claim is safely retried after a post-revoke process crash", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(issueArgs(issuer));
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ status: "revoking", updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));

    const recovered = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: TOKEN,
      issuer,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(recovered).toEqual({ ok: true });
    expect(issuer.revokeCalls).toBe(1);
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
  });

  test("a live revocation claim cannot be stolen before its timeout", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(issueArgs(issuer));
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ status: "revoking", updatedAt: NOW })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));

    const duplicate = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: TOKEN,
      issuer,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(duplicate).toMatchObject({ ok: false, status: 409 });
    expect(issuer.revokeCalls).toBe(0);
  });

  test("bounded expiry changes durable status and appends evidence", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(issueArgs(issuer));
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ expiresAt: new Date(NOW.getTime() - 1) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(
      await expireUpstreamCredentialLeases({
        db: harness.db,
        auditedTransaction: auditedTransaction(),
        tenantId: TENANT,
        now: NOW,
      }),
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

  test("a contract-invalid upstream expiry is revoked or durably flagged for attention", async () => {
    const issuer = new FakeIssuer();
    issuer.expiryOffsetMs = 4_000_000;
    issuer.failRevoke = true;
    issuer.beforeRevoke = async () => {
      const [staged] = await harness.db.select().from(upstreamCredentialLeases);
      expect(staged).toMatchObject({
        status: "revoking",
        tokenHash: sha256(TOKEN),
        tokenCiphertext: Buffer.from(TOKEN).toString("base64"),
        expiresAt: new Date(NOW.getTime() + issuer.expiryOffsetMs),
      });
    };
    const denied = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-expiry-contract"),
    );
    expect(denied).toMatchObject({ ok: false, code: "issuer_contract_violation" });
    expect(issuer.revokeCalls).toBe(1);
    let rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0]).toMatchObject({
      status: "needs_attention",
      tokenHash: sha256(TOKEN),
      tokenCiphertext: Buffer.from(TOKEN).toString("base64"),
      expiresAt: new Date(NOW.getTime() + issuer.expiryOffsetMs),
    });
    expect(JSON.stringify(rows[0])).not.toContain(TOKEN);
    issuer.failRevoke = false;
    issuer.beforeRevoke = undefined;
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, rows[0].id));
    expect(
      await recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0].status).toBe("revoked");
  });

  test("an overlong issued token is sealed before cleanup and recovered exactly", async () => {
    const issuer = new FakeIssuer();
    // Exercise the byte limit, not UTF-16 code-unit length: this is 4,098
    // UTF-8 bytes while remaining only 2,049 JavaScript characters.
    issuer.token = "é".repeat(2049);
    issuer.failRevoke = true;
    issuer.beforeRevoke = async () => {
      const [staged] = await harness.db.select().from(upstreamCredentialLeases);
      expect(staged).toMatchObject({
        status: "revoking",
        tokenHash: sha256(issuer.token),
        tokenCiphertext: Buffer.from(issuer.token).toString("base64"),
        expiresAt: new Date(NOW.getTime() + issuer.expiryOffsetMs),
      });
    };

    const denied = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-overlong-provider-token"),
    );
    expect(denied).toMatchObject({ ok: false, code: "issuer_contract_violation" });
    expect(issuer.revokeCalls).toBe(1);

    let rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0]).toMatchObject({
      status: "needs_attention",
      tokenHash: sha256(issuer.token),
      tokenCiphertext: Buffer.from(issuer.token).toString("base64"),
      expiresAt: new Date(NOW.getTime() + issuer.expiryOffsetMs),
    });
    expect(JSON.stringify(rows[0])).not.toContain(issuer.token);

    issuer.failRevoke = false;
    issuer.beforeRevoke = undefined;
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, rows[0].id));
    expect(
      await recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0].status).toBe("revoked");
  });

  test("a non-GitHub-shaped short upstream expiry is revoked and denied", async () => {
    const issuer = new FakeIssuer();
    issuer.expiryOffsetMs = 15 * 60_000;
    const denied = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-short-provider-expiry"),
    );
    expect(denied).toMatchObject({ ok: false, code: "issuer_contract_violation" });
    expect(issuer.revokeCalls).toBe(1);
  });

  test("delivery requires explicit acknowledgement and stale unacknowledged tokens are revoked", async () => {
    const issuer = new FakeIssuer();
    const auditEvents: unknown[] = [];
    const issued = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-delivery-ack"),
      auditedTransaction: auditedTransaction(async (event) => auditEvents.push(event)),
    });
    if (!issued.ok) throw new Error("expected issuance");
    const sibling = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-delivery-sibling"),
      auditedTransaction: auditedTransaction(async (event) => auditEvents.push(event)),
    });
    if (!sibling.ok) throw new Error("expected sibling issuance");
    expect(await acknowledge(sibling)).toEqual({ ok: true });
    let [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("delivery_pending");
    expect(row.deliveredAt).toBeNull();
    expect(JSON.stringify(row)).not.toContain(TOKEN);
    expect(JSON.stringify(auditEvents)).not.toContain(TOKEN);

    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    const recovered = await recoverInterruptedUpstreamCredentialLeases({
      db: harness.db,
      tenantId: TENANT,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(async (event) => auditEvents.push(event)),
      now: NOW,
    });
    expect(recovered).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
    const [siblingRow] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, sibling.leaseId));
    expect(siblingRow.status).toBe("active");
    expect(issuer.revokeCalls).toBe(1);
  });

  test("acknowledgement after the delivery deadline is rejected", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-late-delivery-ack"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(
      await acknowledgeUpstreamCredentialLease({
        db: harness.db,
        tenantId: TENANT,
        agentId: AGENT,
        leaseId: issued.leaseId,
        token: issued.token,
        auditedTransaction: auditedTransaction(),
        now: new Date(NOW.getTime() + DELIVERY_ACK_TIMEOUT_MS + 1),
      }),
    ).toMatchObject({ ok: false, status: 409 });
  });

  test("acknowledgement cannot activate a provider-expired token", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-provider-expired-ack"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ expiresAt: new Date(NOW.getTime() - 1) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(await acknowledge(issued)).toMatchObject({ ok: false, status: 409 });
  });

  test("all-tenant recovery revokes an abandoned delivery without another issuance", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-autonomous-recovery"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    const result = await recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(result).toMatchObject({ tenants: 1, revoked: 1 });
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
  });

  test("global deadline ordering drains over 100 tenants despite a slow failing oldest tenant", async () => {
    const [baseWorkspace] = await harness.db
      .select()
      .from(workspaces)
      .where(eq(workspaces.id, workspaceId));
    if (!baseWorkspace) throw new Error("expected base workspace");
    const count = 101;
    const tenantRows = Array.from({ length: count }, (_, index) => ({
      id: `lease-load-${index.toString().padStart(3, "0")}`,
      name: `Lease load ${index}`,
      apiKeyHash: `lease-load-hash-${index}`,
    }));
    const uuid = (index: number, suffix: number) =>
      `${index.toString(16).padStart(8, "0")}-0000-4000-8000-${suffix
        .toString(16)
        .padStart(12, "0")}`;
    const workspaceRows = tenantRows.map((tenant, index) => ({
      id: uuid(index + 1, 1),
      tenantId: tenant.id,
      key: "lease-load",
      name: "Lease load",
      environment: "production" as const,
      createdBy: baseWorkspace.createdBy,
    }));
    await harness.db.transaction(async (tx: any) => {
      await tx.insert(tenants).values(tenantRows);
      await tx.insert(agents).values(
        tenantRows.map((tenant, index) => ({
          id: `lease-load-agent-${index}`,
          tenantId: tenant.id,
          name: "Lease load agent",
          walletAddress: "0x0000000000000000000000000000000000000001",
        })),
      );
      await tx.insert(workspaces).values(workspaceRows);
      await tx.insert(upstreamCredentialLeases).values(
        tenantRows.map((tenant, index) => ({
          id: uuid(index + 1, 2),
          tenantId: tenant.id,
          workspaceId: workspaceRows[index]!.id,
          agentId: `lease-load-agent-${index}`,
          grantId: "20000000-0000-4000-8000-000000000099",
          capabilityId: "10000000-0000-4000-8000-000000000099",
          issuer: GITHUB_APP_LEASE_ISSUER,
          resource: { repositories: ["steward"], permissions: { contents: "read" } },
          resourceHash: sha256(`load-resource-${index}`),
          authorityDigest: sha256(`load-authority-${index}`),
          idempotencyKeyHash: sha256(`load-idempotency-${index}`),
          tokenHash: sha256(`${TOKEN}-${index}`),
          tokenCiphertext: Buffer.from(`${TOKEN}-${index}`).toString("base64"),
          tokenIv: "iv",
          tokenAuthTag: "tag",
          tokenSalt: "salt",
          status: "delivery_pending",
          expiresAt: new Date(NOW.getTime() + 3_590_000),
          updatedAt: new Date(NOW.getTime() - 60_000 + index),
        })),
      );
    });

    let releaseOldest!: () => void;
    const oldestBarrier = new Promise<void>((resolve) => {
      releaseOldest = resolve;
    });
    let oldestEntered!: () => void;
    const oldestStarted = new Promise<void>((resolve) => {
      oldestEntered = resolve;
    });
    const issuer: UpstreamTokenIssuer = {
      async issue() {
        throw new Error("not used");
      },
      async revoke(token) {
        if (token !== `${TOKEN}-0`) return;
        oldestEntered();
        await oldestBarrier;
        throw new Error("oldest tenant revoker unavailable");
      },
    };
    const recovery = recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
      workLimit: 200,
      concurrency: 16,
      runDeadlineMs: 5_000,
    });
    await oldestStarted;
    const lastId = uuid(count, 2);
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const [last] = await harness.db
        .select({ status: upstreamCredentialLeases.status })
        .from(upstreamCredentialLeases)
        .where(eq(upstreamCredentialLeases.id, lastId));
      if (last?.status === "revoked") break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const [lastBeforeRelease] = await harness.db
      .select({ status: upstreamCredentialLeases.status })
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, lastId));
    expect(lastBeforeRelease?.status).toBe("revoked");
    releaseOldest();
    const result = await recovery;
    expect(result).toMatchObject({ tenants: 101, revoked: 100, attention: 1, remaining: false });
    const [oldest] = await harness.db
      .select({ status: upstreamCredentialLeases.status })
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, uuid(1, 2)));
    expect(oldest?.status).toBe("needs_attention");
  });

  test("global recovery does not begin a database phase without the minimum budget", async () => {
    let databasePhases = 0;
    const result = await recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer: new FakeIssuer(),
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      deadlineAt: Date.now() + 50,
      databasePhase: async (_deadlineAt, run) => {
        databasePhases += 1;
        return run(harness.db, auditedTransaction());
      },
    });
    expect(databasePhases).toBe(0);
    expect(result).toMatchObject({
      tenants: 0,
      unknown: 0,
      revoked: 0,
      attention: 0,
      expired: 0,
      remaining: true,
    });
  });

  test("global ordering chooses older expiry and authority deadlines before interrupted delivery", async () => {
    const issuer = new FakeIssuer();
    const expiring = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-global-order-expiry"),
    );
    const authority = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-global-order-authority"),
    );
    const interrupted = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-global-order-interrupted"),
    );
    if (!expiring.ok || !authority.ok || !interrupted.ok) {
      throw new Error("expected issuance");
    }
    expect(await acknowledge(expiring)).toEqual({ ok: true });
    expect(await acknowledge(authority)).toEqual({ ok: true });
    await harness.db
      .update(upstreamCredentialLeases)
      .set({
        expiresAt: new Date(NOW.getTime() - 60_000),
        authorityCheckedAt: new Date(NOW.getTime() - 60_000),
      })
      .where(eq(upstreamCredentialLeases.id, expiring.leaseId));
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ authorityCheckedAt: new Date(NOW.getTime() - 60_000) })
      .where(eq(upstreamCredentialLeases.id, authority.leaseId));
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - DELIVERY_ACK_TIMEOUT_MS - 1_000) })
      .where(eq(upstreamCredentialLeases.id, interrupted.leaseId));
    await harness.db
      .update(capabilities)
      .set({ enabled: false })
      .where(eq(capabilities.id, CAPABILITY));

    const first = await recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
      workLimit: 2,
      concurrency: 1,
    });
    expect(first).toMatchObject({ expired: 1, revoked: 1, remaining: true });
    const firstRows = await harness.db.select().from(upstreamCredentialLeases);
    expect(firstRows.find((row) => row.id === expiring.leaseId)?.status).toBe("expired");
    expect(firstRows.find((row) => row.id === authority.leaseId)?.status).toBe("revoked");
    expect(firstRows.find((row) => row.id === interrupted.leaseId)?.status).toBe(
      "delivery_pending",
    );

    const second = await recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
      workLimit: 2,
      concurrency: 1,
    });
    expect(second).toMatchObject({ revoked: 1, remaining: false });
  });

  test("authority backlog over the work cap drains once without a healthy-lease hot loop", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-backlog-base"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    const [base] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    if (!base) throw new Error("expected base lease");
    const authorityCheckedAt = new Date(
      NOW.getTime() - UPSTREAM_LEASE_AUTHORITY_RECHECK_INTERVAL_MS - 1,
    );
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ authorityCheckedAt })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    await harness.db.insert(upstreamCredentialLeases).values(
      Array.from({ length: 500 }, (_, index) => ({
        ...base,
        id: `${(index + 1_000).toString(16).padStart(8, "0")}-1000-4000-8000-${(index + 1)
          .toString(16)
          .padStart(12, "0")}`,
        idempotencyKeyHash: sha256(`authority-backlog-${index}`),
        authorityCheckedAt,
      })),
    );

    const first = await recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
      workLimit: 500,
      concurrency: 16,
    });
    expect(first).toMatchObject({ tenants: 1, revoked: 0, attention: 0, remaining: true });
    let drained = first;
    let immediateRuns = 1;
    while (drained.remaining && immediateRuns < 10) {
      drained = await recoverAllInterruptedUpstreamCredentialLeases({
        db: harness.db,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
        workLimit: 500,
        concurrency: 16,
      });
      immediateRuns += 1;
    }
    expect(drained).toMatchObject({ revoked: 0, attention: 0, remaining: false });
    expect(immediateRuns).toBeLessThan(10);
    const settled = await recoverAllInterruptedUpstreamCredentialLeases({
      db: harness.db,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
      workLimit: 500,
      concurrency: 16,
    });
    expect(settled).toMatchObject({ tenants: 0, revoked: 0, attention: 0, remaining: false });
  });

  test("stale exact-token revocation claims are idempotently reconciled", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-stale-revocation"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ status: "revoking", updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));

    const recovered = await recoverInterruptedUpstreamCredentialLeases({
      db: harness.db,
      tenantId: TENANT,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(recovered).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
    expect(issuer.revokeCalls).toBe(1);
  });

  test("a late acknowledgement racing the sweep cannot activate the stale lease", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-stale-ack-race"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    const staleAt = new Date(NOW.getTime() - 31_000);
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: staleAt })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));

    let interleaved = false;
    __setBeforeUpstreamLeaseRecoveryClaimForTests(async (leaseId) => {
      if (leaseId !== issued.leaseId || interleaved) return;
      interleaved = true;
      expect(await acknowledge(issued)).toMatchObject({ ok: false, status: 409 });
    });
    const recovered = await recoverInterruptedUpstreamCredentialLeases({
      db: harness.db,
      tenantId: TENANT,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });

    expect(interleaved).toBe(true);
    expect(recovered).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    expect(issuer.revokeCalls).toBe(1);
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
  });

  test("authority-change revoker failure retains the exact sealed recovery handle", async () => {
    const issuer = new FakeIssuer();
    issuer.failRevoke = true;
    let releaseIssue!: () => void;
    issuer.issueBarrier = new Promise<void>((resolve) => {
      releaseIssue = resolve;
    });
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    issuer.issueStarted = markStarted;
    const pending = issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-revoke-recovery"),
    );
    await started;
    await harness.db
      .update(capabilityGrants)
      .set({ status: "revoked" })
      .where(eq(capabilityGrants.id, GRANT));
    releaseIssue();
    const denied = await pending;
    expect(denied).toMatchObject({ ok: false, code: "lease_authority_changed" });

    let [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(
        eq(
          upstreamCredentialLeases.idempotencyKeyHash,
          sha256("idempotency-authority-revoke-recovery"),
        ),
      );
    expect(row).toMatchObject({
      status: "needs_attention",
      tokenHash: sha256(TOKEN),
      expiresAt: new Date(NOW.getTime() + issuer.expiryOffsetMs),
    });
    expect(row.tokenCiphertext).toBe(Buffer.from(TOKEN).toString("base64"));
    expect(JSON.stringify(row)).not.toContain(TOKEN);
    issuer.failRevoke = false;
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, row.id));
    expect(
      await recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, row.id));
    expect(row.status).toBe("revoked");
  });

  test("generic finalization revoker failure retains the exact sealed recovery handle", async () => {
    const issuer = new FakeIssuer();
    issuer.failRevoke = true;
    const denied = await issueUpstreamCredentialLease({
      ...issueArgs(issuer, "idempotency-finalization-revoke-recovery"),
      auditedTransaction: auditedTransaction(async () => {
        throw new Error("durable audit unavailable");
      }),
    });
    expect(denied).toMatchObject({ ok: false, code: "lease_finalization_failed" });
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(
        eq(
          upstreamCredentialLeases.idempotencyKeyHash,
          sha256("idempotency-finalization-revoke-recovery"),
        ),
      );
    expect(row).toMatchObject({
      status: "revoking",
      tokenHash: sha256(TOKEN),
      expiresAt: new Date(NOW.getTime() + issuer.expiryOffsetMs),
    });
    expect(row.tokenCiphertext).toBe(Buffer.from(TOKEN).toString("base64"));
    expect(JSON.stringify(row)).not.toContain(TOKEN);
    issuer.failRevoke = false;
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, row.id));
    expect(
      await recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toEqual({ unknown: 0, revoked: 1, attention: 0 });
  });

  test("stale issuance is truthfully escalated because provider outcome is unknowable", async () => {
    const issuer = new FakeIssuer();
    await harness.db.insert(upstreamCredentialLeases).values({
      tenantId: TENANT,
      workspaceId,
      agentId: AGENT,
      grantId: GRANT,
      capabilityId: CAPABILITY,
      issuer: GITHUB_APP_LEASE_ISSUER,
      resource: { repositories: ["steward"], permissions: { contents: "read" } },
      resourceHash: sha256("resource"),
      authorityDigest: sha256("stale-authority"),
      idempotencyKeyHash: sha256("stale-issuing-key"),
      status: "issuing",
      updatedAt: new Date(NOW.getTime() - 31_000),
    });
    const recovered = await recoverInterruptedUpstreamCredentialLeases({
      db: harness.db,
      tenantId: TENANT,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(recovered.unknown).toBe(1);
    const rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows[0]).toMatchObject({
      status: "needs_attention",
      lastError: "issuer outcome unknown after interrupted issuance",
    });
  });

  test("an audit failure rolls back stale attention and a later sweep emits it exactly once", async () => {
    const issuer = new FakeIssuer();
    await harness.db.insert(upstreamCredentialLeases).values({
      tenantId: TENANT,
      workspaceId,
      agentId: AGENT,
      grantId: GRANT,
      capabilityId: CAPABILITY,
      issuer: GITHUB_APP_LEASE_ISSUER,
      resource: { repositories: ["steward"], permissions: { contents: "read" } },
      resourceHash: sha256("audit-retry-resource"),
      authorityDigest: sha256("audit-retry-authority"),
      idempotencyKeyHash: sha256("audit-retry-stale-issuing"),
      status: "issuing",
      updatedAt: new Date(NOW.getTime() - 31_000),
    });
    await expect(
      recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(async () => {
          throw new Error("audit unavailable");
        }),
        now: NOW,
      }),
    ).rejects.toThrow("audit unavailable");
    expect((await harness.db.select().from(upstreamCredentialLeases))[0].status).toBe("issuing");

    const durableAudits: unknown[] = [];
    const recover = () =>
      recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(async (event) => durableAudits.push(event)),
        now: NOW,
      });
    expect((await recover()).unknown).toBe(1);
    expect((await recover()).unknown).toBe(0);
    expect(durableAudits).toHaveLength(1);
  });

  test("issuer failure cannot commit unaudited attention and is later audited exactly once", async () => {
    const issuer = new FakeIssuer();
    issuer.failIssue = true;
    const args = issueArgs(issuer, "idempotency-issuer-audit-retry");
    args.auditedTransaction = auditedTransaction(async () => {
      throw new Error("audit unavailable");
    });
    await expect(issueUpstreamCredentialLease(args)).rejects.toThrow("audit unavailable");
    const [issuing] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.idempotencyKeyHash, sha256(args.idempotencyKey)));
    expect(issuing.status).toBe("issuing");
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issuing.id));

    const durableAudits: unknown[] = [];
    const recover = () =>
      recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(async (event) => durableAudits.push(event)),
        now: NOW,
      });
    expect((await recover()).unknown).toBe(1);
    expect((await recover()).unknown).toBe(0);
    expect(durableAudits).toHaveLength(1);
  });

  test("post-provider revoke audit failure is recovered and audited exactly once", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-holder-revoke-audit-retry"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    const failed = await revokeUpstreamCredentialLease({
      db: harness.db,
      tenantId: TENANT,
      agentId: AGENT,
      leaseId: issued.leaseId,
      token: TOKEN,
      issuer,
      auditedTransaction: auditedTransaction(async () => {
        throw new Error("audit unavailable");
      }),
      now: NOW,
    });
    expect(failed).toMatchObject({ ok: false, status: 503 });
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    const durableAudits: unknown[] = [];
    const recovered = await recoverInterruptedUpstreamCredentialLeases({
      db: harness.db,
      tenantId: TENANT,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(async (event) => durableAudits.push(event)),
      now: NOW,
    });
    expect(recovered.revoked).toBe(1);
    expect(durableAudits).toHaveLength(1);
    expect(
      (
        await recoverInterruptedUpstreamCredentialLeases({
          db: harness.db,
          tenantId: TENANT,
          issuer,
          exerciseToken,
          auditedTransaction: auditedTransaction(async (event) => durableAudits.push(event)),
          now: NOW,
        })
      ).revoked,
    ).toBe(0);
    expect(durableAudits).toHaveLength(1);
  });

  test("authority revocation uses encrypted escrow and append-only evidence cannot be erased", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-revoke"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    const result = await revokeUpstreamLeasesForAuthority({
      db: harness.db,
      tenantId: TENANT,
      capabilityId: CAPABILITY,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(),
      now: NOW,
    });
    expect(result).toEqual({ ok: true, revoked: 1 });
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
    let eventDeleteError = "";
    try {
      await harness.db.execute(
        sql`DELETE FROM upstream_credential_lease_events WHERE lease_id = ${issued.leaseId}`,
      );
    } catch (error) {
      eventDeleteError = String(error);
    }
    expect(eventDeleteError).not.toBe("");
    expect(
      await harness.db
        .select()
        .from(upstreamCredentialLeaseEvents)
        .where(eq(upstreamCredentialLeaseEvents.leaseId, issued.leaseId)),
    ).not.toHaveLength(0);
    let leaseDeleteError = "";
    try {
      await harness.db.execute(
        sql`DELETE FROM upstream_credential_leases WHERE id = ${issued.leaseId}`,
      );
    } catch (error) {
      leaseDeleteError = String(error);
    }
    expect(leaseDeleteError).not.toBe("");
    expect(
      await harness.db
        .select()
        .from(upstreamCredentialLeases)
        .where(eq(upstreamCredentialLeases.id, issued.leaseId)),
    ).toHaveLength(1);
  });

  test("autonomous recovery closes a crash after the authority tombstone commits", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-tombstone-crash"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });

    // Simulate process death after the durable authority mutation but before
    // the route's immediate provider-revocation sweep starts.
    await harness.db
      .update(capabilities)
      .set({ enabled: false })
      .where(eq(capabilities.id, CAPABILITY));
    await harness.db
      .update(upstreamCredentialLeases)
      .set({
        authorityCheckedAt: new Date(
          NOW.getTime() - UPSTREAM_LEASE_AUTHORITY_RECHECK_INTERVAL_MS - 1,
        ),
      })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(
      await recoverAllInterruptedUpstreamCredentialLeases({
        db: harness.db,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toMatchObject({ tenants: 1, unknown: 0, revoked: 1, attention: 0 });
    const [row] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(row.status).toBe("revoked");
  });

  test("authority teardown processes every sibling and later recovers the failed first revoke", async () => {
    const issuer = new FakeIssuer();
    const first = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-sibling-first"),
    );
    const second = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-sibling-second"),
    );
    if (!first.ok || !second.ok) throw new Error("expected issuance");
    expect(await acknowledge(first)).toEqual({ ok: true });
    expect(await acknowledge(second)).toEqual({ ok: true });
    issuer.revokeFailuresRemaining = 1;
    expect(
      await revokeUpstreamLeasesForAuthority({
        db: harness.db,
        tenantId: TENANT,
        capabilityId: CAPABILITY,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toMatchObject({ ok: false });
    let rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows.map((row: { status: string }) => row.status).sort()).toEqual([
      "needs_attention",
      "revoked",
    ]);
    const retry = rows.find((row: { status: string }) => row.status === "needs_attention");
    if (!retry) throw new Error("expected recoverable sibling");
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, retry.id));
    expect(
      await recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(),
        now: NOW,
      }),
    ).toEqual({ unknown: 0, revoked: 1, attention: 0 });
    rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows.every((row: { status: string }) => row.status === "revoked")).toBe(true);
    expect(issuer.revokeCalls).toBe(3);
  });

  test("a thrown first-sibling audit failure does not block later authority revocation", async () => {
    const issuer = new FakeIssuer();
    const first = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-thrown-audit-first"),
    );
    const second = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-thrown-audit-second"),
    );
    if (!first.ok || !second.ok) throw new Error("expected issuance");
    expect(await acknowledge(first)).toEqual({ ok: true });
    expect(await acknowledge(second)).toEqual({ ok: true });
    issuer.revokeFailuresRemaining = 1;
    let auditCalls = 0;
    const result = await revokeUpstreamLeasesForAuthority({
      db: harness.db,
      tenantId: TENANT,
      capabilityId: CAPABILITY,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(async () => {
        auditCalls += 1;
        if (auditCalls === 1) throw new Error("audit store unavailable");
      }),
      now: NOW,
    });
    expect(result).toMatchObject({ ok: false, error: "audit store unavailable" });
    const rows = await harness.db.select().from(upstreamCredentialLeases);
    expect(rows.map((row: { status: string }) => row.status).sort()).toEqual([
      "revoked",
      "revoking",
    ]);
    expect(issuer.revokeCalls).toBe(2);
    expect(auditCalls).toBe(2);
  });

  test("authority revoke audit failure leaves an exact recoverable claim", async () => {
    const issuer = new FakeIssuer();
    const issued = await issueUpstreamCredentialLease(
      issueArgs(issuer, "idempotency-authority-revoke-audit-retry"),
    );
    if (!issued.ok) throw new Error("expected issuance");
    expect(await acknowledge(issued)).toEqual({ ok: true });
    const failed = await revokeUpstreamLeasesForAuthority({
      db: harness.db,
      tenantId: TENANT,
      capabilityId: CAPABILITY,
      issuer,
      exerciseToken,
      auditedTransaction: auditedTransaction(async () => {
        throw new Error("audit unavailable");
      }),
      now: NOW,
    });
    expect(failed).toMatchObject({ ok: false });
    const [claimed] = await harness.db
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));
    expect(claimed.status).toBe("revoking");
    await harness.db
      .update(upstreamCredentialLeases)
      .set({ updatedAt: new Date(NOW.getTime() - 31_000) })
      .where(eq(upstreamCredentialLeases.id, issued.leaseId));

    const durableAudits: unknown[] = [];
    const recover = () =>
      recoverInterruptedUpstreamCredentialLeases({
        db: harness.db,
        tenantId: TENANT,
        issuer,
        exerciseToken,
        auditedTransaction: auditedTransaction(async (event) => durableAudits.push(event)),
        now: NOW,
      });
    expect((await recover()).revoked).toBe(1);
    expect((await recover()).revoked).toBe(0);
    expect(durableAudits).toHaveLength(1);
  });
});
