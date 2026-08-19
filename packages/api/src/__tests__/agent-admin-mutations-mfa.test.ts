import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { revocationStore } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  agentKeyQuorums,
  agentPolicies,
  agentSigners,
  agents,
  agentWallets,
  approvalQueue,
  auditEvents,
  closeDb,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  pendingProxyRequests,
  policies,
  secretRoutes,
  secrets,
  tenants,
  transactions,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
  users,
  workspaces,
} from "@stwd/db";
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import {
  cleanupAgentBehaviorTestDatabase,
  setupAgentBehaviorTestDatabase,
  USING_REAL_POSTGRES,
} from "./agent-behavior-test-database";

/**
 * SEC-209 regression: minting agent tokens, replacing an agent's vault policy
 * set, and deleting agents are root-equivalent mutations. A bare tenant API
 * key is no longer sufficient by default — they require a human owner/admin
 * session with recent MFA. STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS=true is the
 * explicit operator opt-in that restores the legacy api-key path.
 */

const TENANT_ID = `agent-admin-mutations-${Date.now()}`;
const AGENT_ID = `agent-admin-mutations-agent-${Date.now()}`;
const AUDIT_TRIGGER_SUFFIX = `${process.pid}_${Math.random().toString(36).slice(2, 8)}`;
const MUTATED_ENV = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_JWT_SECRET",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS",
] as const;
const originalEnv = new Map(MUTATED_ENV.map((name) => [name, process.env[name]]));

setDefaultTimeout(30000);

type AuthMode = "admin" | "admin-no-mfa" | "member" | "api-key";

async function makeApp(authMode: AuthMode) {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "api-key") {
      c.set("authType", "api-key");
    } else {
      c.set("authType", "session-jwt");
      c.set("tenantRole", authMode === "member" ? "member" : "owner");
      c.set("userId", "admin-mutations-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
  return app;
}

describe("agent admin mutations require human session + MFA (SEC-209)", () => {
  beforeAll(async () => {
    process.env.STEWARD_MASTER_PASSWORD = "agent-admin-mutations-master-password";
    process.env.STEWARD_JWT_SECRET = "agent-admin-mutations-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-admin-mutations-audit-hmac-key-entropy";
    __resetAuditHmacKeyCacheForTests();
    await setupAgentBehaviorTestDatabase();
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Admin Mutations Tenant",
        apiKeyHash: `api-key-hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Admin Mutations Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
  });

  afterAll(async () => {
    try {
      // Real-Postgres coverage retains append-only lease evidence whose
      // workspace intentionally prevents tenant teardown. The CI database is
      // job-scoped; PGLite remains fully hermetic and closes normally.
      if (USING_REAL_POSTGRES) await closeDb();
      else await cleanupAgentBehaviorTestDatabase(TENANT_ID);
    } finally {
      for (const [name, value] of originalEnv) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      __resetAuditHmacKeyCacheForTests();
    }
  });

  it("rejects a bare tenant API key on all three root-equivalent mutations", async () => {
    const app = await makeApp("api-key");

    const tokenRes = await app.request(`/agents/${AGENT_ID}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: "1h" }),
    });
    expect(tokenRes.status).toBe(403);

    const policiesRes = await app.request(`/agents/${AGENT_ID}/policies`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([]),
    });
    expect(policiesRes.status).toBe(403);

    const deleteRes = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(deleteRes.status).toBe(403);
  });

  it("rejects agent, wallet, batch, and token provisioning without recent MFA", async () => {
    const app = await makeApp("admin-no-mfa");
    const beforeAgents = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(eq(agents.tenantId, TENANT_ID));
    const beforeWallets = await getDb()
      .select({ id: agentWallets.id })
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));

    const requests = [
      app.request("/agents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Rejected agent" }),
      }),
      app.request(`/agents/${AGENT_ID}/wallets`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chainType: "evm", venue: "rejected" }),
      }),
      app.request("/agents/batch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agents: [{ name: "Rejected batch agent" }] }),
      }),
      app.request(`/agents/${AGENT_ID}/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ expiresIn: "1h" }),
      }),
    ];
    for (const response of await Promise.all(requests)) {
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({
        ok: false,
        error: expect.stringContaining("recent MFA verification"),
      });
    }

    expect(
      await getDb().select({ id: agents.id }).from(agents).where(eq(agents.tenantId, TENANT_ID)),
    ).toEqual(beforeAgents);
    expect(
      await getDb()
        .select({ id: agentWallets.id })
        .from(agentWallets)
        .where(eq(agentWallets.agentId, AGENT_ID)),
    ).toEqual(beforeWallets);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
  });

  it("rejects deletion without recent MFA before revocation or database mutation", async () => {
    const app = await makeApp("admin-no-mfa");
    const beforeAgent = await getDb().select().from(agents).where(eq(agents.id, AGENT_ID));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));
    expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();

    const response = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA verification"),
    });
    expect(await getDb().select().from(agents).where(eq(agents.id, AGENT_ID))).toEqual(beforeAgent);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
    expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();
  });

  it("rejects non-admin sessions", async () => {
    const app = await makeApp("member");
    const res = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(res.status).toBe(403);
  });

  it("allows the explicit api-key opt-in (documented fully-root escape hatch)", async () => {
    process.env.STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS = "true";
    try {
      const app = await makeApp("api-key");
      const res = await app.request(`/agents/${AGENT_ID}/policies`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify([]),
      });
      expect(res.status).toBe(200);
    } finally {
      delete process.env.STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS;
    }
  });

  it("does not mutate agents, wallets, policies, or revocation state when authorization audit fails", async () => {
    const app = await makeApp("admin");
    const canary = "postgres://agent-authorization-audit-secret";
    const beforeAgents = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(eq(agents.tenantId, TENANT_ID));
    const beforeWallets = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    const beforePolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_authorization_audit_${AUDIT_TRIGGER_SUFFIX}()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.tenant_id = '${TENANT_ID}' AND NEW.action IN (
            'agent.create.authorized',
            'agent.wallet.create.authorized',
            'agent.policies.update.authorized',
            'agent.delete.authorized'
          ) THEN
            RAISE EXCEPTION '${canary}';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_authorization_audit_failure_${AUDIT_TRIGGER_SUFFIX}
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_authorization_audit_${AUDIT_TRIGGER_SUFFIX}()
        `),
      );
      const responses = [
        await app.request("/agents", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ name: "Audit-blocked agent" }),
        }),
        await app.request(`/agents/${AGENT_ID}/wallets`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chainType: "evm", venue: "audit-blocked" }),
        }),
        await app.request(`/agents/${AGENT_ID}/policies`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify([
            {
              type: "spending-limit",
              enabled: true,
              config: { maxPerTx: "1" },
            },
          ]),
        }),
        await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" }),
      ];
      for (const response of responses) {
        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(await response.text()).not.toContain(canary);
      }

      expect(
        await getDb().select({ id: agents.id }).from(agents).where(eq(agents.tenantId, TENANT_ID)),
      ).toEqual(beforeAgents);
      expect(
        await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, AGENT_ID)),
      ).toEqual(beforeWallets);
      expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
        beforePolicies,
      );
      expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();
    } finally {
      try {
        await getDb().execute(
          sql.raw(
            `DROP TRIGGER IF EXISTS agent_authorization_audit_failure_${AUDIT_TRIGGER_SUFFIX} ON audit_events`,
          ),
        );
      } finally {
        await getDb().execute(
          sql.raw(
            `DROP FUNCTION IF EXISTS fail_agent_authorization_audit_${AUDIT_TRIGGER_SUFFIX}()`,
          ),
        );
      }
    }
  });

  it("removes newly created agent and wallet records when completion audit fails", async () => {
    const app = await makeApp("admin");
    const tenantAgentIds = getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(eq(agents.tenantId, TENANT_ID));
    const beforeAgents = await getDb().select().from(agents).where(eq(agents.tenantId, TENANT_ID));
    const beforeWallets = await getDb()
      .select()
      .from(agentWallets)
      .where(inArray(agentWallets.agentId, tenantAgentIds));
    const beforeEvmKeys = await getDb()
      .select()
      .from(encryptedKeys)
      .where(inArray(encryptedKeys.agentId, tenantAgentIds));
    const beforeChainKeys = await getDb()
      .select()
      .from(encryptedChainKeys)
      .where(inArray(encryptedChainKeys.agentId, tenantAgentIds));

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_completion_audit_${AUDIT_TRIGGER_SUFFIX}()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.tenant_id = '${TENANT_ID}' AND NEW.action IN ('agent.create', 'agent.wallet.create') THEN
            RAISE EXCEPTION 'required agent completion audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_completion_audit_failure_${AUDIT_TRIGGER_SUFFIX}
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_completion_audit_${AUDIT_TRIGGER_SUFFIX}()
        `),
      );
      const createResponse = await app.request("/agents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Completion-audit-blocked agent" }),
      });
      expect(createResponse.status).toBeGreaterThanOrEqual(400);

      const walletResponse = await app.request(`/agents/${AGENT_ID}/wallets`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chainType: "evm", venue: "completion-audit-blocked" }),
      });
      expect(walletResponse.status).toBeGreaterThanOrEqual(400);

      expect(await getDb().select().from(agents).where(eq(agents.tenantId, TENANT_ID))).toEqual(
        beforeAgents,
      );
      expect(
        await getDb()
          .select()
          .from(agentWallets)
          .where(inArray(agentWallets.agentId, tenantAgentIds)),
      ).toEqual(beforeWallets);
      expect(
        await getDb()
          .select()
          .from(encryptedKeys)
          .where(inArray(encryptedKeys.agentId, tenantAgentIds)),
      ).toEqual(beforeEvmKeys);
      expect(
        await getDb()
          .select()
          .from(encryptedChainKeys)
          .where(inArray(encryptedChainKeys.agentId, tenantAgentIds)),
      ).toEqual(beforeChainKeys);
    } finally {
      try {
        await getDb().execute(
          sql.raw(
            `DROP TRIGGER IF EXISTS agent_completion_audit_failure_${AUDIT_TRIGGER_SUFFIX} ON audit_events`,
          ),
        );
      } finally {
        await getDb().execute(
          sql.raw(`DROP FUNCTION IF EXISTS fail_agent_completion_audit_${AUDIT_TRIGGER_SUFFIX}()`),
        );
      }
    }
  });

  it("allows an owner/admin session with recent MFA", async () => {
    const app = await makeApp("admin");
    const tokenRes = await app.request(`/agents/${AGENT_ID}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: "1h" }),
    });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(tokenRes.headers.get("Pragma")).toBe("no-cache");
    expect(tokenRes.headers.get("Expires")).toBe("0");
    const tokenAudits = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.token.create.authorized", "agent.token.create"]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(tokenAudits.map(({ action }) => action)).toEqual([
      "agent.token.create.authorized",
      "agent.token.create",
    ]);
    expect(tokenAudits[1]?.seq).toBe(tokenAudits[0]?.seq + 1);
  });

  it("ignores caller agent ids on single and batch creation", async () => {
    const app = await makeApp("admin");
    const single = await app.request("/agents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: AGENT_ID, name: "Server id single" }),
    });
    expect(single.status).toBe(200);
    const singleBody = (await single.json()) as { data: { id: string } };
    expect(singleBody.data.id).not.toBe(AGENT_ID);

    const batch = await app.request("/agents/batch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agents: [{ id: AGENT_ID, name: "Server id batch" }] }),
    });
    expect(batch.status).toBe(200);
    const batchBody = (await batch.json()) as {
      data: { created: Array<{ id: string }>; errors: unknown[] };
    };
    expect(batchBody.data.errors).toEqual([]);
    expect(batchBody.data.created).toHaveLength(1);
    expect(batchBody.data.created[0]?.id).not.toBe(AGENT_ID);
    expect(batchBody.data.created[0]?.id).not.toBe(singleBody.data.id);

    for (const createdId of [singleBody.data.id, batchBody.data.created[0]!.id]) {
      const auditRows = await getDb()
        .select({ action: auditEvents.action, seq: auditEvents.seq })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, TENANT_ID),
            eq(auditEvents.resourceId, createdId),
            inArray(auditEvents.action, ["agent.create.authorized", "agent.create"]),
          ),
        )
        .orderBy(asc(auditEvents.seq));
      expect(auditRows.map(({ action }) => action)).toEqual([
        "agent.create.authorized",
        "agent.create",
      ]);
      expect(auditRows[1]?.seq).toBe(auditRows[0]!.seq + 1);
    }
  });

  it("atomically rolls back dependent rows on failed delete audit and succeeds on retry", async () => {
    const app = await makeApp("admin");
    const walletResponse = await app.request(`/agents/${AGENT_ID}/wallets`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chainType: "evm", venue: "delete-retry" }),
    });
    expect(walletResponse.status).toBe(200);
    const walletAudits = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.wallet.create.authorized", "agent.wallet.create"]),
          sql`${auditEvents.metadata}->>'venue' = 'delete-retry'`,
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(walletAudits.map(({ action }) => action)).toEqual([
      "agent.wallet.create.authorized",
      "agent.wallet.create",
    ]);
    expect(walletAudits[1]?.seq).toBe(walletAudits[0]!.seq + 1);
    await getDb()
      .insert(policies)
      .values({
        id: "delete-retry-policy",
        agentId: AGENT_ID,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "3" },
      });
    await getDb().insert(transactions).values({
      id: "delete-retry-transaction",
      agentId: AGENT_ID,
      status: "pending",
      toAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      value: "3",
      chainId: 1,
      policyResults: [],
    });
    await getDb().insert(approvalQueue).values({
      id: "delete-retry-approval",
      txId: "delete-retry-transaction",
      agentId: AGENT_ID,
      status: "pending",
    });
    const [dependentSigner] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "external",
        subjectId: "delete-retry-dependent-signer",
        permissions: ["sign_transaction"],
        status: "active",
        createdBy: "test",
      })
      .returning();
    const [childQuorum] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Delete retry child quorum",
        threshold: 1,
        memberSignerIds: [dependentSigner!.id],
        permissions: ["sign_transaction"],
        status: "active",
        createdBy: "test",
      })
      .returning();
    await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Delete retry nested quorum",
        threshold: 1,
        memberQuorumIds: [childQuorum!.id],
        permissions: ["sign_transaction"],
        status: "active",
        createdBy: "test",
      });
    await getDb().insert(agentPolicies).values({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      updatedBy: "test",
      updatedReason: "dependent rollback fixture",
    });
    const workspaceId = crypto.randomUUID();
    const secretId = crypto.randomUUID();
    const routeId = crypto.randomUUID();
    const leaseId = crypto.randomUUID();
    const expiredLeaseId = crypto.randomUUID();
    const pendingRequestId = crypto.randomUUID();
    const executingRequestId = crypto.randomUUID();
    const workspaceCreatorId = crypto.randomUUID();
    await getDb()
      .insert(users)
      .values({
        id: workspaceCreatorId,
        email: `${workspaceCreatorId}@delete-retry.test`,
      });
    await getDb()
      .insert(workspaces)
      .values({
        id: workspaceId,
        tenantId: TENANT_ID,
        key: `delete-retry-${workspaceId}`,
        name: "Delete retry workspace",
        environment: "production",
        createdBy: workspaceCreatorId,
      });
    await getDb()
      .insert(secrets)
      .values({
        id: secretId,
        tenantId: TENANT_ID,
        name: `delete-retry-${secretId}`,
        ciphertext: "ciphertext",
        iv: "iv",
        authTag: "auth-tag",
        salt: "salt",
      });
    await getDb().insert(secretRoutes).values({
      id: routeId,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      secretId,
      hostPattern: "delete-retry.example.test",
      injectAs: "header",
      injectKey: "authorization",
      enabled: true,
    });
    const proxyRequestFixture = (id: string, status: "pending" | "approved") => ({
      id,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      routeId,
      method: "POST",
      targetHost: "delete-retry.example.test",
      targetPath: "/mutation",
      requestDigest: "d".repeat(64),
      bodyCiphertext: "body",
      bodyIv: "iv",
      bodyAuthTag: "tag",
      bodySalt: "salt",
      status,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await getDb()
      .insert(pendingProxyRequests)
      .values([
        proxyRequestFixture(pendingRequestId, "pending"),
        proxyRequestFixture(executingRequestId, "approved"),
      ]);
    await getDb()
      .insert(upstreamCredentialLeases)
      .values({
        id: leaseId,
        tenantId: TENANT_ID,
        workspaceId,
        agentId: AGENT_ID,
        grantId: crypto.randomUUID(),
        capabilityId: crypto.randomUUID(),
        issuer: "github-app-installation",
        resource: {},
        resourceHash: "a".repeat(64),
        authorityDigest: "b".repeat(64),
        idempotencyKeyHash: "c".repeat(64),
        tokenHash: null,
        tokenCiphertext: null,
        tokenIv: null,
        tokenAuthTag: null,
        tokenSalt: null,
        status: "revoked",
        revokedAt: new Date(),
      });
    await getDb()
      .insert(upstreamCredentialLeases)
      .values({
        id: expiredLeaseId,
        tenantId: TENANT_ID,
        workspaceId,
        agentId: AGENT_ID,
        grantId: crypto.randomUUID(),
        capabilityId: crypto.randomUUID(),
        issuer: "github-app-installation",
        resource: {},
        resourceHash: "e".repeat(64),
        authorityDigest: "f".repeat(64),
        idempotencyKeyHash: "0".repeat(64),
        tokenHash: null,
        tokenCiphertext: null,
        tokenIv: null,
        tokenAuthTag: null,
        tokenSalt: null,
        status: "expired",
      });
    await getDb()
      .insert(upstreamCredentialLeaseEvents)
      .values({
        leaseId: expiredLeaseId,
        tenantId: TENANT_ID,
        action: "lease.expired",
        decision: "deny",
        metadata: { reason: "fixture" },
      });

    const beforeAgent = await getDb().select().from(agents).where(eq(agents.id, AGENT_ID));
    const beforeWallets = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    const beforeEvmKeys = await getDb()
      .select()
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, AGENT_ID));
    const beforeChainKeys = await getDb()
      .select()
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, AGENT_ID));
    const beforePolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    const beforeTransactions = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.agentId, AGENT_ID));
    const beforeApprovals = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.agentId, AGENT_ID));
    const beforeSigners = await getDb()
      .select()
      .from(agentSigners)
      .where(eq(agentSigners.agentId, AGENT_ID));
    const beforeQuorums = await getDb()
      .select()
      .from(agentKeyQuorums)
      .where(eq(agentKeyQuorums.agentId, AGENT_ID));
    const beforeTradePolicies = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, AGENT_ID));
    const beforeRoutes = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.agentId, AGENT_ID));
    const beforeProxyRequests = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.agentId, AGENT_ID));
    const beforeLeases = await getDb()
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.agentId, AGENT_ID));
    const beforeExpiredLeaseEvents = await getDb()
      .select()
      .from(upstreamCredentialLeaseEvents)
      .where(eq(upstreamCredentialLeaseEvents.leaseId, expiredLeaseId));

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_delete_completion_audit_${AUDIT_TRIGGER_SUFFIX}()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.tenant_id = '${TENANT_ID}' AND NEW.action = 'agent.delete' THEN
            RAISE EXCEPTION 'required agent delete audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_delete_completion_audit_failure_${AUDIT_TRIGGER_SUFFIX}
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_delete_completion_audit_${AUDIT_TRIGGER_SUFFIX}()
        `),
      );
      const failed = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
      expect(failed.status).toBe(500);
      expect(await getDb().select().from(agents).where(eq(agents.id, AGENT_ID))).toEqual(
        beforeAgent,
      );
      expect(
        await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, AGENT_ID)),
      ).toEqual(beforeWallets);
      expect(
        await getDb().select().from(encryptedKeys).where(eq(encryptedKeys.agentId, AGENT_ID)),
      ).toEqual(beforeEvmKeys);
      expect(
        await getDb()
          .select()
          .from(encryptedChainKeys)
          .where(eq(encryptedChainKeys.agentId, AGENT_ID)),
      ).toEqual(beforeChainKeys);
      expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
        beforePolicies,
      );
      expect(
        await getDb().select().from(transactions).where(eq(transactions.agentId, AGENT_ID)),
      ).toEqual(beforeTransactions);
      expect(
        await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, AGENT_ID)),
      ).toEqual(beforeApprovals);
      expect(
        await getDb().select().from(agentSigners).where(eq(agentSigners.agentId, AGENT_ID)),
      ).toEqual(beforeSigners);
      expect(
        await getDb().select().from(agentKeyQuorums).where(eq(agentKeyQuorums.agentId, AGENT_ID)),
      ).toEqual(beforeQuorums);
      expect(
        await getDb().select().from(agentPolicies).where(eq(agentPolicies.agentId, AGENT_ID)),
      ).toEqual(beforeTradePolicies);
      expect(
        await getDb().select().from(secretRoutes).where(eq(secretRoutes.agentId, AGENT_ID)),
      ).toEqual(beforeRoutes);
      expect(
        await getDb()
          .select()
          .from(pendingProxyRequests)
          .where(eq(pendingProxyRequests.agentId, AGENT_ID)),
      ).toEqual(beforeProxyRequests);
      expect(
        await getDb()
          .select()
          .from(upstreamCredentialLeases)
          .where(eq(upstreamCredentialLeases.agentId, AGENT_ID)),
      ).toEqual(beforeLeases);
      expect(
        await getDb()
          .select()
          .from(upstreamCredentialLeaseEvents)
          .where(eq(upstreamCredentialLeaseEvents.leaseId, expiredLeaseId)),
      ).toEqual(beforeExpiredLeaseEvents);
      expect(
        await getDb()
          .select()
          .from(upstreamCredentialLeaseEvents)
          .where(eq(upstreamCredentialLeaseEvents.leaseId, leaseId)),
      ).toHaveLength(0);
      expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).not.toBeNull();
    } finally {
      try {
        await getDb().execute(
          sql.raw(
            `DROP TRIGGER IF EXISTS agent_delete_completion_audit_failure_${AUDIT_TRIGGER_SUFFIX} ON audit_events`,
          ),
        );
      } finally {
        await getDb().execute(
          sql.raw(
            `DROP FUNCTION IF EXISTS fail_agent_delete_completion_audit_${AUDIT_TRIGGER_SUFFIX}()`,
          ),
        );
      }
    }

    const retry = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(retry.status).toBe(200);
    expect(await getDb().select().from(agents).where(eq(agents.id, AGENT_ID))).toHaveLength(0);
    expect(
      await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(transactions).where(eq(transactions.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(agentSigners).where(eq(agentSigners.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(agentKeyQuorums).where(eq(agentKeyQuorums.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(agentPolicies).where(eq(agentPolicies.agentId, AGENT_ID)),
    ).toHaveLength(0);
    const [disabledRoute] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(disabledRoute).toMatchObject({ enabled: false, agentId: AGENT_ID });
    const terminalProxyRequests = await getDb()
      .select({ id: pendingProxyRequests.id, status: pendingProxyRequests.status })
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.agentId, AGENT_ID));
    expect(new Map(terminalProxyRequests.map(({ id, status }) => [id, status]))).toEqual(
      new Map([
        [pendingRequestId, "denied"],
        [executingRequestId, "denied"],
      ]),
    );
    const [disposedLease] = await getDb()
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, leaseId));
    expect(disposedLease).toMatchObject({
      status: "revoked",
      revokedAt: expect.any(Date),
      tokenHash: null,
      tokenCiphertext: null,
      tokenIv: null,
      tokenAuthTag: null,
      tokenSalt: null,
    });
    expect(
      await getDb()
        .select()
        .from(upstreamCredentialLeaseEvents)
        .where(eq(upstreamCredentialLeaseEvents.leaseId, leaseId)),
    ).toEqual([
      expect.objectContaining({
        tenantId: TENANT_ID,
        action: "lease.agent_authority_deleted",
        decision: "deny",
        metadata: { terminalStatus: "revoked" },
      }),
    ]);
    const [preservedExpiredLease] = await getDb()
      .select()
      .from(upstreamCredentialLeases)
      .where(eq(upstreamCredentialLeases.id, expiredLeaseId));
    expect(preservedExpiredLease).toMatchObject({
      status: "expired",
      revokedAt: null,
      tokenHash: null,
      tokenCiphertext: null,
      tokenIv: null,
      tokenAuthTag: null,
      tokenSalt: null,
    });
    const expiredLeaseEvents = await getDb()
      .select()
      .from(upstreamCredentialLeaseEvents)
      .where(eq(upstreamCredentialLeaseEvents.leaseId, expiredLeaseId));
    expect(expiredLeaseEvents).toHaveLength(beforeExpiredLeaseEvents.length + 1);
    expect(expiredLeaseEvents).toEqual(
      expect.arrayContaining([
        ...beforeExpiredLeaseEvents,
        expect.objectContaining({
          tenantId: TENANT_ID,
          action: "lease.agent_authority_deleted",
          decision: "deny",
          metadata: { terminalStatus: "expired" },
        }),
      ]),
    );

    const deleteAudits = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.delete.authorized", "agent.delete"]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(deleteAudits.map(({ action }) => action)).toEqual([
      "agent.delete.authorized",
      "agent.delete.authorized",
      "agent.delete",
    ]);
  });

  it("serializes concurrent deletes and publishes one completion audit on real Postgres", async () => {
    if (!USING_REAL_POSTGRES) return;
    const concurrentAgentId = `concurrent-delete-${crypto.randomUUID()}`;
    await getDb().insert(agents).values({
      id: concurrentAgentId,
      tenantId: TENANT_ID,
      name: "Concurrent delete",
      walletAddress: "0x9999999999999999999999999999999999999999",
    });
    const app = await makeApp("admin");
    const responses = await Promise.all([
      app.request(`/agents/${concurrentAgentId}`, { method: "DELETE" }),
      app.request(`/agents/${concurrentAgentId}`, { method: "DELETE" }),
    ]);
    expect(responses.map(({ status }) => status).sort()).toEqual([200, 404]);
    expect(
      await getDb().select().from(agents).where(eq(agents.id, concurrentAgentId)),
    ).toHaveLength(0);
    const completionAudits = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, concurrentAgentId),
          eq(auditEvents.action, "agent.delete"),
        ),
      );
    expect(completionAudits).toEqual([{ action: "agent.delete" }]);
  });

  it("refuses deletion while proxy work is executing, then deletes after completion", async () => {
    const executingAgentId = `executing-delete-${crypto.randomUUID()}`;
    const requestId = crypto.randomUUID();
    await getDb().insert(agents).values({
      id: executingAgentId,
      tenantId: TENANT_ID,
      name: "Executing delete",
      walletAddress: "0x8888888888888888888888888888888888888888",
    });
    await getDb()
      .insert(pendingProxyRequests)
      .values({
        id: requestId,
        tenantId: TENANT_ID,
        agentId: executingAgentId,
        routeId: crypto.randomUUID(),
        method: "POST",
        targetHost: "executing-delete.example.test",
        targetPath: "/mutation",
        requestDigest: "9".repeat(64),
        bodyCiphertext: "body",
        bodyIv: "iv",
        bodyAuthTag: "tag",
        bodySalt: "salt",
        status: "executing",
        expiresAt: new Date(Date.now() + 60_000),
      });
    const app = await makeApp("admin");
    const blocked = await app.request(`/agents/${executingAgentId}`, { method: "DELETE" });
    expect(blocked.status).toBe(409);
    expect(await getDb().select().from(agents).where(eq(agents.id, executingAgentId))).toHaveLength(
      1,
    );
    await getDb()
      .update(pendingProxyRequests)
      .set({ status: "executed", executedAt: new Date() })
      .where(eq(pendingProxyRequests.id, requestId));
    const completed = await app.request(`/agents/${executingAgentId}`, { method: "DELETE" });
    expect(completed.status).toBe(200);
    expect(await getDb().select().from(agents).where(eq(agents.id, executingAgentId))).toHaveLength(
      0,
    );
  });

  it("fences lease and proxy creation behind a concurrent parent delete on real Postgres", async () => {
    if (!USING_REAL_POSTGRES) return;
    const creatorId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    await getDb()
      .insert(users)
      .values({
        id: creatorId,
        email: `${creatorId}@delete-race.test`,
      });
    await getDb()
      .insert(workspaces)
      .values({
        id: workspaceId,
        tenantId: TENANT_ID,
        key: `delete-race-${workspaceId}`,
        name: "Delete race workspace",
        environment: "production",
        createdBy: creatorId,
      });

    for (const kind of ["lease", "pending", "executing"] as const) {
      const agentId = `${kind}-delete-race-${crypto.randomUUID()}`;
      const proxyRequestId = crypto.randomUUID();
      await getDb()
        .insert(agents)
        .values({
          id: agentId,
          tenantId: TENANT_ID,
          name: `${kind} delete race`,
          walletAddress:
            kind === "lease"
              ? "0x7777777777777777777777777777777777777777"
              : "0x6666666666666666666666666666666666666666",
        });
      if (kind === "executing") {
        await getDb()
          .insert(pendingProxyRequests)
          .values({
            id: proxyRequestId,
            tenantId: TENANT_ID,
            agentId,
            routeId: crypto.randomUUID(),
            method: "POST",
            targetHost: "delete-race.example.test",
            targetPath: "/mutation",
            requestDigest: "6".repeat(64),
            bodyCiphertext: "body",
            bodyIv: "iv",
            bodyAuthTag: "tag",
            bodySalt: "salt",
            status: "approved",
            expiresAt: new Date(Date.now() + 60_000),
          });
      }
      let releaseDelete!: () => void;
      const mayDelete = new Promise<void>((resolve) => {
        releaseDelete = resolve;
      });
      let signalLocked!: () => void;
      const parentLocked = new Promise<void>((resolve) => {
        signalLocked = resolve;
      });
      const deleteTx = getDb().transaction(async (tx) => {
        await tx
          .select({ id: agents.id })
          .from(agents)
          .where(and(eq(agents.id, agentId), eq(agents.tenantId, TENANT_ID)))
          .for("update");
        signalLocked();
        await mayDelete;
        await tx
          .update(pendingProxyRequests)
          .set({ status: "denied", denialReason: "agent authority deleted" })
          .where(
            and(
              eq(pendingProxyRequests.tenantId, TENANT_ID),
              eq(pendingProxyRequests.agentId, agentId),
              inArray(pendingProxyRequests.status, ["pending", "approved"]),
            ),
          );
        await tx.delete(agents).where(and(eq(agents.id, agentId), eq(agents.tenantId, TENANT_ID)));
      });
      await parentLocked;
      const creation =
        kind === "lease"
          ? getDb()
              .insert(upstreamCredentialLeases)
              .values({
                tenantId: TENANT_ID,
                workspaceId,
                agentId,
                grantId: crypto.randomUUID(),
                capabilityId: crypto.randomUUID(),
                issuer: "github-app-installation",
                resource: {},
                resourceHash: "2".repeat(64),
                authorityDigest: "3".repeat(64),
                idempotencyKeyHash: "4".repeat(64),
              })
          : kind === "pending"
            ? getDb()
                .insert(pendingProxyRequests)
                .values({
                  tenantId: TENANT_ID,
                  agentId,
                  routeId: crypto.randomUUID(),
                  method: "POST",
                  targetHost: "delete-race.example.test",
                  targetPath: "/mutation",
                  requestDigest: "5".repeat(64),
                  bodyCiphertext: "body",
                  bodyIv: "iv",
                  bodyAuthTag: "tag",
                  bodySalt: "salt",
                  expiresAt: new Date(Date.now() + 60_000),
                })
            : getDb()
                .update(pendingProxyRequests)
                .set({ status: "executing" })
                .where(eq(pendingProxyRequests.id, proxyRequestId));
      let settled = false;
      const observedCreation = creation.then(
        () => ({ ok: true as const, error: null }),
        (error: unknown) => ({ ok: false as const, error }),
      );
      void observedCreation.then(() => {
        settled = true;
      });
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(settled).toBe(false);
      releaseDelete();
      await deleteTx;
      const result = await observedCreation;
      expect(result.ok).toBe(false);
      expect(result.error).toBeInstanceOf(Error);
    }
  });
});
