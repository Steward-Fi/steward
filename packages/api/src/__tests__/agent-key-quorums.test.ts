import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agentKeyQuorums,
  agentSigners,
  agents,
  auditEvents,
  getDb,
  tenants,
} from "@stwd/db";
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import {
  cleanupAgentBehaviorTestDatabase,
  setupAgentBehaviorTestDatabase,
} from "./agent-behavior-test-database";

const TENANT_ID = `agent-quorums-tenant-${Date.now()}`;
const AGENT_ID = `agent-quorums-agent-${Date.now()}`;
const AUDIT_TRIGGER_SUFFIX = `${process.pid}_${Math.random().toString(36).slice(2, 8)}`;
const MUTATED_ENV = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_AUDIT_HMAC_KEY",
] as const;
const originalEnv = new Map(MUTATED_ENV.map((name) => [name, process.env[name]]));

async function makeApp(authMode: "admin" | "admin-no-mfa" | "api-key" = "admin") {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "admin" || authMode === "admin-no-mfa") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", "quorum-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    } else {
      c.set("authType", "api-key");
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
  return app;
}

describe("agent key quorum API", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let signerA = "";
  let signerB = "";
  let pausedSigner = "";
  let quorumId = "";

  beforeAll(async () => {
    process.env.STEWARD_MASTER_PASSWORD = "agent-quorums-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-quorums-audit-hmac-key-with-enough-entropy";
    __resetAuditHmacKeyCacheForTests();
    await setupAgentBehaviorTestDatabase();
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Agent Quorums Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Agent Quorums Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    const rows = await getDb()
      .insert(agentSigners)
      .values([
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "wallet",
          subjectId: "0xaaa",
          address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          chainFamily: "evm",
          permissions: ["sign_transaction"],
          status: "active",
          createdBy: "seed",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "wallet",
          subjectId: "0xbbb",
          address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          chainFamily: "evm",
          permissions: ["sign_transaction"],
          status: "active",
          createdBy: "seed",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "wallet",
          subjectId: "0xccc",
          address: "0xcccccccccccccccccccccccccccccccccccccccc",
          chainFamily: "evm",
          permissions: ["sign_transaction"],
          status: "paused",
          createdBy: "seed",
        },
      ])
      .returning({ id: agentSigners.id });
    signerA = rows[0].id;
    signerB = rows[1].id;
    pausedSigner = rows[2].id;
    app = await makeApp();
  });

  afterAll(async () => {
    try {
      await cleanupAgentBehaviorTestDatabase(TENANT_ID);
    } finally {
      for (const [name, value] of originalEnv) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      __resetAuditHmacKeyCacheForTests();
    }
  });

  it("creates, lists, updates, and revokes key quorums", async () => {
    const createResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Treasury quorum",
        threshold: 2,
        memberSignerIds: [signerA, signerB],
        permissions: ["sign_transaction"],
        metadata: { scope: "treasury" },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      ok: boolean;
      data: {
        id: string;
        name: string;
        threshold: number;
        memberSignerIds: string[];
        permissions: string[];
        status: string;
        metadata: Record<string, unknown>;
      };
    };
    expect(created.ok).toBe(true);
    expect(created.data.name).toBe("Treasury quorum");
    expect(created.data.threshold).toBe(2);
    expect(created.data.memberSignerIds).toEqual([signerA, signerB]);
    expect(created.data.permissions).toEqual(["sign_transaction"]);
    expect(created.data.status).toBe("active");
    expect(created.data.metadata).toEqual({ scope: "treasury" });
    quorumId = created.data.id;

    const listResponse = await app.request(`/agents/${AGENT_ID}/key-quorums?status=active`);
    expect(listResponse.status).toBe(200);
    const listed = (await listResponse.json()) as {
      ok: boolean;
      data: { quorums: Array<{ id: string; status: string }> };
    };
    expect(listed.ok).toBe(true);
    expect(listed.data.quorums).toHaveLength(1);
    expect(listed.data.quorums[0].id).toBe(quorumId);

    const updateResponse = await app.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ threshold: 1, status: "paused" }),
    });
    expect(updateResponse.status).toBe(200);
    const updated = (await updateResponse.json()) as {
      ok: boolean;
      data: { threshold: number; status: string };
    };
    expect(updated.data.threshold).toBe(1);
    expect(updated.data.status).toBe("paused");

    const revokeResponse = await app.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "DELETE",
    });
    expect(revokeResponse.status).toBe(200);
    const revoked = (await revokeResponse.json()) as { data: { status: string } };
    expect(revoked.data.status).toBe("revoked");

    const auditRows = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          inArray(auditEvents.action, [
            "agent.key_quorum.create.authorized",
            "agent.key_quorum.create",
            "agent.key_quorum.update.authorized",
            "agent.key_quorum.update",
            "agent.key_quorum.revoke.authorized",
            "agent.key_quorum.revoke",
          ]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(auditRows.map(({ action }) => action)).toEqual([
      "agent.key_quorum.create.authorized",
      "agent.key_quorum.create",
      "agent.key_quorum.update.authorized",
      "agent.key_quorum.update",
      "agent.key_quorum.revoke.authorized",
      "agent.key_quorum.revoke",
    ]);
    for (let index = 1; index < auditRows.length; index++) {
      expect(auditRows[index]?.seq).toBe(auditRows[index - 1]!.seq + 1);
    }
  });

  it("rejects invalid thresholds and inactive members", async () => {
    const thresholdResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Bad quorum",
        threshold: 3,
        memberSignerIds: [signerA, signerB],
      }),
    });
    const thresholdBody = (await thresholdResponse.json()) as { ok: boolean; error?: string };
    expect(thresholdResponse.status).toBe(400);
    expect(thresholdBody.ok).toBe(false);
    expect(thresholdBody.error).toContain("threshold");

    const inactiveResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Inactive signer quorum",
        threshold: 1,
        memberSignerIds: [pausedSigner],
      }),
    });
    const inactiveBody = (await inactiveResponse.json()) as { ok: boolean; error?: string };
    expect(inactiveResponse.status).toBe(400);
    expect(inactiveBody.ok).toBe(false);
    expect(inactiveBody.error).toContain("inactive signer");
  });

  it("creates parent quorums with child member quorum ids", async () => {
    const childResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Child quorum",
        threshold: 1,
        memberSignerIds: [signerA],
      }),
    });
    expect(childResponse.status).toBe(201);
    const child = (await childResponse.json()) as { data: { id: string } };

    const parentResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Parent quorum",
        threshold: 2,
        memberSignerIds: [signerB],
        memberQuorumIds: [child.data.id],
        permissions: ["sign_transaction"],
      }),
    });
    expect(parentResponse.status).toBe(201);
    const parent = (await parentResponse.json()) as {
      data: { threshold: number; memberSignerIds: string[]; memberQuorumIds: string[] };
    };
    expect(parent.data.threshold).toBe(2);
    expect(parent.data.memberSignerIds).toEqual([signerB]);
    expect(parent.data.memberQuorumIds).toEqual([child.data.id]);
  });

  it("does not expose key quorums to non-admin tenant credentials", async () => {
    const apiKeyApp = await makeApp("api-key");
    const response = await apiKeyApp.request(`/agents/${AGENT_ID}/key-quorums?status=active`);
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin");
  });

  it("requires recent MFA for key quorum creation and privilege changes", async () => {
    const noMfaApp = await makeApp("admin-no-mfa");
    const beforeQuorum = await getDb()
      .select()
      .from(agentKeyQuorums)
      .where(eq(agentKeyQuorums.id, quorumId));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));
    const createResponse = await noMfaApp.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "No MFA quorum",
        threshold: 1,
        memberSignerIds: [signerA],
        permissions: ["sign_transaction"],
      }),
    });
    expect(createResponse.status).toBe(403);
    await expect(createResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });

    const updateResponse = await noMfaApp.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ permissions: ["sign_transaction", "sign_message"] }),
    });
    expect(updateResponse.status).toBe(403);
    await expect(updateResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });

    const statusResponse = await noMfaApp.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "paused" }),
    });
    expect(statusResponse.status).toBe(403);
    await expect(statusResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });

    const deleteResponse = await noMfaApp.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "DELETE",
    });
    expect(deleteResponse.status).toBe(403);
    await expect(deleteResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });

    expect(
      await getDb().select().from(agentKeyQuorums).where(eq(agentKeyQuorums.id, quorumId)),
    ).toEqual(beforeQuorum);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
  });

  it("rolls back quorum creation, update, and revocation when completion audits fail", async () => {
    const [seeded] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Audit rollback quorum",
        threshold: 1,
        memberSignerIds: [signerA],
        permissions: ["sign_transaction"],
        status: "active",
        createdBy: "seed",
      })
      .returning();

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_quorum_completion_audit_${AUDIT_TRIGGER_SUFFIX}()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.tenant_id = '${TENANT_ID}' AND NEW.action IN (
            'agent.key_quorum.create',
            'agent.key_quorum.update',
            'agent.key_quorum.revoke'
          ) THEN
            RAISE EXCEPTION 'required agent quorum audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_quorum_completion_audit_failure_${AUDIT_TRIGGER_SUFFIX}
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_quorum_completion_audit_${AUDIT_TRIGGER_SUFFIX}()
        `),
      );
      const create = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: "Must not persist",
          threshold: 1,
          memberSignerIds: [signerB],
          permissions: ["sign_transaction"],
        }),
      });
      expect(create.status).toBe(500);
      expect(
        await getDb()
          .select()
          .from(agentKeyQuorums)
          .where(
            and(
              eq(agentKeyQuorums.agentId, AGENT_ID),
              eq(agentKeyQuorums.name, "Must not persist"),
            ),
          ),
      ).toHaveLength(0);

      const update = await app.request(`/agents/${AGENT_ID}/key-quorums/${seeded.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "must roll back" }),
      });
      expect(update.status).toBe(500);
      expect(
        await getDb().select().from(agentKeyQuorums).where(eq(agentKeyQuorums.id, seeded.id)),
      ).toEqual([seeded]);

      const revoke = await app.request(`/agents/${AGENT_ID}/key-quorums/${seeded.id}`, {
        method: "DELETE",
      });
      expect(revoke.status).toBe(500);
      expect(
        await getDb().select().from(agentKeyQuorums).where(eq(agentKeyQuorums.id, seeded.id)),
      ).toEqual([seeded]);
    } finally {
      await getDb().execute(
        sql.raw(
          `DROP TRIGGER IF EXISTS agent_quorum_completion_audit_failure_${AUDIT_TRIGGER_SUFFIX} ON audit_events`,
        ),
      );
      await getDb().execute(
        sql.raw(
          `DROP FUNCTION IF EXISTS fail_agent_quorum_completion_audit_${AUDIT_TRIGGER_SUFFIX}()`,
        ),
      );
    }
  });
});
