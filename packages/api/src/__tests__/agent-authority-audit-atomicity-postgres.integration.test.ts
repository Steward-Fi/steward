import { expect, it, setDefaultTimeout } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agentKeyQuorums,
  agentPolicies,
  agentSigners,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  policies,
  tenants,
} from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";

setDefaultTimeout(120_000);
const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;
type Result = { status: number; body: string };

async function waiters(client: ReturnType<typeof createDb>["client"], count: number) {
  for (let attempt = 0; attempt < 400; attempt++) {
    const [row] = await client<
      { count: string }[]
    >`SELECT count(*)::text count FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory'`;
    if (Number(row?.count ?? 0) >= count) return;
    await Bun.sleep(10);
  }
  throw new Error(`Expected ${count} PostgreSQL advisory-lock waiter(s)`);
}

async function request(
  tenantId: string,
  path: string,
  method: string,
  requestId: string,
  body?: string,
): Promise<Result> {
  const fixture = new URL("./fixtures/agent-authority-route-writer.ts", import.meta.url).pathname;
  const child = Bun.spawn([process.execPath, fixture], {
    cwd: new URL("../../../..", import.meta.url).pathname,
    env: {
      ...process.env,
      TEST_TENANT_ID: tenantId,
      TEST_PATH: path,
      TEST_METHOD: method,
      TEST_REQUEST_ID: requestId,
      ...(body === undefined ? {} : { TEST_BODY: body }),
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (code !== 0) throw new Error(`route fixture failed: ${stderr}`);
  return JSON.parse(stdout.trim().split("\n").at(-1) ?? "") as Result;
}

realPostgresIt(
  "serializes authority races and rolls mutation back with its completion audit",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `authority-atomic-${suffix}`;
    const agentId = `authority-agent-${suffix}`;
    const initialPolicyAgentId = `authority-policy-${suffix}`;
    const signerId = crypto.randomUUID(),
      signerBId = crypto.randomUUID(),
      quorumId = crypto.randomUUID(),
      policyId = crypto.randomUUID();
    const triggerFunction = `fail_authority_audit_${suffix}`,
      triggerName = triggerFunction;
    const failureGate = Number.parseInt(suffix.slice(0, 12), 16);
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    process.env.STEWARD_MASTER_PASSWORD = `authority-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `authority-audit-${suffix}`;
    __resetAuditHmacKeyCacheForTests();
    const admin = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    const rid = (name: string) => `${name}-${suffix}`;
    let heldLock: string | null = null,
      failureGateHeld = false;
    try {
      await admin.db.insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: suffix });
      await admin.db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: "0x1111111111111111111111111111111111111111",
      });
      await admin.db.insert(agents).values({
        id: initialPolicyAgentId,
        tenantId,
        name: initialPolicyAgentId,
        walletAddress: "0x2222222222222222222222222222222222222222",
      });
      await admin.db.insert(agentSigners).values([
        {
          id: signerId,
          tenantId,
          agentId,
          signerType: "delegated",
          subjectType: "external",
          subjectId: `signer-${suffix}`,
          permissions: ["sign_message"],
          label: "initial",
          status: "active",
        },
        {
          id: signerBId,
          tenantId,
          agentId,
          signerType: "delegated",
          subjectType: "external",
          subjectId: `signer-b-${suffix}`,
          permissions: ["sign_message"],
          status: "active",
        },
      ]);
      await admin.db.insert(agentKeyQuorums).values({
        id: quorumId,
        tenantId,
        agentId,
        name: "initial quorum",
        threshold: 1,
        memberSignerIds: [signerId, signerBId],
        permissions: ["sign_message"],
        status: "active",
      });
      await admin.db.insert(policies).values({
        id: policyId,
        agentId,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "100" },
      });
      const authorityKey = `steward_agent_authority_${tenantId}:${agentId}`;
      const race = async (
        firstFactory: () => Promise<Result>,
        secondFactory: () => Promise<Result>,
      ) => {
        await locker`SELECT pg_advisory_lock(hashtextextended(${authorityKey},0))`;
        heldLock = authorityKey;
        const first = firstFactory();
        await waiters(admin.client, 1);
        const second = secondFactory();
        await waiters(admin.client, 2);
        await locker`SELECT pg_advisory_unlock(hashtextextended(${authorityKey},0))`;
        heldLock = null;
        return Promise.all([first, second]);
      };
      const signerResponses = await race(
        () =>
          request(
            tenantId,
            `/agents/${agentId}/signers/${signerId}`,
            "PATCH",
            rid("signer-a"),
            JSON.stringify({ label: "winner-a" }),
          ),
        () =>
          request(
            tenantId,
            `/agents/${agentId}/signers/${signerId}`,
            "PATCH",
            rid("signer-b"),
            JSON.stringify({ label: "loser-b" }),
          ),
      );
      expect(signerResponses.map((x) => x.status)).toEqual([200, 409]);
      expect(
        await admin.db
          .select({ label: agentSigners.label })
          .from(agentSigners)
          .where(eq(agentSigners.id, signerId)),
      ).toEqual([{ label: "winner-a" }]);
      const signerRevokeResponses = await race(
        () =>
          request(
            tenantId,
            `/agents/${agentId}/signers/${signerId}`,
            "DELETE",
            rid("signer-revoke"),
          ),
        () =>
          request(
            tenantId,
            `/agents/${agentId}/signers/${signerId}`,
            "PATCH",
            rid("signer-after-revoke"),
            JSON.stringify({ label: "must-not-resurrect" }),
          ),
      );
      expect(signerRevokeResponses.map((x) => x.status)).toEqual([200, 409]);
      expect(
        await admin.db
          .select({ label: agentSigners.label, status: agentSigners.status })
          .from(agentSigners)
          .where(eq(agentSigners.id, signerId)),
      ).toEqual([{ label: "winner-a", status: "revoked" }]);
      const quorumResponses = await race(
        () =>
          request(
            tenantId,
            `/agents/${agentId}/key-quorums/${quorumId}`,
            "DELETE",
            rid("quorum-revoke"),
          ),
        () =>
          request(
            tenantId,
            `/agents/${agentId}/key-quorums/${quorumId}`,
            "PATCH",
            rid("quorum-update"),
            JSON.stringify({ name: "must-not-overwrite" }),
          ),
      );
      expect(quorumResponses.map((x) => x.status)).toEqual([200, 409]);
      expect(
        await admin.db
          .select({ name: agentKeyQuorums.name, status: agentKeyQuorums.status })
          .from(agentKeyQuorums)
          .where(eq(agentKeyQuorums.id, quorumId)),
      ).toEqual([{ name: "initial quorum", status: "revoked" }]);
      const policyBody = (limit: string) =>
        JSON.stringify([{ type: "spending-limit", enabled: true, config: { maxPerTx: limit } }]);
      const policyResponses = await race(
        () =>
          request(
            tenantId,
            `/agents/${agentId}/policies`,
            "PUT",
            rid("policy-a"),
            policyBody("10"),
          ),
        () =>
          request(
            tenantId,
            `/agents/${agentId}/policies`,
            "PUT",
            rid("policy-b"),
            policyBody("20"),
          ),
      );
      expect(policyResponses.map((x) => x.status)).toEqual([200, 409]);
      expect(
        await admin.db
          .select({ config: policies.config })
          .from(policies)
          .where(eq(policies.agentId, agentId)),
      ).toEqual([{ config: { maxPerTx: "10" } }]);
      const initialPolicyKey = `steward_agent_authority_${tenantId}:${initialPolicyAgentId}`;
      await locker`SELECT pg_advisory_lock(hashtextextended(${initialPolicyKey},0))`;
      heldLock = initialPolicyKey;
      const firstInitialPolicy = request(
        tenantId,
        `/agents/${initialPolicyAgentId}/policy`,
        "PUT",
        rid("initial-policy-a"),
        JSON.stringify({ reason: "create initial policy", dailyCap: 50, perOrderCap: 5 }),
      );
      await waiters(admin.client, 1);
      const secondInitialPolicy = request(
        tenantId,
        `/agents/${initialPolicyAgentId}/policy`,
        "PUT",
        rid("initial-policy-b"),
        JSON.stringify({ reason: "preserve first partial update", leverageCap: 2 }),
      );
      await waiters(admin.client, 2);
      await locker`SELECT pg_advisory_unlock(hashtextextended(${initialPolicyKey},0))`;
      heldLock = null;
      expect(
        (await Promise.all([firstInitialPolicy, secondInitialPolicy])).map((x) => x.status),
      ).toEqual([200, 200]);
      expect(
        await admin.db
          .select({
            dailyCapUsd: agentPolicies.dailyCapUsd,
            perOrderCapUsd: agentPolicies.perOrderCapUsd,
            leverageCap: agentPolicies.leverageCap,
            updatedReason: agentPolicies.updatedReason,
          })
          .from(agentPolicies)
          .where(eq(agentPolicies.agentId, initialPolicyAgentId)),
      ).toEqual([
        {
          dailyCapUsd: "50",
          perOrderCapUsd: "5",
          leverageCap: "2",
          updatedReason: "preserve first partial update",
        },
      ]);
      const failRequestId = rid("fail-signer"),
        successRequestId = rid("success-signer");
      await admin.client.unsafe(
        `CREATE FUNCTION "${triggerFunction}"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.request_id='${failRequestId}' AND NEW.action='agent.signer.update' THEN PERFORM pg_advisory_xact_lock(${failureGate}); RAISE EXCEPTION 'forced authority completion audit failure'; END IF; RETURN NEW; END $$`,
      );
      await admin.client.unsafe(
        `CREATE TRIGGER "${triggerName}" BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION "${triggerFunction}"()`,
      );
      await locker`SELECT pg_advisory_lock(${failureGate})`;
      failureGateHeld = true;
      const failedUpdate = request(
        tenantId,
        `/agents/${agentId}/signers/${signerId}`,
        "PATCH",
        failRequestId,
        JSON.stringify({ label: "must-roll-back" }),
      );
      await waiters(admin.client, 1);
      const successfulUpdate = request(
        tenantId,
        `/agents/${agentId}/signers/${signerId}`,
        "PATCH",
        successRequestId,
        JSON.stringify({ label: "surviving-winner" }),
      );
      await waiters(admin.client, 2);
      await locker`SELECT pg_advisory_unlock(${failureGate})`;
      failureGateHeld = false;
      const [failed, successful] = await Promise.all([failedUpdate, successfulUpdate]);
      expect([failed.status, successful.status]).toEqual([500, 200]);
      expect(
        await admin.db
          .select({ label: agentSigners.label })
          .from(agentSigners)
          .where(eq(agentSigners.id, signerId)),
      ).toEqual([{ label: "surviving-winner" }]);
      const completionEvents = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, tenantId),
            inArray(auditEvents.action, [
              "agent.signer.update",
              "agent.signer.revoke",
              "agent.key_quorum.revoke",
              "agent.key_quorum.update",
              "agent.policies.update",
            ]),
          ),
        );
      expect(completionEvents.filter((x) => x.requestId === failRequestId)).toHaveLength(0);
      expect(completionEvents.filter((x) => x.requestId === successRequestId)).toEqual([
        { action: "agent.signer.update", requestId: successRequestId },
      ]);
      expect(completionEvents).toHaveLength(5);
      expect(
        await admin.db
          .select({ requestId: auditEvents.requestId })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, tenantId),
              eq(auditEvents.action, "agent.policy.updated"),
              eq(auditEvents.resourceId, initialPolicyAgentId),
            ),
          )
          .orderBy(auditEvents.seq),
      ).toEqual([{ requestId: rid("initial-policy-a") }, { requestId: rid("initial-policy-b") }]);
    } finally {
      if (failureGateHeld) await locker`SELECT pg_advisory_unlock(${failureGate})`;
      if (heldLock) await locker`SELECT pg_advisory_unlock(hashtextextended(${heldLock},0))`;
      locker.release();
      await admin.client.unsafe(`DROP TRIGGER IF EXISTS "${triggerName}" ON audit_events`);
      await admin.client.unsafe(`DROP FUNCTION IF EXISTS "${triggerFunction}"()`);
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db.delete(agentKeyQuorums).where(eq(agentKeyQuorums.tenantId, tenantId));
      await admin.db.delete(agentSigners).where(eq(agentSigners.tenantId, tenantId));
      await admin.db.delete(policies).where(eq(policies.agentId, agentId));
      await admin.db.delete(agentPolicies).where(eq(agentPolicies.agentId, initialPolicyAgentId));
      await admin.db.delete(agents).where(inArray(agents.id, [agentId, initialPolicyAgentId]));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.client.end();
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
      __resetAuditHmacKeyCacheForTests();
    }
  },
);
