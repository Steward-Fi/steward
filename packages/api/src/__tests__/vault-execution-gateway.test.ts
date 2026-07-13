import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import {
  agents,
  approvalQueue,
  auditEvents,
  closeDb,
  executionAuthorizationNonces,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import { executionPayloadDigestForEvmSign } from "../services/execution-authorization";

const TENANT_ID = `gateway-tenant-${Date.now()}`;
const AGENT_ID = `gateway-agent-${Date.now()}`;
const USER_ID = "00000000-0000-4000-8000-000000000123";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", USER_ID);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault EVM execution gateway", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_DB_MODE = "pglite";
    process.env.STEWARD_MASTER_PASSWORD = "gateway-test-master-password";
    process.env.STEWARD_JWT_SECRET = "gateway-test-jwt-secret-with-enough-entropy-0123456789";
    process.env.STEWARD_AUDIT_HMAC_KEY = "b".repeat(64);
    process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Gateway Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(users).values({
      id: USER_ID,
      email: "gateway-owner@example.test",
    });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: TENANT_ID,
      role: "owner",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Gateway Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb()
      .insert(policies)
      .values({
        id: `${AGENT_ID}-approved-addresses`,
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: {
          mode: "whitelist",
          addresses: ["0x1111111111111111111111111111111111111111"],
        },
      });
  });

  afterAll(async () => {
    delete process.env.STEWARD_ALLOW_UNSAFE_CONTRACT_CALL_SIGNING;
    await closeDb();
  });

  it("mints and consumes an execution authorization before primary EVM signing", async () => {
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      return "0xsigned";
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          data: "0x12345678",
          chainId: 8453,
          broadcast: false,
        }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);

      const nonceRows = await getDb()
        .select({ status: executionAuthorizationNonces.status })
        .from(executionAuthorizationNonces);
      expect(nonceRows).toEqual([{ status: "consumed" }]);

      const audits = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID));
      expect(audits.map((row) => row.action)).toContain("vault.execution_authorization.minted");
      expect(audits.map((row) => row.action)).toContain("vault.execution_authorization.consumed");
    } finally {
      signSpy.mockRestore();
    }
  });

  it("mints and consumes an execution authorization for primary EVM approval replay", async () => {
    const txId = "tx-gateway-approval-replay";
    const replayRequest = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      to: "0x1111111111111111111111111111111111111111",
      value: "1",
      data: "0x12345678",
      chainId: 8453,
      broadcast: false,
    };
    await getDb()
      .insert(transactions)
      .values({
        id: txId,
        agentId: AGENT_ID,
        status: "pending",
        toAddress: replayRequest.to,
        value: replayRequest.value,
        data: replayRequest.data,
        chainId: replayRequest.chainId,
        actionPayload: { type: "transaction", broadcast: false },
        executionPayloadDigest: executionPayloadDigestForEvmSign(replayRequest),
        executionPolicyRevisionHash: "queued-policy-revision",
        policyResults: [],
      });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: `aq-${txId}`,
        txId,
        agentId: AGENT_ID,
        status: "pending",
        requestedByType: "agent",
        requestedById: AGENT_ID,
      });

    const signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(async () => {
      return "0xsigned";
    });
    try {
      const app = await makeApp();
      const res = await app.request(`/vault/${AGENT_ID}/approve/${txId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(signSpy).toHaveBeenCalledTimes(1);

      const nonceRows = await getDb()
        .select({ status: executionAuthorizationNonces.status })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.requestId, txId));
      expect(nonceRows).toEqual([{ status: "consumed" }]);
    } finally {
      signSpy.mockRestore();
    }
  });
});
