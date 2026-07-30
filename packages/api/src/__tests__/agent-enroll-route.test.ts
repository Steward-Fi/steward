/**
 * agent-enroll-route.test.ts — E2E route test for keypair-only agent enrollment
 * (lane A1, scope 1). Boots the enrollment routes on an in-memory pglite app and
 * proves an agent holding ONLY its keypair can obtain a short-lived agent token,
 * and that every failure path denies.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateP256KeyPair, signP256, verifyToken } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  agentSigners,
  agents,
  auditEvents,
  getDb,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `enroll-tenant-${Date.now()}`;
const AGENT_ID = `enroll-agent-${Date.now()}`;

setDefaultTimeout(30000);

let keypair: Awaited<ReturnType<typeof generateP256KeyPair>>;

async function makeApp() {
  const { agentEnrollRoutes } = await import("../routes/agent-enroll");
  const app = new Hono<{ Variables: AppVariables }>();
  app.route("/agent-enroll", agentEnrollRoutes);
  return app;
}

async function challenge(
  app: Awaited<ReturnType<typeof makeApp>>,
  agentId: string,
): Promise<{ nonce: string; canonicalString: string }> {
  const res = await app.request("/agent-enroll/challenge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ agentId }),
  });
  const body = (await res.json()) as {
    ok: boolean;
    data: { nonce: string; canonicalString: string };
  };
  expect(res.status).toBe(200);
  expect(body.ok).toBe(true);
  return body.data;
}

describe("agent enrollment route (keypair-only boot)", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "enroll-master-password-32-chars-min";
    process.env.STEWARD_JWT_SECRET = "enroll-jwt-secret-at-least-32-chars-long!!";
    process.env.STEWARD_AUDIT_HMAC_KEY = "enroll-audit-hmac-key-at-least-32-chars-long";
    __resetAuditHmacKeyCacheForTests();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    keypair = await generateP256KeyPair();

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Enroll Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Enroll Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    // Register the agent's P-256 enrollment key (this is the "provisioning" step;
    // the agent boots holding the matching PRIVATE key).
    await getDb().insert(agentSigners).values({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      signerType: "service",
      subjectType: "agent",
      subjectId: AGENT_ID,
      keyType: "p256",
      publicKey: keypair.publicKeySpkiBase64,
      status: "active",
    });

    app = await makeApp();
  });

  afterAll(async () => {
    const { closeDb } = await import("@stwd/db");
    await closeDb().catch(() => {});
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    __resetAuditHmacKeyCacheForTests();
  });

  it("issues a short-lived agent token for a valid signed challenge", async () => {
    const { nonce, canonicalString } = await challenge(app, AGENT_ID);
    const signature = await signP256(keypair.privateKey, canonicalString);

    const res = await app.request("/agent-enroll/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: AGENT_ID, nonce, signature }),
    });
    const body = (await res.json()) as {
      ok: boolean;
      data: { token: string; tenantId: string; scope: string };
    };
    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.data.tenantId).toBe(TENANT_ID);
    expect(body.data.scope).toBe("agent");

    const [event] = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "capability.enroll")));
    expect(event?.actorType).toBe("agent");
    expect(event?.actorId).toBe(AGENT_ID);
    expect(event?.resourceType).toBe("agent");
    expect(event?.metadata).toMatchObject({ decision: "allow", ttl: "5m" });

    // The minted token is a real, verifiable short-lived agent token.
    const payload = await verifyToken(body.data.token);
    expect(payload.agentId).toBe(AGENT_ID);
    expect(payload.tenantId).toBe(TENANT_ID);
    expect(payload.scope).toBe("agent");
  });

  it("rejects a wrong-key signature", async () => {
    const other = await generateP256KeyPair();
    const { nonce, canonicalString } = await challenge(app, AGENT_ID);
    const badSig = await signP256(other.privateKey, canonicalString);

    const res = await app.request("/agent-enroll/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: AGENT_ID, nonce, signature: badSig }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects a replayed nonce", async () => {
    const { nonce, canonicalString } = await challenge(app, AGENT_ID);
    const signature = await signP256(keypair.privateKey, canonicalString);
    const first = await app.request("/agent-enroll/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: AGENT_ID, nonce, signature }),
    });
    expect(first.status).toBe(200);
    const second = await app.request("/agent-enroll/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: AGENT_ID, nonce, signature }),
    });
    expect(second.status).toBe(401);
  });

  it("rejects an unknown agent (no registered key)", async () => {
    const { nonce, canonicalString } = await challenge(app, "no-such-agent");
    const signature = await signP256(keypair.privateKey, canonicalString);
    const res = await app.request("/agent-enroll/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: "no-such-agent", nonce, signature }),
    });
    expect(res.status).toBe(401);
  });

  it("requires agentId on challenge", async () => {
    const res = await app.request("/agent-enroll/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });
});
