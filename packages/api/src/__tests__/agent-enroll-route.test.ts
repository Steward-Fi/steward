/**
 * agent-enroll-route.test.ts — E2E route test for keypair-only agent enrollment
 * Boots the enrollment routes on an in-memory PGLite app and
 * proves an agent holding ONLY its keypair can obtain a short-lived agent token,
 * and that every failure path denies.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateP256KeyPair, signP256, verifyToken } from "@stwd/auth";
import { agentSigners, agents, auditEvents, eq, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `enroll-tenant-${Date.now()}`;
const AGENT_ID = `enroll-agent-${Date.now()}`;

setDefaultTimeout(30000);

let keypair: Awaited<ReturnType<typeof generateP256KeyPair>>;
let auditTransactionFailure: Error | undefined;
let successfulAuditTransactionsBeforeFailure = 0;

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

async function verifyEnrollment(
  app: Awaited<ReturnType<typeof makeApp>>,
  agentId = AGENT_ID,
): Promise<Response> {
  const { nonce, canonicalString } = await challenge(app, agentId);
  const signature = await signP256(keypair.privateKey, canonicalString);
  return app.request("/agent-enroll/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ agentId, nonce, signature }),
  });
}

async function enrollmentAuditMetadata(): Promise<Record<string, unknown>[]> {
  const rows = await getDb()
    .select({ metadata: auditEvents.metadata })
    .from(auditEvents)
    .where(eq(auditEvents.actorId, AGENT_ID))
    .orderBy(auditEvents.seq);
  return rows.map((row) => row.metadata);
}

describe("agent enrollment route (keypair-only boot)", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "enroll-master-password-32-chars-min";
    process.env.STEWARD_JWT_SECRET = "enroll-jwt-secret-at-least-32-chars-long!!";
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    const controlledDb = new Proxy(db, {
      get(target, property) {
        if (property === "transaction") {
          return (...args: unknown[]) => {
            if (auditTransactionFailure) {
              if (successfulAuditTransactionsBeforeFailure === 0) throw auditTransactionFailure;
              successfulAuditTransactionsBeforeFailure -= 1;
            }
            const transaction = Reflect.get(target, property, target) as (
              ...params: unknown[]
            ) => unknown;
            return Reflect.apply(transaction, target, args);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    setPGLiteOverride(controlledDb, async () => {
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

    // The minted token is a real, verifiable short-lived agent token.
    const payload = await verifyToken(body.data.token);
    expect(payload.agentId).toBe(AGENT_ID);
    expect(payload.tenantId).toBe(TENANT_ID);
    expect(payload.scope).toBe("agent");

    expect((await enrollmentAuditMetadata()).slice(-2)).toEqual([
      { stage: "authorization", decision: "allow", ttl: "5m" },
      { stage: "issuance", decision: "issued", ttl: "5m" },
    ]);
  });

  it("returns no token when the required authorization audit is unavailable", async () => {
    const diagnosticCanary = "AUDIT_DATABASE_NONCE_SIGNATURE_TOKEN_CANARY";
    const originalError = console.error;
    const diagnostics: unknown[][] = [];
    console.error = (...args: unknown[]) => diagnostics.push(args);
    auditTransactionFailure = new Error(diagnosticCanary);
    const before = await enrollmentAuditMetadata();
    try {
      const res = await verifyEnrollment(app);
      const body = (await res.json()) as { ok: boolean; data?: { token?: string }; error?: string };
      expect(res.status).toBe(503);
      expect(body).toEqual({ ok: false, error: "enrollment unavailable" });
      expect(body.data?.token).toBeUndefined();
    } finally {
      auditTransactionFailure = undefined;
      successfulAuditTransactionsBeforeFailure = 0;
      console.error = originalError;
    }

    expect(await enrollmentAuditMetadata()).toEqual(before);
    expect(JSON.stringify(diagnostics)).not.toContain(diagnosticCanary);
    expect(diagnostics).toEqual([
      ["[agent-enroll] authorization audit unavailable", { errorClass: "Error", errorCode: null }],
    ]);
  });

  it("returns no token when the issuance audit fails after signing", async () => {
    const diagnosticCanary = "ISSUANCE_AUDIT_TOKEN_CANARY";
    const originalError = console.error;
    const diagnostics: unknown[][] = [];
    console.error = (...args: unknown[]) => diagnostics.push(args);
    auditTransactionFailure = new Error(diagnosticCanary);
    // Authorization audit, then the agent-row lock/signing transaction, then
    // the required issuance audit. Fail the third transaction so this remains
    // an issuance-audit failure rather than a signing/lock failure.
    successfulAuditTransactionsBeforeFailure = 2;
    const before = await enrollmentAuditMetadata();
    try {
      const res = await verifyEnrollment(app);
      const body = (await res.json()) as { ok: boolean; data?: { token?: string }; error?: string };
      expect(res.status).toBe(503);
      expect(body).toEqual({ ok: false, error: "enrollment unavailable" });
      expect(body.data?.token).toBeUndefined();
    } finally {
      auditTransactionFailure = undefined;
      successfulAuditTransactionsBeforeFailure = 0;
      console.error = originalError;
    }

    const appended = (await enrollmentAuditMetadata()).slice(before.length);
    expect(appended).toEqual([{ stage: "authorization", decision: "allow", ttl: "5m" }]);
    expect(JSON.stringify(diagnostics)).not.toContain(diagnosticCanary);
    expect(diagnostics).toEqual([
      ["[agent-enroll] issuance audit unavailable", { errorClass: "Error", errorCode: null }],
    ]);
  });

  it("records authorization but never issuance when token signing fails", async () => {
    const { nonce, canonicalString } = await challenge(app, AGENT_ID);
    const signature = await signP256(keypair.privateKey, canonicalString);
    const originalNodeEnv = process.env.NODE_ENV;
    const originalJwtSecret = process.env.STEWARD_JWT_SECRET;
    const originalRateLimitSoftFail = process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    const originalTrustedProxyHops = process.env.STEWARD_TRUSTED_PROXY_HOPS;
    const signingCanary = "SIGNATURE_TOKEN_CANARY";
    const originalError = console.error;
    const diagnostics: unknown[][] = [];
    console.error = (...args: unknown[]) => diagnostics.push(args);
    process.env.NODE_ENV = "production";
    process.env.STEWARD_JWT_SECRET = signingCanary;
    process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    const before = await enrollmentAuditMetadata();
    try {
      const res = await app.request("/agent-enroll/verify", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "203.0.113.10",
        },
        body: JSON.stringify({ agentId: AGENT_ID, nonce, signature }),
      });
      const body = (await res.json()) as { ok: boolean; data?: { token?: string }; error?: string };
      expect(res.status).toBe(503);
      expect(body).toEqual({ ok: false, error: "enrollment unavailable" });
      expect(body.data?.token).toBeUndefined();
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
      if (originalJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = originalJwtSecret;
      if (originalRateLimitSoftFail === undefined) {
        delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
      } else {
        process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = originalRateLimitSoftFail;
      }
      if (originalTrustedProxyHops === undefined) delete process.env.STEWARD_TRUSTED_PROXY_HOPS;
      else process.env.STEWARD_TRUSTED_PROXY_HOPS = originalTrustedProxyHops;
      console.error = originalError;
    }

    const appended = (await enrollmentAuditMetadata()).slice(before.length);
    expect(appended).toEqual([{ stage: "authorization", decision: "allow", ttl: "5m" }]);
    expect(JSON.stringify(diagnostics)).not.toContain(signingCanary);
    expect(diagnostics).toEqual([
      ["[agent-enroll] token signing failed", { errorClass: "Error", errorCode: null }],
    ]);
  });

  it("keeps denial uniform and redacts diagnostics when its audit append fails", async () => {
    const { nonce, canonicalString } = await challenge(app, AGENT_ID);
    const other = await generateP256KeyPair();
    const signature = await signP256(other.privateKey, canonicalString);
    const diagnosticCanary = `DENIAL_${nonce}_${signature}_TOKEN_CANARY`;
    const originalError = console.error;
    const diagnostics: unknown[][] = [];
    console.error = (...args: unknown[]) => diagnostics.push(args);
    auditTransactionFailure = new Error(diagnosticCanary);
    try {
      const res = await app.request("/agent-enroll/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agentId: AGENT_ID, nonce, signature }),
      });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ ok: false, error: "enrollment denied" });
    } finally {
      auditTransactionFailure = undefined;
      successfulAuditTransactionsBeforeFailure = 0;
      console.error = originalError;
    }

    expect(JSON.stringify(diagnostics)).not.toContain(nonce);
    expect(JSON.stringify(diagnostics)).not.toContain(signature);
    expect(JSON.stringify(diagnostics)).not.toContain(diagnosticCanary);
    expect(diagnostics).toEqual([
      ["[agent-enroll] denial audit unavailable", { errorClass: "Error", errorCode: null }],
    ]);
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
