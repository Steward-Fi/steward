import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { createHash } from "node:crypto";
import { generateP256KeyPair } from "@stwd/auth";
import { agentSigners, agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `agent-signers-tenant-${Date.now()}`;
const AGENT_ID = `agent-signers-agent-${Date.now()}`;

setDefaultTimeout(30000);

async function makeApp(authMode: "admin" | "admin-no-mfa" | "api-key" = "admin") {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "admin" || authMode === "admin-no-mfa") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", "signer-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    } else {
      c.set("authType", "api-key");
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

describe("agent signer API", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let signerId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-signers-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-signers-audit-hmac-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Agent Signers Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Agent Signers Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    await getDb()
      .insert(policies)
      .values([
        {
          id: "signer-policy",
          agentId: AGENT_ID,
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "100" },
        },
        {
          id: "signer-policy-2",
          agentId: AGENT_ID,
          type: "rate-limit",
          enabled: true,
          config: { maxTxPerHour: 1, maxTxPerDay: 2 },
        },
      ]);
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("creates, lists, updates, and revokes delegated signer metadata", async () => {
    const createResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "wallet",
        subjectId: "0xabc",
        address: "0x1234567890123456789012345678901234567890",
        chainFamily: "evm",
        label: "Ops signer",
        permissions: ["sign_transaction", "sign_message"],
        policyIds: ["signer-policy"],
        metadata: { ticket: "SEC-1" },
        issueCredential: true,
      }),
    });
    expect(createResponse.status).toBe(201);
    expect(createResponse.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(createResponse.headers.get("Pragma")).toBe("no-cache");
    expect(createResponse.headers.get("Expires")).toBe("0");
    const created = (await createResponse.json()) as {
      ok: boolean;
      data: {
        id: string;
        signerType: string;
        permissions: string[];
        policyIds: string[];
        status: string;
        hasCredential: boolean;
        credentialSecret?: string;
        metadata: Record<string, unknown>;
      };
    };
    expect(created.ok).toBe(true);
    expect(created.data.signerType).toBe("delegated");
    expect(created.data.permissions).toEqual(["sign_transaction", "sign_message"]);
    expect(created.data.policyIds).toEqual(["signer-policy"]);
    expect(created.data.status).toBe("active");
    expect(created.data.hasCredential).toBe(true);
    expect(created.data.credentialSecret?.startsWith("stwd_signer_")).toBe(true);
    expect(created.data.metadata).toEqual({ ticket: "SEC-1" });
    expect(created.data.metadata.credentialHash).toBeUndefined();
    signerId = created.data.id;
    const [storedSigner] = await getDb()
      .select({ metadata: agentSigners.metadata })
      .from(agentSigners)
      .where(eq(agentSigners.id, signerId));
    const storedCredentialHash =
      storedSigner?.metadata && typeof storedSigner.metadata.credentialHash === "string"
        ? storedSigner.metadata.credentialHash
        : "";
    expect(storedCredentialHash.startsWith("stwd_scrypt_v1$")).toBe(true);
    expect(storedCredentialHash).not.toBe(
      createHash("sha256")
        .update(created.data.credentialSecret ?? "")
        .digest("hex"),
    );

    const listResponse = await app.request(`/agents/${AGENT_ID}/signers?status=active`);
    expect(listResponse.status).toBe(200);
    const listed = (await listResponse.json()) as {
      ok: boolean;
      data: {
        signers: Array<{
          id: string;
          label: string | null;
          hasCredential: boolean;
          policyIds: string[];
          credentialSecret?: string;
          metadata: Record<string, unknown>;
        }>;
      };
    };
    expect(listed.ok).toBe(true);
    expect(listed.data.signers).toHaveLength(1);
    expect(listed.data.signers[0].id).toBe(signerId);
    expect(listed.data.signers[0].policyIds).toEqual(["signer-policy"]);
    expect(listed.data.signers[0].hasCredential).toBe(true);
    expect(listed.data.signers[0].credentialSecret).toBeUndefined();
    expect(listed.data.signers[0].metadata.credentialHash).toBeUndefined();

    const updateResponse = await app.request(`/agents/${AGENT_ID}/signers/${signerId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        status: "paused",
        label: "Paused ops signer",
        policyIds: ["signer-policy-2"],
      }),
    });
    expect(updateResponse.status).toBe(200);
    const updated = (await updateResponse.json()) as {
      ok: boolean;
      data: { status: string; label: string | null; policyIds: string[] };
    };
    expect(updated.data.status).toBe("paused");
    expect(updated.data.label).toBe("Paused ops signer");
    expect(updated.data.policyIds).toEqual(["signer-policy-2"]);

    const revokeResponse = await app.request(`/agents/${AGENT_ID}/signers/${signerId}`, {
      method: "DELETE",
    });
    expect(revokeResponse.status).toBe(200);
    const revoked = (await revokeResponse.json()) as { data: { status: string } };
    expect(revoked.data.status).toBe("revoked");
  });

  it("rejects duplicate signer subjects and invalid permissions", async () => {
    const duplicateResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "wallet",
        subjectId: "0xabc",
      }),
    });
    expect(duplicateResponse.status).toBe(409);

    const invalidResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "wallet",
        subjectId: "0xdef",
        permissions: ["ok", ""],
      }),
    });
    const invalid = (await invalidResponse.json()) as { ok: boolean; error?: string };
    expect(invalidResponse.status).toBe(400);
    expect(invalid.ok).toBe(false);
    expect(invalid.error).toContain("permissions");
  });

  it("rejects signer policy scopes that do not belong to the agent", async () => {
    const response = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "foreign-policy-scope",
        permissions: ["sign_transaction"],
        policyIds: ["not-this-agent"],
      }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("policyIds must reference policies on this agent");
  });

  it("requires recent MFA before changing signer policy scope", async () => {
    const noMfaApp = await makeApp("admin-no-mfa");
    const response = await noMfaApp.request(`/agents/${AGENT_ID}/signers/${signerId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policyIds: ["signer-policy"] }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Signer updates requires recent MFA verification");
  });

  it("rejects caller-chosen delegated signer credential secrets", async () => {
    const response = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "weak-credential",
        credentialSecret: "stwd_signer_00000000000000000000",
      }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("server-generated");
  });

  it("registers P-256 authorization-key signers through the public route", async () => {
    const keypair = await generateP256KeyPair();
    const createResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "p256-auth-key",
        keyType: "p256",
        publicKey: keypair.publicKeySpkiBase64,
        permissions: ["sign_message"],
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      data: {
        keyType: string;
        publicKey: string;
        hasCredential: boolean;
        credentialSecret?: string;
      };
    };
    expect(created.data.keyType).toBe("p256");
    expect(created.data.publicKey).toBe(keypair.publicKeySpkiBase64);
    expect(created.data.hasCredential).toBe(false);
    expect(created.data.credentialSecret).toBeUndefined();

    const invalidResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "p256-invalid",
        keyType: "p256",
        publicKey: "not-a-p256-key",
      }),
    });
    const invalid = (await invalidResponse.json()) as { ok: boolean; error?: string };
    expect(invalidResponse.status).toBe(400);
    expect(invalid.ok).toBe(false);
    expect(invalid.error).toContain("valid P-256");
  });

  it("requires recent MFA for signer credential issuance and reserved metadata is not writable", async () => {
    const noMfaApp = await makeApp("admin-no-mfa");
    const noMfaResponse = await noMfaApp.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "no-mfa",
        issueCredential: true,
      }),
    });
    const noMfa = (await noMfaResponse.json()) as { ok: boolean; error?: string };
    expect(noMfaResponse.status).toBe(403);
    expect(noMfa.ok).toBe(false);
    expect(noMfa.error).toContain("recent MFA");

    const reservedResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "reserved-metadata",
        metadata: { credentialHash: "attacker-controlled" },
      }),
    });
    const reserved = (await reservedResponse.json()) as { ok: boolean; error?: string };
    expect(reservedResponse.status).toBe(400);
    expect(reserved.ok).toBe(false);
    expect(reserved.error).toContain("reserved");
  });

  it("requires recent MFA for signer pause and revocation", async () => {
    const noMfaApp = await makeApp("admin-no-mfa");
    const createResponse = await app.request(`/agents/${AGENT_ID}/signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signerType: "delegated",
        subjectType: "external",
        subjectId: "mfa-status-change",
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as { data: { id: string } };

    const pauseResponse = await noMfaApp.request(`/agents/${AGENT_ID}/signers/${created.data.id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "paused" }),
    });
    const pause = (await pauseResponse.json()) as { ok: boolean; error?: string };
    expect(pauseResponse.status).toBe(403);
    expect(pause.ok).toBe(false);
    expect(pause.error).toContain("recent MFA");

    const revokeResponse = await noMfaApp.request(
      `/agents/${AGENT_ID}/signers/${created.data.id}`,
      { method: "DELETE" },
    );
    const revoke = (await revokeResponse.json()) as { ok: boolean; error?: string };
    expect(revokeResponse.status).toBe(403);
    expect(revoke.ok).toBe(false);
    expect(revoke.error).toContain("recent MFA");
  });

  it("does not expose signer inventory to non-admin tenant credentials", async () => {
    const apiKeyApp = await makeApp("api-key");
    const response = await apiKeyApp.request(`/agents/${AGENT_ID}/signers?status=active`);
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin");
  });
});
