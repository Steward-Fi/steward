import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agentKeyQuorums, agentSigners, agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";
import { createSignerCredentialHash } from "../services/signer-credentials";

const TENANT_ID = `delegated-tx-signer-tenant-${Date.now()}`;
const AGENT_ID = `delegated-tx-signer-agent-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const BLOCKED = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SIGNER_SECRET = "stwd_signer_delegated_transaction_signer_secret_0001";
const QUORUM_SIGNER_SECRET = "stwd_signer_delegated_transaction_quorum_secret_0001";
const READ_ONLY_SECRET = "stwd_signer_delegated_transaction_read_only_secret_0001";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "api-key");
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault delegated transaction signer enforcement", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let signerId = "";
  let quorumSignerId = "";
  let noPermissionSignerId = "";
  let quorumId = "";
  let readOnlyQuorumId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-delegated-transaction-signer-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Delegated Transaction Signer Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Delegated Transaction Signer Agent",
      walletAddress: ALLOWED,
    });
    await getDb()
      .insert(policies)
      .values({
        id: "delegated-tx-approved-recipients",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED], mode: "whitelist" },
      });
    const [signer] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "api_key",
        subjectId: "api-key:tx",
        permissions: ["sign_transaction"],
        metadata: { credentialHash: await createSignerCredentialHash(SIGNER_SECRET) },
      })
      .returning();
    signerId = signer.id;
    const [quorumSigner] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "quorum_member",
        subjectType: "api_key",
        subjectId: "api-key:quorum-tx",
        permissions: ["sign_transaction"],
        metadata: { credentialHash: await createSignerCredentialHash(QUORUM_SIGNER_SECRET) },
      })
      .returning();
    quorumSignerId = quorumSigner.id;
    const [noPermissionSigner] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "api_key",
        subjectId: "api-key:read-only",
        permissions: ["read_account"],
        metadata: { credentialHash: await createSignerCredentialHash(READ_ONLY_SECRET) },
      })
      .returning();
    noPermissionSignerId = noPermissionSigner.id;
    const [quorum] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Transaction signing quorum",
        threshold: 2,
        memberSignerIds: [signerId, quorumSignerId],
        permissions: ["sign_transaction"],
      })
      .returning();
    quorumId = quorum.id;
    const [readOnlyQuorum] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Read-only quorum",
        threshold: 1,
        memberSignerIds: [signerId],
        permissions: ["read_account"],
      })
      .returning();
    readOnlyQuorumId = readOnlyQuorum.id;
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("rejects transaction signing without signer-bound authentication", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("signer-bound");
  });

  it("rejects bare delegated signer ids even when the id exists", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": noPermissionSignerId,
      },
      body: JSON.stringify({ to: ALLOWED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("signer-bound");
  });

  it("rejects invalid signer credentials before policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerId,
        "x-steward-signer-secret": "wrong-secret",
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Invalid or inactive");
  });

  it("rejects signer credentials without sign_transaction permission", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": noPermissionSignerId,
        "x-steward-signer-secret": READ_ONLY_SECRET,
      },
      body: JSON.stringify({ to: ALLOWED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("sign_transaction");
  });

  it("allows signer-bound credentials with sign_transaction permission to reach policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerId,
        "x-steward-signer-secret": SIGNER_SECRET,
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Transaction rejected by policy");
  });

  it("rejects key quorum credentials that do not meet threshold", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-key-quorum-id": quorumId,
        "x-steward-key-quorum-credentials": JSON.stringify([
          { signerId, signerSecret: SIGNER_SECRET },
        ]),
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("threshold");
  });

  it("rejects key quorum credentials from non-member signers", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-key-quorum-id": quorumId,
        "x-steward-key-quorum-credentials": JSON.stringify([
          { signerId, signerSecret: SIGNER_SECRET },
          { signerId: noPermissionSignerId, signerSecret: READ_ONLY_SECRET },
        ]),
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("non-member");
  });

  it("rejects key quorums without the requested permission", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-key-quorum-id": readOnlyQuorumId,
        "x-steward-key-quorum-credentials": JSON.stringify([
          { signerId, signerSecret: SIGNER_SECRET },
        ]),
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("sign_transaction");
  });

  it("rejects key quorum members that lack the requested permission", async () => {
    const [escalatingQuorum] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Escalating quorum",
        threshold: 1,
        memberSignerIds: [noPermissionSignerId],
        permissions: ["sign_transaction"],
      })
      .returning();

    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-key-quorum-id": escalatingQuorum.id,
        "x-steward-key-quorum-credentials": JSON.stringify([
          { signerId: noPermissionSignerId, signerSecret: READ_ONLY_SECRET },
        ]),
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("member lacks sign_transaction");
  });

  it("allows key quorum threshold credentials to reach policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-key-quorum-id": quorumId,
        "x-steward-key-quorum-credentials": JSON.stringify([
          { signerId, signerSecret: SIGNER_SECRET },
          { signerId: quorumSignerId, signerSecret: QUORUM_SIGNER_SECRET },
        ]),
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Transaction rejected by policy");
  });
});
