import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agentSigners, agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `delegated-action-signer-tenant-${Date.now()}`;
const AGENT_ID = `delegated-action-signer-agent-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const BLOCKED = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

describe("vault delegated action signer enforcement", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  const signerIds: Record<string, string> = {};

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-delegated-action-signer-master-password";
    process.env.STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING = "true";
    process.env.STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Delegated Action Signer Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Delegated Action Signer Agent",
      walletAddress: ALLOWED,
    });
    await getDb()
      .insert(policies)
      .values({
        id: "delegated-action-approved-recipients",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED], mode: "whitelist" },
      });

    for (const [name, permissions] of Object.entries({
      transfer: ["wallet_action_transfer"],
      sendCalls: ["wallet_action_send_calls"],
      userOperation: ["sign_user_operation"],
      authorization: ["sign_authorization"],
      readOnly: ["read_account"],
    })) {
      const [signer] = await getDb()
        .insert(agentSigners)
        .values({
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "api_key",
          subjectId: `api-key:${name}`,
          permissions,
        })
        .returning();
      signerIds[name] = signer.id;
    }

    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_UNSAFE_USER_OPERATION_SIGNING;
    delete process.env.STEWARD_ALLOW_UNSAFE_AUTHORIZATION_SIGNING;
  });

  it("rejects transfer actions without signer-bound authentication", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("signer-bound");
  });

  it("rejects bare batch-call delegated signer ids before permission evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/send-calls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.readOnly,
      },
      body: JSON.stringify({
        calls: [{ to: ALLOWED, value: "1" }],
        chainId: 8453,
        broadcast: false,
      }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("signer-bound");
  });

  it("rejects forged transfer signer ids before policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.transfer,
      },
      body: JSON.stringify({ to: BLOCKED, value: "1", chainId: 8453, broadcast: false }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("signer-bound");
  });

  it("rejects forged send-calls signer ids before policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/send-calls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.sendCalls,
      },
      body: JSON.stringify({
        calls: [{ to: BLOCKED, value: "1" }],
        chainId: 8453,
        broadcast: false,
      }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("signer-bound");
  });

  it("rejects bare user-operation delegated signer ids before permission evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-user-operation`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.readOnly,
      },
      body: JSON.stringify(userOperationBody(ALLOWED)),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin session with recent MFA");
  });

  it("rejects forged user-operation signer ids before policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-user-operation`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.userOperation,
      },
      body: JSON.stringify(userOperationBody(BLOCKED)),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin session with recent MFA");
  });

  it("rejects bare authorization delegated signer ids before permission evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-authorization`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.readOnly,
      },
      body: JSON.stringify({ contractAddress: ALLOWED, chainId: 8453, nonce: 1 }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin session with recent MFA");
  });

  it("rejects forged authorization signer ids before policy evaluation", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-authorization`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerIds.authorization,
      },
      body: JSON.stringify({ contractAddress: BLOCKED, chainId: 8453, nonce: 1 }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin session with recent MFA");
  });
});

function userOperationBody(to: string) {
  return {
    userOperation: {
      sender: ALLOWED,
      nonce: "0",
      callData: "0x",
      verificationGasLimit: "100000",
      callGasLimit: "100000",
      preVerificationGas: "21000",
      maxPriorityFeePerGas: "1000000",
      maxFeePerGas: "2000000",
    },
    chainId: 8453,
    to,
    value: "0",
  };
}
