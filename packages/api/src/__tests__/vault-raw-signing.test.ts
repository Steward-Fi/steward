import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agentSigners, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { Hono } from "hono";
import { recoverAddress } from "viem";
import type { AppVariables } from "../services/context";

const TENANT_ID = `raw-sign-tenant-${Date.now()}`;
const AGENT_ID = `raw-sign-agent-${Date.now()}`;
const HASH = "0x1111111111111111111111111111111111111111111111111111111111111111" as const;

async function makeApp(authMode: "admin" | "api-key" = "admin") {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "admin") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("userId", "raw-sign-admin");
    } else {
      c.set("authType", "api-key");
    }
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault raw secp256k1 signing", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let walletAddress: string;
  let signerId = "";
  let noPermissionSignerId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-raw-signing-master-password";
    process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING = "true";
    process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Raw Signing Tenant",
      apiKeyHash: "hash",
    });
    const identity = await new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
    }).createAgent(TENANT_ID, AGENT_ID, "Raw Signing Agent");
    walletAddress = identity.walletAddress;
    const [signer] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "api_key",
        subjectId: "api-key:raw",
        permissions: ["sign_raw_hash"],
      })
      .returning();
    signerId = signer.id;
    const [noPermissionSigner] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "api_key",
        subjectId: "api-key:read-only",
        permissions: ["read_account"],
      })
      .returning();
    noPermissionSignerId = noPermissionSigner.id;
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING;
    delete process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING;
  });

  it("signs a 32-byte digest and recovers the agent EVM address", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-hash`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hash: HASH, referenceId: "raw-ref-1" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { signature: `0x${string}`; hash: typeof HASH; walletAddress: string };
    };

    expect(body.ok).toBe(true);
    expect(body.data.hash).toBe(HASH);
    expect(body.data.walletAddress.toLowerCase()).toBe(walletAddress.toLowerCase());

    const recovered = await recoverAddress({ hash: HASH, signature: body.data.signature });
    expect(recovered.toLowerCase()).toBe(walletAddress.toLowerCase());
  });

  it("rejects delegated signer ids for raw hash signing", async () => {
    const delegatedApp = await makeApp("api-key");
    const response = await delegatedApp.request(`/vault/${AGENT_ID}/sign-raw-hash`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerId,
      },
      body: JSON.stringify({ hash: HASH, referenceId: "raw-ref-delegated" }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin session with recent MFA");
  });

  it("rejects delegated signer ids regardless of signer permissions", async () => {
    const delegatedApp = await makeApp("api-key");
    const response = await delegatedApp.request(`/vault/${AGENT_ID}/sign-raw-hash`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": noPermissionSignerId,
      },
      body: JSON.stringify({ hash: HASH }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin session with recent MFA");
  });

  it("rejects non-32-byte hashes", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-hash`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hash: "0x1234" }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toBe("hash must be a 32-byte hex string");
  });
});
