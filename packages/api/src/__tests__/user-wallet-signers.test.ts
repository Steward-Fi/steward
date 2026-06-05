import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { agentSigners, agents, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { eq } from "drizzle-orm";

const USER_ID = crypto.randomUUID();
const USER_ADDRESS = "0x1234567890123456789012345678901234567890";
const PERSONAL_TENANT_ID = `personal-${USER_ID}`;
const PRIMARY_WALLET_AGENT_ID = `user-wallet-${USER_ID}`;
const WALLET_AGENT_ID = `user-wallet-${USER_ID}-2`;
const RECIPIENT = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

describe("user wallet additional signers API", () => {
  let userRoutes: typeof import("../routes/user").userRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-wallet-signers-master-password";
    process.env.STEWARD_JWT_SECRET = "user-wallet-signers-jwt-secret-32chars";
    process.env.STEWARD_AUDIT_HMAC_KEY = "user-wallet-signers-audit-hmac-key-32chars";
    process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING = "true";
    process.env.STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values({ id: PERSONAL_TENANT_ID, name: "User Wallet Signers", apiKeyHash: "hash" });
    await getDb()
      .insert(users)
      .values({ id: USER_ID, walletAddress: USER_ADDRESS, walletChain: "ethereum" });
    await getDb()
      .insert(userTenants)
      .values({ userId: USER_ID, tenantId: PERSONAL_TENANT_ID, role: "owner" });
    await getDb()
      .insert(agents)
      .values([
        {
          id: PRIMARY_WALLET_AGENT_ID,
          tenantId: PERSONAL_TENANT_ID,
          name: "Primary User Wallet",
          walletAddress: USER_ADDRESS,
          platformId: `user:${USER_ID}`,
        },
        {
          id: WALLET_AGENT_ID,
          tenantId: PERSONAL_TENANT_ID,
          name: "Indexed User Wallet",
          walletAddress: USER_ADDRESS,
          platformId: `user:${USER_ID}`,
        },
      ]);

    ({ userRoutes } = await import("../routes/user"));
    ({ createSessionToken } = await import("../routes/auth"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING;
    delete process.env.STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING;
  });

  async function token(opts: { mfa?: boolean } = {}) {
    return createSessionToken(USER_ADDRESS, PERSONAL_TENANT_ID, {
      userId: USER_ID,
      tenantId: PERSONAL_TENANT_ID,
      ...(opts.mfa ? { mfaVerifiedAt: Date.now(), mfaMethod: "totp" } : {}),
    });
  }

  async function createSigner(
    subjectId: string,
    permissions: string[],
  ): Promise<{ id: string; credentialSecret: string }> {
    const response = await userRoutes.request("/me/wallet/signers", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token({ mfa: true })}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        walletIndex: 2,
        subjectId,
        permissions,
      }),
    });
    const body = (await response.json()) as {
      data: { id: string; credentialSecret?: string };
    };
    expect(response.status).toBe(201);
    expect(typeof body.data.credentialSecret).toBe("string");
    return { id: body.data.id, credentialSecret: body.data.credentialSecret as string };
  }

  it("requires recent MFA to create user-wallet signer credentials", async () => {
    const response = await userRoutes.request("/me/wallet/signers", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ walletIndex: 2, subjectId: "device-no-mfa" }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA");
  });

  it("creates, lists, and revokes a bounded signer credential for an indexed wallet", async () => {
    const auth = { Authorization: `Bearer ${await token({ mfa: true })}` };
    const createResponse = await userRoutes.request("/me/wallet/signers", {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({
        walletIndex: 2,
        subjectType: "external",
        subjectId: "device-1",
        label: "Laptop",
        permissions: ["sign_transaction", "sign_message"],
        metadata: { device: "laptop" },
      }),
    });
    const created = (await createResponse.json()) as {
      ok: boolean;
      data: {
        id: string;
        agentId: string;
        signerType: string;
        keyType: string;
        permissions: string[];
        policyIds: string[];
        metadata: Record<string, unknown>;
        hasCredential: boolean;
        credentialSecret?: string;
      };
    };

    expect(createResponse.status).toBe(201);
    expect(createResponse.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(createResponse.headers.get("Pragma")).toBe("no-cache");
    expect(createResponse.headers.get("Expires")).toBe("0");
    expect(created.ok).toBe(true);
    expect(created.data.agentId).toBe(WALLET_AGENT_ID);
    expect(created.data.signerType).toBe("delegated");
    expect(created.data.keyType).toBe("hmac");
    expect(created.data.permissions).toEqual(["sign_transaction", "sign_message"]);
    expect(created.data.policyIds).toEqual([]);
    expect(created.data.hasCredential).toBe(true);
    expect(created.data.credentialSecret?.startsWith("stwd_signer_")).toBe(true);
    expect(created.data.metadata).toEqual({ device: "laptop" });
    expect(created.data.metadata.credentialHash).toBeUndefined();

    const [stored] = await getDb()
      .select({ metadata: agentSigners.metadata })
      .from(agentSigners)
      .where(eq(agentSigners.id, created.data.id));
    expect(typeof stored?.metadata.credentialHash).toBe("string");

    const listResponse = await userRoutes.request(
      "/me/wallet/signers?walletIndex=2&status=active",
      { headers: auth },
    );
    const listed = (await listResponse.json()) as {
      data: {
        signers: Array<{
          id: string;
          credentialSecret?: string;
          metadata: Record<string, unknown>;
          hasCredential: boolean;
        }>;
      };
    };
    expect(listResponse.status).toBe(200);
    expect(listed.data.signers).toHaveLength(1);
    expect(listed.data.signers[0].id).toBe(created.data.id);
    expect(listed.data.signers[0].credentialSecret).toBeUndefined();
    expect(listed.data.signers[0].metadata.credentialHash).toBeUndefined();
    expect(listed.data.signers[0].hasCredential).toBe(true);

    const revokeResponse = await userRoutes.request(
      `/me/wallet/signers/${created.data.id}?walletIndex=2`,
      {
        method: "DELETE",
        headers: auth,
      },
    );
    const revoked = (await revokeResponse.json()) as { data: { status: string } };
    expect(revokeResponse.status).toBe(200);
    expect(revoked.data.status).toBe("revoked");
  });

  it("rejects forbidden non-signing capabilities and caller supplied secrets", async () => {
    const auth = {
      Authorization: `Bearer ${await token({ mfa: true })}`,
      "Content-Type": "application/json",
    };
    const exportPermission = await userRoutes.request("/me/wallet/signers", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        walletIndex: 2,
        subjectId: "bad-export",
        permissions: ["sign_transaction", "export_private_key"],
      }),
    });
    expect(exportPermission.status).toBe(400);
    expect(((await exportPermission.json()) as { error?: string }).error).toContain(
      "private-key export",
    );

    const callerSecret = await userRoutes.request("/me/wallet/signers", {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        walletIndex: 2,
        subjectId: "bad-secret",
        credentialSecret: "stwd_signer_weak",
      }),
    });
    expect(callerSecret.status).toBe(400);
    expect(((await callerSecret.json()) as { error?: string }).error).toContain("server-generated");
  });

  it("allows a user-wallet signer credential to sign transactions for its selected walletIndex", async () => {
    const signer = await createSigner("device-tx-signer", ["sign_transaction"]);
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xsigned");
    try {
      const response = await userRoutes.request("/me/wallet/sign", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-steward-signer-id": signer.id,
          "x-steward-signer-secret": signer.credentialSecret,
        },
        body: JSON.stringify({
          walletIndex: 2,
          to: RECIPIENT,
          value: "1",
          chainId: 8453,
          broadcast: false,
        }),
      });
      const body = (await response.json()) as { ok: boolean; data?: { txHash: string } };

      expect(response.status).toBe(200);
      expect(body.ok).toBe(true);
      expect(body.data?.txHash).toBe("0xsigned");
      expect(signSpy).toHaveBeenCalled();
      const [request] = signSpy.mock.calls[0];
      expect(request.agentId).toBe(WALLET_AGENT_ID);
      expect(request.tenantId).toBe(PERSONAL_TENANT_ID);

      const [stored] = await getDb()
        .select({ metadata: agentSigners.metadata })
        .from(agentSigners)
        .where(eq(agentSigners.id, signer.id));
      expect(typeof stored?.metadata.credentialLastUsedAt).toBe("string");
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  it("rejects a user-wallet signer credential for a different selected walletIndex", async () => {
    const signer = await createSigner("device-wrong-wallet", ["sign_transaction"]);
    const response = await userRoutes.request("/me/wallet/sign", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-steward-signer-id": signer.id,
        "x-steward-signer-secret": signer.credentialSecret,
      },
      body: JSON.stringify({
        walletIndex: 0,
        to: RECIPIENT,
        value: "1",
        chainId: 8453,
        broadcast: false,
      }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("selected walletIndex");
  });

  it("allows signer-authorized message signing but not management, recovery, or export routes", async () => {
    const signer = await createSigner("device-message-signer", ["sign_message"]);
    const signSpy = spyOn(Vault.prototype, "signMessage").mockResolvedValue("0xmessage");
    const signerHeaders = {
      "x-steward-signer-id": signer.id,
      "x-steward-signer-secret": signer.credentialSecret,
    };
    try {
      const signed = await userRoutes.request("/me/wallet/sign-message", {
        method: "POST",
        headers: { ...signerHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ walletIndex: 2, message: "hello from signer" }),
      });
      expect(signed.status).toBe(200);
      expect(signSpy).toHaveBeenCalledWith(
        PERSONAL_TENANT_ID,
        WALLET_AGENT_ID,
        "hello from signer",
      );

      for (const [path, init] of [
        ["/me/wallet/signers?walletIndex=2", { method: "GET" }],
        ["/me/wallet/policies?walletIndex=2", { method: "GET" }],
        ["/me/wallet/export", { method: "POST" }],
        ["/me/wallet/recovery/setup", { method: "POST" }],
        ["/me/wallet/recovery/restore", { method: "POST" }],
      ] as const) {
        const response = await userRoutes.request(path, {
          ...init,
          headers: signerHeaders,
        });
        expect(response.status).toBe(401);
      }
    } finally {
      signSpy.mockRestore();
    }
  });
});
