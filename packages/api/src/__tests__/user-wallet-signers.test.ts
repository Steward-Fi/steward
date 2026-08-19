import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import {
  agentSigners,
  agents,
  auditEvents,
  closeDb,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { and, eq, sql } from "drizzle-orm";

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
    process.env.STEWARD_SIGNER_CREDENTIAL_PEPPER = "user-wallet-signers-credential-pepper-32chars";
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
    delete process.env.STEWARD_SIGNER_CREDENTIAL_PEPPER;
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
      error?: string;
    };
    if (response.status !== 201) throw new Error(`signer creation failed: ${body.error}`);
    expect(typeof body.data.credentialSecret).toBe("string");
    return { id: body.data.id, credentialSecret: body.data.credentialSecret as string };
  }

  async function signerRequest(
    signer: { id: string; credentialSecret: string },
    body: Record<string, unknown>,
    headers: Record<string, string> = {},
  ) {
    return userRoutes.request("/me/wallet/sign", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-steward-signer-id": signer.id,
        "x-steward-signer-secret": signer.credentialSecret,
        ...headers,
      },
      body: JSON.stringify({
        walletIndex: 2,
        to: RECIPIENT,
        value: "1",
        chainId: 8453,
        broadcast: false,
        ...body,
      }),
    });
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

  it("requires replay protection for broadcasts and passes the requested persistence status", async () => {
    const signer = await createSigner("device-replay-status", ["sign_transaction"]);
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xsigned");
    try {
      const missingKey = await signerRequest(signer, { broadcast: true });
      expect(missingKey.status).toBe(400);
      expect(signSpy).not.toHaveBeenCalled();
      expect(rpcSpy).not.toHaveBeenCalled();

      const signed = await signerRequest(signer, { broadcast: false });
      expect(signed.status).toBe(200);
      expect(signSpy.mock.calls[0]?.[1]?.status).toBe("signed");

      const broadcast = await signerRequest(
        signer,
        { broadcast: true },
        { "Idempotency-Key": crypto.randomUUID() },
      );
      expect(broadcast.status).toBe(200);
      expect(signSpy.mock.calls[1]?.[1]?.status).toBe("broadcast");
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  it("rejects non-uint256 values and caller-controlled gas before RPC or signing", async () => {
    const signer = await createSigner("device-value-guards", ["sign_transaction"]);
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xsigned");
    try {
      const invalidValues: unknown[] = ["-1", "1.5", "1e3", "abc", 1, (2n ** 256n).toString()];
      for (const value of invalidValues) {
        expect((await signerRequest(signer, { value })).status).toBe(400);
      }
      expect((await signerRequest(signer, { gasLimit: "21000" })).status).toBe(403);
      expect(rpcSpy).not.toHaveBeenCalled();
      expect(signSpy).not.toHaveBeenCalled();

      expect((await signerRequest(signer, { value: "0" })).status).toBe(200);
      const maxBoundary = await signerRequest(signer, { value: (2n ** 256n - 1n).toString() });
      expect(maxBoundary.status).not.toBe(400);
      expect(rpcSpy).toHaveBeenCalledTimes(2);
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  it("fails closed when recipient contract-code verification is unavailable or unsafe", async () => {
    const signer = await createSigner("device-recipient-guard", ["sign_transaction"]);
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough");
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xsigned");
    try {
      for (const result of [
        Promise.reject(new Error("provider unavailable")),
        Promise.resolve({ jsonrpc: "2.0", id: 1, error: { code: -1, message: "no" } }),
        Promise.resolve({ jsonrpc: "2.0", id: 1, result: "malformed" }),
        Promise.resolve({ jsonrpc: "2.0", id: 1, result: "0x6000" }),
      ]) {
        rpcSpy.mockImplementationOnce(() => result as ReturnType<Vault["rpcPassthrough"]>);
      }
      expect((await signerRequest(signer, {})).status).toBe(502);
      expect((await signerRequest(signer, {})).status).toBe(502);
      expect((await signerRequest(signer, {})).status).toBe(502);
      expect((await signerRequest(signer, {})).status).toBe(403);
      expect(signSpy).not.toHaveBeenCalled();
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  it("enforces indexed-wallet policy against aggregate user-wallet spend", async () => {
    const signer = await createSigner("device-aggregate-spend", ["sign_transaction"]);
    const policyId = `aggregate-${crypto.randomUUID()}`;
    const transactionId = `aggregate-${crypto.randomUUID()}`;
    await getDb()
      .insert(policies)
      .values({
        id: policyId,
        agentId: WALLET_AGENT_ID,
        type: "spending-limit",
        config: { maxPerTx: "100", maxPerDay: "100", maxPerWeek: "100" },
      });
    await getDb().insert(transactions).values({
      id: transactionId,
      agentId: PRIMARY_WALLET_AGENT_ID,
      status: "signed",
      toAddress: RECIPIENT,
      value: "60",
      chainId: 8453,
    });
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xsigned");
    try {
      const response = await signerRequest(signer, { value: "60" });
      expect(response.status).toBe(403);
      expect(signSpy).not.toHaveBeenCalled();
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
      await getDb().delete(transactions).where(eq(transactions.id, transactionId));
      await getDb().delete(policies).where(eq(policies.id, policyId));
    }
  });

  it("returns a completed signing result when only completion auditing fails", async () => {
    const signer = await createSigner("device-bookkeeping-failure", ["sign_transaction"]);
    await getDb().execute(
      sql.raw(`
      CREATE OR REPLACE FUNCTION fail_user_wallet_completion_audit()
      RETURNS trigger AS $$
      BEGIN
        IF NEW.action = 'user.wallet.sign' THEN
          RAISE EXCEPTION 'hostile completion audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `),
    );
    await getDb().execute(
      sql.raw(`
      CREATE TRIGGER user_wallet_completion_audit_failure
      BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION fail_user_wallet_completion_audit()
    `),
    );
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xcompleted");
    try {
      const response = await signerRequest(signer, {});
      const body = (await response.json()) as { ok: boolean; data?: { txHash: string } };
      expect(response.status).toBe(200);
      expect(body).toMatchObject({ ok: true, data: { txHash: "0xcompleted" } });
      const actions = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, PERSONAL_TENANT_ID),
            sql`${auditEvents.action} in ('user.wallet.sign.authorized', 'user.wallet.sign.failed')`,
          ),
        );
      expect(actions.some(({ action }) => action === "user.wallet.sign.authorized")).toBe(true);
      expect(actions.some(({ action }) => action === "user.wallet.sign.failed")).toBe(false);
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
      await getDb().execute(
        sql.raw("DROP TRIGGER user_wallet_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(sql.raw("DROP FUNCTION fail_user_wallet_completion_audit()"));
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

  it("durably records authorization before an unsafe message-signing attempt", async () => {
    const signer = await createSigner("device-message-failure", ["sign_message"]);
    const authorizedBefore = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, PERSONAL_TENANT_ID),
          eq(auditEvents.action, "user.wallet.sign_message.authorized"),
        ),
      );
    const completedBefore = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, PERSONAL_TENANT_ID),
          eq(auditEvents.action, "user.wallet.sign_message"),
        ),
      );
    const signSpy = spyOn(Vault.prototype, "signMessage").mockRejectedValue(
      new Error("hostile signer failure"),
    );
    try {
      const response = await userRoutes.request("/me/wallet/sign-message", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-steward-signer-id": signer.id,
          "x-steward-signer-secret": signer.credentialSecret,
        },
        body: JSON.stringify({ walletIndex: 2, message: "behavioral audit ordering" }),
      });
      expect(response.status).toBe(500);

      const after = await getDb()
        .select({ action: auditEvents.action, metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, PERSONAL_TENANT_ID),
            sql`${auditEvents.action} in ('user.wallet.sign_message.authorized', 'user.wallet.sign_message')`,
          ),
        );
      const authorized = after.filter(
        ({ action }) => action === "user.wallet.sign_message.authorized",
      );
      expect(authorized).toHaveLength(authorizedBefore.length + 1);
      expect(
        authorized.some(
          ({ metadata }) => metadata.unsafeCompatibilityMode === true && metadata.walletIndex === 2,
        ),
      ).toBe(true);
      expect(after.filter(({ action }) => action === "user.wallet.sign_message")).toHaveLength(
        completedBefore.length,
      );
    } finally {
      signSpy.mockRestore();
    }
  });
});
