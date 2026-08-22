import { afterAll, beforeAll, beforeEach, describe, expect, it, spyOn } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
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
import { and, eq, inArray, sql } from "drizzle-orm";

const USER_ID = crypto.randomUUID();
const USER_ADDRESS = "0x1234567890123456789012345678901234567890";
const RECIPIENT = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TENANT_ID = `personal-${USER_ID}`;
const PRIMARY_WALLET = `user-wallet-${USER_ID}`;
const INDEXED_WALLET = `user-wallet-${USER_ID}-2`;
const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const SUFFIX = USER_ID.replaceAll("-", "");
const COMPLETION_TRIGGER = `fail_user_wallet_completion_${SUFFIX}`;
const AUTH_TRIGGER = `fail_user_wallet_authorization_${SUFFIX}`;

describe("mounted user-wallet signing hardening", () => {
  let app: typeof import("../app").app;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-wallet-signing-hardening-master-password";
    process.env.STEWARD_JWT_SECRET = "user-wallet-signing-hardening-jwt-secret";
    process.env.STEWARD_AUDIT_HMAC_KEY = "user-wallet-signing-hardening-audit-hmac-key";
    process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING = "true";
    process.env.STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING = "true";
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Mounted User Wallet Signing",
        apiKeyHash: `hash-${USER_ID}`,
      });
    await getDb().insert(users).values({
      id: USER_ID,
      walletAddress: USER_ADDRESS,
      walletChain: "ethereum",
    });
    await getDb()
      .insert(userTenants)
      .values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });
    await getDb()
      .insert(agents)
      .values([
        {
          id: PRIMARY_WALLET,
          tenantId: TENANT_ID,
          name: "Primary User Wallet",
          walletAddress: USER_ADDRESS,
          platformId: `user:${USER_ID}`,
        },
        {
          id: INDEXED_WALLET,
          tenantId: TENANT_ID,
          name: "Indexed User Wallet",
          walletAddress: USER_ADDRESS,
          platformId: `user:${USER_ID}`,
        },
      ]);

    ({ createSessionToken } = await import("../routes/auth"));
    ({ app } = await import("../app"));
  });

  beforeEach(async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "user-wallet-signing-hardening-audit-hmac-key";
    __resetAuditHmacKeyCacheForTests();
    await dropAuditTrigger(COMPLETION_TRIGGER);
    await dropAuditTrigger(AUTH_TRIGGER);
    await getDb()
      .delete(transactions)
      .where(inArray(transactions.agentId, [PRIMARY_WALLET, INDEXED_WALLET]));
    await getDb()
      .delete(policies)
      .where(inArray(policies.agentId, [PRIMARY_WALLET, INDEXED_WALLET]));
    await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID));
    await getDb().delete(auditChainHeads).where(eq(auditChainHeads.tenantId, TENANT_ID));
  });

  afterAll(async () => {
    await dropAuditTrigger(COMPLETION_TRIGGER);
    await dropAuditTrigger(AUTH_TRIGGER);
    await closeDb();
    for (const name of [
      "STEWARD_PGLITE_MEMORY",
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_JWT_SECRET",
      "STEWARD_AUDIT_HMAC_KEY",
      "STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING",
      "STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING",
      "STEWARD_ALLOW_KEY_EXPORT",
      "STEWARD_ALLOW_PRIVATE_KEY_EXPORT",
      "STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT",
    ])
      delete process.env[name];
    __resetAuditHmacKeyCacheForTests();
  });

  async function token(): Promise<string> {
    return createSessionToken(USER_ADDRESS, TENANT_ID, {
      userId: USER_ID,
      tenantId: TENANT_ID,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
  }

  async function signRequest(body: Record<string, unknown>, headers: Record<string, string> = {}) {
    return app.request("/user/me/wallet/sign", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify(body),
    });
  }

  async function installAuditFailure(trigger: string, action: string): Promise<void> {
    await getDb().execute(
      sql.raw(`
      CREATE OR REPLACE FUNCTION ${trigger}() RETURNS trigger AS $$
      BEGIN
        IF NEW.tenant_id = '${TENANT_ID}' AND NEW.action = '${action}' THEN
          RAISE EXCEPTION 'forced user-wallet audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `),
    );
    await getDb().execute(
      sql.raw(`
      CREATE TRIGGER ${trigger} BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION ${trigger}()
    `),
    );
  }

  async function dropAuditTrigger(trigger: string): Promise<void> {
    await getDb().execute(sql.raw(`DROP TRIGGER IF EXISTS ${trigger} ON audit_events`));
    await getDb().execute(sql.raw(`DROP FUNCTION IF EXISTS ${trigger}()`));
  }

  it("requires broadcast idempotency and replays without a second submit", async () => {
    const rpc = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const sign = spyOn(Vault.prototype, "signTransaction").mockResolvedValue("0xbroadcast-once");
    const body = { to: RECIPIENT, value: "1", chainId: 8453, broadcast: true };
    const authorization = `Bearer ${await token()}`;
    try {
      expect((await signRequest(body)).status).toBe(400);
      expect(sign).not.toHaveBeenCalled();
      const first = await signRequest(body, {
        Authorization: authorization,
        "Idempotency-Key": "wallet-broadcast-once",
      });
      const replay = await signRequest(body, {
        Authorization: authorization,
        "Idempotency-Key": "wallet-broadcast-once",
      });
      expect(first.status).toBe(200);
      expect(replay.status).toBe(200);
      expect(await replay.json()).toEqual(await first.json());
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(sign).toHaveBeenCalledTimes(1);
    } finally {
      rpc.mockRestore();
      sign.mockRestore();
    }
  });

  it("rejects malformed, negative, and overflowing uint256 values before signing", async () => {
    const sign = spyOn(Vault.prototype, "signTransaction");
    try {
      for (const value of ["-1", "1.5", "not-a-number", `${BigInt(MAX_UINT256) + 1n}`]) {
        const response = await signRequest({
          to: RECIPIENT,
          value,
          chainId: 8453,
          broadcast: false,
        });
        expect(response.status).toBe(400);
        expect(((await response.json()) as { error: string }).error).toContain("uint256");
      }
      expect(sign).not.toHaveBeenCalled();
    } finally {
      sign.mockRestore();
    }
  });

  it("rejects caller-controlled gas limits before signing", async () => {
    const rpc = spyOn(Vault.prototype, "rpcPassthrough");
    const sign = spyOn(Vault.prototype, "signTransaction");
    try {
      const response = await signRequest({
        to: RECIPIENT,
        value: "1",
        chainId: 8453,
        gasLimit: "21000",
        broadcast: false,
      });
      expect(response.status).toBe(403);
      expect(((await response.json()) as { error: string }).error).toContain(
        "gas spend is not policy-accounted",
      );
      expect(rpc).not.toHaveBeenCalled();
      expect(sign).not.toHaveBeenCalled();
    } finally {
      rpc.mockRestore();
      sign.mockRestore();
    }
  });

  it("fails closed on code lookup failure or nonempty contract code before signing", async () => {
    const sign = spyOn(Vault.prototype, "signTransaction");
    const unavailable = spyOn(Vault.prototype, "rpcPassthrough").mockRejectedValue(
      new Error("rpc unavailable"),
    );
    try {
      expect(
        (await signRequest({ to: RECIPIENT, value: "1", chainId: 8453, broadcast: false })).status,
      ).toBe(502);
      expect(sign).not.toHaveBeenCalled();
    } finally {
      unavailable.mockRestore();
    }
    const contract = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x6080604052",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    try {
      const response = await signRequest({
        to: RECIPIENT,
        value: "1",
        chainId: 8453,
        broadcast: false,
      });
      expect(response.status).toBe(403);
      expect(((await response.json()) as { error: string }).error).toContain(
        "contract recipients are disabled",
      );
      expect(sign).not.toHaveBeenCalled();
    } finally {
      contract.mockRestore();
      sign.mockRestore();
    }
  });

  it("includes indexed-wallet spend when enforcing policy on another wallet index", async () => {
    await getDb().insert(transactions).values({
      id: crypto.randomUUID(),
      agentId: INDEXED_WALLET,
      status: "signed",
      toAddress: RECIPIENT,
      value: "9",
      chainId: 8453,
      txHash: "0xindexed-spend",
      policyResults: [],
    });
    await getDb()
      .insert(policies)
      .values({
        id: `aggregate-spend-${USER_ID}`,
        agentId: PRIMARY_WALLET,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "10", maxPerDay: "10", maxPerWeek: "10" },
      });
    const rpc = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const sign = spyOn(Vault.prototype, "signTransaction");
    try {
      const response = await signRequest({
        walletIndex: 0,
        to: RECIPIENT,
        value: "2",
        chainId: 8453,
        broadcast: false,
      });
      const body = (await response.json()) as {
        error: string;
        data: { results: Array<{ type: string; passed: boolean }> };
      };
      expect(response.status).toBe(403);
      expect(body.error).toBe("Transaction rejected by policy");
      expect(body.data.results).toContainEqual(
        expect.objectContaining({ type: "spending-limit", passed: false }),
      );
      expect(sign).not.toHaveBeenCalled();
    } finally {
      rpc.mockRestore();
      sign.mockRestore();
    }
  });

  it("preserves a durable broadcast across completion-bookkeeping failure and replay", async () => {
    await installAuditFailure(COMPLETION_TRIGGER, "user.wallet.sign");
    const rpc = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const sign = spyOn(Vault.prototype, "signTransaction").mockImplementation(
      async (request, options) => {
        await getDb().insert(transactions).values({
          id: options.txId,
          agentId: request.agentId,
          status: "broadcast",
          toAddress: request.to,
          value: request.value,
          chainId: request.chainId,
          txHash: "0xdurable-broadcast",
          policyResults: options.policyResults,
        });
        return "0xdurable-broadcast";
      },
    );
    const body = { to: RECIPIENT, value: "3", chainId: 8453, broadcast: true };
    const authorization = `Bearer ${await token()}`;
    try {
      const first = await signRequest(body, {
        Authorization: authorization,
        "Idempotency-Key": "durable-wallet-result",
      });
      const replay = await signRequest(body, {
        Authorization: authorization,
        "Idempotency-Key": "durable-wallet-result",
      });
      expect(first.status).toBe(200);
      expect(replay.status).toBe(200);
      expect(await replay.json()).toEqual(await first.json());
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(sign).toHaveBeenCalledTimes(1);
      const rows = await getDb()
        .select({ status: transactions.status, txHash: transactions.txHash })
        .from(transactions)
        .where(eq(transactions.agentId, PRIMARY_WALLET));
      expect(rows).toEqual([{ status: "broadcast", txHash: "0xdurable-broadcast" }]);
      const failed = await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, TENANT_ID),
            eq(auditEvents.action, "user.wallet.sign.failed"),
          ),
        );
      expect(failed).toHaveLength(0);
    } finally {
      rpc.mockRestore();
      sign.mockRestore();
      await dropAuditTrigger(COMPLETION_TRIGGER);
    }
  });

  it("requires the authorization audit to succeed before message signing", async () => {
    await installAuditFailure(AUTH_TRIGGER, "user.wallet.sign_message.authorized");
    const sign = spyOn(Vault.prototype, "signMessage").mockResolvedValue("0xmessage-signature");
    try {
      const response = await app.request("/user/me/wallet/sign-message", {
        method: "POST",
        headers: { Authorization: `Bearer ${await token()}`, "Content-Type": "application/json" },
        body: JSON.stringify({ message: "non-authentication compatibility payload" }),
      });
      expect(response.status).toBe(500);
      expect(sign).not.toHaveBeenCalled();
    } finally {
      sign.mockRestore();
      await dropAuditTrigger(AUTH_TRIGGER);
    }
  });

  it("marks every private-key export response variant as no-store", async () => {
    const assertNoStore = (response: Response) => {
      expect(response.headers.get("Cache-Control")).toBe("no-store, max-age=0");
      expect(response.headers.get("Pragma")).toBe("no-cache");
      expect(response.headers.get("Expires")).toBe("0");
    };
    const unauthenticated = await app.request("/user/me/wallet/export", { method: "POST" });
    expect(unauthenticated.status).toBe(401);
    assertNoStore(unauthenticated);

    process.env.STEWARD_ALLOW_KEY_EXPORT = "false";
    const disabled = await app.request("/user/me/wallet/export", {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
    });
    expect(disabled.status).toBe(403);
    assertNoStore(disabled);
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";

    const exportKey = spyOn(Vault.prototype, "exportPrivateKey")
      .mockResolvedValueOnce({ evm: { privateKey: "0xprivate", address: USER_ADDRESS } })
      .mockRejectedValueOnce(new Error("hsm unavailable"));
    try {
      const request = async () =>
        app.request("/user/me/wallet/export", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${await token()}`,
            "Content-Type": "application/json",
          },
          body: "{}",
        });
      const success = await request();
      expect(success.status).toBe(200);
      assertNoStore(success);
      const failure = await request();
      expect(failure.status).toBe(500);
      assertNoStore(failure);
    } finally {
      exportKey.mockRestore();
    }
  });
});
