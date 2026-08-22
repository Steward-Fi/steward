import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  agentWallets,
  auditEvents,
  closeDb,
  encryptedChainKeys,
  getDb,
  pregeneratedWalletClaimLifecycles,
  tenants,
  users,
  userTenants,
  vaultSigningFreezes,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { _clearConfiguredVaultsForTests, getConfiguredVault } from "../services/vault-factory";

const SOURCE_TENANT = `claim-source-${Date.now()}`;
const SOURCE_AGENT = `claim-source-agent-${Date.now()}`;
const USER_ID = crypto.randomUUID();
const PERSONAL_TENANT = `personal-${USER_ID}`;
const CLAIM_TOKEN = `stwd_claim_${crypto.randomUUID()}`;
const CLAIM_HASH = new Bun.CryptoHasher("sha256").update(CLAIM_TOKEN).digest("hex");
const AUDIT_KEY = "claim-lifecycle-audit-key-with-enough-entropy";

describe("pregenerated wallet claim durable lifecycle", () => {
  let app: Hono;
  let sessionToken: string;

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "claim-lifecycle-master-password";
    process.env.STEWARD_JWT_SECRET = "claim-lifecycle-jwt-secret-with-enough-entropy";
    process.env.JWT_SECRET = process.env.STEWARD_JWT_SECRET;
    process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb()
      .insert(tenants)
      .values([
        { id: SOURCE_TENANT, name: SOURCE_TENANT, apiKeyHash: "source-hash" },
        { id: PERSONAL_TENANT, name: PERSONAL_TENANT, apiKeyHash: "personal-hash" },
      ]);
    await getDb()
      .insert(users)
      .values({
        id: USER_ID,
        email: `${USER_ID}@example.test`,
        emailVerified: true,
      });
    await getDb()
      .insert(userTenants)
      .values({ userId: USER_ID, tenantId: PERSONAL_TENANT, role: "owner" });
    const vault = getConfiguredVault();
    await vault.createAgent(
      SOURCE_TENANT,
      SOURCE_AGENT,
      "Pregenerated",
      `pregenerated:${CLAIM_HASH}`,
    );
    await getDb()
      .update(agents)
      .set({ walletType: "pregenerated_user" })
      .where(and(eq(agents.tenantId, SOURCE_TENANT), eq(agents.id, SOURCE_AGENT)));
    const { createSessionToken } = await import("../routes/auth");
    sessionToken = await createSessionToken("", PERSONAL_TENANT, {
      userId: USER_ID,
      tenantId: PERSONAL_TENANT,
      email: `${USER_ID}@example.test`,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const { userRoutes } = await import("../routes/user");
    app = new Hono();
    app.route("/user", userRoutes);
  });

  afterAll(async () => {
    await closeDb();
    _clearConfiguredVaultsForTests();
    for (const key of [
      "STEWARD_PGLITE_MEMORY",
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_JWT_SECRET",
      "JWT_SECRET",
      "STEWARD_AUDIT_HMAC_KEY",
    ]) {
      delete process.env[key];
    }
  });

  const claim = () =>
    app.request("/user/me/wallet/claim-pregenerated", {
      method: "POST",
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ tenantId: SOURCE_TENANT, claimToken: CLAIM_TOKEN }),
    });

  it("recovers a partial chain import without reusing the token or duplicating authority", async () => {
    const originalImportKey = Vault.prototype.importKey;
    let failedEvmOnce = false;
    Vault.prototype.importKey = async function (...args) {
      if (args[3] === "evm" && !failedEvmOnce) {
        failedEvmOnce = true;
        throw new Error("injected EVM import failure");
      }
      return originalImportKey.apply(this, args);
    };

    const failed = await claim();
    expect(failed.status).toBe(500);
    const [recoverable] = await getDb()
      .select()
      .from(pregeneratedWalletClaimLifecycles)
      .where(eq(pregeneratedWalletClaimLifecycles.claimTokenHash, CLAIM_HASH));
    expect(recoverable).toMatchObject({
      sourceTenantId: SOURCE_TENANT,
      sourceAgentId: SOURCE_AGENT,
      targetTenantId: PERSONAL_TENANT,
      targetAgentId: `user-wallet-${USER_ID}`,
      userId: USER_ID,
      walletIndex: 0,
      state: "recoverable",
      solanaImported: true,
      evmImported: false,
      targetAdopted: false,
    });
    const [consumedSource] = await getDb()
      .select({ platformId: agents.platformId })
      .from(agents)
      .where(and(eq(agents.tenantId, SOURCE_TENANT), eq(agents.id, SOURCE_AGENT)));
    expect(consumedSource?.platformId).toBe(`claimed:${CLAIM_HASH}`);
    const [activeFreeze] = await getDb()
      .select({ liftedAt: vaultSigningFreezes.liftedAt })
      .from(vaultSigningFreezes)
      .where(
        and(
          eq(vaultSigningFreezes.tenantId, PERSONAL_TENANT),
          eq(vaultSigningFreezes.agentId, `user-wallet-${USER_ID}`),
        ),
      );
    expect(activeFreeze?.liftedAt).toBeNull();

    Vault.prototype.importKey = async function (...args) {
      const imported = await originalImportKey.apply(this, args);
      if (args[3] === "evm") {
        process.env.STEWARD_AUDIT_HMAC_KEY = "too-short";
        __resetAuditHmacKeyCacheForTests();
      }
      return imported;
    };
    const failedCompletionAudit = await claim();
    expect(failedCompletionAudit.status).toBe(500);
    const [adoptedRecovery] = await getDb()
      .select()
      .from(pregeneratedWalletClaimLifecycles)
      .where(eq(pregeneratedWalletClaimLifecycles.claimTokenHash, CLAIM_HASH));
    expect(adoptedRecovery).toMatchObject({ state: "recoverable", targetAdopted: true });
    expect(
      await getDb()
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.tenantId, SOURCE_TENANT), eq(agents.id, SOURCE_AGENT))),
    ).toHaveLength(1);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, PERSONAL_TENANT),
            eq(auditEvents.action, "user.wallet.pregenerated_claim"),
          ),
        ),
    ).toHaveLength(0);
    process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();
    Vault.prototype.importKey = originalImportKey;
    const completed = await claim();
    expect(completed.status).toBe(201);
    const [lifecycle] = await getDb()
      .select()
      .from(pregeneratedWalletClaimLifecycles)
      .where(eq(pregeneratedWalletClaimLifecycles.claimTokenHash, CLAIM_HASH));
    expect(lifecycle).toMatchObject({
      state: "completed",
      solanaImported: true,
      evmImported: true,
      targetAdopted: true,
      ownerToken: null,
    });
    const [liftedFreeze] = await getDb()
      .select({ liftedAt: vaultSigningFreezes.liftedAt })
      .from(vaultSigningFreezes)
      .where(
        and(
          eq(vaultSigningFreezes.tenantId, PERSONAL_TENANT),
          eq(vaultSigningFreezes.agentId, `user-wallet-${USER_ID}`),
        ),
      );
    expect(liftedFreeze?.liftedAt).toBeInstanceOf(Date);
    expect(
      await getDb()
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.tenantId, SOURCE_TENANT), eq(agents.id, SOURCE_AGENT))),
    ).toHaveLength(0);
    const targetAgentId = `user-wallet-${USER_ID}`;
    expect(
      await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, targetAgentId)),
    ).toHaveLength(2);
    expect(
      await getDb()
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, targetAgentId)),
    ).toHaveLength(2);
    const completionAudits = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, PERSONAL_TENANT),
          eq(auditEvents.action, "user.wallet.pregenerated_claim"),
        ),
      );
    expect(completionAudits).toHaveLength(1);

    const replay = await claim();
    expect(replay.status).toBe(200);
    expect(
      await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, PERSONAL_TENANT),
            eq(auditEvents.action, "user.wallet.pregenerated_claim"),
          ),
        ),
    ).toHaveLength(1);
  });

  it("fences deterministic concurrent claimants to one bound target and one completion", async () => {
    const token = `stwd_claim_${crypto.randomUUID()}`;
    const tokenHash = new Bun.CryptoHasher("sha256").update(token).digest("hex");
    const sourceAgentId = `claim-race-source-${Date.now()}`;
    const claimantIds = [crypto.randomUUID(), crypto.randomUUID()];
    const claimantTenants = claimantIds.map((id) => `personal-${id}`);
    await getDb()
      .insert(tenants)
      .values(
        claimantTenants.map((id, index) => ({
          id,
          name: id,
          apiKeyHash: `claimant-${index}`,
        })),
      );
    await getDb()
      .insert(users)
      .values(
        claimantIds.map((id, index) => ({
          id,
          email: `claimant-${index}-${id}@example.test`,
          emailVerified: true,
        })),
      );
    await getDb()
      .insert(userTenants)
      .values(
        claimantIds.map((userId, index) => ({
          userId,
          tenantId: claimantTenants[index]!,
          role: "owner",
        })),
      );
    const vault = getConfiguredVault();
    await vault.createAgent(
      SOURCE_TENANT,
      sourceAgentId,
      "Concurrent pregenerated",
      `pregenerated:${tokenHash}`,
    );
    await getDb()
      .update(agents)
      .set({ walletType: "pregenerated_user" })
      .where(and(eq(agents.tenantId, SOURCE_TENANT), eq(agents.id, sourceAgentId)));
    const { createSessionToken } = await import("../routes/auth");
    const claimantTokens = await Promise.all(
      claimantIds.map((userId, index) =>
        createSessionToken("", claimantTenants[index]!, {
          userId,
          tenantId: claimantTenants[index],
          email: `claimant-${index}-${userId}@example.test`,
          mfaVerifiedAt: Date.now(),
          mfaMethod: "totp",
        }),
      ),
    );
    const responses = await Promise.all(
      claimantTokens.map((jwt) =>
        app.request("/user/me/wallet/claim-pregenerated", {
          method: "POST",
          headers: { authorization: `Bearer ${jwt}`, "content-type": "application/json" },
          body: JSON.stringify({ tenantId: SOURCE_TENANT, claimToken: token }),
        }),
      ),
    );
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409]);
    const rows = await getDb()
      .select()
      .from(pregeneratedWalletClaimLifecycles)
      .where(eq(pregeneratedWalletClaimLifecycles.claimTokenHash, tokenHash));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.state).toBe("completed");
    expect(claimantIds).toContain(rows[0]?.userId);
    expect(
      await getDb()
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.tenantId, SOURCE_TENANT), eq(agents.id, sourceAgentId))),
    ).toHaveLength(0);
    const completions = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, rows[0]!.targetTenantId),
          eq(auditEvents.action, "user.wallet.pregenerated_claim"),
        ),
      );
    expect(completions).toHaveLength(1);
  });
});
