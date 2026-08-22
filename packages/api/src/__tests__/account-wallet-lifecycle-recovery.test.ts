import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditEvents,
  closeDb,
  digitalAssetAccountWalletLifecycles,
  getDb,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import {
  accountWalletLifecycleUsesPglite,
  lockAccountMutation,
  recoverStaleAccountWalletLifecyclesForTenant,
  retireStagedAccountWallets,
} from "../services/account-wallet-lifecycle";
import { _clearConfiguredVaultsForTests, getConfiguredVault } from "../services/vault-factory";

const TENANT_ID = `account-wallet-recovery-${Date.now()}`;
const AUDIT_KEY = "account-wallet-recovery-audit-key-with-sufficient-entropy";

describe("configured account wallet durable recovery", () => {
  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.STEWARD_DB_MODE = "pglite";
    delete process.env.STEWARD_PGLITE_MEMORY;
    process.env.STEWARD_MASTER_PASSWORD = "account-wallet-recovery-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: TENANT_ID, name: TENANT_ID, apiKeyHash: "hash" });
  });

  afterAll(async () => {
    await closeDb();
    _clearConfiguredVaultsForTests();
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    __resetAuditHmacKeyCacheForTests();
  });

  it("uses the canonical persistent-PGLite predicate and never issues an advisory lock", async () => {
    expect(accountWalletLifecycleUsesPglite()).toBe(true);
    let executed = false;
    await lockAccountMutation(
      {
        execute: async () => {
          executed = true;
          throw new Error("PGLite must not execute PostgreSQL advisory SQL");
        },
      } as never,
      TENANT_ID,
      "account",
    );
    expect(executed).toBe(false);
  });

  it("retires a crash-orphaned Vault authority exactly once under concurrent takeover", async () => {
    const lifecycleId = crypto.randomUUID();
    const walletAgentId = `crash-wallet-${Date.now()}`;
    const vault = getConfiguredVault();
    await getDb()
      .insert(digitalAssetAccountWalletLifecycles)
      .values({
        id: lifecycleId,
        tenantId: TENANT_ID,
        accountId: "crashed-account",
        walletAgentId,
        chainFamily: "evm",
        state: "staging",
        ownerToken: crypto.randomUUID(),
        leaseExpiresAt: new Date(Date.now() - 60_000),
      });
    await vault.createAgent(
      TENANT_ID,
      walletAgentId,
      "Crash orphan",
      `account-provision:${lifecycleId}`,
      "evm",
    );

    const [first, second] = await Promise.all([
      recoverStaleAccountWalletLifecyclesForTenant(TENANT_ID),
      recoverStaleAccountWalletLifecyclesForTenant(TENANT_ID),
    ]);
    expect(first.retired + second.retired).toBe(1);
    expect(
      await getDb()
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.tenantId, TENANT_ID), eq(agents.id, walletAgentId))),
    ).toHaveLength(0);
    const [lifecycle] = await getDb()
      .select({ state: digitalAssetAccountWalletLifecycles.state })
      .from(digitalAssetAccountWalletLifecycles)
      .where(eq(digitalAssetAccountWalletLifecycles.id, lifecycleId));
    expect(lifecycle?.state).toBe("retired");
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, TENANT_ID),
            eq(auditEvents.action, "account.wallet_provision.retire"),
          ),
        ),
    ).toHaveLength(1);
  });

  it("persists a failed inline retirement for the autonomous recovery consumer", async () => {
    const lifecycleId = crypto.randomUUID();
    const ownerToken = crypto.randomUUID();
    const walletAgentId = `failed-retirement-${Date.now()}`;
    await getDb()
      .insert(digitalAssetAccountWalletLifecycles)
      .values({
        id: lifecycleId,
        tenantId: TENANT_ID,
        accountId: "failed-retirement-account",
        walletAgentId,
        chainFamily: "evm",
        state: "provisioned",
        ownerToken,
        leaseExpiresAt: new Date(Date.now() + 60_000),
      });
    await getConfiguredVault().createAgent(
      TENANT_ID,
      walletAgentId,
      "Failed retirement",
      `account-provision:${lifecycleId}`,
      "evm",
    );

    process.env.STEWARD_AUDIT_HMAC_KEY = "too-short";
    __resetAuditHmacKeyCacheForTests();
    await retireStagedAccountWallets([
      { lifecycleId, ownerToken, tenantId: TENANT_ID, accountId: "failed", walletAgentId },
    ]);
    process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();

    const [recoverable] = await getDb()
      .select({
        state: digitalAssetAccountWalletLifecycles.state,
        leaseExpiresAt: digitalAssetAccountWalletLifecycles.leaseExpiresAt,
      })
      .from(digitalAssetAccountWalletLifecycles)
      .where(eq(digitalAssetAccountWalletLifecycles.id, lifecycleId));
    expect(recoverable?.state).toBe("recoverable");
    expect(recoverable!.leaseExpiresAt.getTime()).toBeLessThanOrEqual(Date.now());

    const recovered = await recoverStaleAccountWalletLifecyclesForTenant(TENANT_ID);
    expect(recovered.retired).toBe(1);
    expect(
      await getDb()
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.tenantId, TENANT_ID), eq(agents.id, walletAgentId))),
    ).toHaveLength(0);
  });
});
