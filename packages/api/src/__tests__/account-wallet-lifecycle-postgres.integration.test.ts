import { expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  digitalAssetAccountWalletLifecycles,
  encryptedChainKeys,
  tenants,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { _clearConfiguredVaultsForTests, getConfiguredVault } from "../services/vault-factory";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt =
  databaseUrl && process.env.STEWARD_DB_MODE !== "pglite" && !process.env.STEWARD_PGLITE_MEMORY
    ? it
    : it.skip;

realPostgresIt(
  "fences two real-Postgres recovery workers and retires Vault authority atomically",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `account-wallet-pg-${suffix}`;
    const lifecycleId = crypto.randomUUID();
    const walletAgentId = `account-wallet-pg-agent-${suffix}`;
    const previousMaster = process.env.STEWARD_MASTER_PASSWORD;
    const previousAudit = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_MASTER_PASSWORD = `account-wallet-pg-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `account-wallet-pg-audit-${suffix}`;
    __resetAuditHmacKeyCacheForTests();
    const admin = createDb(databaseUrl!);
    try {
      await admin.db.insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: "hash" });
      await admin.db.insert(digitalAssetAccountWalletLifecycles).values({
        id: lifecycleId,
        tenantId,
        accountId: "crashed-account",
        walletAgentId,
        chainFamily: "evm",
        state: "provisioned",
        ownerToken: crypto.randomUUID(),
        leaseExpiresAt: new Date(Date.now() - 60_000),
      });
      await getConfiguredVault().createAgent(
        tenantId,
        walletAgentId,
        "Postgres crash orphan",
        `account-provision:${lifecycleId}`,
        "evm",
      );
      expect(
        (
          await admin.db
            .select({ id: encryptedChainKeys.id })
            .from(encryptedChainKeys)
            .where(eq(encryptedChainKeys.agentId, walletAgentId))
        ).length,
      ).toBeGreaterThan(0);

      const worker = new URL(
        "./fixtures/account-wallet-lifecycle-recovery-worker.ts",
        import.meta.url,
      ).pathname;
      const workerEnv = {
        ...process.env,
        DATABASE_URL: databaseUrl!,
        TEST_TENANT_ID: tenantId,
        STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD!,
        STEWARD_AUDIT_HMAC_KEY: process.env.STEWARD_AUDIT_HMAC_KEY!,
      };
      const first = Bun.spawn([process.execPath, worker], {
        cwd: new URL("../../../..", import.meta.url).pathname,
        env: workerEnv,
        stdout: "pipe",
        stderr: "pipe",
      });
      const second = Bun.spawn([process.execPath, worker], {
        cwd: new URL("../../../..", import.meta.url).pathname,
        env: workerEnv,
        stdout: "pipe",
        stderr: "pipe",
      });
      const exits = await Promise.all([first.exited, second.exited]);
      const errors = await Promise.all([
        new Response(first.stderr).text(),
        new Response(second.stderr).text(),
      ]);
      expect(exits).toEqual([0, 0]);
      expect(errors).toEqual(["", ""]);
      expect(
        await admin.db
          .select({ id: agents.id })
          .from(agents)
          .where(and(eq(agents.tenantId, tenantId), eq(agents.id, walletAgentId))),
      ).toHaveLength(0);
      expect(
        await admin.db
          .select({ id: encryptedChainKeys.id })
          .from(encryptedChainKeys)
          .where(eq(encryptedChainKeys.agentId, walletAgentId)),
      ).toHaveLength(0);
      expect(
        await admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, tenantId),
              eq(auditEvents.action, "account.wallet_provision.retire"),
            ),
          ),
      ).toHaveLength(1);
    } finally {
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db
        .delete(digitalAssetAccountWalletLifecycles)
        .where(eq(digitalAssetAccountWalletLifecycles.tenantId, tenantId));
      await admin.db.delete(agents).where(eq(agents.tenantId, tenantId));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.client.end();
      _clearConfiguredVaultsForTests();
      if (previousMaster === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMaster;
      if (previousAudit === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAudit;
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);
