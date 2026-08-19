import { expect, it, spyOn } from "bun:test";
import { createRequire } from "node:module";
import {
  agents,
  auditChainHeads,
  auditEvents,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { Vault } from "@stwd/vault";
import { and, eq, inArray } from "drizzle-orm";

type Sql = {
  <T extends unknown[]>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T>;
  end(): Promise<void>;
};

const requireFromDb = createRequire(new URL("../../../db/package.json", import.meta.url));
const postgresModule = requireFromDb("postgres") as { default?: unknown } | unknown;
const postgres = ((postgresModule as { default?: unknown }).default ?? postgresModule) as (
  url: string,
  options: { max: number },
) => Sql;

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt =
  databaseUrl &&
  process.env.STEWARD_PGLITE_MEMORY !== "true" &&
  process.env.STEWARD_DB_MODE !== "pglite"
    ? it
    : it.skip;

realPostgresIt(
  "serializes aggregate spend admission across concurrent indexed user wallets",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const userId = crypto.randomUUID();
    const tenantId = `personal-${userId}`;
    const baseAgentId = `user-wallet-${userId}`;
    const indexedAgentId = `${baseAgentId}-2`;
    const agentIds = [baseAgentId, indexedAgentId];
    const recipient = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const previousSignerPepper = process.env.STEWARD_SIGNER_CREDENTIAL_PEPPER;
    process.env.STEWARD_JWT_SECRET = "wallet-lock-postgres-jwt-secret-32chars";
    process.env.STEWARD_MASTER_PASSWORD = "wallet-lock-postgres-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "wallet-lock-postgres-audit-hmac-key-32chars";
    process.env.STEWARD_SIGNER_CREDENTIAL_PEPPER = "wallet-lock-postgres-credential-pepper-32chars";

    const holder = postgres(databaseUrl!, { max: 1 });
    const admin = postgres(databaseUrl!, { max: 1 });
    let lockHeld = false;
    let requests: Promise<Response>[] = [];
    let rpcSpy: ReturnType<typeof spyOn> | undefined;
    let signSpy: ReturnType<typeof spyOn> | undefined;
    try {
      await getDb()
        .insert(tenants)
        .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${suffix}` });
      await getDb().insert(users).values({
        id: userId,
        walletAddress: "0x1234567890123456789012345678901234567890",
        walletChain: "ethereum",
      });
      await getDb().insert(userTenants).values({ userId, tenantId, role: "owner" });
      await getDb()
        .insert(agents)
        .values(
          agentIds.map((id) => ({
            id,
            tenantId,
            name: id,
            walletAddress: "0x1234567890123456789012345678901234567890",
            platformId: `user:${userId}`,
          })),
        );
      await getDb()
        .insert(policies)
        .values(
          agentIds.map((agentId, index) => ({
            id: `wallet-lock-policy-${index}-${suffix}`,
            agentId,
            type: "spending-limit" as const,
            config: { maxPerTx: "100", maxPerDay: "100", maxPerWeek: "1000" },
          })),
        );

      const [{ userRoutes }, { createSessionToken }] = await Promise.all([
        import("../routes/user"),
        import("../routes/auth"),
      ]);
      const token = await createSessionToken(
        "0x1234567890123456789012345678901234567890",
        tenantId,
        {
          userId,
          tenantId,
          mfaVerifiedAt: Date.now(),
          mfaMethod: "totp",
        },
      );
      rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
        jsonrpc: "2.0",
        id: 1,
        result: "0x",
      } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
      signSpy = spyOn(Vault.prototype, "signTransaction").mockImplementation(
        async (request, persistence) => {
          await getDb().insert(transactions).values({
            id: persistence.txId,
            agentId: request.agentId,
            status: "signed",
            toAddress: request.to,
            value: request.value,
            chainId: request.chainId,
            policyResults: persistence.policyResults,
            signedAt: new Date(),
          });
          return `0xsigned${request.agentId === baseAgentId ? "0" : "2"}`;
        },
      );

      const [{ pid: holderPid }] = await holder<{ pid: number }[]>`
        select pg_backend_pid()::int as pid
      `;
      await holder`select pg_advisory_lock(hashtextextended(${baseAgentId}, 0))`;
      lockHeld = true;

      const sign = (walletIndex: number) =>
        userRoutes.request("/me/wallet/sign", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            walletIndex,
            to: recipient,
            value: "60",
            chainId: 8453,
            broadcast: false,
          }),
        });
      requests = [sign(0), sign(2)];

      let waitingPids: number[] = [];
      for (let attempt = 0; attempt < 1_000 && waitingPids.length < 2; attempt += 1) {
        const rows = await admin<{ pid: number }[]>`
          select distinct waiter.pid::int as pid
          from pg_locks holder_lock
          join pg_locks waiter
            on waiter.locktype = holder_lock.locktype
           and waiter.database is not distinct from holder_lock.database
           and waiter.classid is not distinct from holder_lock.classid
           and waiter.objid is not distinct from holder_lock.objid
           and waiter.objsubid is not distinct from holder_lock.objsubid
          where holder_lock.pid = ${holderPid}
            and holder_lock.locktype = 'advisory'
            and holder_lock.granted
            and not waiter.granted
            and waiter.pid <> holder_lock.pid
        `;
        waitingPids = [...new Set(rows.map(({ pid }) => pid))];
      }
      expect(waitingPids).toHaveLength(2);

      await holder`select pg_advisory_unlock(hashtextextended(${baseAgentId}, 0))`;
      lockHeld = false;
      const responses = await Promise.all(requests);
      requests = [];
      expect(responses.map(({ status }) => status).sort()).toEqual([200, 403]);
      expect(signSpy).toHaveBeenCalledTimes(1);

      const rejected = responses.find(({ status }) => status === 403);
      const rejection = (await rejected?.json()) as {
        error?: string;
        data?: { results?: Array<{ type: string; passed: boolean; reason?: string }> };
      };
      expect(rejection.error).toBe("Transaction rejected by policy");
      expect(
        rejection.data?.results?.some(
          ({ type, passed, reason }) =>
            type === "spending-limit" && !passed && reason?.toLowerCase().includes("daily"),
        ),
      ).toBe(true);
      const committed = await getDb()
        .select({ id: transactions.id })
        .from(transactions)
        .where(inArray(transactions.agentId, agentIds));
      expect(committed).toHaveLength(1);
    } finally {
      if (lockHeld) {
        await holder`select pg_advisory_unlock(hashtextextended(${baseAgentId}, 0))`;
      }
      await Promise.allSettled(requests);
      rpcSpy?.mockRestore();
      signSpy?.mockRestore();
      await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await getDb().delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await getDb().delete(transactions).where(inArray(transactions.agentId, agentIds));
      await getDb().delete(policies).where(inArray(policies.agentId, agentIds));
      await getDb().delete(agents).where(inArray(agents.id, agentIds));
      await getDb()
        .delete(userTenants)
        .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)));
      await getDb().delete(users).where(eq(users.id, userId));
      await getDb().delete(tenants).where(eq(tenants.id, tenantId));
      await Promise.all([holder.end(), admin.end()]);
      if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      if (previousSignerPepper === undefined) delete process.env.STEWARD_SIGNER_CREDENTIAL_PEPPER;
      else process.env.STEWARD_SIGNER_CREDENTIAL_PEPPER = previousSignerPepper;
    }
  },
  120_000,
);
