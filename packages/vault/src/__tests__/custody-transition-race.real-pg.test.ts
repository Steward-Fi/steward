import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agentWallets,
  and,
  closeDb,
  createPostgresClient,
  encryptedChainKeys,
  encryptedKeys,
  eq,
  getDb,
  isNull,
  tenants,
} from "@stwd/db";
import type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
} from "../external-key-custody";
import { Vault } from "../vault";

setDefaultTimeout(120_000);

const databaseUrl = process.env.DATABASE_URL;
const suite =
  databaseUrl && !databaseUrl.startsWith("file:") && !process.env.STEWARD_PGLITE_MEMORY
    ? describe
    : describe.skip;
const MASTER_PASSWORD = "custody-race-real-pg-master-password";
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `custody-race-tenant-${suffix}`;
const agentId = `custody-race-agent-${suffix}`;
const restoreFirstAgentId = `custody-race-restore-first-${suffix}`;
const blocker = databaseUrl ? createPostgresClient(databaseUrl) : null;
const inspector = databaseUrl ? createPostgresClient(databaseUrl) : null;

class RealPgRaceProvider implements ExternalKeyCustodyProvider {
  readonly id = "real-pg-race-provider";
  readonly contractVersion = 1 as const;
  registrationCalls = 0;

  async registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration> {
    this.registrationCalls += 1;
    return {
      custody: "external",
      tenantId: request.tenantId,
      agentId: request.agentId,
      chainFamily: request.chainFamily,
      address: request.address,
      handle: request.handle,
      venue: request.venue ?? null,
      purpose: request.purpose ?? null,
      metadata: request.metadata ?? {},
      registeredAt: new Date("2026-08-18T00:00:00.000Z"),
      exportablePrivateKey: false,
      signingAvailability: "not-supported",
    };
  }
}

async function waitForBlockedAdvisoryConnections(expected: number): Promise<number[]> {
  if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await inspector<{ pid: number }[]>`
      select distinct pid
      from pg_locks
      where locktype = 'advisory'
        and granted = false
        and database = (select oid from pg_database where datname = current_database())
    `;
    if (rows.length >= expected) return rows.map((row) => row.pid);
    await Bun.sleep(10);
  }
  throw new Error(`timed out waiting for ${expected} blocked advisory-lock connections`);
}

async function holdCustodyLock(lockedAgentId: string): Promise<{
  release: () => void;
  done: Promise<void>;
}> {
  if (!blocker) throw new Error("real PostgreSQL blocker is unavailable");
  const lockKey = JSON.stringify(["vault-custody-v1", tenantId, lockedAgentId, "evm", null]);
  let releaseBlocker!: () => void;
  const release = new Promise<void>((resolve) => {
    releaseBlocker = resolve;
  });
  let blockerHasLock!: () => void;
  const blockerReady = new Promise<void>((resolve) => {
    blockerHasLock = resolve;
  });
  const done = blocker.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`;
    blockerHasLock();
    await release;
  });
  await blockerReady;
  return { release: releaseBlocker, done };
}

async function seedBareRecoverableAgent(seededAgentId: string): Promise<{
  vault: Vault;
  address: string;
}> {
  const db = getDb();
  const vault = new Vault({ masterPassword: MASTER_PASSWORD });
  const created = await vault.createAgentFromMnemonic(
    tenantId,
    seededAgentId,
    "Custody Race Agent",
    TEST_MNEMONIC,
    { walletType: "recoverable_user" },
  );
  await db.delete(encryptedKeys).where(eq(encryptedKeys.agentId, seededAgentId));
  await db.delete(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, seededAgentId));
  await db.delete(agentWallets).where(eq(agentWallets.agentId, seededAgentId));
  return { vault, address: created.walletAddress };
}

suite("custody transitions across real PostgreSQL connections", () => {
  beforeAll(async () => {
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_PGLITE_MEMORY;
    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Custody Race Tenant",
        apiKeyHash: `hash-${tenantId}`,
      });
  });

  afterAll(async () => {
    await getDb()
      .delete(tenants)
      .where(eq(tenants.id, tenantId))
      .catch(() => {});
    await closeDb();
    await Promise.all([blocker?.end(), inspector?.end()]);
  });

  test("an external import queued first prevents a concurrent mnemonic restore from recreating local keys", async () => {
    if (!blocker || !inspector) throw new Error("real PostgreSQL clients are unavailable");
    const db = getDb();
    // Preserve the recoverable identity while making both transitions race
    // from an empty custody scope.
    const { vault: localVault, address } = await seedBareRecoverableAgent(agentId);
    const heldLock = await holdCustodyLock(agentId);

    const provider = new RealPgRaceProvider();
    const externalVault = new Vault({
      masterPassword: MASTER_PASSWORD,
      externalKeyCustodyProvider: provider,
    });
    const externalImport = externalVault.importExternalKeyHandle({
      tenantId,
      agentId,
      chainFamily: "evm",
      address,
      handle: { providerId: provider.id, keyId: `key-${suffix}` },
    });
    const firstWaiters = await waitForBlockedAdvisoryConnections(1);

    const restore = localVault.restoreAgentFromMnemonic(
      tenantId,
      agentId,
      "Custody Race Agent",
      TEST_MNEMONIC,
      { walletType: "recoverable_user" },
    );
    const allWaiters = await waitForBlockedAdvisoryConnections(2);
    expect(new Set(allWaiters).size).toBeGreaterThanOrEqual(2);
    expect(allWaiters).toEqual(expect.arrayContaining(firstWaiters));

    heldLock.release();
    await heldLock.done;
    const [externalResult, restoreResult] = await Promise.allSettled([externalImport, restore]);
    expect(externalResult.status).toBe("fulfilled");
    expect(restoreResult.status).toBe("rejected");
    if (restoreResult.status === "rejected") {
      expect(String(restoreResult.reason)).toContain("external-custody");
    }
    expect(provider.registrationCalls).toBe(1);

    const [externalWallet] = await db
      .select({ metadata: agentWallets.metadata })
      .from(agentWallets)
      .where(
        and(
          eq(agentWallets.agentId, agentId),
          eq(agentWallets.chainFamily, "evm"),
          isNull(agentWallets.venue),
        ),
      );
    expect((externalWallet?.metadata as Record<string, unknown>)?.custody).toBe("external");
    expect(
      await db.select().from(encryptedKeys).where(eq(encryptedKeys.agentId, agentId)),
    ).toHaveLength(0);
    expect(
      await db.select().from(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, agentId)),
    ).toHaveLength(0);
  });

  test("a mnemonic restore queued first makes a concurrent external import revalidate and fail closed", async () => {
    const db = getDb();
    const { vault: localVault, address } = await seedBareRecoverableAgent(restoreFirstAgentId);
    const heldLock = await holdCustodyLock(restoreFirstAgentId);

    const restore = localVault.restoreAgentFromMnemonic(
      tenantId,
      restoreFirstAgentId,
      "Custody Race Agent",
      TEST_MNEMONIC,
      { walletType: "recoverable_user" },
    );
    const firstWaiters = await waitForBlockedAdvisoryConnections(1);

    const provider = new RealPgRaceProvider();
    const externalVault = new Vault({
      masterPassword: MASTER_PASSWORD,
      externalKeyCustodyProvider: provider,
    });
    const externalImport = externalVault.importExternalKeyHandle({
      tenantId,
      agentId: restoreFirstAgentId,
      chainFamily: "evm",
      address,
      handle: { providerId: provider.id, keyId: `restore-first-key-${suffix}` },
    });
    const allWaiters = await waitForBlockedAdvisoryConnections(2);
    expect(new Set(allWaiters).size).toBeGreaterThanOrEqual(2);
    expect(allWaiters).toEqual(expect.arrayContaining(firstWaiters));

    heldLock.release();
    await heldLock.done;
    const [restoreResult, externalResult] = await Promise.allSettled([restore, externalImport]);
    expect(restoreResult.status).toBe("fulfilled");
    expect(externalResult.status).toBe("rejected");
    if (externalResult.status === "rejected") {
      expect(String(externalResult.reason)).toContain("server-managed signing key");
    }
    expect(provider.registrationCalls).toBe(1);

    expect(
      await db.select().from(encryptedKeys).where(eq(encryptedKeys.agentId, restoreFirstAgentId)),
    ).toHaveLength(1);
    expect(
      await db
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, restoreFirstAgentId)),
    ).toHaveLength(2);
    const wallets = await db
      .select({ metadata: agentWallets.metadata })
      .from(agentWallets)
      .where(eq(agentWallets.agentId, restoreFirstAgentId));
    expect(wallets).toHaveLength(2);
    expect(
      wallets.some(
        (wallet) => (wallet.metadata as Record<string, unknown> | null)?.custody === "external",
      ),
    ).toBe(false);
  });
});
