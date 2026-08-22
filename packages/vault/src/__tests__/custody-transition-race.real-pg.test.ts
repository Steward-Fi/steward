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
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
} from "../external-key-custody";
import { KeyStore } from "../keystore";
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
const externalBeforeImportAgentId = `race-external-first-${suffix}`;
const importBeforeExternalAgentId = `race-local-first-${suffix}`;
const typedDataRotationAgentId = `typed-data-rotation-${suffix}`;
const transactionRotationAgentId = `transaction-rotation-${suffix}`;
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

async function waitForBlockedAdvisoryConnections(
  lockKey: string,
  expected: number,
): Promise<number[]> {
  if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await inspector<{ pid: number }[]>`
      with target as (
        select hashtextextended(${lockKey}, 0)::bigint as key
      )
      select distinct locks.pid
      from pg_locks as locks
      cross join target
      where locks.locktype = 'advisory'
        and locks.granted = false
        and locks.database = (select oid from pg_database where datname = current_database())
        and locks.classid::bigint = ((target.key >> 32) & 4294967295)
        and locks.objid::bigint = (target.key & 4294967295)
        and locks.objsubid = 1
    `;
    if (rows.length >= expected) return rows.map((row) => row.pid);
    await Bun.sleep(10);
  }
  throw new Error(`timed out waiting for ${expected} blocked advisory-lock connections`);
}

async function holdCustodyLock(lockedAgentId: string): Promise<{
  lockKey: string;
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
  return { lockKey, release: releaseBlocker, done };
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
    const pending: Promise<unknown>[] = [externalImport];
    let restore: Promise<unknown> | undefined;
    let firstWaiters: number[] = [];
    let allWaiters: number[] = [];
    try {
      firstWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 1);
      restore = localVault.restoreAgentFromMnemonic(
        tenantId,
        agentId,
        "Custody Race Agent",
        TEST_MNEMONIC,
        { walletType: "recoverable_user" },
      );
      pending.push(restore);
      allWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 2);
    } finally {
      heldLock.release();
      await Promise.allSettled([heldLock.done, ...pending]);
    }
    expect(new Set(allWaiters).size).toBeGreaterThanOrEqual(2);
    expect(allWaiters).toEqual(expect.arrayContaining(firstWaiters));

    if (!restore) throw new Error("mnemonic restore did not start");
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

  test("an external registration queued first prevents a concurrent EVM import from creating local keys", async () => {
    const db = getDb();
    const { vault: localVault, address } = await seedBareRecoverableAgent(
      externalBeforeImportAgentId,
    );
    const heldLock = await holdCustodyLock(externalBeforeImportAgentId);

    const provider = new RealPgRaceProvider();
    const externalVault = new Vault({
      masterPassword: MASTER_PASSWORD,
      externalKeyCustodyProvider: provider,
    });
    const externalImport = externalVault.importExternalKeyHandle({
      tenantId,
      agentId: externalBeforeImportAgentId,
      chainFamily: "evm",
      address,
      handle: { providerId: provider.id, keyId: `external-before-import-${suffix}` },
    });
    const pending: Promise<unknown>[] = [externalImport];
    let localImport: Promise<unknown> | undefined;
    let firstWaiters: number[] = [];
    let allWaiters: number[] = [];
    try {
      firstWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 1);
      localImport = localVault.importKey(
        tenantId,
        externalBeforeImportAgentId,
        generatePrivateKey(),
        "evm",
      );
      pending.push(localImport);
      allWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 2);
    } finally {
      heldLock.release();
      await Promise.allSettled([heldLock.done, ...pending]);
    }
    expect(new Set(allWaiters).size).toBeGreaterThanOrEqual(2);
    expect(allWaiters).toEqual(expect.arrayContaining(firstWaiters));

    if (!localImport) throw new Error("local import did not start");
    const [externalResult, localResult] = await Promise.allSettled([externalImport, localImport]);
    expect(externalResult.status).toBe("fulfilled");
    expect(localResult.status).toBe("rejected");
    if (localResult.status === "rejected") {
      expect(String(localResult.reason)).toContain("external-custody");
    }
    expect(provider.registrationCalls).toBe(1);
    expect(
      await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, externalBeforeImportAgentId)),
    ).toHaveLength(0);
    expect(
      await db
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, externalBeforeImportAgentId)),
    ).toHaveLength(0);
  });

  test("an EVM import queued first makes external registration revalidate and fail closed", async () => {
    const db = getDb();
    const { vault: localVault, address } = await seedBareRecoverableAgent(
      importBeforeExternalAgentId,
    );
    const heldLock = await holdCustodyLock(importBeforeExternalAgentId);

    const localImport = localVault.importKey(
      tenantId,
      importBeforeExternalAgentId,
      generatePrivateKey(),
      "evm",
    );
    const pending: Promise<unknown>[] = [localImport];
    const provider = new RealPgRaceProvider();
    let externalImport: Promise<unknown> | undefined;
    let firstWaiters: number[] = [];
    let allWaiters: number[] = [];
    try {
      firstWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 1);
      const externalVault = new Vault({
        masterPassword: MASTER_PASSWORD,
        externalKeyCustodyProvider: provider,
      });
      externalImport = externalVault.importExternalKeyHandle({
        tenantId,
        agentId: importBeforeExternalAgentId,
        chainFamily: "evm",
        address,
        handle: { providerId: provider.id, keyId: `import-before-external-${suffix}` },
      });
      pending.push(externalImport);
      allWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 2);
    } finally {
      heldLock.release();
      await Promise.allSettled([heldLock.done, ...pending]);
    }
    expect(new Set(allWaiters).size).toBeGreaterThanOrEqual(2);
    expect(allWaiters).toEqual(expect.arrayContaining(firstWaiters));

    if (!externalImport) throw new Error("external import did not start");
    const [localResult, externalResult] = await Promise.allSettled([localImport, externalImport]);
    expect(localResult.status).toBe("fulfilled");
    expect(externalResult.status).toBe("rejected");
    if (externalResult.status === "rejected") {
      expect(String(externalResult.reason)).toContain("server-managed key");
    }
    expect(provider.registrationCalls).toBe(1);
    expect(
      await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, importBeforeExternalAgentId)),
    ).toHaveLength(1);
    expect(
      await db
        .select()
        .from(encryptedChainKeys)
        .where(eq(encryptedChainKeys.agentId, importBeforeExternalAgentId)),
    ).toHaveLength(1);
    const [wallet] = await db
      .select({ metadata: agentWallets.metadata })
      .from(agentWallets)
      .where(
        and(
          eq(agentWallets.agentId, importBeforeExternalAgentId),
          eq(agentWallets.chainFamily, "evm"),
          isNull(agentWallets.venue),
        ),
      );
    expect((wallet?.metadata as Record<string, unknown> | null)?.custody).not.toBe("external");
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
    const pending: Promise<unknown>[] = [restore];
    const provider = new RealPgRaceProvider();
    let externalImport: Promise<unknown> | undefined;
    let firstWaiters: number[] = [];
    let allWaiters: number[] = [];
    try {
      firstWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 1);
      const externalVault = new Vault({
        masterPassword: MASTER_PASSWORD,
        externalKeyCustodyProvider: provider,
      });
      externalImport = externalVault.importExternalKeyHandle({
        tenantId,
        agentId: restoreFirstAgentId,
        chainFamily: "evm",
        address,
        handle: { providerId: provider.id, keyId: `restore-first-key-${suffix}` },
      });
      pending.push(externalImport);
      allWaiters = await waitForBlockedAdvisoryConnections(heldLock.lockKey, 2);
    } finally {
      heldLock.release();
      await Promise.allSettled([heldLock.done, ...pending]);
    }
    expect(new Set(allWaiters).size).toBeGreaterThanOrEqual(2);
    expect(allWaiters).toEqual(expect.arrayContaining(firstWaiters));

    if (!externalImport) throw new Error("external import did not start");
    const [restoreResult, externalResult] = await Promise.allSettled([restore, externalImport]);
    expect(restoreResult.status).toBe("fulfilled");
    expect(externalResult.status).toBe("rejected");
    if (externalResult.status === "rejected") {
      expect(String(externalResult.reason)).toContain("server-managed key");
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

  test("a queued typed-data signature revalidates the venue wallet after a concurrent rotation", async () => {
    if (!blocker || !inspector) throw new Error("real PostgreSQL clients are unavailable");
    const venue = "hyperliquid";
    const vault = new Vault({ masterPassword: MASTER_PASSWORD });
    await vault.createAgent(tenantId, typedDataRotationAgentId, "Typed Data Rotation Agent");
    const original = await vault.provisionVenueWallet({
      tenantId,
      agentId: typedDataRotationAgentId,
      venue,
      chainFamily: "evm",
      approvedAddresses: [],
    });

    const replacementPrivateKey = generatePrivateKey();
    const replacementAddress = privateKeyToAccount(replacementPrivateKey).address;
    const replacement = new KeyStore(MASTER_PASSWORD).encrypt(replacementPrivateKey, {
      tenantId,
      agentId: typedDataRotationAgentId,
      chainFamily: "evm",
      venue,
    });
    const lockKey = JSON.stringify([
      "vault-custody-v1",
      tenantId,
      typedDataRotationAgentId,
      "evm",
      venue,
    ]);
    let signingResult!: Promise<
      { status: "fulfilled"; value: string } | { status: "rejected"; reason: unknown }
    >;

    await blocker.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`;
      signingResult = vault
        .signTypedData({
          tenantId,
          agentId: typedDataRotationAgentId,
          venue,
          expectedWalletAddress: original.address,
          domain: { name: "Steward wallet rotation", version: "1", chainId: 8453 },
          types: { Rotation: [{ name: "session", type: "string" }] },
          primaryType: "Rotation",
          value: { session: "authorized-before-rotation" },
        })
        .then(
          (value) => ({ status: "fulfilled" as const, value }),
          (reason: unknown) => ({ status: "rejected" as const, reason }),
        );
      await waitForBlockedAdvisoryConnections(lockKey, 1);
      await tx`
        update encrypted_chain_keys
        set ciphertext = ${replacement.ciphertext}, iv = ${replacement.iv},
            tag = ${replacement.tag}, salt = ${replacement.salt}
        where agent_id = ${typedDataRotationAgentId}
          and chain_family = 'evm'
          and venue = ${venue}
      `;
      await tx`
        update agent_wallets
        set address = ${replacementAddress}
        where agent_id = ${typedDataRotationAgentId}
          and chain_family = 'evm'
          and venue = ${venue}
      `;
    });

    const result = await signingResult;
    expect(result.status).toBe("rejected");
    if (result.status === "rejected") {
      expect(String(result.reason)).toContain(
        "Typed-data signer no longer matches the authorized wallet",
      );
    }
  });

  test("a queued transaction signature cannot use a concurrently rotated venue key", async () => {
    if (!blocker || !inspector) throw new Error("real PostgreSQL clients are unavailable");
    const venue = "hyperliquid";
    const vault = new Vault({ masterPassword: MASTER_PASSWORD });
    await vault.createAgent(tenantId, transactionRotationAgentId, "Transaction Rotation Agent");
    const original = await vault.provisionVenueWallet({
      tenantId,
      agentId: transactionRotationAgentId,
      venue,
      chainFamily: "evm",
      approvedAddresses: [],
    });

    const replacementPrivateKey = generatePrivateKey();
    const replacementAddress = privateKeyToAccount(replacementPrivateKey).address;
    const replacement = new KeyStore(MASTER_PASSWORD).encrypt(replacementPrivateKey, {
      tenantId,
      agentId: transactionRotationAgentId,
      chainFamily: "evm",
      venue,
    });
    const lockKey = JSON.stringify([
      "vault-custody-v1",
      tenantId,
      transactionRotationAgentId,
      "evm",
      venue,
    ]);
    let signingResult!: Promise<
      { status: "fulfilled"; value: string } | { status: "rejected"; reason: unknown }
    >;

    await blocker.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))`;
      signingResult = vault
        .signTransaction({
          tenantId,
          agentId: transactionRotationAgentId,
          venue,
          walletAddress: original.address,
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          nonce: 0,
          gasLimit: "21000",
          broadcast: false,
        })
        .then(
          (value) => ({ status: "fulfilled" as const, value }),
          (reason: unknown) => ({ status: "rejected" as const, reason }),
        );
      await waitForBlockedAdvisoryConnections(lockKey, 1);
      await tx`
        update encrypted_chain_keys
        set ciphertext = ${replacement.ciphertext}, iv = ${replacement.iv},
            tag = ${replacement.tag}, salt = ${replacement.salt}
        where agent_id = ${transactionRotationAgentId}
          and chain_family = 'evm'
          and venue = ${venue}
      `;
      await tx`
        update agent_wallets
        set address = ${replacementAddress}
        where agent_id = ${transactionRotationAgentId}
          and chain_family = 'evm'
          and venue = ${venue}
      `;
    });

    const result = await signingResult;
    expect(result.status).toBe("rejected");
    if (result.status === "rejected") {
      expect(String(result.reason)).toContain(
        "Transaction signer no longer matches the authorized wallet",
      );
    }
  });
});
