import { afterAll, expect, it, setDefaultTimeout } from "bun:test";
import { closeDb, createDb, eq, secrets, tenants } from "@stwd/db";
import { SecretVault } from "../secret-vault";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;
setDefaultTimeout(30_000);

afterAll(async () => {
  await closeDb().catch(() => undefined);
});

realPostgresIt("legacy public rotation waits on the canonical lineage lock", async () => {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const tenantId = `secret-cross-writer-${suffix}`;
  const name = `kms/agent-${suffix}/key`;
  const admin = createDb(databaseUrl!);
  const blocker = await admin.client.reserve();
  const vault = new SecretVault(`secret-cross-writer-master-${suffix}`);
  let transactionOpen = false;

  try {
    await admin.db.insert(tenants).values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: `hash-${suffix}`,
    });
    const first = await vault.createSecret(tenantId, name, "version-one");

    await blocker`begin`;
    transactionOpen = true;
    const [owner] = await blocker<{ pid: number }[]>`select pg_backend_pid() as pid`;
    await blocker`
      select pg_advisory_xact_lock(
        hashtextextended(${`steward_secret_${tenantId}:${name}`}, 0)
      )
    `;

    const rotation = vault.rotateSecret(tenantId, name, "version-two");
    const deadline = Date.now() + 10_000;
    let observedWaiter = false;
    while (Date.now() < deadline) {
      const rows = await admin.client<{ count: string }[]>`
        select count(*)::text as count
        from pg_stat_activity
        where wait_event = 'advisory'
          and ${Number(owner?.pid)} = any(pg_blocking_pids(pid))
      `;
      if (Number(rows[0]?.count ?? 0) > 0) {
        observedWaiter = true;
        break;
      }
      await Bun.sleep(20);
    }
    expect(observedWaiter).toBe(true);
    expect(
      await admin.db
        .select({ version: secrets.version })
        .from(secrets)
        .where(eq(secrets.id, first.id)),
    ).toEqual([{ version: 1 }]);

    await blocker`commit`;
    transactionOpen = false;
    const rotated = await rotation;
    expect(rotated.version).toBe(2);
    expect(await vault.decryptSecret(tenantId, rotated.id)).toBe("version-two");
  } finally {
    if (transactionOpen) await blocker`rollback`;
    blocker.release();
    await admin.db.delete(secrets).where(eq(secrets.tenantId, tenantId));
    await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin.client.end();
  }
});
