import { expect, it } from "bun:test";
import { createRequire } from "node:module";

type Sql = {
  <T extends unknown[]>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T>;
  unsafe<T extends unknown[]>(query: string): Promise<T>;
  begin<T>(callback: (tx: Sql) => Promise<T>): Promise<T>;
  end(): Promise<void>;
};

const requireFromDb = createRequire(new URL("../../../db/package.json", import.meta.url));
const postgresModule = requireFromDb("postgres") as { default?: unknown } | unknown;
const postgres = ((postgresModule as { default?: unknown }).default ?? postgresModule) as (
  url: string,
  options: { max: number },
) => Sql;

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt("serializes cumulative operator reservations across real connections", async () => {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const table = `operator_lock_test_${suffix}`;
  // Match the shared per-agent lock used by vault/intents/operator transfers.
  const agentId = `operator-lock-test-${suffix}`;
  const admin = postgres(databaseUrl!, { max: 1 });
  const first = postgres(databaseUrl!, { max: 1 });
  const second = postgres(databaseUrl!, { max: 1 });
  try {
    await admin.unsafe(
      `create table "${table}" (amount bigint not null, status text not null, created_at timestamptz not null default now())`,
    );
    const reserve = (client: Sql) =>
      client.begin(async (tx) => {
        await tx`select pg_advisory_xact_lock(hashtext(${agentId}))`;
        const [row] = await tx.unsafe<{ total: string }[]>(
          `select coalesce(sum(amount), 0)::text as total from "${table}" where status in ('pending', 'final')`,
        );
        if (BigInt(row?.total ?? "0") + 60n > 100n) return false;
        await Bun.sleep(25);
        await tx.unsafe(`insert into "${table}" (amount, status) values (60, 'pending')`);
        return true;
      });

    const admitted = await Promise.all([reserve(first), reserve(second)]);
    expect(admitted.sort()).toEqual([false, true]);
    const [count] = await admin.unsafe<{ count: string }[]>(
      `select count(*)::text as count from "${table}"`,
    );
    expect(count?.count).toBe("1");
  } finally {
    await admin.unsafe(`drop table if exists "${table}"`);
    await Promise.all([admin.end(), first.end(), second.end()]);
  }
});
