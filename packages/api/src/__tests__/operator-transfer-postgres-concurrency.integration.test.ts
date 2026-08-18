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
        await tx`select pg_advisory_xact_lock(hashtextextended(${agentId}, 0))`;
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

realPostgresIt(
  "accounts operator and vault spend conjunctively under the shared lock in either order",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const admin = postgres(databaseUrl!, { max: 1 });
    const first = postgres(databaseUrl!, { max: 1 });
    const second = postgres(databaseUrl!, { max: 1 });
    const tenantId = `cross-spend-tenant-${suffix}`;

    const runOrderedRace = async (firstKind: "operator" | "vault") => {
      const agentId = `cross-spend-${firstKind}-${suffix}`;
      await admin`insert into tenants (id, name, api_key_hash) values (${tenantId}, ${tenantId}, ${`hash-${tenantId}`}) on conflict (id) do nothing`;
      await admin`insert into agents (id, tenant_id, name, wallet_address) values (${agentId}, ${tenantId}, ${agentId}, '0x1234567890123456789012345678901234567890')`;

      let unlockFirst: (() => void) | undefined;
      const firstHasLock = new Promise<void>((resolve) => {
        unlockFirst = resolve;
      });
      const attempt = (client: Sql, kind: "operator" | "vault", onLocked?: () => void) =>
        client.begin(async (tx) => {
          await tx`select pg_advisory_xact_lock(hashtextextended(${agentId}, 0))`;
          onLocked?.();
          // The fixture pins both rails to one USD-micro denomination. Production
          // keeps native counters separate and adds operator USDC only in the USD
          // evaluator; this query exercises the same conjunctive admission rule.
          const [totals] = await tx<[{ vault: string; operator: string }]>`
            select
              coalesce((select sum(value::numeric) from transactions where agent_id = ${agentId} and status in ('signed', 'broadcast', 'confirmed', 'outcome_unknown')), 0)::text as vault,
              coalesce((select sum(amount_base_units::numeric) from operator_transfer_reservations where agent_id = ${agentId} and status in ('pending', 'final')), 0)::text as operator
          `;
          if (BigInt(totals.vault) + BigInt(totals.operator) + 60_000_000n > 100_000_000n) {
            return false;
          }
          await Bun.sleep(25);
          if (kind === "operator") {
            await tx`
              insert into operator_transfer_reservations
                (tenant_id, agent_id, rail, idempotency_key, request_digest, destination,
                 amount_base_units, status)
              values
                (${tenantId}, ${agentId}, 'usd-send', ${`${kind}-${agentId}`}, ${"a".repeat(64)},
                 '0x2222222222222222222222222222222222222222', '60000000', 'pending')
            `;
          } else {
            await tx`
              insert into transactions
                (id, agent_id, status, to_address, value, chain_id, policy_results)
              values
                (${`${kind}-${agentId}`}, ${agentId}, 'signed', '0x2222222222222222222222222222222222222222', '60000000', 8453, '[]'::jsonb)
            `;
          }
          return true;
        });

      const secondKind = firstKind === "operator" ? "vault" : "operator";
      const firstAttempt = attempt(first, firstKind, unlockFirst);
      await firstHasLock;
      const secondAttempt = attempt(second, secondKind);
      const admitted = await Promise.all([firstAttempt, secondAttempt]);
      expect(admitted).toEqual([true, false]);
    };

    try {
      await runOrderedRace("operator");
      await runOrderedRace("vault");
    } finally {
      await admin`delete from tenants where id = ${tenantId}`;
      await Promise.all([admin.end(), first.end(), second.end()]);
    }
  },
);

realPostgresIt(
  "preserves ambiguous cross-rail counters and releases only reconciled failures",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `operator-stats-tenant-${suffix}`;
    const agentId = `operator-stats-agent-${suffix}`;
    const otherAgentId = `operator-stats-other-${suffix}`;
    const admin = postgres(databaseUrl!, { max: 1 });
    try {
      await admin`insert into tenants (id, name, api_key_hash) values (${tenantId}, ${tenantId}, ${`hash-${tenantId}`})`;
      await admin`
        insert into agents (id, tenant_id, name, wallet_address) values
          (${agentId}, ${tenantId}, ${agentId}, '0x1234567890123456789012345678901234567890'),
          (${otherAgentId}, ${tenantId}, ${otherAgentId}, '0x2234567890123456789012345678901234567890')
      `;
      await admin`
        insert into transactions (id, agent_id, status, to_address, value, chain_id, policy_results) values
          (${`unknown-${suffix}`}, ${agentId}, 'outcome_unknown', '0x3234567890123456789012345678901234567890', '95', 42161, '[]'::jsonb),
          (${`failed-${suffix}`}, ${agentId}, 'failed', '0x3234567890123456789012345678901234567890', '999', 42161, '[]'::jsonb),
          (${`other-${suffix}`}, ${otherAgentId}, 'confirmed', '0x3234567890123456789012345678901234567890', '777', 42161, '[]'::jsonb)
      `;
      await admin`
        insert into operator_transfer_reservations
          (tenant_id, agent_id, rail, idempotency_key, request_digest, destination,
           amount_base_units, status, finalized_at, response_status, response_body)
        values
          (${tenantId}, ${agentId}, 'withdraw', ${`pending-${suffix}`}, ${"b".repeat(64)}, '0x4234567890123456789012345678901234567890', '60000000', 'pending', null, null, null),
          (${tenantId}, ${agentId}, 'usd-send', ${`final-${suffix}`}, ${"c".repeat(64)}, '0x4234567890123456789012345678901234567890', '10000000', 'final', now(), 200, '{"ok":true}'::jsonb),
          (${tenantId}, ${agentId}, 'withdraw', ${`released-${suffix}`}, ${"d".repeat(64)}, '0x4234567890123456789012345678901234567890', '999000000', 'released', now(), null, null),
          (${tenantId}, ${otherAgentId}, 'withdraw', ${`other-${suffix}`}, ${"e".repeat(64)}, '0x4234567890123456789012345678901234567890', '888000000', 'final', now(), 200, '{"ok":true}'::jsonb)
      `;

      const { getTransactionStats } = await import("../services/context");
      const ambiguous = await getTransactionStats(agentId, 42161);
      expect(ambiguous.recentTxCount1h).toBe(3);
      expect(ambiguous.recentTxCount24h).toBe(3);
      expect(ambiguous.spentToday).toBe(95n);
      expect(ambiguous.additionalUsdSpentTodayMicros).toBe(70_000_000n);

      await admin`update transactions set status = 'failed' where id = ${`unknown-${suffix}`}`;
      await admin`
        update operator_transfer_reservations set status = 'released', finalized_at = now()
        where tenant_id = ${tenantId} and agent_id = ${agentId} and idempotency_key = ${`pending-${suffix}`}
      `;
      const reconciled = await getTransactionStats(agentId, 42161);
      expect(reconciled.recentTxCount1h).toBe(1);
      expect(reconciled.recentTxCount24h).toBe(1);
      expect(reconciled.spentToday).toBe(0n);
      expect(reconciled.additionalUsdSpentTodayMicros).toBe(10_000_000n);
    } finally {
      await admin`delete from tenants where id = ${tenantId}`;
      await admin.end();
    }
  },
);
