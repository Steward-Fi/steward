/**
 * cumulative-spend-tracker.test.ts - proves the #206 atomic, configurable-window
 * cumulative spend reservation against a REAL Redis (STEWARD_REDIS_TESTS=1).
 *
 * Adversarial coverage:
 *  - reserve admits under cap, rejects at/over cap (boundary inclusive).
 *  - REAL concurrency: N parallel reserves that would collectively exceed the cap
 *    admit only as many as fit (atomic single-winner, no read-then-check race).
 *  - MULTI-CAP on one stream: a single invoke checked against several caps is
 *    counted ONCE; a breach on ANY cap rejects the whole invoke.
 *  - STREAM key excludes window/max (codex P1): lowering a cap re-evaluates
 *    against the SAME history, not a fresh empty bucket.
 *  - window ageout boundary (half-open).
 *  - release reclaims budget; settle keeps it counted.
 *  - scope + currency isolation.
 *  - corrupt member => fail closed.
 *  - windowed invoke count (maxCalls) atomic reserve + release.
 */

import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { disconnectRedis, getRedis } from "../client.js";
import {
  __setBeforeCumulativeSpendSumImportForTests,
  cumulativeSpendStreamKeyForTest,
  getCumulativeSpendSum,
  getWindowedInvokeCount,
  releaseCumulativeSpend,
  releaseLegacyCumulativeSpendAfterCutover,
  releaseLegacyWindowedInvokeAfterCutover,
  releaseWindowedInvoke,
  reserveCumulativeSpend,
  reserveCumulativeSpendBatch,
  reserveWindowedInvoke,
  settleCumulativeSpend,
} from "../cumulative-spend-tracker.js";

const runRedis = process.env.STEWARD_REDIS_TESTS === "1";
const describeRedis = runRedis ? describe : describe.skip;

const AGENT = `cumspend-test-${Date.now()}`;
const STREAM = { agentId: AGENT, scope: "agent" as const, scopeKey: "", currency: "USD" };

async function cleanup() {
  const redis = getRedis();
  for (const pattern of [`cumspend:${AGENT}*`, `cumspend:v2:*${AGENT}*`]) {
    let cursor = "0";
    do {
      const [next, keys] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
      cursor = next;
      if (keys.length > 0) await redis.del(...keys);
    } while (cursor !== "0");
  }
}

beforeEach(async () => {
  __setBeforeCumulativeSpendSumImportForTests();
  if (!runRedis) return;
  await cleanup();
});

afterAll(async () => {
  __setBeforeCumulativeSpendSumImportForTests();
  if (!runRedis) return;
  await cleanup();
  await disconnectRedis();
});

describeRedis("reserveCumulativeSpend - under / boundary / over", () => {
  test("under cap admits and reports priorSums", async () => {
    const r = await reserveCumulativeSpend({
      stream: STREAM,
      caps: [{ windowSeconds: 3600, max: 5_000_000 }],
      amount: 1_000_000,
    });
    expect(r.ok).toBe(true);
    expect(r.priorSums[0]).toBe(0);
    expect(typeof r.reservationId).toBe("string");
  });

  test("EXACT boundary admits (sum lands on max), one micro over rejects", async () => {
    const caps = [{ windowSeconds: 3600, max: 5_000_000 }];
    expect((await reserveCumulativeSpend({ stream: STREAM, caps, amount: 4_000_000 })).ok).toBe(
      true,
    );
    expect((await reserveCumulativeSpend({ stream: STREAM, caps, amount: 1_000_000 })).ok).toBe(
      true,
    );
    const over = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 1 });
    expect(over.ok).toBe(false);
    expect(over.priorSums[0]).toBe(5_000_000);
    expect(over.reservationId).toBeUndefined();
  });
});

describeRedis("reserveCumulativeSpend - REAL concurrency single-winner", () => {
  test("100 parallel reserves of 100k against a 1M cap admit exactly 10", async () => {
    const caps = [{ windowSeconds: 3600, max: 1_000_000 }];
    const results = await Promise.all(
      Array.from({ length: 100 }, () =>
        reserveCumulativeSpend({ stream: STREAM, caps, amount: 100_000 }),
      ),
    );
    expect(results.filter((r) => r.ok).length).toBe(10);
    const snap = await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 });
    expect(snap?.sum).toBe(1_000_000);
  });
});

describeRedis("tenant-bound atomic reservation batches", () => {
  test("bridges live v1 history before v2 admission without resetting the cap", async () => {
    const common = {
      agentId: AGENT,
      scope: "operation" as const,
      scopeKey: "legacy-history",
      currency: "USD",
    };
    const caps = [{ windowSeconds: 3600, max: 10 }];
    const legacy = await reserveCumulativeSpend({
      stream: common,
      caps,
      amount: 7,
      reservationId: "legacy-settled",
    });
    await settleCumulativeSpend({ stream: common, reservationId: legacy.reservationId as string });

    const denied = await reserveCumulativeSpend({
      stream: { ...common, tenantId: "tenant-history" },
      caps,
      amount: 4,
      reservationId: "v2-must-see-v1",
    });
    expect(denied).toEqual({ ok: false, priorSums: [7] });
    expect(
      await getCumulativeSpendSum({
        ...common,
        tenantId: "tenant-history",
        windowSeconds: 3600,
      }),
    ).toEqual({ sum: 7 });

    // The legacy ZSET is now a durable snapshot/fence. An unaware old binary
    // cannot write after cutover and silently escape the tenant-bound stream.
    await expect(
      reserveCumulativeSpend({
        stream: common,
        caps,
        amount: 1,
        reservationId: "late-old-writer",
      }),
    ).rejects.toThrow();
  });

  test("concurrent old/new writers have no cutover gap", async () => {
    const caps = [{ windowSeconds: 3600, max: 10 }];
    for (let i = 0; i < 25; i++) {
      const common = {
        agentId: AGENT,
        scope: "operation" as const,
        scopeKey: `rolling-cutover-${i}`,
        currency: "USD",
      };
      await reserveCumulativeSpend({
        stream: common,
        caps,
        amount: 4,
        reservationId: `seed-${i}`,
      });
      const [oldWriter, newWriter] = await Promise.allSettled([
        reserveCumulativeSpend({
          stream: common,
          caps,
          amount: 4,
          reservationId: `old-${i}`,
        }),
        reserveCumulativeSpend({
          stream: { ...common, tenantId: "tenant-rolling" },
          caps,
          amount: 4,
          reservationId: `new-${i}`,
        }),
      ]);
      const oldAdmitted = oldWriter.status === "fulfilled" && oldWriter.value.ok;
      const newAdmitted = newWriter.status === "fulfilled" && newWriter.value.ok;
      expect(Number(oldAdmitted) + Number(newAdmitted)).toBe(1);
      expect(
        await getCumulativeSpendSum({
          ...common,
          tenantId: "tenant-rolling",
          windowSeconds: 3600,
        }),
      ).toEqual({ sum: 8 });
    }
  });

  test("a pre-rollout release cannot be reimported after the v2 fence", async () => {
    const common = {
      agentId: AGENT,
      scope: "operation" as const,
      scopeKey: "legacy-release",
      currency: "USD",
    };
    const legacy = await reserveCumulativeSpend({
      stream: common,
      caps: [{ windowSeconds: 3600, max: 20 }],
      amount: 7,
      reservationId: "legacy-release-id",
    });
    expect(legacy.ok).toBe(true);
    expect(
      await reserveCumulativeSpend({
        stream: { ...common, tenantId: "tenant-release" },
        caps: [{ windowSeconds: 3600, max: 20 }],
        amount: 3,
        reservationId: "v2-survivor",
      }),
    ).toMatchObject({ ok: true, priorSums: [7] });

    const release = () =>
      releaseLegacyCumulativeSpendAfterCutover({
        stream: { ...common, tenantId: "tenant-release" },
        reservationId: "legacy-release-id",
        amount: 7,
      });
    await release();
    await release(); // crash retry is idempotent
    expect(
      await reserveCumulativeSpend({
        stream: { ...common, tenantId: "tenant-release" },
        caps: [{ windowSeconds: 3600, max: 20 }],
        amount: 7,
        reservationId: "legacy-release-id",
      }),
    ).toMatchObject({ ok: false });
    expect(
      await getCumulativeSpendSum({
        ...common,
        tenantId: "tenant-release",
        windowSeconds: 3600,
      }),
    ).toEqual({ sum: 3 });
    // Re-reading/importing the fenced snapshot must not resurrect the 7 units.
    expect(
      await reserveCumulativeSpend({
        stream: { ...common, tenantId: "tenant-release" },
        caps: [{ windowSeconds: 3600, max: 20 }],
        amount: 1,
        reservationId: "after-release",
      }),
    ).toMatchObject({ ok: true, priorSums: [3] });
  });

  test("release racing a v2 importer leaves only the new reservation", async () => {
    const caps = [{ windowSeconds: 3600, max: 20 }];
    for (let i = 0; i < 25; i++) {
      const common = {
        agentId: AGENT,
        scope: "operation" as const,
        scopeKey: `legacy-release-race-${i}`,
        currency: "USD",
      };
      const reservationId = `legacy-race-${i}`;
      await reserveCumulativeSpend({ stream: common, caps, amount: 7, reservationId });
      const [released, admitted] = await Promise.all([
        releaseLegacyCumulativeSpendAfterCutover({
          stream: { ...common, tenantId: "tenant-release-race" },
          reservationId,
          amount: 7,
        }),
        reserveCumulativeSpend({
          stream: { ...common, tenantId: "tenant-release-race" },
          caps,
          amount: 3,
          reservationId: `new-race-${i}`,
        }),
      ]);
      expect(released).toBeUndefined();
      expect(admitted.ok).toBe(true);
      expect(
        await getCumulativeSpendSum({
          ...common,
          tenantId: "tenant-release-race",
          windowSeconds: 3600,
        }),
      ).toEqual({ sum: 3 });
    }
  });

  test("a release after advisory snapshot-read cannot be resurrected by SUM import", async () => {
    const common = {
      agentId: AGENT,
      scope: "operation" as const,
      scopeKey: "legacy-release-sum-race",
      currency: "USD",
    };
    const stream = { ...common, tenantId: "tenant-release-sum-race" };
    const caps = [{ windowSeconds: 3600, max: 10 }];
    await reserveCumulativeSpend({
      stream: common,
      caps,
      amount: 7,
      reservationId: "legacy-sum-race",
    });

    let snapshotRead!: () => void;
    const snapshotReady = new Promise<void>((resolve) => {
      snapshotRead = resolve;
    });
    let continueImport!: () => void;
    const importBarrier = new Promise<void>((resolve) => {
      continueImport = resolve;
    });
    __setBeforeCumulativeSpendSumImportForTests(async () => {
      snapshotRead();
      await importBarrier;
    });
    const sumPending = getCumulativeSpendSum({ ...stream, windowSeconds: 3600 });
    await snapshotReady;
    await releaseLegacyCumulativeSpendAfterCutover({
      stream,
      reservationId: "legacy-sum-race",
      amount: 7,
    });
    continueImport();
    expect(await sumPending).toEqual({ sum: 0 });
    __setBeforeCumulativeSpendSumImportForTests();

    expect(
      await reserveCumulativeSpend({
        stream,
        caps,
        amount: 4,
        reservationId: "after-sum-race",
      }),
    ).toMatchObject({ ok: true, priorSums: [0] });
  });

  test("the same agent id in two tenants has independent history", async () => {
    const common = { agentId: AGENT, scope: "agent" as const, scopeKey: "", currency: "USD" };
    await reserveCumulativeSpend({
      stream: { ...common, tenantId: "tenant-a" },
      caps: [{ windowSeconds: 3600, max: 10 }],
      amount: 10,
    });
    expect(
      await reserveCumulativeSpend({
        stream: { ...common, tenantId: "tenant-b" },
        caps: [{ windowSeconds: 3600, max: 10 }],
        amount: 10,
      }),
    ).toMatchObject({ ok: true, priorSums: [0] });
  });

  test("a denied workspace stream cannot leave a provisional global debit", async () => {
    const tenantId = "tenant-atomic";
    const global = {
      tenantId,
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "budget:global:count",
      currency: "__agent_budget_count__",
    };
    const workspace = {
      ...global,
      scopeKey: "budget:workspace:w1:count",
    };
    await reserveCumulativeSpend({
      stream: workspace,
      caps: [{ windowSeconds: 3600, max: 1 }],
      amount: 1,
      reservationId: "workspace-full",
    });
    const denied = await reserveCumulativeSpendBatch({
      groups: [
        {
          stream: global,
          caps: [{ windowSeconds: 3600, max: 10 }],
          amount: 1,
          reservationId: "atomic-global",
        },
        {
          stream: workspace,
          caps: [{ windowSeconds: 3600, max: 1 }],
          amount: 1,
          reservationId: "atomic-workspace",
        },
      ],
    });
    expect(denied.ok).toBe(false);
    expect(await getCumulativeSpendSum({ ...global, windowSeconds: 3600 })).toEqual({ sum: 0 });
    expect(await getCumulativeSpendSum({ ...workspace, windowSeconds: 3600 })).toEqual({ sum: 1 });
  });

  test("duplicate streams are rejected before they can bypass an aggregate cap", async () => {
    const stream = {
      tenantId: "tenant-duplicate",
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "budget:global:count",
      currency: "__agent_budget_count__",
    };
    await expect(
      reserveCumulativeSpendBatch({
        groups: [
          {
            stream,
            caps: [{ windowSeconds: 3600, max: 1 }],
            amount: 1,
            reservationId: "duplicate-a",
          },
          {
            stream,
            caps: [{ windowSeconds: 3600, max: 1 }],
            amount: 1,
            reservationId: "duplicate-b",
          },
        ],
      }),
    ).rejects.toThrow("duplicate stream");
    expect(await getCumulativeSpendSum({ ...stream, windowSeconds: 3600 })).toEqual({ sum: 0 });
  });

  test("cross-tenant or cross-agent batches fail before Redis Cluster dispatch", async () => {
    const group = (tenantId: string, agentId: string, reservationId: string) => ({
      stream: {
        tenantId,
        agentId,
        scope: "agent" as const,
        scopeKey: "",
        currency: "USD",
      },
      caps: [{ windowSeconds: 3600, max: 10 }],
      amount: 1,
      reservationId,
    });
    await expect(
      reserveCumulativeSpendBatch({
        groups: [group("tenant-a", AGENT, "tenant-a"), group("tenant-b", AGENT, "tenant-b")],
      }),
    ).rejects.toThrow("share one tenant and agent");
    await expect(
      reserveCumulativeSpendBatch({
        groups: [group("tenant-a", AGENT, "agent-a"), group("tenant-a", `${AGENT}-b`, "agent-b")],
      }),
    ).rejects.toThrow("share one tenant and agent");
  });

  test("releases a v1 maxCalls slot after its legacy stream was fenced", async () => {
    const operationKey = "legacy-windowed-release";
    const legacy = await reserveWindowedInvoke({
      agentId: AGENT,
      operationKey,
      caps: [{ windowSeconds: 3600, max: 5 }],
      reservationId: "legacy-windowed-slot",
    });
    expect(legacy.ok).toBe(true);
    expect(
      (
        await reserveWindowedInvoke({
          tenantId: "tenant-windowed-release",
          agentId: AGENT,
          operationKey,
          caps: [{ windowSeconds: 3600, max: 5 }],
          reservationId: "v2-windowed-slot",
        })
      ).ok,
    ).toBe(true);
    await releaseLegacyWindowedInvokeAfterCutover({
      tenantId: "tenant-windowed-release",
      agentId: AGENT,
      operationKey,
      reservationId: "legacy-windowed-slot",
    });
    expect(
      await getWindowedInvokeCount({
        tenantId: "tenant-windowed-release",
        agentId: AGENT,
        operationKey,
        windowSeconds: 3600,
      }),
    ).toBe(1);
  });

  test("a crash retry reuses every member in the batch exactly once", async () => {
    const tenantId = "tenant-retry";
    const t0 = Date.now();
    const groups = ["global", "workspace"].map((scope) => ({
      stream: {
        tenantId,
        agentId: AGENT,
        scope: "agent" as const,
        scopeKey: `budget:${scope}:count`,
        currency: "__agent_budget_count__",
      },
      caps: [{ windowSeconds: 3600, max: 5 }],
      amount: 1,
      reservationId: `stable-${scope}`,
    }));
    expect(await reserveCumulativeSpendBatch({ groups, now: t0 })).toMatchObject({ ok: true });
    expect(await reserveCumulativeSpendBatch({ groups, now: t0 + 1_000 })).toMatchObject({
      ok: true,
      priorSums: [[0], [0]],
    });
    for (const group of groups) {
      expect(
        await getCumulativeSpendSum({
          ...group.stream,
          windowSeconds: 3600,
          // The original pre-crash score has just aged out. The adopted retry
          // remains, proving ZADD refreshed one member rather than adding two.
          now: t0 + 3_600_500,
        }),
      ).toEqual({ sum: 1 });
    }
  });
});

describeRedis("stable reservation identity - crash retry semantics", () => {
  test("parallel retries debit once and a now-denied orphan is atomically reclaimed", async () => {
    const stable = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const input = {
      stream: STREAM,
      caps: [{ windowSeconds: 3600, max: 10 }],
      amount: 4,
      reservationId: stable,
    };
    const [a, b] = await Promise.all([
      reserveCumulativeSpend(input),
      reserveCumulativeSpend(input),
    ]);
    expect(a).toMatchObject({ ok: true, priorSums: [0], reservationId: stable });
    expect(b).toMatchObject({ ok: true, priorSums: [0], reservationId: stable });
    expect(await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 })).toEqual({ sum: 4 });

    // If current authoritative policy no longer admits the pre-commit orphan,
    // retry denies and removes that exact member in the same Lua operation.
    const denied = await reserveCumulativeSpend({
      ...input,
      caps: [{ windowSeconds: 3600, max: 3 }],
    });
    expect(denied).toMatchObject({ ok: false, priorSums: [0] });
    expect(await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 })).toEqual({ sum: 0 });
  });
});

describeRedis("multi-cap on one stream (codex P2: counted once, any breach rejects)", () => {
  test("an invoke governed by a 1h AND 24h cap is counted once; a 1h breach rejects", async () => {
    // Fill the 1h window to 90 while the 24h window has plenty of room.
    const caps = [
      { windowSeconds: 3600, max: 100 },
      { windowSeconds: 86400, max: 1000 },
    ];
    await reserveCumulativeSpend({ stream: STREAM, caps, amount: 90 });
    // +60 => 1h sum 150 > 100 (breach) even though 24h sum 150 <= 1000 => REJECT,
    // and the entry is NOT added (counted once, not double).
    const r = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 60 });
    expect(r.ok).toBe(false);
    // priorSums reflect the SAME single prior entry (90) for both caps.
    expect(r.priorSums).toEqual([90, 90]);
    // The stream still holds exactly one entry of 90.
    const snap = await getCumulativeSpendSum({ ...STREAM, windowSeconds: 86400 });
    expect(snap?.sum).toBe(90);
  });

  test("passes when EVERY cap holds, adding the entry once", async () => {
    const caps = [
      { windowSeconds: 3600, max: 100 },
      { windowSeconds: 86400, max: 1000 },
    ];
    const r = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 50 });
    expect(r.ok).toBe(true);
    const snap = await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 });
    expect(snap?.sum).toBe(50); // one entry, not two
  });
});

describeRedis("stream key excludes cap threshold (codex P1)", () => {
  test("lowering a cap re-evaluates against the SAME history, not a fresh bucket", async () => {
    // Spend 800 under a generous 1000 cap.
    await reserveCumulativeSpend({
      stream: STREAM,
      caps: [{ windowSeconds: 3600, max: 1000 }],
      amount: 800,
    });
    // Now the operator LOWERS the cap to 500. A further 100 must see the prior
    // 800 (history is keyed by the stream, not the cap) => 800 + 100 > 500 =>
    // REJECT. If history were keyed by cap value this would wrongly pass.
    const r = await reserveCumulativeSpend({
      stream: STREAM,
      caps: [{ windowSeconds: 3600, max: 500 }],
      amount: 100,
    });
    expect(r.ok).toBe(false);
    expect(r.priorSums[0]).toBe(800);
  });
});

describeRedis("window ageout", () => {
  test("boundary: an entry EXACTLY windowSeconds old has aged out (half-open)", async () => {
    const caps = [{ windowSeconds: 100, max: 10_000_000 }];
    const t0 = Date.now();
    // exactly 100s old => excluded.
    await reserveCumulativeSpend({ stream: STREAM, caps, amount: 2_000_000, now: t0 - 100_000 });
    const r = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 1_000_000, now: t0 });
    expect(r.priorSums[0]).toBe(0);
    // 99s old IS in-window.
    await cleanup();
    await reserveCumulativeSpend({ stream: STREAM, caps, amount: 2_000_000, now: t0 - 99_000 });
    const r2 = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 1_000_000, now: t0 });
    expect(r2.priorSums[0]).toBe(2_000_000);
  });
});

describeRedis("release / settle lifecycle", () => {
  test("release reclaims the reserved budget", async () => {
    const caps = [{ windowSeconds: 3600, max: 1_000_000 }];
    const first = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 1_000_000 });
    expect(first.ok).toBe(true);
    expect((await reserveCumulativeSpend({ stream: STREAM, caps, amount: 1 })).ok).toBe(false);
    await releaseCumulativeSpend({
      stream: STREAM,
      reservationId: first.reservationId as string,
      amount: 1_000_000,
    });
    const after = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 500_000 });
    expect(after.ok).toBe(true);
    expect(after.priorSums[0]).toBe(0);
  });

  test("settle keeps the reservation counted (no-op mark)", async () => {
    const caps = [{ windowSeconds: 3600, max: 1_000_000 }];
    const r = await reserveCumulativeSpend({ stream: STREAM, caps, amount: 600_000 });
    await settleCumulativeSpend({ stream: STREAM, reservationId: r.reservationId as string });
    const snap = await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 });
    expect(snap?.sum).toBe(600_000);
  });
});

describeRedis("scope + currency isolation", () => {
  test("operation / agent / grant + currency each get a distinct stream", async () => {
    const k = (scope: "operation" | "agent" | "grant", scopeKey: string, currency: string) =>
      cumulativeSpendStreamKeyForTest({ agentId: AGENT, scope, scopeKey, currency });
    const keys = new Set([
      k("agent", "", "USD"),
      k("operation", "wallet.transfer", "USD"),
      k("grant", "grant-1", "USD"),
      k("agent", "", "USDC"),
    ]);
    expect(keys.size).toBe(4);
    await reserveCumulativeSpend({
      stream: { agentId: AGENT, scope: "operation", scopeKey: "wallet.transfer", currency: "USD" },
      caps: [{ windowSeconds: 3600, max: 5_000_000 }],
      amount: 4_000_000,
    });
    const agentSnap = await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 });
    expect(agentSnap?.sum).toBe(0);
  });
});

describeRedis("fail closed", () => {
  test("a corrupt member makes reserve throw + sum return null", async () => {
    const redis = getRedis();
    const key = cumulativeSpendStreamKeyForTest(STREAM);
    await redis.zadd(key, Date.now(), "garbage-no-bars");
    await expect(
      reserveCumulativeSpend({
        stream: STREAM,
        caps: [{ windowSeconds: 3600, max: 5_000_000 }],
        amount: 1,
      }),
    ).rejects.toThrow();
    const snap = await getCumulativeSpendSum({ ...STREAM, windowSeconds: 3600 });
    expect(snap).toBeNull();
  });

  test("invalid amount / window / empty caps throws (never free budget)", async () => {
    const caps = [{ windowSeconds: 3600, max: 5_000_000 }];
    await expect(reserveCumulativeSpend({ stream: STREAM, caps, amount: -1 })).rejects.toThrow();
    await expect(reserveCumulativeSpend({ stream: STREAM, caps, amount: 1.5 })).rejects.toThrow();
    await expect(
      reserveCumulativeSpend({ stream: STREAM, caps, amount: Number.MAX_SAFE_INTEGER + 1 }),
    ).rejects.toThrow();
    await expect(reserveCumulativeSpend({ stream: STREAM, caps: [], amount: 1 })).rejects.toThrow();
    await expect(
      reserveCumulativeSpend({
        stream: STREAM,
        caps: [{ windowSeconds: 0, max: 1 }],
        amount: 1,
      }),
    ).rejects.toThrow();
  });

  test("over-retention window (> 30d) throws (codex P1)", async () => {
    await expect(
      reserveCumulativeSpend({
        stream: STREAM,
        caps: [{ windowSeconds: 2_592_001, max: 1 }],
        amount: 1,
      }),
    ).rejects.toThrow();
  });
});

describeRedis("windowed invoke count (#206 maxCalls atomic reservation)", () => {
  test("reserve admits under cap, rejects at cap (single-winner)", async () => {
    const base = {
      agentId: AGENT,
      operationKey: "wallet.transfer",
      caps: [{ windowSeconds: 3600, max: 2 }],
    };
    const r1 = await reserveWindowedInvoke(base);
    expect(r1.ok).toBe(true);
    expect(r1.priorCounts[0]).toBe(0);
    const r2 = await reserveWindowedInvoke(base);
    expect(r2.ok).toBe(true);
    expect(r2.priorCounts[0]).toBe(1);
    const r3 = await reserveWindowedInvoke(base);
    expect(r3.ok).toBe(false);
    expect(r3.priorCounts[0]).toBe(2);
    expect(
      await getWindowedInvokeCount({
        agentId: AGENT,
        operationKey: "wallet.transfer",
        windowSeconds: 3600,
      }),
    ).toBe(2);
  });

  test("multi-window: one invoke counted ONCE across an hourly AND daily cap (codex P2)", async () => {
    const caps = [
      { windowSeconds: 3600, max: 2 },
      { windowSeconds: 86400, max: 10 },
    ];
    const base = { agentId: AGENT, operationKey: "op.multi", caps };
    const r1 = await reserveWindowedInvoke(base);
    expect(r1.ok).toBe(true);
    expect(r1.priorCounts).toEqual([0, 0]);
    // second invoke: the SAME single prior entry is seen by BOTH windows (1, 1),
    // not (2, 1) - the invoke was counted once, not once per cap.
    const r2 = await reserveWindowedInvoke(base);
    expect(r2.ok).toBe(true);
    expect(r2.priorCounts).toEqual([1, 1]);
    // third: hourly at cap 2 => reject even though daily has room.
    const r3 = await reserveWindowedInvoke(base);
    expect(r3.ok).toBe(false);
    expect(r3.priorCounts[0]).toBe(2);
    // the stream holds exactly 2 entries.
    expect(
      await getWindowedInvokeCount({
        agentId: AGENT,
        operationKey: "op.multi",
        windowSeconds: 86400,
      }),
    ).toBe(2);
  });

  test("100 parallel invoke reserves against maxCalls=10 admit exactly 10", async () => {
    const base = {
      agentId: AGENT,
      operationKey: "op.race",
      caps: [{ windowSeconds: 3600, max: 10 }],
    };
    const results = await Promise.all(
      Array.from({ length: 100 }, () => reserveWindowedInvoke(base)),
    );
    expect(results.filter((r) => r.ok).length).toBe(10);
    expect(
      await getWindowedInvokeCount({
        agentId: AGENT,
        operationKey: "op.race",
        windowSeconds: 3600,
      }),
    ).toBe(10);
  });

  test("release reclaims an invoke slot", async () => {
    const base = {
      agentId: AGENT,
      operationKey: "op.rel",
      caps: [{ windowSeconds: 3600, max: 1 }],
    };
    const r = await reserveWindowedInvoke(base);
    expect(r.ok).toBe(true);
    expect((await reserveWindowedInvoke(base)).ok).toBe(false); // cap full
    await releaseWindowedInvoke({
      agentId: AGENT,
      operationKey: "op.rel",
      reservationId: r.reservationId as string,
    });
    expect((await reserveWindowedInvoke(base)).ok).toBe(true); // slot reclaimed
  });

  test("over-retention count window returns ok:false (fail closed)", async () => {
    const r = await reserveWindowedInvoke({
      agentId: AGENT,
      operationKey: "op.big",
      caps: [{ windowSeconds: 2_592_001, max: 3 }],
    });
    expect(r.ok).toBe(false);
  });
});
