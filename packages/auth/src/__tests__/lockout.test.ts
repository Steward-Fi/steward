import { describe, expect, test } from "bun:test";

import { InMemoryLockoutStore, Lockout } from "../lockout";

function frozenClock(start = 1_700_000_000_000) {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
    set(v: number) {
      t = v;
    },
  };
}

describe("Lockout", () => {
  test("allows attempts up to maxAttempts, then locks", async () => {
    const clock = frozenClock();
    const lo = new Lockout({ maxAttempts: 3, lockoutMs: 1000, now: clock.now });
    expect((await lo.check("u1")).allowed).toBe(true);
    expect((await lo.recordFailure("u1")).remaining).toBe(2);
    expect((await lo.recordFailure("u1")).remaining).toBe(1);
    const third = await lo.recordFailure("u1");
    expect(third.allowed).toBe(false);
    expect(third.retryAfterMs).toBe(1000);
    expect((await lo.check("u1")).allowed).toBe(false);
  });

  test("lock window doubles on additional failures during lockout, capped at maxLockoutMs", async () => {
    const clock = frozenClock();
    const lo = new Lockout({
      maxAttempts: 1,
      lockoutMs: 100,
      maxLockoutMs: 800,
      now: clock.now,
    });
    expect((await lo.recordFailure("u")).retryAfterMs).toBe(100);
    expect((await lo.recordFailure("u")).retryAfterMs).toBe(200);
    expect((await lo.recordFailure("u")).retryAfterMs).toBe(400);
    expect((await lo.recordFailure("u")).retryAfterMs).toBe(800);
    // Cap holds — additional failures do not grow past maxLockoutMs.
    expect((await lo.recordFailure("u")).retryAfterMs).toBe(800);
  });

  test("recordSuccess clears the counter", async () => {
    const clock = frozenClock();
    const lo = new Lockout({ maxAttempts: 3, now: clock.now });
    await lo.recordFailure("u");
    await lo.recordFailure("u");
    await lo.recordSuccess("u");
    const c = await lo.check("u");
    expect(c.allowed).toBe(true);
    expect(c.remaining).toBe(3);
  });

  test("lock auto-clears once the window passes", async () => {
    const clock = frozenClock();
    const lo = new Lockout({ maxAttempts: 1, lockoutMs: 500, now: clock.now });
    expect((await lo.recordFailure("u")).allowed).toBe(false);
    clock.advance(501);
    const c = await lo.check("u");
    expect(c.allowed).toBe(true);
  });

  test("idleResetMs of inactivity wipes the counter on next check", async () => {
    const clock = frozenClock();
    const lo = new Lockout({
      maxAttempts: 5,
      lockoutMs: 1000,
      idleResetMs: 10_000,
      now: clock.now,
    });
    await lo.recordFailure("u");
    await lo.recordFailure("u");
    clock.advance(11_000);
    const c = await lo.check("u");
    expect(c.allowed).toBe(true);
    expect(c.remaining).toBe(5);
  });

  test("subjects are isolated from each other", async () => {
    const clock = frozenClock();
    const lo = new Lockout({ maxAttempts: 2, lockoutMs: 100, now: clock.now });
    await lo.recordFailure("a");
    await lo.recordFailure("a");
    expect((await lo.check("a")).allowed).toBe(false);
    expect((await lo.check("b")).allowed).toBe(true);
  });

  test("a custom store implementation is honored", async () => {
    const clock = frozenClock();
    const store = new InMemoryLockoutStore();
    const lo = new Lockout({ store, maxAttempts: 1, lockoutMs: 100, now: clock.now });
    await lo.recordFailure("x");
    expect(store.get("x")?.lockedUntil).toBeGreaterThan(0);
  });
});
