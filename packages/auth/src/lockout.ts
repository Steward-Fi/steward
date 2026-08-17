/**
 * Lockout — exponential brute-force protection for credential-verification
 * endpoints (password, OTP, recovery codes, passkey verify).
 *
 * Behavior:
 *  - Each failure increments a per-subject counter and extends a temporary
 *    lock window. After `maxAttempts` consecutive failures the subject is
 *    locked for `lockoutMs`; the lock window doubles on every additional
 *    failure during lockout, capped at `maxLockoutMs`.
 *  - A successful `recordSuccess()` clears the counter atomically.
 *  - Counter and lock state expire after `idleResetMs` of inactivity so
 *    long-quiet subjects start fresh; defaults to 1 day.
 *
 * The "subject" is whatever identifier the calling endpoint uses to key
 * brute-force budget — phone number for SMS OTP, user id for password,
 * `(userId, "recovery")` for recovery codes, etc. Callers SHOULD also key
 * a parallel IP-based budget at the network edge to defeat distributed
 * guessers that rotate subjects.
 *
 * Storage is pluggable so production deployments can back this with Redis;
 * the default in-memory store is fine for tests and single-node dev. NOTE:
 * the default store is per-process — each instance of a multi-instance
 * deployment gets its own independent guess budget. Use a shared store in
 * multi-instance deployments.
 *
 * Concurrency: `check()` + `recordFailure()` are separate round-trips, so N
 * parallel attempts can all pass `check()` before any failure is recorded,
 * multiplying the guess budget by the parallelism factor. Prefer
 * `checkAndRecord()` on contention-prone endpoints; it is genuinely atomic
 * with the default (synchronous) in-memory store.
 */

export interface LockoutState {
  failures: number;
  /** Wall-clock epoch ms at which the subject is allowed to try again. */
  lockedUntil: number;
  /** Wall-clock epoch ms of the most recent attempt — drives idleResetMs. */
  lastAttempt: number;
}

export interface LockoutStore {
  get(key: string): Promise<LockoutState | undefined> | LockoutState | undefined;
  set(key: string, state: LockoutState): Promise<void> | void;
  delete(key: string): Promise<void> | void;
}

export class InMemoryLockoutStore implements LockoutStore {
  private data = new Map<string, LockoutState>();
  get(key: string) {
    return this.data.get(key);
  }
  set(key: string, state: LockoutState) {
    this.data.set(key, state);
  }
  delete(key: string) {
    this.data.delete(key);
  }
}

export interface LockoutConfig {
  store?: LockoutStore;
  /** Failures before the first lock. Default 5. */
  maxAttempts?: number;
  /** Initial lock duration. Default 60s. */
  lockoutMs?: number;
  /** Cap on the exponentially-grown lock duration. Default 1h. */
  maxLockoutMs?: number;
  /** Idle window after which counter resets. Default 24h. */
  idleResetMs?: number;
  /** Override clock — for deterministic tests. */
  now?: () => number;
}

export interface CheckResult {
  allowed: boolean;
  /** When `allowed` is false: epoch ms at which the next attempt is permitted. */
  retryAfterMs?: number;
  /** Remaining attempts before the next lock kicks in. */
  remaining?: number;
}

const DEFAULTS = {
  maxAttempts: 5,
  lockoutMs: 60_000,
  maxLockoutMs: 60 * 60_000,
  idleResetMs: 24 * 60 * 60_000,
};

export class Lockout {
  private store: LockoutStore;
  private cfg: Required<Omit<LockoutConfig, "store" | "now">>;
  private now: () => number;

  constructor(config: LockoutConfig = {}) {
    this.store = config.store ?? new InMemoryLockoutStore();
    this.cfg = {
      maxAttempts: config.maxAttempts ?? DEFAULTS.maxAttempts,
      lockoutMs: config.lockoutMs ?? DEFAULTS.lockoutMs,
      maxLockoutMs: config.maxLockoutMs ?? DEFAULTS.maxLockoutMs,
      idleResetMs: config.idleResetMs ?? DEFAULTS.idleResetMs,
    };
    this.now = config.now ?? (() => Date.now());
  }

  /** Check before attempting; call recordFailure/recordSuccess after the attempt. */
  async check(key: string): Promise<CheckResult> {
    const state = await this.store.get(key);
    if (!state) return { allowed: true, remaining: this.cfg.maxAttempts };

    const now = this.now();
    if (now - state.lastAttempt > this.cfg.idleResetMs) {
      await this.store.delete(key);
      return { allowed: true, remaining: this.cfg.maxAttempts };
    }
    if (state.lockedUntil > now) {
      return { allowed: false, retryAfterMs: state.lockedUntil - now };
    }
    return {
      allowed: true,
      remaining: Math.max(0, this.cfg.maxAttempts - state.failures),
    };
  }

  /**
   * Record a failed attempt. Returns the new lock state so callers can
   * surface "N attempts remaining" / "locked for X seconds" to the user.
   */
  async recordFailure(key: string): Promise<CheckResult> {
    const now = this.now();
    const existing = await this.store.get(key);
    const stale = existing && now - existing.lastAttempt > this.cfg.idleResetMs;
    const base: LockoutState =
      stale || !existing ? { failures: 0, lockedUntil: 0, lastAttempt: now } : existing;

    const failures = base.failures + 1;
    let lockedUntil = base.lockedUntil;
    if (failures >= this.cfg.maxAttempts) {
      const over = failures - this.cfg.maxAttempts;
      const window = Math.min(this.cfg.lockoutMs * 2 ** over, this.cfg.maxLockoutMs);
      lockedUntil = now + window;
    }
    const next: LockoutState = { failures, lockedUntil, lastAttempt: now };
    await this.store.set(key, next);

    if (lockedUntil > now) {
      return { allowed: false, retryAfterMs: lockedUntil - now };
    }
    return { allowed: true, remaining: Math.max(0, this.cfg.maxAttempts - failures) };
  }

  /** Clear counter on successful authentication. */
  async recordSuccess(key: string): Promise<void> {
    await this.store.delete(key);
  }

  /**
   * Atomically check the budget and, when allowed, record a failure in one
   * call (SEC-057). Prefer this over check()+recordFailure() pairs: separate
   * calls let N parallel attempts all pass check() before any failure lands.
   *
   * With a synchronous store (the default InMemoryLockoutStore) the
   * read-modify-write below never yields to the event loop, so it is truly
   * atomic. With an async remote store the operations can still interleave —
   * use a backend with server-side atomicity (e.g. a Lua-scripted Redis
   * store) for strict guarantees across instances.
   */
  async checkAndRecord(key: string): Promise<CheckResult> {
    const stateOrPromise = this.store.get(key);
    if (stateOrPromise instanceof Promise) {
      return this.checkAndRecordAsync(key, await stateOrPromise);
    }
    // Sync fast path: no awaits, so no interleaving between read and write.
    return this.checkAndRecordSync(key, stateOrPromise);
  }

  private checkAndRecordSync(key: string, state: LockoutState | undefined): CheckResult {
    const now = this.now();
    const base = state && now - state.lastAttempt <= this.cfg.idleResetMs ? state : undefined;
    if (base && base.lockedUntil > now) {
      return { allowed: false, retryAfterMs: base.lockedUntil - now };
    }
    const next = this.nextFailureState(base, now);
    this.store.set(key, next);
    return this.failureResult(next, now);
  }

  private async checkAndRecordAsync(
    key: string,
    state: LockoutState | undefined,
  ): Promise<CheckResult> {
    const now = this.now();
    const base = state && now - state.lastAttempt <= this.cfg.idleResetMs ? state : undefined;
    if (base && base.lockedUntil > now) {
      return { allowed: false, retryAfterMs: base.lockedUntil - now };
    }
    const next = this.nextFailureState(base, now);
    await this.store.set(key, next);
    return this.failureResult(next, now);
  }

  private nextFailureState(state: LockoutState | undefined, now: number): LockoutState {
    const failures = (state?.failures ?? 0) + 1;
    let lockedUntil = state?.lockedUntil ?? 0;
    if (failures >= this.cfg.maxAttempts) {
      const over = failures - this.cfg.maxAttempts;
      const window = Math.min(this.cfg.lockoutMs * 2 ** over, this.cfg.maxLockoutMs);
      lockedUntil = now + window;
    }
    return { failures, lockedUntil, lastAttempt: now };
  }

  private failureResult(state: LockoutState, now: number): CheckResult {
    if (state.lockedUntil > now) {
      return { allowed: false, retryAfterMs: state.lockedUntil - now };
    }
    return { allowed: true, remaining: Math.max(0, this.cfg.maxAttempts - state.failures) };
  }
}
