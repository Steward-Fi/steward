/**
 * In-memory challenge store with TTL for WebAuthn challenges.
 * Challenges are keyed by userId or email, expire after 5 minutes,
 * and are cleaned up automatically.
 */

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000;   // run cleanup every 60 seconds

interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

export class ChallengeStore {
  private readonly store = new Map<string, ChallengeEntry>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(ttlMs = CHALLENGE_TTL_MS) {
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, CLEANUP_INTERVAL_MS);

    // Allow the timer to be GC'd if the process exits — don't keep it alive
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /** Store a challenge for a given key (userId or email). Overwrites any existing entry. */
  set(key: string, challenge: string): void {
    this.store.set(key, {
      challenge,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });
  }

  /** Retrieve and immediately delete a challenge (one-time-use). Returns null if missing or expired. */
  consume(key: string): string | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    this.store.delete(key);

    if (Date.now() > entry.expiresAt) return null;

    return entry.challenge;
  }

  /** Peek at a challenge without consuming it. Returns null if missing or expired. */
  get(key: string): string | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.challenge;
  }

  /** Delete a challenge explicitly. */
  delete(key: string): void {
    this.store.delete(key);
  }

  /** Remove all expired entries. Called automatically on a timer. */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.expiresAt) {
        this.store.delete(key);
      }
    }
  }

  /** Stop the background cleanup timer. Call when tearing down (e.g., in tests). */
  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.store.clear();
  }

  /** Current number of stored (possibly expired) challenges. */
  get size(): number {
    return this.store.size;
  }
}

/** Singleton default store — use this unless you need an isolated instance. */
export const challengeStore = new ChallengeStore();
