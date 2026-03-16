/**
 * In-memory token store with TTL support.
 * Used for magic link tokens (and can be reused for WebAuthn challenges).
 * For production, swap this backing store for Redis or Postgres.
 */

interface TokenEntry {
  email: string;
  expiresAt: number; // unix ms
}

const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000; // 60 seconds

export class TokenStore {
  private _map = new Map<string, TokenEntry>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.cleanupTimer = setInterval(() => this._cleanup(), CLEANUP_INTERVAL_MS);
    // Allow the process to exit even if this timer is still running
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Store a hash → email mapping with a TTL.
   * @param hash   SHA-256 hex of the raw token
   * @param email  Email address tied to this token
   * @param ttlMs  Time-to-live in milliseconds (default 10 min)
   */
  store(hash: string, email: string, ttlMs: number = DEFAULT_TTL_MS): void {
    this._map.set(hash, {
      email,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Verify a hash and return the associated email if it exists and hasn't expired.
   * Does NOT delete the entry — call delete() explicitly after use.
   */
  verify(hash: string): string | null {
    const entry = this._map.get(hash);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this._map.delete(hash);
      return null;
    }
    return entry.email;
  }

  /**
   * Delete a hash from the store (called after one-time token consumption).
   */
  delete(hash: string): void {
    this._map.delete(hash);
  }

  /**
   * Purge all expired entries.  Called automatically every 60 seconds.
   */
  private _cleanup(): void {
    const now = Date.now();
    for (const [hash, entry] of this._map.entries()) {
      if (now > entry.expiresAt) {
        this._map.delete(hash);
      }
    }
  }

  /**
   * Stop the background cleanup timer (useful in tests).
   */
  destroy(): void {
    if (this.cleanupTimer !== null) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}
