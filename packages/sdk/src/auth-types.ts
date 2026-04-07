/**
 * auth-types.ts — Type definitions for StewardAuth
 */

// ─── Storage interface ────────────────────────────────────────────────────────

/**
 * Interface for pluggable session storage.
 * Compatible with `localStorage`, `sessionStorage`, or any custom implementation.
 */
export interface SessionStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

// ─── User & session types ─────────────────────────────────────────────────────

export interface StewardUser {
  id: string;
  email: string;
  walletAddress?: string;
}

export interface StewardSession {
  /** Raw JWT string (access token, 15 min) */
  token: string;
  /** Parsed token payload fields */
  address: string;
  tenantId: string;
  userId?: string;
  email?: string;
  /** Expiry as unix timestamp (seconds) — parsed from JWT `exp` claim */
  expiresAt?: number;
  /** The user object returned at sign-in time (if available) */
  user?: StewardUser;
}

// ─── Auth result types ────────────────────────────────────────────────────────

export interface StewardAuthResult {
  /** Short-lived access token (15 min) */
  token: string;
  /** Long-lived refresh token (30 days). Store securely and never expose in URLs. */
  refreshToken: string;
  /** Access token lifetime in seconds (900) */
  expiresIn: number;
  user: StewardUser;
}

export interface StewardEmailResult {
  ok: boolean;
  expiresAt: string;
}

// ─── Config ───────────────────────────────────────────────────────────────────

export interface StewardAuthConfig {
  /** Base URL of the Steward API, e.g. "https://api.steward.fi" */
  baseUrl: string;
  /**
   * Optional storage backend for persisting the JWT.
   * Defaults to in-memory (session lost on page reload / process restart).
   * Pass `localStorage` or `sessionStorage` in browsers for persistence.
   */
  storage?: SessionStorage;
  /**
   * Called whenever the session changes (sign-in, sign-out, token refresh).
   * Receives `null` when signed out, `StewardSession` when signed in.
   */
  onSessionChange?: (session: StewardSession | null) => void;
}

/** Response shape from POST /auth/refresh */
export interface StewardRefreshResult {
  token: string;
  refreshToken: string;
  expiresIn: number;
}
