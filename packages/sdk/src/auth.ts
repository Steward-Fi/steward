/**
 * auth.ts — StewardAuth: complete authentication module for the Steward SDK
 *
 * Supports:
 *   - Passkey (WebAuthn) — browser only, via @simplewebauthn/browser peer dep
 *   - Email magic link — browser + Node
 *   - SIWE (Sign-In With Ethereum) — browser + Node
 *
 * Usage:
 *   const auth = new StewardAuth({ baseUrl: "https://api.steward.fi" });
 *   const { token, user } = await auth.signInWithPasskey("me@example.com");
 *   const client = new StewardClient({ baseUrl, bearerToken: auth.getToken() });
 */

import { StewardApiError } from "./client.ts";
import type {
  StewardAuthConfig,
  StewardAuthResult,
  StewardEmailResult,
  StewardRefreshResult,
  StewardSession,
  StewardUser,
  SessionStorage,
} from "./auth-types.ts";

// ─── Storage key ──────────────────────────────────────────────────────────────

const STORAGE_KEY = "steward_session_token";
const REFRESH_TOKEN_KEY = "steward_refresh_token";

/** Kick off a token refresh when fewer than this many seconds remain on the access token */
const REFRESH_THRESHOLD_SECS = 120;

// ─── Minimal JWT decode (no verification — server already verified) ───────────

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    // base64url → base64 → decode
    // atob is available globally in browsers and Node.js >= 18
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const json = atob(padded);
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function sessionFromToken(token: string, user?: StewardUser): StewardSession | null {
  const payload = decodeJwtPayload(token);
  if (!payload) return null;
  return {
    token,
    address: (payload.address as string) ?? "",
    tenantId: (payload.tenantId as string) ?? "",
    userId: payload.userId as string | undefined,
    email: payload.email as string | undefined,
    expiresAt: payload.exp as number | undefined,
    user,
  };
}

// ─── In-memory fallback storage ───────────────────────────────────────────────

class MemoryStorage implements SessionStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
  removeItem(key: string): void {
    this.store.delete(key);
  }
}

// ─── Detect browser environment ───────────────────────────────────────────────

function isBrowser(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.document !== "undefined" &&
    typeof navigator !== "undefined"
  );
}

// ─── Fetch helpers — same pattern as StewardClient ───────────────────────────

type AuthApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: string };

async function authRequest<T>(
  baseUrl: string,
  path: string,
  init: RequestInit = {},
  token?: string | null,
): Promise<AuthApiResult<T>> {
  const headers = new Headers({
    "Content-Type": "application/json",
    Accept: "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  });

  // Merge caller headers without clobbering defaults
  if (init.headers) {
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  }

  let response: Response;
  try {
    response = await fetch(`${baseUrl.replace(/\/+$/, "")}${path}`, {
      ...init,
      headers,
    });
  } catch (err) {
    throw new StewardApiError(
      err instanceof Error ? err.message : "Network request failed",
      0,
    );
  }

  const text = await response.text();
  let payload: Record<string, unknown> = { ok: response.ok };

  if (text) {
    try {
      payload = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new StewardApiError("Received invalid JSON from Steward API", response.status);
    }
  }

  if (!response.ok || payload.ok === false) {
    const errMsg =
      typeof payload.error === "string"
        ? payload.error
        : `Request failed with status ${response.status}`;
    return { ok: false, status: response.status, error: errMsg };
  }

  return { ok: true, status: response.status, data: payload as unknown as T };
}

// ─── StewardAuth ──────────────────────────────────────────────────────────────

export class StewardAuth {
  private readonly baseUrl: string;
  private readonly storage: SessionStorage;
  private readonly listeners: Array<(session: StewardSession | null) => void> = [];

  constructor({ baseUrl, storage, onSessionChange }: StewardAuthConfig) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");

    // Use provided storage, else localStorage when in browser, else in-memory
    if (storage) {
      this.storage = storage;
    } else if (isBrowser() && typeof localStorage !== "undefined") {
      this.storage = localStorage;
    } else {
      this.storage = new MemoryStorage();
    }

    if (onSessionChange) {
      this.listeners.push(onSessionChange);
    }
  }

  // ─── Session management ─────────────────────────────────────────────────────

  /**
   * Returns the current session decoded from the stored JWT, or null if not signed in.
   */
  getSession(): StewardSession | null {
    const token = this.storage.getItem(STORAGE_KEY);
    if (!token) return null;

    const session = sessionFromToken(token);
    if (!session) return null;

    // Treat expired tokens as signed out
    if (session.expiresAt && session.expiresAt * 1000 < Date.now()) {
      this.clearToken();
      return null;
    }

    return session;
  }

  /**
   * Returns true if the access token is within REFRESH_THRESHOLD_SECS of expiry.
   * Call `refreshSession()` proactively when this returns true.
   */
  isNearExpiry(): boolean {
    const session = this.getSession();
    if (!session?.expiresAt) return false;
    const secsRemaining = session.expiresAt - Date.now() / 1000;
    return secsRemaining < REFRESH_THRESHOLD_SECS;
  }

  /**
   * Returns the raw access JWT string, or null if not signed in.
   * Automatically triggers a background refresh if the token is near expiry.
   */
  getToken(): string | null {
    const session = this.getSession();
    if (!session) return null;
    // Kick off a background refresh if near expiry (non-blocking)
    if (this.isNearExpiry()) {
      void this.refreshSession().catch(() => { /* swallow — caller still gets old token */ });
    }
    return session.token;
  }

  /** Returns the stored refresh token, or null if not available. */
  getRefreshToken(): string | null {
    return this.storage.getItem(REFRESH_TOKEN_KEY);
  }

  /**
   * Returns true if there is a valid (non-expired) session.
   */
  isAuthenticated(): boolean {
    return this.getSession() !== null;
  }

  /**
   * Clears the stored session (both tokens) and notifies listeners.
   */
  signOut(): void {
    this.clearToken();
    this.notifyListeners(null);
  }

  /**
   * Exchange the stored refresh token for a new access token + rotated refresh token.
   * Stores both tokens and notifies session listeners.
   * Returns the new session, or null if the refresh token is missing or invalid.
   */
  async refreshSession(): Promise<StewardSession | null> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return null;

    const res = await authRequest<StewardRefreshResult>(
      this.baseUrl,
      "/auth/refresh",
      { method: "POST", body: JSON.stringify({ refreshToken }) },
    );

    if (!res.ok) {
      // Refresh token invalid/expired — sign the user out
      this.signOut();
      return null;
    }

    this.storage.setItem(STORAGE_KEY, res.data.token);
    this.storage.setItem(REFRESH_TOKEN_KEY, res.data.refreshToken);
    const session = sessionFromToken(res.data.token);
    this.notifyListeners(session);
    return session;
  }

  /**
   * Revoke the stored refresh token on the server (single-device sign out).
   * Also clears local session state.
   */
  async revokeSession(): Promise<void> {
    const refreshToken = this.getRefreshToken();
    if (refreshToken) {
      await authRequest(this.baseUrl, "/auth/revoke", {
        method: "POST",
        body: JSON.stringify({ refreshToken }),
      }).catch(() => { /* best-effort */ });
    }
    this.clearToken();
    this.notifyListeners(null);
  }

  /**
   * Register a listener that fires whenever the session changes.
   * Returns a cleanup function that removes the listener.
   */
  onSessionChange(callback: (session: StewardSession | null) => void): () => void {
    this.listeners.push(callback);
    return () => {
      const idx = this.listeners.indexOf(callback);
      if (idx !== -1) this.listeners.splice(idx, 1);
    };
  }

  // ─── Passkey (WebAuthn) ─────────────────────────────────────────────────────

  /**
   * Sign in with a passkey. Smart flow: tries login first, falls back to registration.
   *
   * Requires a browser environment and `@simplewebauthn/browser` installed.
   * Throws `StewardApiError` in Node or when the dependency is missing.
   */
  async signInWithPasskey(email: string): Promise<StewardAuthResult> {
    if (!isBrowser()) {
      throw new StewardApiError(
        "Passkeys require a browser environment. Use signInWithEmail or signInWithSIWE in Node.",
        0,
      );
    }

    // Dynamically import @simplewebauthn/browser — peer dep, may not be installed
    type SimpleWebAuthnBrowser = {
      startAuthentication: (opts: unknown, useBrowserAutofill?: boolean) => Promise<unknown>;
      startRegistration: (opts: unknown) => Promise<unknown>;
    };
    let browserLib: SimpleWebAuthnBrowser;
    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const mod = await import("@simplewebauthn/browser" as string);
      browserLib = mod as SimpleWebAuthnBrowser;
    } catch {
      throw new StewardApiError(
        "Missing peer dependency: @simplewebauthn/browser. Install it to use passkeys.",
        0,
      );
    }

    // 1. Try login options. If user has no passkeys (404), fall back to register.
    const loginOptsRes = await authRequest<Record<string, unknown>>(
      this.baseUrl,
      "/auth/passkey/login/options",
      { method: "POST", body: JSON.stringify({ email }) },
    );

    if (loginOptsRes.ok) {
      // User exists with passkeys — run authentication flow
      return this.completePasskeyLogin(email, loginOptsRes.data, browserLib);
    }

    if (loginOptsRes.status === 404) {
      // No account or no passkeys — run registration flow
      return this.completePasskeyRegister(email, browserLib);
    }

    throw new StewardApiError(loginOptsRes.error, loginOptsRes.status);
  }

  private async completePasskeyLogin(
    email: string,
    options: unknown,
    lib: { startAuthentication: (opts: unknown) => Promise<unknown> },
  ): Promise<StewardAuthResult> {
    let authResponse: unknown;
    try {
      authResponse = await lib.startAuthentication(options);
    } catch (err) {
      throw new StewardApiError(
        `WebAuthn authentication cancelled or failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const verifyRes = await authRequest<{ ok: boolean; token: string; user: StewardUser }>(
      this.baseUrl,
      "/auth/passkey/login/verify",
      { method: "POST", body: JSON.stringify({ email, response: authResponse }) },
    );

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    return this.storeAndReturn(
        verifyRes.data.token,
        (verifyRes.data as { refreshToken?: string }).refreshToken ?? "",
        verifyRes.data.user,
        (verifyRes.data as { expiresIn?: number }).expiresIn,
      );
  }

  private async completePasskeyRegister(
    email: string,
    lib: { startRegistration: (opts: unknown) => Promise<unknown> },
  ): Promise<StewardAuthResult> {
    // Fetch registration options
    const regOptsRes = await authRequest<Record<string, unknown>>(
      this.baseUrl,
      "/auth/passkey/register/options",
      { method: "POST", body: JSON.stringify({ email }) },
    );

    if (!regOptsRes.ok) {
      throw new StewardApiError(regOptsRes.error, regOptsRes.status);
    }

    let regResponse: unknown;
    try {
      regResponse = await lib.startRegistration(regOptsRes.data);
    } catch (err) {
      throw new StewardApiError(
        `WebAuthn registration cancelled or failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const verifyRes = await authRequest<{ ok: boolean; token: string; user: StewardUser }>(
      this.baseUrl,
      "/auth/passkey/register/verify",
      { method: "POST", body: JSON.stringify({ email, response: regResponse }) },
    );

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    return this.storeAndReturn(
        verifyRes.data.token,
        (verifyRes.data as { refreshToken?: string }).refreshToken ?? "",
        verifyRes.data.user,
        (verifyRes.data as { expiresIn?: number }).expiresIn,
      );
  }

  // ─── Email magic link ───────────────────────────────────────────────────────

  /**
   * Send a magic link to the given email address.
   * Returns `{ ok: true, expiresAt }` — the actual sign-in happens in `verifyEmailCallback`.
   */
  async signInWithEmail(email: string): Promise<StewardEmailResult> {
    // API shape: { ok: true, data: { expiresAt: string } }
    const res = await authRequest<Record<string, unknown>>(
      this.baseUrl,
      "/auth/email/send",
      { method: "POST", body: JSON.stringify({ email }) },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    // Unwrap the expiresAt — may sit directly on the response or inside `data`
    const expiresAt =
      typeof res.data.expiresAt === "string"
        ? res.data.expiresAt
        : ((res.data.data as { expiresAt?: string } | undefined)?.expiresAt ?? "");

    return { ok: true, expiresAt };
  }

  /**
   * Exchange a magic link token for a session JWT.
   * Call this from the callback URL handler with the `token` and `email` query params.
   */
  async verifyEmailCallback(token: string, email: string): Promise<StewardAuthResult> {
    const res = await authRequest<{ ok: boolean; token: string; user: StewardUser }>(
      this.baseUrl,
      "/auth/email/verify",
      { method: "POST", body: JSON.stringify({ token, email }) },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeAndReturn(
      res.data.token,
      (res.data as { refreshToken?: string }).refreshToken ?? "",
      res.data.user,
      (res.data as { expiresIn?: number }).expiresIn,
    );
  }

  // ─── SIWE ───────────────────────────────────────────────────────────────────

  /**
   * Sign in with an Ethereum wallet via SIWE (EIP-4361).
   *
   * @param address  - The signer's EVM address (checksummed or lowercase).
   * @param signMessage - Async function that signs an arbitrary string with the wallet.
   *                      Compatible with ethers.js `signer.signMessage`, viem's `walletClient.signMessage`,
   *                      or any custom implementation.
   *
   * Flow: GET /auth/nonce → build SIWE message → caller signs → POST /auth/verify → store JWT.
   */
  async signInWithSIWE(
    address: string,
    signMessage: (msg: string) => Promise<string>,
  ): Promise<StewardAuthResult> {
    // 1. Fetch a fresh nonce
    const nonceRes = await authRequest<{ nonce: string }>(
      this.baseUrl,
      "/auth/nonce",
    );

    if (!nonceRes.ok) {
      throw new StewardApiError(nonceRes.error, nonceRes.status);
    }

    const { nonce } = nonceRes.data;

    // 2. Build a minimal SIWE message string (EIP-4361)
    const domain = isBrowser() ? window.location.host : "steward.fi";
    const origin = isBrowser() ? window.location.origin : "https://steward.fi";
    const issuedAt = new Date().toISOString();

    const siweMessage = [
      `${domain} wants you to sign in with your Ethereum account:`,
      address,
      "",
      "Sign in to Steward",
      "",
      `URI: ${origin}`,
      "Version: 1",
      `Chain ID: 1`,
      `Nonce: ${nonce}`,
      `Issued At: ${issuedAt}`,
    ].join("\n");

    // 3. Have the caller sign the message
    let signature: string;
    try {
      signature = await signMessage(siweMessage);
    } catch (err) {
      throw new StewardApiError(
        `Wallet signing failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    // 4. Verify with the API
    const verifyRes = await authRequest<{
      ok: boolean;
      token: string;
      address: string;
      tenant: { id: string; name: string; apiKey?: string };
    }>(
      this.baseUrl,
      "/auth/verify",
      {
        method: "POST",
        body: JSON.stringify({ message: siweMessage, signature }),
      },
    );

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    // SIWE response has no `user` object — synthesise one from address
    const user: StewardUser = {
      id: verifyRes.data.tenant.id,
      email: "",
      walletAddress: verifyRes.data.address,
    };

    return this.storeAndReturn(
      verifyRes.data.token,
      (verifyRes.data as { refreshToken?: string }).refreshToken ?? "",
      user,
      (verifyRes.data as { expiresIn?: number }).expiresIn,
    );
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  private storeAndReturn(
    token: string,
    refreshToken: string,
    user: StewardUser,
    expiresIn = 900,
  ): StewardAuthResult {
    this.storage.setItem(STORAGE_KEY, token);
    this.storage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    const session = sessionFromToken(token, user);
    this.notifyListeners(session);
    return { token, refreshToken, expiresIn, user };
  }

  private clearToken(): void {
    this.storage.removeItem(STORAGE_KEY);
    this.storage.removeItem(REFRESH_TOKEN_KEY);
  }

  private notifyListeners(session: StewardSession | null): void {
    for (const listener of this.listeners) {
      try {
        listener(session);
      } catch {
        // listeners must not crash the auth flow
      }
    }
  }
}
