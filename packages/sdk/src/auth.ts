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

import bs58 from "bs58";
import type {
  SessionStorage,
  StewardAuthConfig,
  StewardAuthExchangeResponse,
  StewardAuthResult,
  StewardCurrentUserResult,
  StewardDeviceCodeOptions,
  StewardDeviceCodeResult,
  StewardDeviceTokenPendingResult,
  StewardDeviceVerifyResult,
  StewardEmailGrantResult,
  StewardEmailOtpResult,
  StewardEmailResult,
  StewardFarcasterLoginConfig,
  StewardFarcasterLoginPayload,
  StewardGuestDeleteResult,
  StewardGuestSignInOptions,
  StewardGuestState,
  StewardGuestUpgradeEmailInput,
  StewardIdentityTokenResult,
  StewardJwtLoginConfig,
  StewardMfaRequiredResult,
  StewardOAuthConfig,
  StewardOAuthResult,
  StewardProviders,
  StewardRecoveryCodeStatus,
  StewardRecoveryCodesResult,
  StewardRefreshResult,
  StewardSession,
  StewardSmsMfaEnrollResult,
  StewardSmsMfaStatus,
  StewardSmsMfaVerifyResult,
  StewardSmsOtpResult,
  StewardTelegramLoginConfig,
  StewardTelegramLoginPayload,
  StewardTenantMembership,
  StewardTestAccountLoginOptions,
  StewardTotpEnrollResult,
  StewardTotpStatus,
  StewardTotpVerifyResult,
  StewardUser,
  StewardWhatsAppOtpResult,
} from "./auth-types.ts";
import { StewardApiError } from "./client.ts";

// ─── Storage key ──────────────────────────────────────────────────────────────

const STORAGE_KEY = "steward_session_token";
const REFRESH_TOKEN_KEY = "steward_refresh_token";
const OAUTH_STATE_KEY = "steward_oauth_state";
const OAUTH_VERIFIER_KEY = "steward_oauth_verifier";
const OAUTH_TENANT_KEY = "steward_oauth_tenant";

/** Kick off a token refresh when fewer than this many seconds remain on the access token */
const REFRESH_THRESHOLD_SECS = 120;
const GUEST_EXPIRY_WARNING_DAYS = 30;

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
  const mfaVerifiedAt =
    typeof payload.mfaVerifiedAt === "number" && Number.isFinite(payload.mfaVerifiedAt)
      ? payload.mfaVerifiedAt
      : undefined;
  const factorEnrollmentVerifiedAt =
    typeof payload.factorEnrollmentVerifiedAt === "number" &&
    Number.isFinite(payload.factorEnrollmentVerifiedAt)
      ? payload.factorEnrollmentVerifiedAt
      : undefined;
  return {
    token,
    address: (payload.address as string) ?? "",
    tenantId: (payload.tenantId as string) ?? "",
    userId: payload.userId as string | undefined,
    email: payload.email as string | undefined,
    isGuest: payload.guest === true,
    guestExpiresAt: typeof payload.guestExpiresAt === "string" ? payload.guestExpiresAt : null,
    mfaVerifiedAt,
    mfaMethod: typeof payload.mfaMethod === "string" ? payload.mfaMethod : undefined,
    factorEnrollmentVerifiedAt,
    expiresAt: payload.exp as number | undefined,
    user,
  };
}

function guestExpiryMessage(expiresAtMs: number | null | undefined): string | null {
  if (!expiresAtMs || Number.isNaN(expiresAtMs)) return null;
  const remainingMs = expiresAtMs - Date.now();
  if (remainingMs <= 0) return "Guest account expired. Sign in or start a new guest session.";
  const days = Math.ceil(remainingMs / 86_400_000);
  if (days > GUEST_EXPIRY_WARNING_DAYS) return null;
  if (days <= 1) return "Guest account expires today. Upgrade to keep your wallet and data.";
  return `Guest account expires in ${days} days. Upgrade to keep your wallet and data.`;
}

function getOAuthCallbackParams(url: URL): { code?: string; state?: string; error?: string } {
  const params = new URLSearchParams(url.search);
  const fragment = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
  if (fragment) {
    const hashParams = new URLSearchParams(fragment);
    hashParams.forEach((value, key) => {
      if (!params.has(key)) params.set(key, value);
    });
  }
  return {
    code: params.get("code") ?? undefined,
    state: params.get("state") ?? undefined,
    error: params.get("error") ?? undefined,
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

function getSignInOrigin(): { domain: string; origin: string } {
  return isBrowser()
    ? { domain: window.location.host, origin: window.location.origin }
    : { domain: "steward.fi", origin: "https://steward.fi" };
}

// Default EVM chain id (Ethereum mainnet) used only when the caller does not
// supply the wallet's actually-connected chain. The server reads the Chain ID
// from the signed message itself (siwe parses it, and it is used for EIP-1271
// smart-contract-wallet lookups) rather than hardcode-comparing it, so passing
// the wallet's real chain id is both safe for existing verification and more
// correct for non-mainnet wallets (e.g. Base, BSC).
const DEFAULT_EVM_CHAIN_ID = 1;
// Default SIWS network used only when the caller does not supply one.
const DEFAULT_SOLANA_CHAIN = "mainnet";

function buildSiweMessage(
  address: string,
  nonce: string,
  issuedAt: string,
  chainId: number = DEFAULT_EVM_CHAIN_ID,
): string {
  const { domain, origin } = getSignInOrigin();
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to Steward",
    "",
    `URI: ${origin}`,
    "Version: 1",
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

function buildSiwsMessage(
  publicKey: string,
  nonce: string,
  issuedAt: string,
  chain: string = DEFAULT_SOLANA_CHAIN,
): string {
  const { domain, origin } = getSignInOrigin();
  return [
    `${domain} wants you to sign in with your Solana account:`,
    publicKey,
    "",
    "Sign in to Steward",
    "",
    `URI: ${origin}`,
    "Version: 1",
    `Chain ID: ${chain}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

// ─── Fetch helpers — same pattern as StewardClient ───────────────────────────

type AuthApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: string };

// Narrow view of @simplewebauthn/browser — a peer dep we import dynamically.
type SimpleWebAuthnBrowser = Pick<
  typeof import("@simplewebauthn/browser"),
  "startAuthentication" | "startRegistration"
>;

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
    throw new StewardApiError(err instanceof Error ? err.message : "Network request failed", 0);
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
  private readonly tenantId: string | undefined;
  private readonly listeners: Array<(session: StewardSession | null) => void> = [];

  constructor({ baseUrl, storage, onSessionChange, tenantId }: StewardAuthConfig) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.tenantId = tenantId;

    // Use caller-provided storage only. Tokens default to memory so a browser
    // XSS cannot read long-lived refresh tokens from localStorage by default.
    if (storage) {
      this.storage = storage;
    } else {
      this.storage = new MemoryStorage();
    }

    if (onSessionChange) {
      this.listeners.push(onSessionChange);
    }
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  /** Returns the configured default tenantId, if any. */
  getTenantId(): string | undefined {
    return this.tenantId;
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
      void this.refreshSession().catch(() => {
        /* swallow — caller still gets old token */
      });
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
   * Fetch the authenticated user's bootstrap payload. When a tenant is
   * configured, it is sent as both query and header so backend app-level
   * create-on-login wallet config can resolve without exposing platform keys.
   */
  async getCurrentUser(options: { tenantId?: string } = {}): Promise<StewardCurrentUserResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);
    const tenantId = options.tenantId ?? this.tenantId;
    const path = tenantId ? `/user/me?tenantId=${encodeURIComponent(tenantId)}` : "/user/me";
    const res = await authRequest<{
      ok: boolean;
      data: StewardCurrentUserResult;
    }>(
      this.baseUrl,
      path,
      {
        headers: tenantId ? { "X-Steward-Tenant": tenantId } : undefined,
      },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data.data;
  }

  /**
   * Create or replace the current local session with a bounded guest account.
   * Guest sessions are persisted through the configured storage just like other
   * auth flows, so reloads can continue until the server-side guest expiry.
   */
  async signInAsGuest(options: StewardGuestSignInOptions = {}): Promise<StewardAuthResult> {
    const body: Record<string, unknown> = {};
    const tenantId = options.tenantId ?? this.tenantId;
    if (tenantId) body.tenantId = tenantId;
    if (options.expiresIn) body.expiresIn = options.expiresIn;

    const res = await authRequest<StewardAuthExchangeResponse>(this.baseUrl, "/auth/guest", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return this.storeExchangeResponse(res.data) as StewardAuthResult;
  }

  /**
   * Returns guest lifecycle state for the current session, including the
   * 30-day expiry warning copy consumers can surface in their own UI.
   */
  getGuestState(): StewardGuestState {
    const session = this.getSession();
    if (!session?.isGuest) {
      return {
        isGuest: false,
        isExpired: false,
        expiryMessage: null,
      };
    }
    const expiresAtMs = session.guestExpiresAt ? Date.parse(session.guestExpiresAt) : null;
    const isExpired = !!expiresAtMs && expiresAtMs <= Date.now();
    const secondsUntilExpiry =
      expiresAtMs && !Number.isNaN(expiresAtMs)
        ? Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000))
        : null;
    return {
      isGuest: true,
      userId: session.userId,
      tenantId: session.tenantId,
      expiresAt: session.guestExpiresAt ?? null,
      expiresAtMs: expiresAtMs && !Number.isNaN(expiresAtMs) ? expiresAtMs : null,
      isExpired,
      secondsUntilExpiry,
      expiryMessage: guestExpiryMessage(expiresAtMs),
    };
  }

  /**
   * Upgrade the current guest into a full user using a verified email magic-link
   * token. This is intentionally guest-only: callers signed into a full account
   * must not use this path to merge guest data into an existing identity.
   */
  async upgradeGuestWithEmail(
    input: StewardGuestUpgradeEmailInput,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in as a guest first.", 0);
    if (!this.getGuestState().isGuest) {
      throw new StewardApiError("Current session is not a guest account.", 0);
    }
    const email = input.email.trim();
    if (!email || !input.token.trim()) {
      throw new StewardApiError("email and token are required to upgrade a guest", 0);
    }

    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/guest/upgrade",
      {
        method: "POST",
        body: JSON.stringify({ method: "email", email, token: input.token }),
      },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return this.storeExchangeResponse(res.data);
  }

  /**
   * Explicitly delete the current guest account server-side and clear local
   * persisted tokens. Full accounts are rejected locally and by the API.
   */
  async deleteGuest(): Promise<StewardGuestDeleteResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in as a guest first.", 0);
    if (!this.getGuestState().isGuest) {
      throw new StewardApiError("Current session is not a guest account.", 0);
    }

    const res = await authRequest<{ ok: boolean; deleted: boolean; userId?: string }>(
      this.baseUrl,
      "/auth/guest",
      { method: "DELETE" },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    this.clearToken();
    this.notifyListeners(null);
    return res.data;
  }

  async getIdentityToken(): Promise<StewardIdentityTokenResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardIdentityTokenResult>(
      this.baseUrl,
      "/auth/identity-token",
      {},
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
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

    let res: Awaited<ReturnType<typeof authRequest<StewardRefreshResult>>>;
    try {
      res = await authRequest<StewardRefreshResult>(this.baseUrl, "/auth/refresh", {
        method: "POST",
        body: JSON.stringify({ refreshToken }),
      });
    } catch {
      return null;
    }

    if (!res.ok) {
      if (res.status === 401) {
        this.signOut();
      }
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
      }).catch(() => {
        /* best-effort */
      });
    }
    this.clearToken();
    this.notifyListeners(null);
  }

  async requestDeviceCode(
    options: StewardDeviceCodeOptions = {},
  ): Promise<StewardDeviceCodeResult> {
    const tenantId = options.tenantId ?? this.tenantId;
    if (!tenantId) {
      throw new StewardApiError("tenantId is required for device authorization", 400);
    }
    const res = await authRequest<StewardDeviceCodeResult>(this.baseUrl, "/auth/device/code", {
      method: "POST",
      body: JSON.stringify({
        tenantId,
        ...(options.clientId ? { client_id: options.clientId } : {}),
        ...(options.scope ? { scope: options.scope } : {}),
      }),
    });
    if (!res.ok) throw new StewardApiError(res.error, res.status);
    return res.data;
  }

  async verifyDeviceCode(
    userCode: string,
    action: "approve" | "deny" = "approve",
  ): Promise<StewardDeviceVerifyResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);
    const res = await authRequest<StewardDeviceVerifyResult>(
      this.baseUrl,
      "/auth/device/verify",
      {
        method: "POST",
        body: JSON.stringify({ user_code: userCode, action }),
      },
      token,
    );
    if (!res.ok) throw new StewardApiError(res.error, res.status);
    return res.data;
  }

  async pollDeviceToken(input: {
    deviceCode: string;
    clientId?: string;
  }): Promise<StewardAuthResult | StewardDeviceTokenPendingResult> {
    const response = await fetch(`${this.baseUrl}/auth/device/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: input.deviceCode,
        ...(input.clientId ? { client_id: input.clientId } : {}),
      }),
    }).catch((err) => {
      throw new StewardApiError(err instanceof Error ? err.message : "Network request failed", 0);
    });

    const text = await response.text();
    const payload = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    if (!response.ok || payload.ok === false) {
      const error = typeof payload.error === "string" ? payload.error : `status_${response.status}`;
      if (
        error === "authorization_pending" ||
        error === "slow_down" ||
        error === "access_denied" ||
        error === "expired_token" ||
        error === "invalid_client" ||
        error === "invalid_request" ||
        error === "unsupported_grant_type"
      ) {
        return {
          ok: false,
          error,
          ...(typeof payload.interval === "number" ? { interval: payload.interval } : {}),
        };
      }
      throw new StewardApiError(error, response.status);
    }

    return this.storeExchangeResponse(
      payload as unknown as StewardAuthExchangeResponse,
    ) as StewardAuthResult;
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
  async signInWithPasskey(email: string): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    if (!isBrowser()) {
      throw new StewardApiError(
        "Passkeys require a browser environment. Use signInWithEmail or signInWithSIWE in Node.",
        0,
      );
    }

    // Dynamically import @simplewebauthn/browser — peer dep, may not be installed
    let browserLib: SimpleWebAuthnBrowser;
    try {
      browserLib = await import("@simplewebauthn/browser");
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
      {
        method: "POST",
        body: JSON.stringify({
          email,
          ...(this.tenantId ? { tenantId: this.tenantId } : {}),
        }),
      },
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

  /**
   * Register a new passkey for the given email, regardless of whether the
   * user already has other passkeys on other relying parties (RPs).
   *
   * Use this after a successful magic-link / OAuth sign-in to offer the
   * user one-tap passkey login on the current device. Existing passkeys
   * for this user on OTHER RPs (e.g. a passkey from `elizacloud.ai` when
   * the user is now on `waifu.fun`) won’t be removed; this just adds a
   * fresh credential bound to the current origin’s RP.
   *
   * Behavior mirrors `signInWithPasskey` when no credentials exist, except
   * it skips the login-options probe and goes straight to registration.
   *
   * Requires a browser environment and `@simplewebauthn/browser` installed.
   * Throws `StewardApiError` otherwise.
   */
  async addPasskey(
    email: string,
    options: { emailGrant?: string } = {},
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    if (!isBrowser()) {
      throw new StewardApiError("Passkeys require a browser environment.", 0);
    }
    let browserLib: SimpleWebAuthnBrowser;
    try {
      browserLib = await import("@simplewebauthn/browser");
    } catch {
      throw new StewardApiError(
        "Missing peer dependency: @simplewebauthn/browser. Install it to use passkeys.",
        0,
      );
    }
    return this.completePasskeyRegister(email, browserLib, options.emailGrant);
  }

  private async completePasskeyLogin(
    email: string,
    options: unknown,
    lib: Pick<SimpleWebAuthnBrowser, "startAuthentication">,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const challengeId =
      options && typeof options === "object" && "challengeId" in options
        ? String((options as { challengeId?: unknown }).challengeId ?? "")
        : "";
    if (!challengeId) {
      throw new StewardApiError("Passkey login options did not include a challengeId.", 0);
    }

    let authResponse: unknown;
    try {
      // Server-provided options; types are validated by the WebAuthn browser library.
      authResponse = await lib.startAuthentication(
        options as Parameters<SimpleWebAuthnBrowser["startAuthentication"]>[0],
      );
    } catch (err) {
      throw new StewardApiError(
        `WebAuthn authentication cancelled or failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const verifyRes = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/passkey/login/verify",
      {
        method: "POST",
        body: JSON.stringify({
          email,
          challengeId,
          response: authResponse,
          ...(this.tenantId ? { tenantId: this.tenantId } : {}),
        }),
      },
    );

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    return this.storeExchangeResponse(verifyRes.data);
  }

  private async completePasskeyRegister(
    email: string,
    lib: Pick<SimpleWebAuthnBrowser, "startRegistration">,
    emailGrant?: string,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    // Fetch registration options. When an `emailGrant` is supplied (from
    // `verifyEmailOtp`), Steward accepts it in place of a session so a
    // brand-new, signed-out user can register their FIRST passkey — the
    // grant proves ownership of the email. Without it, register/options
    // requires an authenticated session.
    const regOptsRes = await authRequest<Record<string, unknown>>(
      this.baseUrl,
      "/auth/passkey/register/options",
      {
        method: "POST",
        body: JSON.stringify({
          email,
          ...(emailGrant ? { emailGrant } : {}),
          ...(this.tenantId ? { tenantId: this.tenantId } : {}),
        }),
      },
    );

    if (!regOptsRes.ok) {
      throw new StewardApiError(regOptsRes.error, regOptsRes.status);
    }

    let regResponse: unknown;
    try {
      // Server-provided options; types are validated by the WebAuthn browser library.
      regResponse = await lib.startRegistration(
        regOptsRes.data as Parameters<SimpleWebAuthnBrowser["startRegistration"]>[0],
      );
    } catch (err) {
      throw new StewardApiError(
        `WebAuthn registration cancelled or failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const verifyRes = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/passkey/register/verify",
      {
        method: "POST",
        body: JSON.stringify({
          email,
          response: regResponse,
          ...(emailGrant ? { emailGrant } : {}),
          ...(this.tenantId ? { tenantId: this.tenantId } : {}),
        }),
      },
    );

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    return this.storeExchangeResponse(verifyRes.data);
  }

  // ─── Email magic link ───────────────────────────────────────────────────────

  /**
   * Send a magic link to the given email address.
   * Returns `{ ok: true, expiresAt }` — the actual sign-in happens in `verifyEmailCallback`.
   */
  async signInWithEmail(email: string, captchaToken?: string): Promise<StewardEmailResult> {
    // API shape: { ok: true, data: { expiresAt: string } }
    const res = await authRequest<Record<string, unknown>>(this.baseUrl, "/auth/email/send", {
      method: "POST",
      body: JSON.stringify({
        email,
        ...(captchaToken ? { captchaToken } : {}),
        ...(this.tenantId ? { tenantId: this.tenantId } : {}),
      }),
    });

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
  async verifyEmailCallback(
    token: string,
    email: string,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const res = await authRequest<StewardAuthExchangeResponse>(this.baseUrl, "/auth/email/verify", {
      method: "POST",
      body: JSON.stringify({
        token,
        email,
        ...(this.tenantId ? { tenantId: this.tenantId } : {}),
      }),
    });

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeExchangeResponse(res.data);
  }

  // ─── SMS OTP ───────────────────────────────────────────────────────────────

  async sendSmsOtp(phone: string, captchaToken?: string): Promise<StewardSmsOtpResult> {
    const res = await authRequest<StewardSmsOtpResult>(this.baseUrl, "/auth/sms/send", {
      method: "POST",
      body: JSON.stringify({
        phone,
        ...(captchaToken ? { captchaToken } : {}),
        ...(this.tenantId ? { tenantId: this.tenantId } : {}),
      }),
    });

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return res.data;
  }

  async verifySmsOtp(
    phone: string,
    code: string,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const res = await authRequest<StewardAuthExchangeResponse>(this.baseUrl, "/auth/sms/verify", {
      method: "POST",
      body: JSON.stringify({
        phone,
        code,
        ...(this.tenantId ? { tenantId: this.tenantId } : {}),
      }),
    });

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeExchangeResponse(res.data);
  }

  // ─── WhatsApp OTP ─────────────────────────────────────────────────────────

  async sendWhatsAppOtp(phone: string, captchaToken?: string): Promise<StewardWhatsAppOtpResult> {
    const res = await authRequest<StewardWhatsAppOtpResult>(this.baseUrl, "/auth/whatsapp/send", {
      method: "POST",
      body: JSON.stringify({
        phone,
        ...(captchaToken ? { captchaToken } : {}),
        ...(this.tenantId ? { tenantId: this.tenantId } : {}),
      }),
    });

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return res.data;
  }

  async verifyWhatsAppOtp(
    phone: string,
    code: string,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/whatsapp/verify",
      {
        method: "POST",
        body: JSON.stringify({
          phone,
          code,
          ...(this.tenantId ? { tenantId: this.tenantId } : {}),
        }),
      },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeExchangeResponse(res.data);
  }

  // ─── Email OTP (Privy-style verified signup) ──────────────────────────

  /**
   * Email a 6-digit one-time code (Privy-style signup). Unlike
   * `signInWithEmail` (magic link), this issues a code the user types back
   * via `verifyEmailOtp` to obtain an `emailGrant`. The grant lets a
   * brand-new, signed-out user register their first passkey with
   * `addPasskey(email, { emailGrant })` — no prior session required.
   */
  async sendEmailOtp(email: string, captchaToken?: string): Promise<StewardEmailOtpResult> {
    // authRequest returns the raw `{ ok, data }` envelope; the send route's
    // payload (e.g. { expiresAt }) is nested under `data`.
    const res = await authRequest<{ ok: boolean; data?: { expiresAt?: string } }>(
      this.baseUrl,
      "/auth/email/otp/send",
      {
        method: "POST",
        body: JSON.stringify({
          email,
          ...(captchaToken ? { captchaToken } : {}),
          ...(this.tenantId ? { tenantId: this.tenantId } : {}),
        }),
      },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return { ok: true, expiresAt: res.data?.data?.expiresAt };
  }

  /**
   * Exchange the 6-digit code from `sendEmailOtp` for a short-lived,
   * single-use `emailGrant` proving ownership of the email. Pass the grant
   * to `addPasskey(email, { emailGrant })`.
   *
   * NOTE: this does NOT sign the user in by itself — it returns proof of
   * email ownership, intentionally decoupled so the caller drives the
   * passkey registration step.
   */
  async verifyEmailOtp(email: string, code: string): Promise<StewardEmailGrantResult> {
    // The verify route returns { ok, data: { emailGrant, expiresInSeconds } }
    // and authRequest hands back the raw envelope, so unwrap `.data`.
    const res = await authRequest<{
      ok: boolean;
      data?: { emailGrant?: string; expiresInSeconds?: number };
    }>(this.baseUrl, "/auth/email/otp/verify", {
      method: "POST",
      body: JSON.stringify({
        email,
        code,
        ...(this.tenantId ? { tenantId: this.tenantId } : {}),
      }),
    });

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    const grant = res.data?.data?.emailGrant;
    if (typeof grant !== "string" || grant.length === 0) {
      throw new StewardApiError("Email OTP verify did not return a grant.", res.status);
    }

    return {
      ok: true,
      emailGrant: grant,
      expiresInSeconds: res.data?.data?.expiresInSeconds ?? 0,
    };
  }

  async getTestAccessToken(
    options: StewardTestAccountLoginOptions,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const tenantId = options.tenantId ?? this.tenantId;
    const res = await authRequest<StewardAuthExchangeResponse>(this.baseUrl, "/auth/test/token", {
      method: "POST",
      body: JSON.stringify({
        ...(tenantId ? { tenantId } : {}),
        ...(options.email ? { email: options.email } : {}),
        ...(options.phone ? { phone: options.phone } : {}),
        otp: options.otp,
      }),
    });

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeExchangeResponse(res.data);
  }

  // ─── Telegram Login Widget ────────────────────────────────────────────────

  async signInWithTelegram(
    payload: StewardTelegramLoginPayload,
    config: StewardTelegramLoginConfig = {},
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const tenantId = config.tenantId ?? this.tenantId;
    const challenge = await authRequest<{ challengeId: string }>(
      this.baseUrl,
      "/auth/telegram/challenge",
      {
        method: "POST",
        body: JSON.stringify({
          ...(tenantId ? { tenantId } : {}),
        }),
      },
    );
    if (!challenge.ok) {
      throw new StewardApiError(challenge.error, challenge.status);
    }

    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/telegram/verify",
      {
        method: "POST",
        body: JSON.stringify({
          ...payload,
          challengeId: challenge.data.challengeId,
          ...(tenantId ? { tenantId } : {}),
        }),
      },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeExchangeResponse({
      ...res.data,
      user: {
        ...res.data.user,
        id: res.data.user?.id ?? res.data.userId ?? String(payload.id),
        email: res.data.user?.email ?? "",
        walletAddress: res.data.user?.walletAddress ?? res.data.address,
        walletChain: res.data.user?.walletChain,
      },
    });
  }

  async signInWithFarcaster(
    payload: StewardFarcasterLoginPayload,
    config: StewardFarcasterLoginConfig = {},
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const tenantId = config.tenantId ?? this.tenantId;
    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/farcaster/verify",
      {
        method: "POST",
        body: JSON.stringify({
          ...payload,
          ...(tenantId ? { tenantId } : {}),
        }),
      },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return this.storeExchangeResponse({
      ...res.data,
      user: {
        ...res.data.user,
        id: res.data.user?.id ?? res.data.userId ?? String(payload.fid ?? ""),
        email: res.data.user?.email ?? "",
        walletAddress: res.data.user?.walletAddress ?? res.data.address,
        walletChain: res.data.user?.walletChain,
      },
    });
  }

  // ─── TOTP MFA ──────────────────────────────────────────────────────────────

  async getTotpStatus(): Promise<StewardTotpStatus> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardTotpStatus>(
      this.baseUrl,
      "/auth/mfa/totp/status",
      {},
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async enrollTotp(): Promise<StewardTotpEnrollResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardTotpEnrollResult>(
      this.baseUrl,
      "/auth/mfa/totp/enroll",
      { method: "POST", body: JSON.stringify({}) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async verifyTotp(code: string): Promise<StewardTotpVerifyResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardTotpVerifyResult>(
      this.baseUrl,
      "/auth/mfa/totp/verify",
      { method: "POST", body: JSON.stringify({ code }) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async completeTotpMfa(challengeId: string, code: string): Promise<StewardAuthResult> {
    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/totp/complete",
      {
        method: "POST",
        body: JSON.stringify({ challengeId, code }),
      },
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

  async completeRecoveryCodeMfa(
    challengeId: string,
    recoveryCode: string,
  ): Promise<StewardAuthResult> {
    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/totp/complete",
      {
        method: "POST",
        body: JSON.stringify({ challengeId, recoveryCode }),
      },
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

  async stepUpWithTotp(code: string): Promise<StewardAuthResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/totp/step-up",
      {
        method: "POST",
        body: JSON.stringify({ code }),
      },
      token,
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

  async stepUpWithRecoveryCode(recoveryCode: string): Promise<StewardAuthResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/totp/step-up",
      {
        method: "POST",
        body: JSON.stringify({ recoveryCode }),
      },
      token,
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

  async getRecoveryCodeStatus(): Promise<StewardRecoveryCodeStatus> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardRecoveryCodeStatus>(
      this.baseUrl,
      "/auth/mfa/recovery-codes/status",
      {},
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async regenerateRecoveryCodes(code: string): Promise<StewardRecoveryCodesResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardRecoveryCodesResult>(
      this.baseUrl,
      "/auth/mfa/recovery-codes/regenerate",
      { method: "POST", body: JSON.stringify({ code }) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async unenrollTotp(code: string): Promise<{ ok: boolean }> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<{ ok: boolean }>(
      this.baseUrl,
      "/auth/mfa/totp/unenroll",
      { method: "POST", body: JSON.stringify({ code }) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  // ─── SMS MFA ───────────────────────────────────────────────────────────────

  async getSmsMfaStatus(): Promise<StewardSmsMfaStatus> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardSmsMfaStatus>(
      this.baseUrl,
      "/auth/mfa/sms/status",
      {},
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async enrollSmsMfa(phone: string): Promise<StewardSmsMfaEnrollResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardSmsMfaEnrollResult>(
      this.baseUrl,
      "/auth/mfa/sms/enroll",
      { method: "POST", body: JSON.stringify({ phone }) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async verifySmsMfa(code: string): Promise<StewardSmsMfaVerifyResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardSmsMfaVerifyResult>(
      this.baseUrl,
      "/auth/mfa/sms/verify",
      { method: "POST", body: JSON.stringify({ code }) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async sendSmsMfaCode(): Promise<StewardSmsMfaEnrollResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardSmsMfaEnrollResult>(
      this.baseUrl,
      "/auth/mfa/sms/send",
      { method: "POST", body: JSON.stringify({}) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  async completeSmsMfa(challengeId: string, code: string): Promise<StewardAuthResult> {
    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/sms/complete",
      {
        method: "POST",
        body: JSON.stringify({ challengeId, code }),
      },
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

  async stepUpWithSms(code: string): Promise<StewardAuthResult> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/sms/step-up",
      {
        method: "POST",
        body: JSON.stringify({ code }),
      },
      token,
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

  async completePasskeyMfa(): Promise<StewardAuthResult> {
    if (!isBrowser()) {
      throw new StewardApiError("Passkey MFA requires a browser environment.", 0);
    }
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    let browserLib: SimpleWebAuthnBrowser;
    try {
      browserLib = await import("@simplewebauthn/browser");
    } catch {
      throw new StewardApiError(
        "Missing peer dependency: @simplewebauthn/browser. Install it to use passkeys.",
        0,
      );
    }

    const optionsRes = await authRequest<Record<string, unknown>>(
      this.baseUrl,
      "/auth/mfa/passkey/options",
      { method: "POST", body: JSON.stringify({}) },
      token,
    );
    if (!optionsRes.ok) {
      throw new StewardApiError(optionsRes.error, optionsRes.status);
    }

    const challengeId =
      typeof optionsRes.data.challengeId === "string" ? optionsRes.data.challengeId : "";
    if (!challengeId) {
      throw new StewardApiError("Passkey MFA options did not include a challengeId.", 0);
    }

    let authResponse: unknown;
    try {
      authResponse = await browserLib.startAuthentication(
        optionsRes.data as Parameters<SimpleWebAuthnBrowser["startAuthentication"]>[0],
      );
    } catch (err) {
      throw new StewardApiError(
        `WebAuthn authentication cancelled or failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const verifyRes = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/mfa/passkey/complete",
      {
        method: "POST",
        body: JSON.stringify({ challengeId, response: authResponse }),
      },
      token,
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

  async unenrollSmsMfa(code: string): Promise<{ ok: boolean }> {
    const token = this.getToken();
    if (!token) throw new StewardApiError("Not authenticated. Sign in first.", 0);

    const res = await authRequest<{ ok: boolean }>(
      this.baseUrl,
      "/auth/mfa/sms/unenroll",
      { method: "POST", body: JSON.stringify({ code }) },
      token,
    );
    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
    return res.data;
  }

  // ─── SIWE ───────────────────────────────────────────────────────────────────

  /**
   * Sign in with an Ethereum wallet via SIWE (EIP-4361).
   *
   * @param address  - The signer's EVM address (checksummed or lowercase).
   * @param signMessage - Async function that signs an arbitrary string with the wallet.
   *                      Compatible with ethers.js `signer.signMessage`, viem's `walletClient.signMessage`,
   *                      or any custom implementation.
   * @param chainId    - The EVM chain id the wallet is connected to (e.g. 1, 8453, 56).
   *                      Defaults to Ethereum mainnet (1) when omitted. The web app should
   *                      pass the real connected chain id (e.g. from wagmi `useChainId()`)
   *                      so the signed message and EIP-1271 verification reflect reality.
   *
   * Flow: GET /auth/nonce → build SIWE message → caller signs → POST /auth/verify → store JWT.
   */
  async signInWithSIWE(
    address: string,
    signMessage: (msg: string) => Promise<string>,
    chainId?: number,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    // 1. Fetch a fresh nonce
    const nonceRes = await authRequest<{ nonce: string }>(this.baseUrl, "/auth/nonce");

    if (!nonceRes.ok) {
      throw new StewardApiError(nonceRes.error, nonceRes.status);
    }

    const { nonce } = nonceRes.data;

    // 2. Build a minimal SIWE message string (EIP-4361)
    const issuedAt = new Date().toISOString();
    const siweMessage = buildSiweMessage(address, nonce, issuedAt, chainId);

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
    const verifyRes = await authRequest<StewardAuthExchangeResponse>(this.baseUrl, "/auth/verify", {
      method: "POST",
      body: JSON.stringify({ message: siweMessage, signature }),
      ...(this.tenantId ? { headers: { "X-Steward-Tenant": this.tenantId } } : {}),
    });

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    // SIWE response has no `user` object — synthesise one from address
    const user: StewardUser = {
      id: verifyRes.data.userId ?? verifyRes.data.tenant?.id ?? "",
      email: "",
      walletAddress: verifyRes.data.address,
      walletChain: verifyRes.data.walletChain ?? "ethereum",
    };

    return this.storeExchangeResponse({
      ...verifyRes.data,
      user: verifyRes.data.user ?? user,
    });
  }

  /**
   * Sign in with a Solana wallet via Sign-In With Solana.
   */
  async signInWithSolana(
    publicKey: string,
    signMessage: (message: Uint8Array) => Promise<Uint8Array>,
    chain?: string,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const nonceRes = await authRequest<{ nonce: string }>(this.baseUrl, "/auth/nonce");
    if (!nonceRes.ok) {
      throw new StewardApiError(nonceRes.error, nonceRes.status);
    }

    const issuedAt = new Date().toISOString();
    const message = buildSiwsMessage(publicKey, nonceRes.data.nonce, issuedAt, chain);

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = await signMessage(new TextEncoder().encode(message));
    } catch (err) {
      throw new StewardApiError(
        `Wallet signing failed: ${err instanceof Error ? err.message : String(err)}`,
        0,
      );
    }

    const verifyRes = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      "/auth/verify/solana",
      {
        method: "POST",
        body: JSON.stringify({
          message,
          signature: bs58.encode(signatureBytes),
          publicKey,
        }),
        ...(this.tenantId ? { headers: { "X-Steward-Tenant": this.tenantId } } : {}),
      },
    );

    if (!verifyRes.ok) {
      throw new StewardApiError(verifyRes.error, verifyRes.status);
    }

    const user: StewardUser = {
      id: verifyRes.data.userId ?? verifyRes.data.tenant?.id ?? "",
      email: "",
      walletAddress: verifyRes.data.publicKey ?? verifyRes.data.address,
      walletChain: verifyRes.data.walletChain ?? "solana",
    };

    return this.storeExchangeResponse({
      ...verifyRes.data,
      user: verifyRes.data.user ?? user,
    });
  }

  // ─── OAuth / Provider Discovery ───────────────────────────────────────────

  private providersCache: { data: StewardProviders; fetchedAt: number } | null = null;
  private static readonly PROVIDERS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

  /**
   * Fetch the list of enabled authentication providers from the server.
   * Results are cached for 5 minutes to avoid hammering the endpoint on every render.
   */
  async getProviders(forceRefresh = false): Promise<StewardProviders> {
    if (
      !forceRefresh &&
      this.providersCache &&
      Date.now() - this.providersCache.fetchedAt < StewardAuth.PROVIDERS_CACHE_TTL_MS
    ) {
      return this.providersCache.data;
    }

    const res = await authRequest<StewardProviders>(this.baseUrl, "/auth/providers");

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    this.providersCache = { data: res.data, fetchedAt: Date.now() };
    return res.data;
  }

  async signInWithJwt(
    token: string,
    config: StewardJwtLoginConfig,
  ): Promise<StewardAuthResult | StewardMfaRequiredResult> {
    const tenantId = config.tenantId || this.tenantId;
    if (!tenantId) {
      throw new StewardApiError("tenantId is required for JWT login", 400);
    }
    const res = await authRequest<StewardAuthExchangeResponse>(this.baseUrl, "/auth/jwt/login", {
      method: "POST",
      body: JSON.stringify({
        tenantId,
        providerId: config.providerId,
        token,
      }),
    });
    if (!res.ok) throw new StewardApiError(res.error, res.status);

    const user: StewardUser = {
      id: res.data.user?.id ?? res.data.userId ?? "",
      email: res.data.user?.email ?? "",
      walletAddress: res.data.user?.walletAddress ?? res.data.address,
      walletChain: res.data.user?.walletChain,
    };
    return this.storeExchangeResponse({
      ...res.data,
      user: res.data.user ?? user,
    });
  }

  /**
   * Sign in with an OAuth provider using a popup-based PKCE flow.
   *
   * In a browser environment, opens a popup to the provider's authorization page,
   * listens for the callback, and exchanges the code for a session.
   *
   * In non-browser environments (Node), throws with the authorization URL.
   * Use `handleOAuthCallback` to complete the flow after redirect.
   *
   * @param provider - OAuth provider name (e.g. "google", "discord")
   * @param config   - Optional configuration overrides
   */
  async signInWithOAuth(
    provider: string,
    config?: Partial<Omit<StewardOAuthConfig, "provider">>,
  ): Promise<StewardOAuthResult | StewardMfaRequiredResult> {
    // Generate PKCE pair
    const codeVerifier = await generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Generate random state
    const stateBytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(stateBytes);
    const state = Array.from(stateBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Store state + verifier for later verification
    this.storage.setItem(OAUTH_STATE_KEY, state);
    this.storage.setItem(OAUTH_VERIFIER_KEY, codeVerifier);
    if (config?.tenantId) {
      this.storage.setItem(OAUTH_TENANT_KEY, config.tenantId);
    } else {
      this.storage.removeItem(OAUTH_TENANT_KEY);
    }

    // Build the redirect URI
    const redirectUri =
      config?.redirectUri ??
      (isBrowser() ? `${window.location.origin}/auth/callback` : "http://localhost/auth/callback");

    // Build the authorization URL
    const params = new URLSearchParams({
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    });
    if (config?.tenantId) {
      params.set("tenant_id", config.tenantId);
    }
    const authorizeUrl = `${this.baseUrl}/auth/oauth/${encodeURIComponent(provider)}/authorize?${params.toString()}`;

    if (!isBrowser()) {
      throw new StewardApiError(
        `OAuth popup flow requires a browser. Redirect to: ${authorizeUrl}`,
        0,
      );
    }

    // Open popup
    const popupWidth = config?.popupWidth ?? 500;
    const popupHeight = config?.popupHeight ?? 600;
    const left = Math.round(window.screenX + (window.outerWidth - popupWidth) / 2);
    const top = Math.round(window.screenY + (window.outerHeight - popupHeight) / 2);

    const popup = window.open(
      authorizeUrl,
      "steward-oauth",
      `width=${popupWidth},height=${popupHeight},left=${left},top=${top},popup=yes`,
    );

    if (!popup) {
      throw new StewardApiError(
        "Failed to open OAuth popup. Check that popups are not blocked.",
        0,
      );
    }

    // Wait for the popup to redirect back with the code
    const callbackParams = await this.waitForPopupCallback(popup, redirectUri);

    // Validate state
    if (callbackParams.state !== state) {
      throw new StewardApiError("OAuth state mismatch, possible CSRF attack", 0);
    }

    if (callbackParams.error) {
      throw new StewardApiError(`OAuth error: ${callbackParams.error}`, 0);
    }

    if (!callbackParams.code) {
      throw new StewardApiError("No authorization code received from OAuth provider", 0);
    }

    // Exchange code for tokens via PKCE
    return this.exchangeOAuthCode(
      provider,
      callbackParams.code,
      redirectUri,
      state,
      codeVerifier,
      config?.tenantId,
    );
  }

  /**
   * Complete an OAuth flow from a redirect callback (non-popup flow).
   *
   * Call this from your callback route handler after the OAuth provider
   * redirects back with `code` and `state` query parameters.
   *
   * @param provider - OAuth provider name (e.g. "google", "discord")
   * @param params   - The URL search params from the callback (code, state, error)
   */
  async handleOAuthCallback(
    provider: string,
    params: { code?: string; state?: string; error?: string },
  ): Promise<StewardOAuthResult | StewardMfaRequiredResult> {
    if (params.error) {
      throw new StewardApiError(`OAuth error: ${params.error}`, 0);
    }

    if (!params.code || !params.state) {
      throw new StewardApiError("Missing code or state in OAuth callback", 0);
    }

    // Retrieve stored state + verifier
    const storedState = this.storage.getItem(OAUTH_STATE_KEY);
    const storedVerifier = this.storage.getItem(OAUTH_VERIFIER_KEY);
    const storedTenantId = this.storage.getItem(OAUTH_TENANT_KEY) ?? undefined;

    if (!storedState || !storedVerifier) {
      throw new StewardApiError(
        "No OAuth state found in storage. Did you call signInWithOAuth first?",
        0,
      );
    }

    if (params.state !== storedState) {
      throw new StewardApiError("OAuth state mismatch, possible CSRF attack", 0);
    }

    // Build redirect URI from current location (or fallback)
    const redirectUri = isBrowser()
      ? `${window.location.origin}${window.location.pathname}`
      : "http://localhost/auth/callback";

    return this.exchangeOAuthCode(
      provider,
      params.code,
      redirectUri,
      params.state,
      storedVerifier,
      storedTenantId,
    );
  }

  /**
   * Exchange an OAuth authorization code for session tokens via PKCE.
   */
  private async exchangeOAuthCode(
    provider: string,
    code: string,
    redirectUri: string,
    state: string,
    codeVerifier: string,
    tenantId?: string,
  ): Promise<StewardOAuthResult | StewardMfaRequiredResult> {
    const body: Record<string, string> = { code, redirectUri, state, codeVerifier };
    if (tenantId) body.tenantId = tenantId;
    const res = await authRequest<StewardAuthExchangeResponse>(
      this.baseUrl,
      `/auth/oauth/${encodeURIComponent(provider)}/token`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    // Clean up stored PKCE state
    this.storage.removeItem(OAUTH_STATE_KEY);
    this.storage.removeItem(OAUTH_VERIFIER_KEY);
    this.storage.removeItem(OAUTH_TENANT_KEY);

    const result = this.storeExchangeResponse(res.data);
    if ("mfaRequired" in result && result.mfaRequired) return result;

    return { ...result, provider };
  }

  /**
   * Wait for the OAuth popup to redirect back to the callback URL.
   * Polls the popup location and listens for postMessage as a fallback.
   */
  private waitForPopupCallback(
    popup: Window,
    expectedOrigin: string,
  ): Promise<{ code?: string; state?: string; error?: string }> {
    return new Promise((resolve, reject) => {
      let resolved = false;
      const pollInterval = 200; // ms
      const timeout = 5 * 60 * 1000; // 5 min max
      const startTime = Date.now();

      // Parse the expected origin from the redirect URI
      let origin: string;
      try {
        origin = new URL(expectedOrigin).origin;
      } catch {
        origin = isBrowser() ? window.location.origin : "http://localhost";
      }

      // Listen for postMessage from the popup (if the callback page sends one)
      const messageHandler = (event: MessageEvent): void => {
        if (resolved) return;
        if (event.origin !== origin) return;
        const data = event.data as
          | { type?: string; code?: string; state?: string; error?: string }
          | undefined;
        if (data?.type === "steward-oauth-callback") {
          resolved = true;
          window.removeEventListener("message", messageHandler);
          resolve({ code: data.code, state: data.state, error: data.error });
        }
      };
      window.addEventListener("message", messageHandler);

      // Poll the popup location
      const poll = setInterval(() => {
        if (resolved) {
          clearInterval(poll);
          return;
        }

        // Check timeout
        if (Date.now() - startTime > timeout) {
          resolved = true;
          clearInterval(poll);
          window.removeEventListener("message", messageHandler);
          reject(new StewardApiError("OAuth popup timed out after 5 minutes", 0));
          return;
        }

        // Check if popup was closed by user
        if (popup.closed) {
          resolved = true;
          clearInterval(poll);
          window.removeEventListener("message", messageHandler);
          reject(new StewardApiError("OAuth popup was closed before completing sign-in", 0));
          return;
        }

        // Try to read the popup URL (cross-origin will throw)
        try {
          const popupUrl = popup.location.href;
          if (popupUrl?.startsWith(origin)) {
            resolved = true;
            clearInterval(poll);
            window.removeEventListener("message", messageHandler);
            popup.close();

            resolve(getOAuthCallbackParams(new URL(popupUrl)));
          }
        } catch {
          // Cross-origin: popup still on provider's domain, keep polling
        }
      }, pollInterval);
    });
  }

  // ─── Multi-tenant ───────────────────────────────────────────────────────────

  /**
   * List all tenants/apps the current user belongs to.
   * Requires an active session.
   */
  async listTenants(): Promise<StewardTenantMembership[]> {
    const token = this.getToken();
    if (!token) {
      throw new StewardApiError("Not authenticated. Sign in first.", 0);
    }

    const res = await authRequest<StewardTenantMembership[] | { data: StewardTenantMembership[] }>(
      this.baseUrl,
      "/user/me/tenants",
      {},
      token,
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return Array.isArray(res.data) ? res.data : res.data.data;
  }

  /** Join an open tenant/app. Invite-only tenants require acceptTenantInvitation. */
  async joinTenant(tenantId: string): Promise<StewardTenantMembership> {
    const token = this.getToken();
    if (!token) {
      throw new StewardApiError("Not authenticated. Sign in first.", 0);
    }

    const res = await authRequest<StewardTenantMembership & { ok?: boolean }>(
      this.baseUrl,
      `/user/me/tenants/${encodeURIComponent(tenantId)}/join`,
      { method: "POST" },
      token,
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return res.data;
  }

  /**
   * Accept a tenant invitation using a single-use invite token.
   * Requires an active personal session with a verified email.
   */
  async acceptTenantInvitation(
    tenantId: string,
    token: string,
  ): Promise<{ tenantId: string; role: string; invitationId: string }> {
    const sessionToken = this.getToken();
    if (!sessionToken) {
      throw new StewardApiError("Not authenticated. Sign in first.", 0);
    }

    const res = await authRequest<{ tenantId: string; role: string; invitationId: string }>(
      this.baseUrl,
      `/user/me/tenants/${encodeURIComponent(tenantId)}/invitations/accept`,
      {
        method: "POST",
        body: JSON.stringify({ token }),
      },
      sessionToken,
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }

    return res.data;
  }

  /**
   * Leave a tenant/app. Cannot leave your personal tenant.
   * Requires an active session.
   */
  async leaveTenant(tenantId: string): Promise<void> {
    const token = this.getToken();
    if (!token) {
      throw new StewardApiError("Not authenticated. Sign in first.", 0);
    }

    const res = await authRequest<{ ok: boolean }>(
      this.baseUrl,
      `/user/me/tenants/${encodeURIComponent(tenantId)}/leave`,
      { method: "DELETE" },
      token,
    );

    if (!res.ok) {
      throw new StewardApiError(res.error, res.status);
    }
  }

  /**
   * Switch the active tenant context by refreshing the session with a new tenantId.
   * Returns the new session, or null if the switch failed (user may need to re-auth).
   */
  async switchTenant(tenantId: string): Promise<StewardSession | null> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      return null;
    }

    const res = await authRequest<StewardRefreshResult>(this.baseUrl, "/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refreshToken, tenantId }),
    });

    if (!res.ok) {
      // Refresh failed, user needs to re-authenticate
      return null;
    }

    this.storage.setItem(STORAGE_KEY, res.data.token);
    this.storage.setItem(REFRESH_TOKEN_KEY, res.data.refreshToken);
    const session = sessionFromToken(res.data.token);
    this.notifyListeners(session);
    return session;
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  private storeAndReturn(
    token: string | undefined,
    refreshToken: string,
    user: StewardUser,
    expiresIn = 900,
  ): StewardAuthResult {
    if (!token) {
      throw new StewardApiError("Auth response did not include a session token", 0);
    }
    this.storage.setItem(STORAGE_KEY, token);
    // Only persist the refresh token when it's a non-empty string.
    // An empty string means the API didn't issue one (e.g. SIWE flow).
    if (refreshToken) {
      this.storage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    }
    const session = sessionFromToken(token, user);
    this.notifyListeners(session);
    return { token, refreshToken, expiresIn, user };
  }

  private storeExchangeResponse(
    data: StewardAuthExchangeResponse,
  ): StewardAuthResult | StewardMfaRequiredResult {
    if (data.mfaRequired) {
      if (!data.mfa) {
        throw new StewardApiError("MFA challenge is missing from auth response", 0);
      }
      return {
        ok: true,
        mfaRequired: true,
        mfa: data.mfa,
        user: data.user,
      };
    }
    return this.storeAndReturn(data.token, data.refreshToken ?? "", data.user, data.expiresIn);
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

// ─── PKCE Helpers (module-private) ──────────────────────────────────────────

/**
 * Generate a cryptographically random PKCE code_verifier.
 * Returns a 43-128 character base64url string (RFC 7636 Section 4.1).
 * Uses Web Crypto API for browser + Node 18+ compatibility.
 */
async function generateCodeVerifier(): Promise<string> {
  const bytes = new Uint8Array(32); // 32 bytes → 43 base64url chars
  globalThis.crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

/**
 * Generate a PKCE code_challenge from a code_verifier using SHA-256.
 * Uses Web Crypto API (globalThis.crypto.subtle) for cross-platform support.
 */
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(new Uint8Array(digest));
}

/**
 * Encode a Uint8Array as a base64url string (no padding).
 */
function base64urlEncode(bytes: Uint8Array): string {
  // btoa is available in all browsers and Node 18+
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Export PKCE helpers for testing
export {
  generateCodeChallenge as _generateCodeChallenge,
  generateCodeVerifier as _generateCodeVerifier,
  getOAuthCallbackParams as _getOAuthCallbackParams,
};
