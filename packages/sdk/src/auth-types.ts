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
  walletChain?: "ethereum" | "solana";
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

export interface StewardMfaRequiredResult {
  ok: true;
  mfaRequired: true;
  mfa: {
    type: "totp" | "sms" | "passkey";
    challengeId: string;
    expiresAt: string;
  };
  user: StewardUser;
}

/** Shared response shape for auth flows that exchange a challenge or callback for a session. */
export interface StewardAuthExchangeResponse {
  ok: boolean;
  token?: string;
  user: StewardUser;
  refreshToken?: string;
  expiresIn?: number;
  mfaRequired?: boolean;
  mfa?: StewardMfaRequiredResult["mfa"];
  userId?: string;
  address?: string;
  publicKey?: string;
  walletChain?: "ethereum" | "solana";
  tenant?: {
    id: string;
    name: string;
    apiKey?: string;
  };
}

export interface StewardEmailResult {
  ok: boolean;
  expiresAt: string;
}

export interface StewardSmsOtpResult {
  ok: boolean;
  expiresAt: string;
}

export interface StewardWhatsAppOtpResult {
  ok: boolean;
  expiresAt: string;
}

export interface StewardTestAccountLoginOptions {
  tenantId?: string;
  email?: string;
  phone?: string;
  otp: string;
}

export interface StewardTelegramLoginPayload {
  id: string | number;
  first_name?: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  auth_date: string | number;
  hash: string;
  [key: string]: string | number | boolean | null | undefined;
}

export interface StewardTelegramLoginConfig {
  tenantId?: string;
}

export interface StewardFarcasterLoginPayload {
  message: string;
  signature: string;
  custodyAddress?: string;
  address?: string;
  fid?: string | number;
  username?: string;
  displayName?: string;
  pfpUrl?: string;
  pfp?: string;
}

export interface StewardFarcasterLoginConfig {
  tenantId?: string;
}

export interface StewardTotpEnrollResult {
  ok: boolean;
  secret: string;
  otpauthUri: string;
  expiresAt: string;
}

export interface StewardTotpVerifyResult {
  ok: boolean;
  enabled?: boolean;
  verified?: boolean;
  recoveryCodes?: string[];
}

export interface StewardTotpStatus {
  ok: boolean;
  enabled: boolean;
  pending: boolean;
}

export interface StewardRecoveryCodeStatus {
  ok: boolean;
  enabled: boolean;
  remaining: number;
}

export interface StewardRecoveryCodesResult {
  ok: boolean;
  recoveryCodes: string[];
}

export interface StewardSmsMfaStatus {
  ok: boolean;
  enabled: boolean;
  pending: boolean;
  phone?: string;
}

export interface StewardSmsMfaEnrollResult {
  ok: boolean;
  phone: string;
  expiresAt: string;
}

export interface StewardSmsMfaVerifyResult {
  ok: boolean;
  enabled: boolean;
  phone: string;
}

export interface StewardLinkedAccount {
  id: string;
  provider: string;
  providerAccountId: string;
  expiresAt: number | null;
}

export interface StewardIdentityClaims {
  sub: string;
  userId: string;
  tenantId: string;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  image: string | null;
  walletAddress: string | null;
  walletChain: string | null;
  customMetadata: Record<string, unknown>;
  tenantIds: string[];
  linkedAccounts: StewardLinkedAccount[];
}

export interface StewardIdentityTokenResult {
  ok: boolean;
  token: string;
  expiresIn: number;
  claims: StewardIdentityClaims;
  user: {
    id: string;
    email: string | null;
    walletAddress?: string | null;
    walletChain?: string | null;
    emailVerified?: boolean | null;
    name?: string | null;
    image?: string | null;
    customMetadata?: Record<string, unknown>;
    linkedAccounts?: StewardLinkedAccount[];
  };
}

// ─── Config ───────────────────────────────────────────────────────────────────

export interface StewardAuthConfig {
  /** Base URL of the Steward API, e.g. "https://api.steward.fi" */
  baseUrl: string;
  /**
   * Optional storage backend for persisting access and refresh tokens.
   * Defaults to in-memory (session lost on page reload / process restart) so
   * browser XSS cannot read long-lived refresh tokens from localStorage by default.
   * Pass `sessionStorage`, `localStorage`, or a custom implementation only when
   * that persistence tradeoff is explicit.
   */
  storage?: SessionStorage;
  /**
   * Called whenever the session changes (sign-in, sign-out, token refresh).
   * Receives `null` when signed out, `StewardSession` when signed in.
   */
  onSessionChange?: (session: StewardSession | null) => void;
  /**
   * Default tenant to authenticate against.
   * When set, all sign-in methods include this tenantId in requests.
   */
  tenantId?: string;
}

/** Response shape from POST /auth/refresh */
export interface StewardRefreshResult {
  token: string;
  refreshToken: string;
  expiresIn: number;
}

// ─── OAuth types ──────────────────────────────────────────────────────────────

/**
 * Configuration for an OAuth sign-in attempt.
 */
export interface StewardOAuthConfig {
  /** OAuth provider name, e.g. "google" or "discord" */
  provider: string;
  /** Override the redirect URI (defaults to current page origin + /auth/callback) */
  redirectUri?: string;
  /** Tenant to authenticate into */
  tenantId?: string;
  /** Popup window width in pixels (default: 500) */
  popupWidth?: number;
  /** Popup window height in pixels (default: 600) */
  popupHeight?: number;
}

/**
 * Result from a successful OAuth sign-in.
 */
export interface StewardOAuthResult extends StewardAuthResult {
  /** The OAuth provider that was used */
  provider: string;
}

export interface StewardJwtLoginConfig {
  tenantId: string;
  providerId?: string;
}

/**
 * Discovery response from GET /auth/providers.
 * Indicates which authentication methods are enabled on the server.
 */
export interface StewardProviders {
  passkey: boolean;
  email: boolean;
  sms?: boolean;
  whatsapp?: boolean;
  totp?: boolean;
  siwe: boolean;
  siws: boolean;
  google: boolean;
  discord: boolean;
  github: boolean;
  twitter: boolean;
  telegram?: boolean;
  farcaster?: boolean;
  linkedin?: boolean;
  spotify?: boolean;
  twitch?: boolean;
  instagram?: boolean;
  line?: boolean;
  jwt?: boolean;
  oidc?: string[];
  captcha?: {
    enabled?: boolean;
    provider?: "turnstile" | "hcaptcha";
    siteKey?: string;
    requiredFor?: Array<"email_otp" | "sms_otp">;
  };
  /** List of all enabled OAuth provider names */
  oauth: string[];
  disabled?: string[];
}

// ─── Multi-tenant types ───────────────────────────────────────────────────────

/** A user's membership in a tenant/app. */
export interface StewardTenantMembership {
  tenantId: string;
  tenantName: string;
  role: string;
  joinedAt: string;
}

/** Tenant info (from admin/discovery endpoints). */
export interface StewardTenantInfo {
  id: string;
  name: string;
  joinMode: "open" | "invite" | "closed";
  memberCount?: number;
}
