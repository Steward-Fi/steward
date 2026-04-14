/**
 * auth-api.ts — Client-side helpers for passkey and email magic-link auth.
 *
 * Uses @simplewebauthn/browser v13 for WebAuthn interactions.
 * All network calls go to the API server (NEXT_PUBLIC_STEWARD_API_URL).
 */

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";

import { API_URL } from "@/lib/api";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  email: string;
}

export interface AuthResult {
  token: string;
  user: AuthUser;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function apiPost<T = unknown>(
  path: string,
  body: unknown,
): Promise<{ ok: true; data: T } | { ok: false; error: string }> {
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  // Normalize: some endpoints return { ok, token, user } (flat)
  // while others return { ok, data: { ... } } (nested).
  // Wrap flat responses into { ok, data } for consistent access.
  if (json.ok && !json.data && !json.error) {
    const { ok, ...rest } = json;
    return { ok: true, data: rest as T };
  }
  return json;
}

// ─── Passkey ──────────────────────────────────────────────────────────────────

/**
 * Fetch WebAuthn registration options for the given email.
 * Lazily creates the user record on the server if needed.
 */
async function getPasskeyRegisterOptions(email: string) {
  const res = await fetch(`${API_URL}/auth/passkey/register/options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const json = await res.json();
  // This endpoint returns raw WebAuthn options (no ok wrapper) on success,
  // or { ok: false, error } on failure
  if (json.ok === false) throw new Error(json.error || "Failed to get registration options");
  return json;
}

/**
 * Fetch WebAuthn authentication options for the given email.
 * Returns `allowCredentials` if the user has registered passkeys.
 */
async function getPasskeyLoginOptions(email: string) {
  const res = await fetch(`${API_URL}/auth/passkey/login/options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const json = await res.json();
  if (json.ok === false) throw new Error(json.error || "Failed to get login options");
  return json as {
    allowCredentials?: Array<{ id: string }>;
    [key: string]: unknown;
  };
}

async function verifyPasskeyRegistration(email: string, response: unknown): Promise<AuthResult> {
  const result = await apiPost<AuthResult>("/auth/passkey/register/verify", {
    email,
    response,
  });
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

async function verifyPasskeyLogin(email: string, response: unknown): Promise<AuthResult> {
  const result = await apiPost<AuthResult>("/auth/passkey/login/verify", {
    email,
    response,
  });
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

/**
 * Smart passkey flow:
 *  - If the user already has registered passkeys → authentication
 *  - If the user has no passkeys (or is new) → registration
 *
 * The browser handles the biometric/PIN prompt automatically.
 */
export async function signInWithPasskey(email: string): Promise<AuthResult> {
  // Try authentication first (existing user with passkeys)
  let authOpts: {
    allowCredentials?: Array<{ id: string }>;
    [key: string]: unknown;
  } | null = null;
  try {
    authOpts = await getPasskeyLoginOptions(email);
  } catch {
    // User doesn't exist or has no passkeys — fall through to registration
    authOpts = null;
  }

  const hasCredentials =
    authOpts !== null &&
    Array.isArray(authOpts.allowCredentials) &&
    authOpts.allowCredentials.length > 0;

  if (hasCredentials && authOpts) {
    // ── Existing passkey — authenticate ──────────────────────────────────
    const authResponse = await startAuthentication({
      optionsJSON: authOpts as unknown as Parameters<typeof startAuthentication>[0]["optionsJSON"],
    });
    return verifyPasskeyLogin(email, authResponse);
  } else {
    // ── New passkey — register ────────────────────────────────────────────
    const regOpts = await getPasskeyRegisterOptions(email);
    const regResponse = await startRegistration({
      optionsJSON: regOpts as unknown as Parameters<typeof startRegistration>[0]["optionsJSON"],
    });
    return verifyPasskeyRegistration(email, regResponse);
  }
}

// ─── Email magic link ─────────────────────────────────────────────────────────

/**
 * Send a magic link to the given email address.
 * Returns the expiry time so the UI can show a countdown.
 */
export async function sendMagicLink(email: string): Promise<{ ok: boolean; expiresAt?: string }> {
  const result = await apiPost<{ expiresAt: string }>("/auth/email/send", {
    email,
  });
  if (!result.ok) throw new Error(result.error);
  return { ok: true, expiresAt: result.data.expiresAt };
}

/**
 * Verify the raw token from the magic link URL.
 * Called by the /auth/callback/email page after the user clicks the link.
 */
export async function verifyMagicLink(token: string, email: string): Promise<AuthResult> {
  const result = await apiPost<AuthResult>("/auth/email/verify", {
    token,
    email,
  });
  if (!result.ok) throw new Error(result.error);
  return result.data;
}
