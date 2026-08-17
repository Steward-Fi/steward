import { DEFAULT_STEWARD_API_URL } from "@/lib/steward-api-url";

/**
 * Same-origin auth proxy (BFF) helpers — SEC-018.
 *
 * The dashboard keeps the long-lived Steward refresh token in an HttpOnly,
 * SameSite=Strict cookie that page JavaScript cannot read, instead of
 * `window.sessionStorage`. The SDK's auth client (see `authProxyUrl` in
 * `@stwd/sdk`) talks to the route handlers under `app/api/auth/`:
 *
 *   POST /api/auth/session  — deposit a freshly issued refresh token (sets cookie)
 *   DELETE /api/auth/session — clear the cookie (sign-out)
 *   POST /api/auth/refresh  — exchange the cookie-held token at the Steward API,
 *                             rotate the cookie, return only the access token
 *   POST /api/auth/revoke   — revoke the cookie-held token at the Steward API
 *
 * CSRF posture: the cookie is SameSite=Strict, so browsers never send it on
 * cross-site requests; every handler additionally requires a custom header
 * (`x-steward-auth-proxy`) that cross-site forms/fetches cannot set without a
 * CORS preflight.
 */

export const REFRESH_COOKIE_NAME = "steward_rt";
export const REFRESH_COOKIE_PATH = "/api/auth";
export const AUTH_PROXY_HEADER = "x-steward-auth-proxy";
export const AUTH_PROXY_HEADER_VALUE = "1";

/** Cap on cookie lifetime; the API-side refresh token expires well before this. */
const REFRESH_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60; // 30 days

/** Sanity bound so a malformed deposit cannot write an oversized cookie. */
const MAX_REFRESH_TOKEN_LENGTH = 8192;

function cookieAttributes(secure: boolean): string {
  return `Path=${REFRESH_COOKIE_PATH}; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}`;
}

/**
 * Serialize the refresh-token cookie. `Secure` is set whenever this app is
 * itself served over HTTPS; it is omitted on the plain-http local e2e/dev
 * origin, which browsers would otherwise reject.
 */
export function buildRefreshCookie(refreshToken: string, secure: boolean): string {
  return `${REFRESH_COOKIE_NAME}=${encodeURIComponent(refreshToken)}; ${cookieAttributes(secure)}; Max-Age=${REFRESH_COOKIE_MAX_AGE_SECONDS}`;
}

/** Serialize an immediately-expiring cookie (sign-out / failed refresh). */
export function buildExpiredRefreshCookie(secure: boolean): string {
  return `${REFRESH_COOKIE_NAME}=; ${cookieAttributes(secure)}; Max-Age=0`;
}

/** Extract the refresh token from a request's Cookie header, or null. */
export function readRefreshCookie(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === REFRESH_COOKIE_NAME) {
      const value = part.slice(eq + 1).trim();
      if (!value) return null;
      try {
        return decodeURIComponent(value);
      } catch {
        return null;
      }
    }
  }
  return null;
}

/** True when the request carries the SDK's custom proxy header (CSRF check). */
export function hasProxyHeader(request: Request): boolean {
  return request.headers.get(AUTH_PROXY_HEADER) === AUTH_PROXY_HEADER_VALUE;
}

/** JSON response that is never cached (auth material must not be stored). */
export function proxyJson(
  body: Record<string, unknown>,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

export function isHttpsRequest(request: Request): boolean {
  try {
    return new URL(request.url).protocol === "https:";
  } catch {
    return false;
  }
}

/** Validate + normalize a deposited refresh token. Returns null when invalid. */
export function normalizeRefreshToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_REFRESH_TOKEN_LENGTH) return null;
  return value;
}

/**
 * Forward a JSON payload to the Steward API from the server side. Returns the
 * upstream status and parsed body (or null when the body is not JSON).
 */
export async function forwardToApi(
  path: string,
  payload: Record<string, unknown>,
): Promise<{ status: number; json: Record<string, unknown> | null }> {
  // Resolved per call: route handlers run server-side, where the env var is
  // available at request time (and tests can point it at a stub server).
  const apiBase = (process.env.NEXT_PUBLIC_STEWARD_API_URL || DEFAULT_STEWARD_API_URL).replace(
    /\/+$/,
    "",
  );
  const response = await fetch(`${apiBase}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let json: Record<string, unknown> | null = null;
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json };
}
