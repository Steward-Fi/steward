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
const AUTH_UPSTREAM_TIMEOUT_MS = 10_000;
const AUTH_UPSTREAM_MAX_BYTES = 1024 * 1024;

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
    const url = new URL(request.url);
    if (url.protocol === "https:") return true;
    // Local test/dev origins need a non-Secure cookie. Everywhere else in a
    // production build, require Secure even if a reverse proxy presented an
    // internal http URL; omitting it would silently weaken browser custody.
    const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const loopback = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
    return process.env.NODE_ENV === "production" && !loopback;
  } catch {
    return process.env.NODE_ENV === "production";
  }
}

/** Validate + normalize a deposited refresh token. Returns null when invalid. */
export function normalizeRefreshToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_REFRESH_TOKEN_LENGTH) return null;
  return value;
}

/**
 * Accept only the compact-JWT shape Steward issues for browser access tokens.
 * The proxy is not a verifier, but this prevents a malformed upstream response
 * from reflecting either submitted refresh token into browser-visible JSON.
 */
export function normalizeAccessToken(
  value: unknown,
  forbiddenTokens: readonly (string | null)[] = [],
): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_REFRESH_TOKEN_LENGTH) {
    return null;
  }
  if (forbiddenTokens.includes(value)) return null;
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value) ? value : null;
}

/**
 * Forward a JSON payload to the Steward API from the server side. Returns the
 * upstream status and parsed body (or null when the body is not JSON).
 */
export async function forwardToApi(
  path: string,
  payload: Record<string, unknown>,
  limits: { timeoutMs?: number; maxBytes?: number } = {},
): Promise<{ status: number; json: Record<string, unknown> | null }> {
  // Resolved per call: route handlers run server-side, where the env var is
  // available at request time (and tests can point it at a stub server).
  const apiBase = (process.env.NEXT_PUBLIC_STEWARD_API_URL || DEFAULT_STEWARD_API_URL).replace(
    /\/+$/,
    "",
  );
  const timeoutMs = limits.timeoutMs ?? AUTH_UPSTREAM_TIMEOUT_MS;
  const maxBytes = limits.maxBytes ?? AUTH_UPSTREAM_MAX_BYTES;
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${apiBase}${path}`, {
      method: "POST",
      // A 307/308 would otherwise replay the refresh-token-bearing POST body to
      // the redirect target. The configured Steward origin is the only trusted
      // recipient, so redirects are always a hard failure at this boundary.
      redirect: "error",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });

    const declaredLength = response.headers.get("content-length");
    if (declaredLength && /^\d+$/.test(declaredLength)) {
      const bytes = Number(declaredLength);
      if (!Number.isSafeInteger(bytes) || bytes > maxBytes) {
        controller.abort();
        throw new Error("Steward API response is too large");
      }
    }

    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          controller.abort();
          throw new Error("Steward API response is too large");
        }
        chunks.push(value);
      }
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder().decode(body);
    let json: Record<string, unknown> | null = null;
    try {
      json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
    } catch {
      json = null;
    }
    return { status: response.status, json };
  } finally {
    clearTimeout(deadline);
  }
}
