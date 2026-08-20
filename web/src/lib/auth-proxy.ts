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

export const REFRESH_COOKIE_NAME = "__Host-steward_rt";
export const DEV_REFRESH_COOKIE_NAME = "steward_rt";
export const REFRESH_COOKIE_PATH = "/api/auth";
export const AUTH_PROXY_HEADER = "x-steward-auth-proxy";
export const AUTH_PROXY_HEADER_VALUE = "1";

/** Cap on cookie lifetime; the API-side refresh token expires well before this. */
const REFRESH_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60; // 30 days

/** Sanity bound so a malformed deposit cannot write an oversized cookie. */
const MAX_REFRESH_TOKEN_LENGTH = 8192;
const AUTH_PROXY_REQUEST_MAX_BYTES = 16 * 1024;
const AUTH_UPSTREAM_TIMEOUT_MS = 10_000;
const AUTH_UPSTREAM_MAX_BYTES = 1024 * 1024;

function cookieAttributes(secure: boolean): string {
  // __Host- forbids Domain cookies and therefore closes sibling-subdomain
  // cookie tossing/session fixation. Browsers require Path=/ + Secure for that
  // prefix; plain-http loopback development uses the legacy scoped name.
  return `Path=${secure ? "/" : REFRESH_COOKIE_PATH}; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}`;
}

function refreshCookieName(secure: boolean): string {
  return secure ? REFRESH_COOKIE_NAME : DEV_REFRESH_COOKIE_NAME;
}

/**
 * Serialize the refresh-token cookie. `Secure` is set whenever this app is
 * itself served over HTTPS; it is omitted on the plain-http local e2e/dev
 * origin, which browsers would otherwise reject.
 */
export function buildRefreshCookie(refreshToken: string, secure: boolean): string {
  return `${refreshCookieName(secure)}=${encodeURIComponent(refreshToken)}; ${cookieAttributes(secure)}; Max-Age=${REFRESH_COOKIE_MAX_AGE_SECONDS}`;
}

/** Serialize an immediately-expiring cookie (sign-out / failed refresh). */
export function buildExpiredRefreshCookie(secure: boolean): string {
  return `${refreshCookieName(secure)}=; ${cookieAttributes(secure)}; Max-Age=0`;
}

/** Extract the refresh token from a request's Cookie header, or null. */
export function readRefreshCookie(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  const expectedName = refreshCookieName(isHttpsRequest(request));
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === expectedName) {
      const value = part.slice(eq + 1).trim();
      if (!value) return null;
      try {
        return normalizeRefreshToken(decodeURIComponent(value));
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
      Pragma: "no-cache",
      Expires: "0",
      "X-Content-Type-Options": "nosniff",
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

export class AuthProxyRequestError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 413,
  ) {
    super(message);
  }
}

/** Parse a small JSON object without allowing chunked request-body memory DoS. */
export async function readBoundedJsonObject(request: Request): Promise<Record<string, unknown>> {
  if (!request.body) return {};
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new AuthProxyRequestError("Content-Type must be application/json", 400);
  }
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) throw new AuthProxyRequestError("Invalid Content-Length", 400);
    const bytes = Number(declared);
    if (!Number.isSafeInteger(bytes) || bytes > AUTH_PROXY_REQUEST_MAX_BYTES) {
      throw new AuthProxyRequestError("Request body is too large", 413);
    }
  }
  const encoding = request.headers.get("content-encoding");
  if (encoding && encoding.toLowerCase() !== "identity") {
    throw new AuthProxyRequestError("Encoded request bodies are not accepted", 400);
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > AUTH_PROXY_REQUEST_MAX_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new AuthProxyRequestError("Request body is too large", 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new AuthProxyRequestError("Invalid JSON body", 400);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AuthProxyRequestError("JSON body must be an object", 400);
  }
  return parsed as Record<string, unknown>;
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
  path: "/auth/refresh" | "/auth/revoke",
  payload: Record<string, unknown>,
  limits: { timeoutMs?: number; maxBytes?: number } = {},
): Promise<{ status: number; json: Record<string, unknown> | null }> {
  // Resolved per call: route handlers run server-side, where the env var is
  // available at request time (and tests can point it at a stub server).
  const rawApiBase = process.env.NEXT_PUBLIC_STEWARD_API_URL || DEFAULT_STEWARD_API_URL;
  const parsedApiBase = new URL(rawApiBase);
  if (
    !["http:", "https:"].includes(parsedApiBase.protocol) ||
    parsedApiBase.username ||
    parsedApiBase.password ||
    parsedApiBase.search ||
    parsedApiBase.hash
  ) {
    throw new Error("Steward API URL must be an absolute credential-free HTTP(S) URL");
  }
  const apiHostname = parsedApiBase.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const loopback =
    apiHostname === "localhost" || apiHostname === "127.0.0.1" || apiHostname === "::1";
  if (process.env.NODE_ENV === "production" && parsedApiBase.protocol !== "https:" && !loopback) {
    throw new Error("Steward API URL must use HTTPS in production");
  }
  const apiBase = parsedApiBase.toString().replace(/\/+$/, "");
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
