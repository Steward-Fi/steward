import {
  buildExpiredRefreshCookie,
  forwardToApi,
  hasProxyHeader,
  isHttpsRequest,
  proxyJson,
  readRefreshCookie,
} from "@/lib/auth-proxy";

/**
 * Session revoke proxy (SEC-018).
 *
 * Forwards the cookie-held refresh token to the Steward API `/auth/revoke`
 * (single-device sign out) and always expires the local cookie — revocation
 * is best-effort upstream, but the browser must not retain a usable token.
 */
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  if (!hasProxyHeader(request)) {
    return proxyJson({ ok: false, error: "Forbidden" }, 403);
  }
  const secure = isHttpsRequest(request);
  const clearCookie = { "Set-Cookie": buildExpiredRefreshCookie(secure) };
  const refreshToken = readRefreshCookie(request);
  if (!refreshToken) {
    return proxyJson({ ok: true }, 200, clearCookie);
  }

  try {
    const upstream = await forwardToApi("/auth/revoke", { refreshToken });
    return proxyJson(upstream.json ?? { ok: true }, upstream.status, clearCookie);
  } catch {
    return proxyJson({ ok: true }, 200, clearCookie);
  }
}
