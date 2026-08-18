import {
  AuthProxyRequestError,
  buildExpiredRefreshCookie,
  buildRefreshCookie,
  hasProxyHeader,
  isHttpsRequest,
  normalizeRefreshToken,
  proxyJson,
  readBoundedJsonObject,
} from "@/lib/auth-proxy";

/**
 * Refresh-token custody endpoint (SEC-018).
 *
 * POST   { refreshToken } — store the token in an HttpOnly, SameSite=Strict
 *         cookie after sign-in. The token never persists in JS-readable storage.
 * DELETE  — expire the cookie (sign-out / session invalidation).
 *
 * Both require the SDK's custom proxy header; the SameSite=Strict cookie is
 * never sent cross-site, and these routes accept no cross-origin callers.
 */
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  if (!hasProxyHeader(request)) {
    return proxyJson({ ok: false, error: "Forbidden" }, 403);
  }
  let body: Record<string, unknown>;
  try {
    body = await readBoundedJsonObject(request);
  } catch (error) {
    const status = error instanceof AuthProxyRequestError ? error.status : 400;
    return proxyJson(
      { ok: false, error: status === 413 ? "Request body is too large" : "Invalid JSON body" },
      status,
    );
  }
  const refreshToken = normalizeRefreshToken(body.refreshToken);
  if (!refreshToken) {
    return proxyJson({ ok: false, error: "refreshToken is required" }, 400);
  }
  return proxyJson({ ok: true }, 200, {
    "Set-Cookie": buildRefreshCookie(refreshToken, isHttpsRequest(request)),
  });
}

export async function DELETE(request: Request): Promise<Response> {
  if (!hasProxyHeader(request)) {
    return proxyJson({ ok: false, error: "Forbidden" }, 403);
  }
  return proxyJson({ ok: true }, 200, {
    "Set-Cookie": buildExpiredRefreshCookie(isHttpsRequest(request)),
  });
}
