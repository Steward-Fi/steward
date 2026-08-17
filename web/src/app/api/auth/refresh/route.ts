import {
  buildExpiredRefreshCookie,
  buildRefreshCookie,
  forwardToApi,
  hasProxyHeader,
  isHttpsRequest,
  normalizeRefreshToken,
  proxyJson,
  readRefreshCookie,
} from "@/lib/auth-proxy";

/**
 * Session refresh proxy (SEC-018).
 *
 * Reads the HttpOnly refresh cookie, forwards it to the Steward API
 * `/auth/refresh` (optionally with a tenantId for tenant switching), rotates
 * the cookie from the API response, and returns only the short-lived access
 * token to the browser. The rotated refresh token never reaches JS.
 *
 * Fails closed: a missing cookie or an upstream 401 clears the cookie so the
 * client drops the session instead of retrying a dead token.
 */
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  if (!hasProxyHeader(request)) {
    return proxyJson({ ok: false, error: "Forbidden" }, 403);
  }
  const secure = isHttpsRequest(request);
  const refreshToken = readRefreshCookie(request);
  if (!refreshToken) {
    return proxyJson({ ok: false, error: "No refresh session" }, 401, {
      "Set-Cookie": buildExpiredRefreshCookie(secure),
    });
  }

  let tenantId: string | undefined;
  try {
    const body = (await request.json()) as { tenantId?: unknown } | null;
    if (typeof body?.tenantId === "string" && body.tenantId.length > 0) {
      tenantId = body.tenantId;
    }
  } catch {
    // Empty / non-JSON body is fine — tenantId is optional.
  }

  let upstream: Awaited<ReturnType<typeof forwardToApi>>;
  try {
    upstream = await forwardToApi("/auth/refresh", {
      refreshToken,
      ...(tenantId ? { tenantId } : {}),
    });
  } catch {
    return proxyJson({ ok: false, error: "Steward API unreachable" }, 502);
  }

  if (upstream.status === 401 || upstream.status === 403) {
    // The refresh token is dead — drop the cookie so the client signs out.
    return proxyJson(
      {
        ok: false,
        error:
          typeof upstream.json?.error === "string"
            ? upstream.json.error
            : "Refresh session rejected",
      },
      upstream.status,
      { "Set-Cookie": buildExpiredRefreshCookie(secure) },
    );
  }
  if (upstream.status !== 200 || !upstream.json || upstream.json.ok !== true) {
    return proxyJson(
      {
        ok: false,
        error: typeof upstream.json?.error === "string" ? upstream.json.error : "Refresh failed",
      },
      upstream.status >= 400 && upstream.status <= 599 ? upstream.status : 502,
    );
  }

  const rotatedToken = normalizeRefreshToken(upstream.json.refreshToken);
  const accessToken =
    typeof upstream.json.token === "string" && upstream.json.token.length > 0
      ? upstream.json.token
      : null;
  const expiresIn = upstream.json.expiresIn;
  if (
    !rotatedToken ||
    !accessToken ||
    typeof expiresIn !== "number" ||
    !Number.isFinite(expiresIn)
  ) {
    // Whitelist the exact upstream success contract. Besides failing closed on
    // malformed responses, this prevents an upstream reflection from putting
    // refresh-token material into any browser-visible response field.
    return proxyJson({ ok: false, error: "Malformed refresh response" }, 502, {
      "Set-Cookie": buildExpiredRefreshCookie(secure),
    });
  }
  return proxyJson({ ok: true, token: accessToken, expiresIn }, 200, {
    "Set-Cookie": buildRefreshCookie(rotatedToken, secure),
  });
}
