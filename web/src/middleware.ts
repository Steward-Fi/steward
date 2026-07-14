import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { STEWARD_API_URL } from "@/lib/steward-api-url";

const SECURITY_HEADERS = [
  ["X-Frame-Options", "DENY"],
  ["X-Content-Type-Options", "nosniff"],
  ["Referrer-Policy", "strict-origin-when-cross-origin"],
  ["Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"],
  [
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()",
  ],
] as const;

// HTTPS enforcement is ON by default and MUST stay on in production. Both HSTS
// and the CSP `upgrade-insecure-requests` directive cause WebKit to upgrade
// same-origin http://localhost asset requests to https:// (which the http-only
// dev server cannot answer). The local e2e harness sets this flag — an explicit,
// secure-by-default opt-OUT — to omit both; absent the flag, full enforcement
// applies, so production is never weakened.
const ALLOW_INSECURE_HTTP = process.env.STEWARD_ALLOW_INSECURE_HTTP === "true";

function makeNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

// Resolve the Steward API origin the client will actually call. This uses the
// SAME resolved base URL as `lib/api.ts` / providers (env override or the
// self-host default from `lib/steward-api-url.ts`), so the CSP `connect-src`
// allowlist stays in sync with the request origin.
function configuredApiUrl(): URL | null {
  try {
    return new URL(STEWARD_API_URL);
  } catch {
    return null;
  }
}

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

// An http origin on a loopback host (the self-host local-dev default,
// http://localhost:3200) is legitimate and cannot be served over https by the
// plain-http compose API. Detecting it lets us keep the CSP `connect-src`
// allowlist correct AND skip `upgrade-insecure-requests` for that origin only,
// without weakening production (a real deployment sets NEXT_PUBLIC_STEWARD_API_URL
// to an https origin, so the upgrade stays fully enforced there).
function isLoopbackHttp(url: URL | null): boolean {
  return !!url && url.protocol === "http:" && LOOPBACK_HOSTNAMES.has(url.hostname);
}

function buildCsp(nonce: string): string {
  const apiUrl = configuredApiUrl();
  const apiOrigin = apiUrl?.origin ?? null;
  const connectSrc = ["'self'", "https:", "wss:"];
  if (apiOrigin) connectSrc.push(apiOrigin);

  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'wasm-unsafe-eval'`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data: https://fonts.gstatic.com",
    `connect-src ${connectSrc.join(" ")}`,
    "frame-src 'self' https://verify.walletconnect.com https://verify.walletconnect.org https://*.walletconnect.com https://*.walletconnect.org",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ];
  // Keep HTTPS enforcement ON everywhere EXCEPT when the app itself is served
  // over plain http for local e2e (ALLOW_INSECURE_HTTP) or when the configured
  // API is an http loopback origin (the self-host local-dev default). In both
  // cases upgrade-insecure-requests would break same-origin/localhost calls the
  // plain-http server cannot answer. Production points at an https API origin,
  // so the upgrade stays fully enforced there.
  if (!ALLOW_INSECURE_HTTP && !isLoopbackHttp(apiUrl)) {
    directives.push("upgrade-insecure-requests");
  }
  return directives.join("; ");
}

export function middleware(request: NextRequest) {
  const nonce = makeNonce();
  const csp = buildCsp(nonce);
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  response.headers.set("Content-Security-Policy", csp);
  for (const [key, value] of SECURITY_HEADERS) {
    if (ALLOW_INSECURE_HTTP && key === "Strict-Transport-Security") continue;
    response.headers.set(key, value);
  }

  return response;
}

export const config = {
  matcher: [
    {
      source:
        "/((?!api|_next/static|_next/image|favicon.ico|icon-192.png|icon-512.png|apple-touch-icon.png|site.webmanifest).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
