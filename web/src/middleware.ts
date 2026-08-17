import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { buildCsp } from "@/lib/csp";

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
// applies, so production is never weakened. The E2E_ prefix marks it test-only:
// the production deploy pipeline (cf:build/cf:deploy) refuses to run with it
// set (see scripts/assert-production-deploy-env.mjs).
const ALLOW_INSECURE_HTTP = process.env.E2E_ALLOW_INSECURE_HTTP === "true";

function makeNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export function middleware(request: NextRequest) {
  const nonce = makeNonce();
  const csp = buildCsp(nonce, ALLOW_INSECURE_HTTP);
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
