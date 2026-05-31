import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const configDir = path.dirname(fileURLToPath(import.meta.url));

// HSTS (HTTPS enforcement) is ON by default and MUST stay on in production.
// The local e2e harness serves the app over plain http://localhost, where
// WebKit honors HSTS and upgrades same-origin asset requests to https:// — which
// the http-only dev server cannot answer, blanking the page. This flag is an
// explicit, secure-by-default opt-OUT set ONLY by that harness; absent the flag,
// full enforcement applies, so production is never weakened.
const ALLOW_INSECURE_HTTP = process.env.STEWARD_ALLOW_INSECURE_HTTP === "true";

/** Security headers applied to static assets. Page CSP is nonce-based in middleware. */
const SECURITY_HEADERS = [
  // X-Frame-Options is the legacy companion to frame-ancestors for old browsers.
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // 2 years, include subdomains, eligible for preload list.
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  // Lock down powerful features the dapp does not use.
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()",
  },
];

const config: NextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: path.resolve(configDir, ".."),
  transpilePackages: ["@stwd/sdk", "@stwd/shared", "@stwd/react", "@simplewebauthn/browser"],
  async headers() {
    const headers = ALLOW_INSECURE_HTTP
      ? SECURITY_HEADERS.filter((h) => h.key !== "Strict-Transport-Security")
      : SECURITY_HEADERS;
    return [
      {
        source: "/:path*",
        headers,
      },
    ];
  },
  webpack: (config) => {
    config.resolve.fallback = {
      ...config.resolve.fallback,
      "pino-pretty": false,
      "@react-native-async-storage/async-storage": false,
    };
    return config;
  },
};

export default config;
