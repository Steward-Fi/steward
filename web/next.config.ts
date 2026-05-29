import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const configDir = path.dirname(fileURLToPath(import.meta.url));

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
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
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
