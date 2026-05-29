import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const configDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * Content-Security-Policy for the Steward web app.
 *
 * The app is a wallet dapp that uses wagmi + RainbowKit + WalletConnect for EVM,
 * @solana/* for Solana, and talks to the Steward control-plane API. The CSP is
 * locked down hard on script/object/base while staying permissive enough on
 * connect-src / frame-src to keep wallet flows working.
 *
 * Per-directive rationale:
 *  - default-src 'self'            — deny by default; everything must opt in below.
 *  - script-src 'self'             — PRIMARY XSS mitigation. Only first-party
 *      JS runs. 'wasm-unsafe-eval' is allowed because some wallet/crypto libs
 *      (WalletConnect, Solana) instantiate WebAssembly. No 'unsafe-inline' and
 *      no remote script origins — injected/3rd-party script cannot execute.
 *  - style-src 'self' 'unsafe-inline' — Next.js and RainbowKit inject inline
 *      styles; 'unsafe-inline' for styles is low risk (no script execution).
 *  - img-src 'self' data: blob: https: — wallet/token icons come from many
 *      CDNs (RainbowKit, WalletConnect explorer, token lists); data:/blob: for
 *      generated avatars/QR codes.
 *  - font-src 'self' data:         — self-hosted fonts + inlined data: fonts.
 *  - connect-src 'self' https: wss: — XHR/fetch/WebSocket targets. A wallet
 *      dapp legitimately talks to: the Steward API (api.steward.fi or a
 *      self-hosted control plane), the WalletConnect relay (wss://relay.
 *      walletconnect.{com,org}) + HTTP services, and many EVM/Solana JSON-RPC
 *      endpoints (wagmi http() default public RPCs per chain + the Solana RPC,
 *      both env-configurable). Enumerating every RPC host would silently break
 *      wallets whenever a default RPC changes, so connect is allowed over any
 *      https:/wss: origin. This is the deliberate strict-script / functional-
 *      connect tradeoff: script execution stays first-party-only while network
 *      egress (which cannot by itself run code) stays broad enough for wallets.
 *  - frame-src ...walletconnect... — the WalletConnect "verify" iframe and the
 *      RainbowKit/WC modal embed walletconnect.{com,org} frames.
 *  - frame-ancestors 'none'        — this app may not be framed (clickjacking).
 *  - object-src 'none' / base-uri 'self' — block plugins and <base> hijacking.
 *  - form-action 'self'            — forms can only post to first party.
 *  - upgrade-insecure-requests     — force https for any stray http subresource.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https: wss:",
  "frame-src 'self' https://verify.walletconnect.com https://verify.walletconnect.org https://*.walletconnect.com https://*.walletconnect.org",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "upgrade-insecure-requests",
].join("; ");

/**
 * Security headers applied to every route. Mirrored in vercel.json so they also
 * apply on the Vercel production edge (next.config headers() apply to the
 * Next.js server; vercel.json ensures parity for statically-served paths).
 */
const SECURITY_HEADERS = [
  { key: "Content-Security-Policy", value: CSP },
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
