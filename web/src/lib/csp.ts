import { DEFAULT_STEWARD_API_URL } from "@/lib/steward-api-url";

/**
 * Content-Security-Policy construction (extracted from middleware.ts so it can
 * be unit-tested without importing `next/server`).
 *
 * SEC-077: `connect-src` is an explicit allowlist instead of the previous
 * blanket `https: wss:`, which let any injected script exfiltrate data to any
 * origin — undermining the CSP's role as the primary XSS mitigation for the
 * tokens the dashboard handles. The list covers exactly what the wallet dapp
 * needs:
 *   - 'self' (same-origin API proxy routes, Next data fetches, dev HMR)
 *   - the configured Steward API origin
 *   - the configured Solana RPC origin (https + its websocket form)
 *   - the default public RPC endpoints of the EVM chains wired in lib/wagmi.ts
 *   - WalletConnect relay/verify/push origins (wildcards cover relay., echo.,
 *     pulse., keys., verify. on both .com and .org)
 *   - Coinbase Wallet's popup origin
 * Self-hosters overriding RPC endpoints via NEXT_PUBLIC_SOLANA_RPC_URL stay
 * allowlisted automatically; a custom EVM RPC must be added here when wired.
 */

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

const DEFAULT_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";

/** Default viem RPC origins for the chains configured in lib/wagmi.ts. */
const EVM_RPC_ORIGINS = [
  "https://eth.merkle.io", // mainnet
  "https://mainnet.base.org", // base
  "https://polygon-rpc.com", // polygon
  "https://rpc.gnosischain.com", // gnosis
  "https://mainnet.optimism.io", // optimism
  "https://arb1.arbitrum.io", // arbitrum
  "https://rpc.ankr.com", // bsc
] as const;

const WALLETCONNECT_ORIGINS = [
  "https://*.walletconnect.com",
  "https://*.walletconnect.org",
  "wss://*.walletconnect.com",
  "wss://*.walletconnect.org",
] as const;

const WALLET_SDK_ORIGINS = ["https://www.coinbase.com"] as const;

// Resolve the Steward API origin the client will actually call. This uses the
// SAME resolved base URL as `lib/api.ts` / providers (env override or the
// self-host default from `lib/steward-api-url.ts`), so the CSP `connect-src`
// allowlist stays in sync with the request origin. Read per call so middleware
// reflects the runtime environment.
function configuredApiUrl(): URL | null {
  try {
    return new URL(process.env.NEXT_PUBLIC_STEWARD_API_URL || DEFAULT_STEWARD_API_URL);
  } catch {
    return null;
  }
}

// An http origin on a loopback host (the self-host local-dev default,
// http://localhost:3200) is legitimate and cannot be served over https by the
// plain-http compose API. Detecting it lets us keep the CSP `connect-src`
// allowlist correct AND skip `upgrade-insecure-requests` for that origin only,
// without weakening production (a real deployment sets NEXT_PUBLIC_STEWARD_API_URL
// to an https origin, so the upgrade stays fully enforced there).
export function isLoopbackHttp(url: URL | null): boolean {
  return !!url && url.protocol === "http:" && LOOPBACK_HOSTNAMES.has(url.hostname);
}

function solanaRpcOrigin(): string {
  return process.env.NEXT_PUBLIC_SOLANA_RPC_URL || DEFAULT_SOLANA_RPC_URL;
}

/** Map an https?:// origin to its websocket equivalent for connect-src. */
function websocketOrigin(origin: string): string | null {
  if (origin.startsWith("https://")) return `wss://${origin.slice("https://".length)}`;
  if (origin.startsWith("http://")) return `ws://${origin.slice("http://".length)}`;
  return null;
}

function buildConnectSrc(apiOrigin: string | null): string[] {
  const connectSrc = new Set<string>(["'self'"]);
  if (apiOrigin) connectSrc.add(apiOrigin);
  try {
    // @solana/web3.js also opens a websocket to the RPC host for subscriptions.
    const solanaOrigin = new URL(solanaRpcOrigin()).origin;
    connectSrc.add(solanaOrigin);
    const ws = websocketOrigin(solanaOrigin);
    if (ws) connectSrc.add(ws);
  } catch {
    connectSrc.add(new URL(DEFAULT_SOLANA_RPC_URL).origin);
  }
  for (const origin of EVM_RPC_ORIGINS) connectSrc.add(origin);
  for (const origin of WALLETCONNECT_ORIGINS) connectSrc.add(origin);
  for (const origin of WALLET_SDK_ORIGINS) connectSrc.add(origin);
  return [...connectSrc];
}

export function buildCsp(nonce: string, allowInsecureHttp: boolean): string {
  const apiUrl = configuredApiUrl();
  const apiOrigin = apiUrl?.origin ?? null;
  const connectSrc = buildConnectSrc(apiOrigin);

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
  // over plain http for local e2e (allowInsecureHttp) or when the configured
  // API is an http loopback origin (the self-host local-dev default). In both
  // cases upgrade-insecure-requests would break same-origin/localhost calls the
  // plain-http server cannot answer. Production points at an https API origin,
  // so the upgrade stays fully enforced there.
  if (!allowInsecureHttp && !isLoopbackHttp(apiUrl)) {
    directives.push("upgrade-insecure-requests");
  }
  return directives.join("; ");
}
