import { afterEach, describe, expect, test } from "bun:test";
import { buildCsp } from "@/lib/csp";

/**
 * SEC-077: connect-src must be an explicit allowlist. The previous blanket
 * `https: wss:` let any injected script exfiltrate data to an arbitrary origin.
 */

function connectSrc(csp: string): string[] {
  const directive = csp.split("; ").find((d) => d.startsWith("connect-src "));
  if (!directive) throw new Error("connect-src directive missing");
  return directive.slice("connect-src ".length).split(" ");
}

function imgSrc(csp: string): string[] {
  const directive = csp.split("; ").find((d) => d.startsWith("img-src "));
  if (!directive) throw new Error("img-src directive missing");
  return directive.slice("img-src ".length).split(" ");
}

describe("CSP connect-src allowlist (SEC-077)", () => {
  afterEach(() => {
    delete process.env.NEXT_PUBLIC_SOLANA_RPC_URL;
    delete process.env.NEXT_PUBLIC_STEWARD_API_URL;
  });

  test("no longer permits arbitrary https/wss origins", () => {
    const sources = connectSrc(buildCsp("nonce", false));
    expect(sources).not.toContain("https:");
    expect(sources).not.toContain("wss:");
  });

  test("allowlists self, the configured API origin, and the Solana RPC (https + ws)", () => {
    const sources = connectSrc(buildCsp("nonce", false));
    expect(sources).toContain("'self'");
    // Default self-host API origin (steward-api-url.ts fallback).
    expect(sources).toContain("http://localhost:3200");
    expect(sources).toContain("https://api.mainnet-beta.solana.com");
    expect(sources).toContain("wss://api.mainnet-beta.solana.com");
  });

  test("allowlists a configured https API origin", () => {
    process.env.NEXT_PUBLIC_STEWARD_API_URL = "https://api.steward.example";
    const sources = connectSrc(buildCsp("nonce", false));
    expect(sources).toContain("https://api.steward.example");
    expect(sources).not.toContain("http://localhost:3200");
  });

  test("honors a custom NEXT_PUBLIC_SOLANA_RPC_URL", () => {
    process.env.NEXT_PUBLIC_SOLANA_RPC_URL = "https://solana-rpc.example.com/path";
    const sources = connectSrc(buildCsp("nonce", false));
    expect(sources).toContain("https://solana-rpc.example.com");
    expect(sources).toContain("wss://solana-rpc.example.com");
    expect(sources).not.toContain("https://api.mainnet-beta.solana.com");
  });

  test("allowlists the EVM chain RPCs, WalletConnect, and Coinbase origins the dapp uses", () => {
    const sources = connectSrc(buildCsp("nonce", false));
    for (const origin of [
      "https://eth.merkle.io",
      "https://mainnet.base.org",
      "https://polygon-rpc.com",
      "https://rpc.gnosischain.com",
      "https://mainnet.optimism.io",
      "https://arb1.arbitrum.io",
      "https://rpc.ankr.com",
      "https://api.web3modal.org",
      "https://*.walletconnect.com",
      "https://*.walletconnect.org",
      "wss://*.walletconnect.com",
      "wss://*.walletconnect.org",
      "https://keys.coinbase.com",
      "https://rpc.wallet.coinbase.com",
      "https://www.walletlink.org",
    ]) {
      expect(sources).toContain(origin);
    }
    // RainbowKit disables Coinbase's optional analytics. Keep the CSP narrow
    // instead of permitting an endpoint this app never calls.
    expect(sources).not.toContain("https://cca-lite.coinbase.com");
  });

  test("keeps HTTPS enforcement on for an https API and off only for loopback/e2e", () => {
    process.env.NEXT_PUBLIC_STEWARD_API_URL = "https://api.steward.example";
    expect(buildCsp("nonce", false)).toContain("upgrade-insecure-requests");
    expect(buildCsp("nonce", true)).not.toContain("upgrade-insecure-requests");
    // Loopback http API (self-host default): upgrade would break the plain-http
    // API origin, so it is deliberately omitted for that configuration only.
    delete process.env.NEXT_PUBLIC_STEWARD_API_URL;
    expect(buildCsp("nonce", false)).not.toContain("upgrade-insecure-requests");
  });
});

describe("CSP img-src (SEC-077 residual channel)", () => {
  test("keeps only the documented tenant-logo exception — never a full wildcard or plain http", () => {
    // Tenant theme logos/favicons are operator-supplied URLs on arbitrary
    // https origins, so `https:` cannot be dropped without breaking tenant
    // branding (documented at the directive in csp.ts). What must never
    // regress: a bare `*` or plain `http:` source, which would widen the
    // residual GET-only beacon channel beyond encrypted origins.
    const sources = imgSrc(buildCsp("nonce", false));
    expect(sources).toEqual(["'self'", "data:", "blob:", "https:"]);
    expect(sources).not.toContain("*");
    expect(sources).not.toContain("http:");
  });
});
