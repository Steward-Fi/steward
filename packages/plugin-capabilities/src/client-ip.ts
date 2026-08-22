import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
/**
 * client-ip.ts - best-effort trustworthy client IP for the capability audit
 * trail.
 *
 * Mirrors `@stwd/api`'s `trustedClientIp` (routes/auth.ts); the plugin cannot
 * import the core (circular dependency - the core builds and injects the
 * plugin context), so the same rules are re-implemented here and read the SAME
 * operator env vars:
 *
 * - cf-connecting-ip is honored only when STEWARD_TRUST_CLOUDFLARE=true AND
 *   origin ingress is locked to Cloudflare; otherwise the header is
 *   client-forgeable and ignored.
 * - x-envoy-external-address / x-forwarded-for are consulted only once the
 *   operator opts into a trusted edge via STEWARD_TRUSTED_PROXY_HOPS: the N
 *   trusted proxies APPEND the peer they observed, so the client entry is the
 *   N-th from the RIGHT. The left-most x-forwarded-for entry is
 *   client-supplied and never read.
 * - x-real-ip is deliberately not consulted: no proxy in this topology sets it
 *   authoritatively, so a client-set value would pass through verbatim.
 *
 * Every candidate is validated with isIP (after unambiguous :port stripping).
 * With no trust configured the raw headers are spoofable by any caller, so
 * undefined is returned and the audit row records NULL rather than an
 * attacker-chosen IP (fail closed).
 */

import { isIP } from "node:net";
import type { Context } from "hono";

/**
 * Number of trusted reverse proxies that APPEND to x-forwarded-for before
 * requests reach this process (see the core's auth.ts for the full topology
 * discussion). Unset/invalid means no forwarded header is trusted (safe
 * default); the deprecated STEWARD_TRUST_PROXY_HEADERS=true maps to hops=1.
 */
function trustedProxyHops(): number {
  const raw = runtimeEnvironmentValue("STEWARD_TRUSTED_PROXY_HOPS")?.trim();
  if (raw === undefined || raw === "") {
    return runtimeEnvironmentValue("STEWARD_TRUST_PROXY_HEADERS") === "true" ? 1 : 0;
  }
  // Canonical non-negative integer only: "1.5" must not truncate into trust.
  if (!/^\d+$/.test(raw)) return 0;
  const parsed = Number.parseInt(raw, 10);
  return parsed > 0 && parsed <= 10 ? parsed : 0;
}

/**
 * Normalize one forwarded-address candidate to a bare IP, or undefined.
 * Proxies sometimes forward `ip:port` or `[ipv6]:port`, so the port is
 * stripped first - but only where unambiguous: brackets always delimit IPv6,
 * and a single colon can only be IPv4:port.
 */
function normalizeIpCandidate(value: string | undefined): string | undefined {
  let candidate = value?.trim();
  if (!candidate) return undefined;
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(candidate);
  if (bracketed?.[1]) {
    candidate = bracketed[1];
  } else {
    const ipv4Port = /^([^:]+):\d{1,5}$/.exec(candidate);
    if (ipv4Port?.[1]) candidate = ipv4Port[1];
  }
  return isIP(candidate) ? candidate : undefined;
}

/** Best-effort trustworthy client IP, or undefined when none can be derived. */
export function trustedClientIp(c: Context): string | undefined {
  const trustCloudflare = runtimeEnvironmentValue("STEWARD_TRUST_CLOUDFLARE") === "true";
  if (trustCloudflare) {
    const cf = c.req.header("cf-connecting-ip")?.trim();
    if (cf && isIP(cf)) return cf;
    // Cloudflare mode is exclusive: a missing/invalid authoritative header
    // may indicate edge bypass, so never fall through to client-forgeable
    // forwarded headers.
    return undefined;
  }
  const hops = trustedProxyHops();
  if (hops === 0) return undefined;

  const fromEnvoy = () => normalizeIpCandidate(c.req.header("x-envoy-external-address"));
  const fromForwardedFor = () => {
    if (hops === 0) return undefined;
    const entries = (c.req.header("x-forwarded-for") ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    return normalizeIpCandidate(entries[entries.length - hops]);
  };

  // x-envoy-external-address identifies the client only when the trusted edge
  // is the outermost hop, so with hops >= 2 the positional read stays
  // authoritative. A missing/invalid positional entry is a trust-topology
  // failure and must not fall back to the adjacent proxy's address.
  return hops >= 2 ? fromForwardedFor() : (fromEnvoy() ?? fromForwardedFor());
}
