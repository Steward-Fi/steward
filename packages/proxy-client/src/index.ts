/**
 * @stwd/proxy-client — agent-side client for the Steward proxy.
 *
 * The proxy holds the upstream credentials; agents authenticate with a scoped
 * JWT and (in production) an HMAC request signature. This package provides a
 * generic signed HTTP client plus the signing primitives, kept in lockstep with
 * the proxy verifier via golden-vector tests.
 */

export type {
  ProxyHealth,
  StewardProxyClientOptions,
} from "./client";
export { SIGNATURE_MAX_AGE_MS, StewardProxyClient } from "./client";
export type { ProxySignatureInput } from "./signature";
export { buildCanonicalRequest, SIGNATURE_PREFIX, signProxyRequest } from "./signature";
