import { lookup as dnsLookup } from "node:dns";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import type { TenantOidcProviderConfig } from "@stwd/shared";
import {
  createRemoteJWKSet,
  customFetch,
  decodeProtectedHeader,
  type JWTPayload,
  jwtVerify,
} from "jose";
import { assertPublicHttpsEndpoint, assertPublicInternetAddress } from "./public-endpoint";
import {
  assertPinnedDnsTransportSupported,
  createPublicInternetLookup,
} from "./public-endpoint-node";

interface CachedJwks {
  jwks: ReturnType<typeof createRemoteJWKSet>;
  createdAt: number;
}

const JWKS_CACHE = new Map<string, CachedJwks>();
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const JWKS_MAX_BYTES = 256 * 1024;
const JWKS_CACHE_MAX_ENTRIES = 256;
// Hard ceiling on how long a remote JWKS set is cached before it is rebuilt.
// jose's internal cooldown only limits how *often* it refetches on unknown-kid;
// it never evicts known keys, so a process-lifetime cache would not pick up an
// IdP emergency key revocation. Rebuilding the set after this TTL guarantees a
// rotated/revoked key stops verifying within the window. Configurable via env.
const JWKS_MAX_AGE_MS = (() => {
  const raw = Number(process.env.STEWARD_OIDC_JWKS_MAX_AGE_MS);
  if (Number.isFinite(raw) && raw >= 60_000) return raw;
  return 60 * 60 * 1000; // 1 hour default
})();
function allowTestJwksFetch(): boolean {
  return (
    process.env.NODE_ENV === "test" && process.env.STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH === "true"
  );
}

export interface VerifiedOidcToken {
  subject: string;
  claims: JWTPayload;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  picture?: string;
}

function cacheKey(tenantId: string, provider: TenantOidcProviderConfig): string {
  return `${tenantId}:${provider.id}:${provider.issuer}:${provider.jwksUri}`;
}

function claimString(claims: JWTPayload, name: string | undefined): string | undefined {
  if (!name) return undefined;
  const value = claims[name];
  return typeof value === "string" && value.trim() ? value : undefined;
}

function claimBoolean(claims: JWTPayload, name: string | undefined): boolean | undefined {
  if (!name) return undefined;
  const value = claims[name];
  return typeof value === "boolean" ? value : undefined;
}

function assertSafeJwksUri(jwksUri: string): URL {
  return assertPublicHttpsEndpoint(jwksUri, "OIDC jwksUri");
}

function assertPublicJwksAddress(address: string, family: number): void {
  assertPublicInternetAddress(address, family, "OIDC jwksUri");
}

export async function assertPublicJwksDestination(jwksUri: string): Promise<void> {
  const url = assertSafeJwksUri(jwksUri);
  assertPinnedDnsTransportSupported("OIDC jwksUri");
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const literalVersion = isIP(hostname);
  if (literalVersion !== 0) {
    assertPublicJwksAddress(hostname, literalVersion);
    return;
  }

  const addresses = await new Promise<Array<{ address: string; family: number }>>(
    (resolve, reject) => {
      let settled = false;
      const finish = <T>(fn: (value: T) => void, value: T) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        fn(value);
      };
      const deadline = setTimeout(
        () => finish(reject, new Error("OIDC jwksUri DNS lookup timed out")),
        JWKS_FETCH_TIMEOUT_MS,
      );
      dnsLookup(hostname, { all: true, verbatim: true }, (error, resolved) => {
        if (error) {
          finish(reject, new Error("OIDC jwksUri host did not resolve"));
          return;
        }
        finish(resolve, resolved);
      });
    },
  );
  if (addresses.length === 0) throw new Error("OIDC jwksUri host did not resolve");
  for (const { address, family } of addresses) {
    assertPublicJwksAddress(address, family);
  }
}

/**
 * Builds (or returns a cached) remote JWKS set whose key fetches are routed
 * through the SSRF-guarded {@link fetchPublicJwks} transport. The set is
 * rebuilt once it exceeds {@link JWKS_MAX_AGE_MS} so rotated or emergency-
 * revoked IdP keys stop verifying within the window.
 *
 * Reused by both the tenant OIDC path ({@link verifyOidcJwt}) and the
 * built-in "Sign in with Apple" id_token verifier so there is a single,
 * hardened JWKS transport in the codebase.
 *
 * @param jwksUri  - The IdP JWKS endpoint (must be a public https URL).
 * @param cacheKey - Stable cache key the caller controls (e.g. issuer:jwksUri).
 */
export async function getPublicRemoteJWKSet(
  jwksUri: string,
  cacheKey: string,
): Promise<ReturnType<typeof createRemoteJWKSet>> {
  assertPinnedDnsTransportSupported("OIDC jwksUri");
  const cached = JWKS_CACHE.get(cacheKey);
  if (cached && Date.now() - cached.createdAt <= JWKS_MAX_AGE_MS) {
    // Refresh insertion order so the bounded map acts as an LRU cache.
    JWKS_CACHE.delete(cacheKey);
    JWKS_CACHE.set(cacheKey, cached);
    return cached.jwks;
  }
  const url = assertSafeJwksUri(jwksUri);
  const jwks = createRemoteJWKSet(url, {
    [customFetch]: (fetchUrl, init) => fetchPublicJwks(fetchUrl, init),
  });
  JWKS_CACHE.delete(cacheKey);
  while (JWKS_CACHE.size >= JWKS_CACHE_MAX_ENTRIES) {
    const oldestKey = JWKS_CACHE.keys().next().value;
    if (oldestKey === undefined) break;
    JWKS_CACHE.delete(oldestKey);
  }
  JWKS_CACHE.set(cacheKey, { jwks, createdAt: Date.now() });
  return jwks;
}

async function fetchPublicJwks(url: string | URL, init?: RequestInit): Promise<Response> {
  const jwksUrl = assertSafeJwksUri(url.toString());
  assertPinnedDnsTransportSupported("OIDC jwksUri");
  if (allowTestJwksFetch()) {
    return fetch(jwksUrl, init);
  }

  const result = await new Promise<{
    body: Uint8Array;
    headers: Headers;
    status: number;
  }>((resolve, reject) => {
    let settled = false;
    let req: ReturnType<typeof httpsRequest> | undefined;
    const finish = <T>(fn: (value: T) => void, value: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      init?.signal?.removeEventListener("abort", abortRequest);
      fn(value);
    };
    const abortRequest = () => {
      req?.destroy();
      finish(reject, new Error("OIDC JWKS request was aborted"));
    };
    const deadline = setTimeout(() => {
      req?.destroy();
      finish(reject, new Error("OIDC JWKS request timed out"));
    }, JWKS_FETCH_TIMEOUT_MS);

    if (init?.signal?.aborted) {
      abortRequest();
      return;
    }
    init?.signal?.addEventListener("abort", abortRequest, { once: true });

    req = httpsRequest(
      jwksUrl,
      {
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        method: init?.method ?? "GET",
        timeout: JWKS_FETCH_TIMEOUT_MS,
        lookup: createPublicInternetLookup("OIDC jwksUri"),
      },
      (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
          finish(reject, new Error("OIDC jwksUri redirects are not allowed"));
          res.resume();
          return;
        }
        const declaredLength = Number(res.headers["content-length"]);
        if (Number.isFinite(declaredLength) && declaredLength > JWKS_MAX_BYTES) {
          finish(reject, new Error("OIDC JWKS response is too large"));
          res.resume();
          return;
        }
        const chunks: Uint8Array[] = [];
        let size = 0;
        res.on("data", (chunk: Uint8Array) => {
          size += chunk.byteLength;
          if (size > JWKS_MAX_BYTES) {
            req?.destroy();
            finish(reject, new Error("OIDC JWKS response is too large"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          const body = new Uint8Array(size);
          let offset = 0;
          for (const chunk of chunks) {
            body.set(chunk, offset);
            offset += chunk.byteLength;
          }
          const headers = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            if (Array.isArray(value)) {
              for (const item of value) headers.append(name, item);
            } else if (value !== undefined) {
              headers.set(name, value);
            }
          }
          const status =
            res.statusCode && res.statusCode >= 200 && res.statusCode <= 599 ? res.statusCode : 502;
          finish(resolve, { body, headers, status });
        });
        res.on("aborted", () => finish(reject, new Error("OIDC JWKS response was interrupted")));
        res.on("error", () => finish(reject, new Error("OIDC JWKS response failed")));
      },
    );

    req.on("timeout", () => {
      req?.destroy();
      finish(reject, new Error("OIDC JWKS request timed out"));
    });
    req.on("error", () => finish(reject, new Error("OIDC JWKS request failed")));
    req.end();
  });

  const responseBody =
    result.body.byteLength === 0 && (result.status === 204 || result.status === 205)
      ? null
      : new Uint8Array(result.body);
  return new Response(responseBody, { headers: result.headers, status: result.status });
}

export async function verifyOidcJwt(
  tenantId: string,
  provider: TenantOidcProviderConfig,
  token: string,
): Promise<VerifiedOidcToken> {
  const algorithms = provider.allowedAlgs?.length ? provider.allowedAlgs : ["RS256", "ES256"];
  const protectedHeader = decodeProtectedHeader(token);
  if (!protectedHeader.alg || !algorithms.includes(protectedHeader.alg as "RS256" | "ES256")) {
    throw new Error("Unsupported OIDC token algorithm");
  }

  const jwks = await getPublicRemoteJWKSet(provider.jwksUri, cacheKey(tenantId, provider));

  const { payload } = await jwtVerify(token, jwks, {
    issuer: provider.issuer,
    audience: provider.audience,
    algorithms,
    // Fail closed on non-compliant IdPs: an id_token without exp/iat never
    // expires (jose only validates exp when present) and cannot be age-bound.
    requiredClaims: ["exp", "iat"],
  });

  // OIDC Core §3.1.3.7: the `azp` (authorized party) claim, when present, MUST
  // equal the client_id. If the token carries more than one audience, `azp`
  // MUST be present (and equal to client_id). Without this check a token minted
  // for a different relying party but listing this provider's audience among
  // several would be accepted (multi-audience token substitution). jose only
  // verifies that *one* of the configured audiences matches, so we enforce azp
  // here. Fail closed. clientId is optional config (id-token-only providers may
  // omit it); when absent we cannot bind azp, so single-aud back-compat applies.
  const audiences = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
  const azp = claimString(payload, "azp");
  const clientId = provider.clientId?.trim() || undefined;
  if (azp !== undefined) {
    if (!clientId || azp !== clientId) {
      throw new Error("OIDC token azp does not match the configured client_id");
    }
  } else if (clientId && !audiences.includes(clientId)) {
    throw new Error("OIDC token audience does not include the configured client_id");
  } else if (audiences.length > 1) {
    throw new Error("OIDC token with multiple audiences must include an azp claim");
  }

  const subjectClaim = provider.subjectClaim ?? "sub";
  const subject = claimString(payload, subjectClaim);
  if (!subject) throw new Error("OIDC token subject is missing");

  return {
    subject,
    claims: payload,
    email: claimString(payload, provider.emailClaim ?? "email"),
    emailVerified: claimBoolean(payload, provider.emailVerifiedClaim ?? "email_verified"),
    name: claimString(payload, provider.nameClaim ?? "name"),
    picture: claimString(payload, provider.pictureClaim ?? "picture"),
  };
}

export function clearOidcJwksCacheForTests(): void {
  JWKS_CACHE.clear();
}
