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

interface CachedJwks {
  jwks: ReturnType<typeof createRemoteJWKSet>;
  createdAt: number;
}

const JWKS_CACHE = new Map<string, CachedJwks>();
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const JWKS_MAX_BYTES = 256 * 1024;
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
const ALLOW_TEST_JWKS_FETCH =
  process.env.NODE_ENV === "test" && process.env.STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH === "true";

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
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const literalVersion = isIP(hostname);
  if (literalVersion !== 0) {
    assertPublicJwksAddress(hostname, literalVersion);
    return;
  }

  const addresses = await new Promise<Array<{ address: string; family: number }>>(
    (resolve, reject) => {
      dnsLookup(hostname, { all: true, verbatim: true }, (error, resolved) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(resolved);
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
  const cached = JWKS_CACHE.get(cacheKey);
  if (cached && Date.now() - cached.createdAt <= JWKS_MAX_AGE_MS) {
    return cached.jwks;
  }
  const url = assertSafeJwksUri(jwksUri);
  if (!ALLOW_TEST_JWKS_FETCH) {
    await assertPublicJwksDestination(url.toString());
  }
  const jwks = createRemoteJWKSet(url, {
    [customFetch]: (fetchUrl, init) => fetchPublicJwks(fetchUrl, init),
  });
  JWKS_CACHE.set(cacheKey, { jwks, createdAt: Date.now() });
  return jwks;
}

async function fetchPublicJwks(url: string | URL, init?: RequestInit): Promise<Response> {
  const jwksUrl = assertSafeJwksUri(url.toString());
  if (ALLOW_TEST_JWKS_FETCH) {
    return fetch(jwksUrl, init);
  }

  const body = await new Promise<Uint8Array>((resolve, reject) => {
    const req = httpsRequest(
      jwksUrl,
      {
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        method: init?.method ?? "GET",
        timeout: JWKS_FETCH_TIMEOUT_MS,
        lookup(hostname, options, callback) {
          dnsLookup(
            hostname,
            { all: false, family: options.family, verbatim: true },
            (error, address, family) => {
              if (error) {
                callback(error, address, family);
                return;
              }
              try {
                assertPublicJwksAddress(address, family);
                callback(null, address, family);
              } catch (privateAddressError) {
                callback(privateAddressError as NodeJS.ErrnoException, address, family);
              }
            },
          );
        },
      },
      (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
          reject(new Error("OIDC jwksUri redirects are not allowed"));
          res.resume();
          return;
        }
        const chunks: Uint8Array[] = [];
        let size = 0;
        res.on("data", (chunk: Uint8Array) => {
          size += chunk.byteLength;
          if (size > JWKS_MAX_BYTES) {
            req.destroy(new Error("OIDC JWKS response is too large"));
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
          resolve(body);
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error("OIDC JWKS request timed out")));
    req.on("error", reject);
    req.end();
  });

  const responseBody = new ArrayBuffer(body.byteLength);
  new Uint8Array(responseBody).set(body);
  return new Response(responseBody);
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
