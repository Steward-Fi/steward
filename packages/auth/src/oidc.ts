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

function isPrivateIpv4(hostname: string): boolean {
  const parts = hostname.split(".").map((part) => Number(part));
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function expandIpv6Words(address: string): number[] | null {
  let normalized = address.toLowerCase();
  // Convert a dotted-quad tail (e.g. 64:ff9b::10.0.0.1) to two hex words.
  if (normalized.includes(".")) {
    const colonIndex = normalized.lastIndexOf(":");
    if (colonIndex === -1) return null;
    const quad = normalized
      .slice(colonIndex + 1)
      .split(".")
      .map((part) => Number(part));
    if (
      quad.length !== 4 ||
      quad.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
    ) {
      return null;
    }
    normalized = `${normalized.slice(0, colonIndex)}:${((quad[0] << 8) | quad[1]).toString(16)}:${((quad[2] << 8) | quad[3]).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;

  const parseWords = (part: string): number[] | null => {
    if (!part) return [];
    const words = part.split(":");
    const parsed = words.map((word) => {
      if (!/^[0-9a-f]{1,4}$/.test(word)) return Number.NaN;
      return Number.parseInt(word, 16);
    });
    return parsed.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)
      ? null
      : parsed;
  };

  const left = parseWords(halves[0]);
  const right = parseWords(halves[1] ?? "");
  if (!left || !right) return null;

  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;

  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

/**
 * Extract the IPv4 address embedded in an IPv6 transition mechanism
 * (NAT64 64:ff9b::/96 + local-use 64:ff9b:1::/48 per RFC 6052/8215,
 * 6to4 2002::/16 per RFC 3056) so it can be screened against isPrivateIpv4.
 */
function embeddedTransitionIpv4(address: string): string | null {
  const words = expandIpv6Words(address);
  if (!words) return null;
  const fromWords = (high: number, low: number) =>
    [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
  const isNat64 =
    words[0] === 0x64 &&
    words[1] === 0xff9b &&
    ((words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0) ||
      (words[2] === 1 && words[3] === 0));
  if (isNat64) return fromWords(words[6], words[7]);
  if (words[0] === 0x2002) return fromWords(words[1], words[2]);
  return null;
}

function isPrivateIpv6(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  const ipv4Mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Mapped) return isPrivateIpv4(ipv4Mapped[1]);
  const hexIpv4Mapped = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexIpv4Mapped) {
    const high = Number.parseInt(hexIpv4Mapped[1], 16);
    const low = Number.parseInt(hexIpv4Mapped[2], 16);
    if (Number.isFinite(high) && Number.isFinite(low) && high <= 0xffff && low <= 0xffff) {
      return isPrivateIpv4(`${(high >> 8) & 255}.${high & 255}.${(low >> 8) & 255}.${low & 255}`);
    }
  }
  const embedded = embeddedTransitionIpv4(normalized);
  if (embedded) return isPrivateIpv4(embedded);
  const words = expandIpv6Words(normalized);
  // Teredo (2001:0000::/32) obfuscates the embedded client IPv4 — block outright.
  if (words?.[0] === 0x2001 && words[1] === 0) return true;
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8:")
  );
}

function isBlockedJwksHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const ipv4Mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Mapped) return isPrivateIpv4(ipv4Mapped[1]);
  const literalVersion = isIP(host);
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".internal") ||
    host.endsWith(".local") ||
    (literalVersion === 4 && isPrivateIpv4(host)) ||
    (literalVersion === 6 && isPrivateIpv6(host))
  );
}

function assertSafeJwksUri(jwksUri: string): URL {
  const url = new URL(jwksUri);
  if (url.protocol !== "https:" || isBlockedJwksHost(url.hostname)) {
    throw new Error("OIDC jwksUri must be a public https URL");
  }
  return url;
}

function assertPublicJwksAddress(address: string, family: number): void {
  if ((family === 4 && isPrivateIpv4(address)) || (family === 6 && isPrivateIpv6(address))) {
    throw new Error("OIDC jwksUri must resolve to a public address");
  }
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
