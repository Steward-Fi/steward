/** RFC 6750 `b64token` syntax used by OAuth 2.0 Bearer credentials. */
const OAUTH_BEARER_TOKEN_RE = /^[A-Za-z0-9._~+/-]+={0,}$/;

export const MAX_OAUTH_TOKEN_LENGTH = 16_384;

export function isValidOAuthBearerToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_OAUTH_TOKEN_LENGTH &&
    OAUTH_BEARER_TOKEN_RE.test(value)
  );
}

/**
 * Refresh tokens are opaque rather than Bearer-header values, but X token
 * endpoint responses still need a strict storage bound and must not contain
 * controls or whitespace that can create log/form/header ambiguity later.
 */
export function isValidOAuthOpaqueToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_OAUTH_TOKEN_LENGTH &&
    /^[\x21-\x7e]+$/.test(value)
  );
}
