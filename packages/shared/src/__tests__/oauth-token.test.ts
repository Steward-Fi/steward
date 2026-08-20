import { describe, expect, test } from "bun:test";
import {
  isValidOAuthBearerToken,
  isValidOAuthOpaqueToken,
  MAX_OAUTH_TOKEN_LENGTH,
} from "../oauth-token";

describe("OAuth token validation", () => {
  test("implements the RFC 6750 b64token grammar exactly", () => {
    for (const token of ["a", "AZaz09-._~+/", "abc=", "abc====", "ya29.a0-token_value"]) {
      expect(isValidOAuthBearerToken(token), token).toBe(true);
    }
    for (const token of ["", "=abc", "ab=c", '"quoted"', "with space", "line\nfeed"]) {
      expect(isValidOAuthBearerToken(token), token).toBe(false);
    }
  });

  test("enforces the shared bound and keeps opaque refresh tokens off headers", () => {
    expect(isValidOAuthBearerToken("x".repeat(MAX_OAUTH_TOKEN_LENGTH))).toBe(true);
    expect(isValidOAuthBearerToken("x".repeat(MAX_OAUTH_TOKEN_LENGTH + 1))).toBe(false);
    expect(isValidOAuthOpaqueToken("opaque:{refresh}=token&value")).toBe(true);
    expect(isValidOAuthOpaqueToken("opaque refresh")).toBe(false);
    expect(isValidOAuthOpaqueToken("refresh\rcontrol")).toBe(false);
  });
});
