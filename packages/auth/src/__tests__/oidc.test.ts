import { describe, expect, it, spyOn } from "bun:test";
import { readFileSync } from "node:fs";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";

import {
  assertPublicJwksDestination,
  clearOidcJwksCacheForTests,
  getPublicRemoteJWKSet,
} from "../oidc";

describe("assertPublicJwksDestination SSRF guard", () => {
  it("preserves HTTP status and bounds all production JWKS I/O", () => {
    const source = readFileSync(new URL("../oidc.ts", import.meta.url), "utf8");
    expect(source).toContain("status: result.status");
    expect(source).toContain('res.headers["content-length"]');
    expect(source).toContain("size > JWKS_MAX_BYTES");
    expect(source).toContain("init?.signal?.addEventListener");
    expect(source).toContain("JWKS_FETCH_TIMEOUT_MS");
    expect(source).toContain("OIDC jwksUri redirects are not allowed");
  });
  it("rejects IPv4-mapped IPv6 literals that embed private IPv4 targets", async () => {
    await expect(assertPublicJwksDestination("https://[::ffff:10.0.0.1]/jwks")).rejects.toThrow();
    await expect(assertPublicJwksDestination("https://[::ffff:a00:1]/jwks")).rejects.toThrow();
  });

  it("rejects IPv4-compatible and translated IPv6 literals", async () => {
    await expect(assertPublicJwksDestination("https://[::127.0.0.1]/jwks")).rejects.toThrow();
    await expect(assertPublicJwksDestination("https://[::7f00:1]/jwks")).rejects.toThrow();
    await expect(
      assertPublicJwksDestination("https://[::ffff:0:127.0.0.1]/jwks"),
    ).rejects.toThrow();
  });

  it("rejects special-purpose IPv4 and IPv6 literals", async () => {
    for (const uri of [
      "https://192.0.2.1/jwks",
      "https://198.51.100.1/jwks",
      "https://203.0.113.1/jwks",
      "https://[100::1]/jwks",
      "https://[3fff::1]/jwks",
    ]) {
      await expect(assertPublicJwksDestination(uri), uri).rejects.toThrow();
    }
  });

  it("rejects NAT64 literals that embed private IPv4 targets", async () => {
    // 64:ff9b::/96 well-known prefix — 10.0.0.1 and 169.254.169.254 embedded.
    await expect(assertPublicJwksDestination("https://[64:ff9b::a00:1]/jwks")).rejects.toThrow();
    await expect(assertPublicJwksDestination("https://[64:ff9b::10.0.0.1]/jwks")).rejects.toThrow();
    await expect(
      assertPublicJwksDestination("https://[64:ff9b::a9fe:a9fe]/jwks"),
    ).rejects.toThrow();
    // 64:ff9b:1::/48 is local-use and non-globally-reachable.
    await expect(
      assertPublicJwksDestination("https://[64:ff9b:1:c0a8:1:100::]/jwks"),
    ).rejects.toThrow();
    // RFC 8215 does not define an embedded IPv4 position for this local-use
    // prefix, so it must be rejected even when the low 32 bits look public.
    await expect(
      assertPublicJwksDestination("https://[64:ff9b:1:beef::808:808]/jwks"),
    ).rejects.toThrow();
  });

  it("rejects 6to4 literals that embed private IPv4 targets", async () => {
    // 2002::/16 — 10.0.0.1 and 127.0.0.1 embedded.
    await expect(assertPublicJwksDestination("https://[2002:a00:1::]/jwks")).rejects.toThrow();
    await expect(assertPublicJwksDestination("https://[2002:7f00:1::]/jwks")).rejects.toThrow();
  });

  it("rejects Teredo literals outright", async () => {
    await expect(
      assertPublicJwksDestination("https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/jwks"),
    ).rejects.toThrow();
  });

  it("still allows transition literals that embed public IPv4 targets", async () => {
    // Well-known NAT64/6to4 embeddings of 8.8.8.8 are public.
    await expect(
      assertPublicJwksDestination("https://[64:ff9b::808:808]/jwks"),
    ).resolves.toBeUndefined();
    await expect(
      assertPublicJwksDestination("https://[2002:808:808::]/jwks"),
    ).resolves.toBeUndefined();
  });

  it("bounds the tenant-controlled remote JWKS cache", async () => {
    clearOidcJwksCacheForTests();
    const first = await getPublicRemoteJWKSet("https://idp.example.com/jwks", "tenant:first");
    for (let index = 0; index < 256; index += 1) {
      await getPublicRemoteJWKSet(`https://idp.example.com/jwks/${index}`, `tenant:${index}`);
    }
    const reloaded = await getPublicRemoteJWKSet("https://idp.example.com/jwks", "tenant:first");
    expect(reloaded).not.toBe(first);
    clearOidcJwksCacheForTests();
  });

  it("applies the request-local JWKS maximum age to each cache decision", async () => {
    clearOidcJwksCacheForTests();
    let now = 1_000_000;
    const nowSpy = spyOn(Date, "now").mockImplementation(() => now);
    try {
      const first = await withRuntimeEnvironment({ STEWARD_OIDC_JWKS_MAX_AGE_MS: "60000" }, () =>
        getPublicRemoteJWKSet("https://idp.example.com/jwks", "tenant:runtime-age"),
      );
      now += 60_001;
      const retained = await withRuntimeEnvironment(
        { STEWARD_OIDC_JWKS_MAX_AGE_MS: "120000" },
        () => getPublicRemoteJWKSet("https://idp.example.com/jwks", "tenant:runtime-age"),
      );
      expect(retained).toBe(first);

      const rebuilt = await withRuntimeEnvironment({ STEWARD_OIDC_JWKS_MAX_AGE_MS: "60000" }, () =>
        getPublicRemoteJWKSet("https://idp.example.com/jwks", "tenant:runtime-age"),
      );
      expect(rebuilt).not.toBe(first);
    } finally {
      nowSpy.mockRestore();
      clearOidcJwksCacheForTests();
    }
  });
});
