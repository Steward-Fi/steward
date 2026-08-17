import { describe, expect, it } from "bun:test";

import { assertPublicJwksDestination } from "../oidc";

describe("assertPublicJwksDestination SSRF guard", () => {
  it("rejects IPv4-mapped IPv6 literals that embed private IPv4 targets", async () => {
    await expect(assertPublicJwksDestination("https://[::ffff:10.0.0.1]/jwks")).rejects.toThrow();
    await expect(assertPublicJwksDestination("https://[::ffff:a00:1]/jwks")).rejects.toThrow();
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
});
