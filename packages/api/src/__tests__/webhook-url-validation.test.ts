import { describe, expect, it } from "bun:test";
import { validateWebhookUrl, validateWebhookUrlResolved } from "../services/webhook-url";

describe("webhook URL validation", () => {
  it("rejects IPv4-mapped IPv6 private addresses in dotted and hex forms", () => {
    for (const url of [
      "https://[::ffff:127.0.0.1]/hook",
      "https://[::ffff:7f00:1]/hook",
      "https://[0:0:0:0:0:ffff:a9fe:a9fe]/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects NAT64 and 6to4 addresses that embed private IPv4 targets", () => {
    for (const url of [
      "https://[64:ff9b::a9fe:a9fe]/hook",
      "https://[64:ff9b:1::a9fe:a9fe]/hook",
      "https://[2002:7f00:1::]/hook",
      "https://localhost./hook",
      "https://service.internal./hook",
      "https://printer.local./hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects the entire NAT64 local-use range 64:ff9b:1::/48 (RFC 8215)", () => {
    // No assumption can be made about an embedded IPv4 address or its location
    // in the local-use range, so the whole /48 is non-public — including
    // variants whose fourth word is non-zero (the old /96-suffix extraction
    // both misread the suffix placement and let these through entirely).
    for (const url of [
      "https://[64:ff9b:1::a9fe:a9fe]/hook",
      "https://[64:ff9b:1:1::a9fe:a9fe]/hook",
      "https://[64:ff9b:1:ffff::]/hook",
      "https://[64:ff9b:1::808:808]/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("still allows public IPv6 and well-known NAT64 embeddings of public IPv4", () => {
    expect(validateWebhookUrl("https://[2001:4860:4860::8888]/hook")).toBeNull();
    expect(validateWebhookUrl("https://[64:ff9b::808:808]/hook")).toBeNull();
    // IPv4-translated form with a public embedding stays allowed (no over-block).
    expect(validateWebhookUrl("https://[::ffff:0:808:808]/hook")).toBeNull();
  });

  it("rejects Teredo and documentation IPv6 addresses", () => {
    for (const url of ["https://[2001::]/hook", "https://[2001:db8::1]/hook"]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects complete benchmarking and discard-only IPv6 prefixes", () => {
    for (const url of [
      "https://[2001:2::1]/hook",
      "https://[2001:2:0:ffff:ffff:ffff:ffff:ffff]/hook",
      "https://[100::1]/hook",
      "https://[100::ffff:ffff:ffff:ffff]/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
    // Adjacent prefixes are not accidentally widened by the exact word masks.
    expect(validateWebhookUrl("https://[2001:2:1::1]/hook")).toBeNull();
    expect(validateWebhookUrl("https://[100:0:0:1::1]/hook")).toBeNull();
  });

  it("rejects IPv6 site-local addresses", () => {
    for (const url of ["https://[fec0::1]/hook", "https://[feff::1]/hook"]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects the full IPv6 link-local range", () => {
    for (const url of [
      "https://[fe80::1]/hook",
      "https://[fe90::1]/hook",
      "https://[fea0::1]/hook",
      "https://[febf::1]/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects special-use IPv4 literal addresses", () => {
    for (const url of [
      "https://0.0.0.0/hook",
      "https://192.0.0.9/hook",
      "https://192.0.2.10/hook",
      "https://192.88.99.10/hook",
      "https://198.18.0.1/hook",
      "https://198.51.100.20/hook",
      "https://203.0.113.30/hook",
      "https://224.0.0.1/hook",
      "https://255.255.255.255/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects IPv6 translations that embed special-use IPv4 targets", () => {
    for (const url of [
      "https://[::ffff:c633:6414]/hook",
      "https://[64:ff9b::cb00:711e]/hook",
      "https://[2002:c000:020a::]/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects IPv4-translated ::ffff:0:0/96 and deprecated ::/96 forms at registration", () => {
    // Parity with the delivery-time dispatcher screen (SEC-178): these forms
    // embed an IPv4 reachable via NAT64/SIIT translators and must be refused
    // up front, not only at delivery.
    for (const url of [
      "https://[::ffff:0:7f00:1]/hook",
      "https://[::ffff:0:a9fe:a9fe]/hook",
      "https://[::7f00:1]/hook",
      "https://[::127.0.0.1]/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });
});

describe("validateWebhookUrlResolved (SEC-017)", () => {
  const publicAnswer = [{ address: "93.184.216.34", family: 4 }];

  it("rejects a public hostname that resolves to a private address (nip.io style)", async () => {
    const result = await validateWebhookUrlResolved(
      "https://169.254.169.254.nip.io/hook",
      async () => [{ address: "169.254.169.254", family: 4 }],
    );
    expect(result).toBe("url host must resolve to a public address");
  });

  it("rejects when ANY DNS answer is non-public (rebinding hedge)", async () => {
    const result = await validateWebhookUrlResolved("https://hooks.example.com/hook", async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.7", family: 4 },
    ]);
    expect(result).toBe("url host must resolve to a public address");
  });

  it("rejects IPv6 answers that embed private IPv4 targets", async () => {
    const result = await validateWebhookUrlResolved("https://hooks.example.com/hook", async () => [
      { address: "::ffff:127.0.0.1", family: 6 },
    ]);
    expect(result).toBe("url host must resolve to a public address");
  });

  it("fails closed when the hostname cannot be resolved", async () => {
    const result = await validateWebhookUrlResolved("https://gone.example.com/hook", async () => {
      throw new Error("ENOTFOUND");
    });
    expect(result).toBe("url host could not be resolved");

    const empty = await validateWebhookUrlResolved("https://gone.example.com/hook", async () => []);
    expect(empty).toBe("url host could not be resolved");
  });

  it("accepts a public hostname with only public answers", async () => {
    const result = await validateWebhookUrlResolved(
      "https://hooks.example.com/hook",
      async () => publicAnswer,
    );
    expect(result).toBeNull();
  });

  it("keeps string-level rejections and skips DNS for IP literals", async () => {
    expect(await validateWebhookUrlResolved("https://10.0.0.1/hook")).toBe(
      "url host must be public",
    );
    let called = false;
    const literal = await validateWebhookUrlResolved("https://93.184.216.34/hook", async () => {
      called = true;
      return [];
    });
    expect(literal).toBeNull();
    expect(called).toBe(false);
  });
});
