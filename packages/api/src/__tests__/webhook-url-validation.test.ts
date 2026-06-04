import { describe, expect, it } from "bun:test";
import { validateWebhookUrl } from "../services/webhook-url";

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

  it("rejects Teredo and documentation IPv6 addresses", () => {
    for (const url of ["https://[2001::]/hook", "https://[2001:db8::1]/hook"]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects IPv6 site-local addresses", () => {
    for (const url of ["https://[fec0::1]/hook", "https://[feff::1]/hook"]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });

  it("rejects IPv4 special-use ranges that must not receive webhook traffic", () => {
    for (const url of [
      "https://0.0.0.0/hook",
      "https://192.0.0.8/hook",
      "https://192.0.2.10/hook",
      "https://198.18.0.1/hook",
      "https://198.19.255.254/hook",
      "https://198.51.100.20/hook",
      "https://203.0.113.30/hook",
      "https://224.0.0.1/hook",
      "https://240.0.0.1/hook",
      "https://255.255.255.255/hook",
    ]) {
      expect(validateWebhookUrl(url)).toBe("url host must be public");
    }
  });
});
