/**
 * SEC-048 — HTTPS enforcement on SDK baseUrl.
 *
 * StewardClient, StewardAuth, and AgentClient transmit platform keys, app
 * secrets, bearer tokens, and HMAC-signed credentials. Plaintext non-loopback
 * baseUrls must be rejected by default (the CLI has always enforced this);
 * loopback http stays allowed for local development, and an explicit
 * allowInsecureBaseUrl opt-out warns loudly for trusted private networks.
 */

import { describe, expect, spyOn, test } from "bun:test";
import { AgentClient } from "../agent-client";
import { AgentKeypair } from "../agent-keypair";
import { StewardAuth } from "../auth";
import { assertSecureBaseUrl } from "../base-url";
import { StewardClient } from "../client";
import { generateMockKeyPair } from "./agent-client-mock-server";

describe("assertSecureBaseUrl", () => {
  test("accepts HTTPS and loopback HTTP", () => {
    expect(() => assertSecureBaseUrl("https://api.steward.example")).not.toThrow();
    expect(() => assertSecureBaseUrl("http://localhost:3200")).not.toThrow();
    expect(() => assertSecureBaseUrl("http://127.0.0.1:3200")).not.toThrow();
    expect(() => assertSecureBaseUrl("http://[::1]:3200")).not.toThrow();
  });

  test("rejects plaintext non-loopback baseUrls", () => {
    expect(() => assertSecureBaseUrl("http://api.steward.example")).toThrow(/must use HTTPS/);
    expect(() => assertSecureBaseUrl("http://192.168.1.10:3200")).toThrow(/must use HTTPS/);
    expect(() => assertSecureBaseUrl("ftp://api.steward.example")).toThrow(/must use HTTPS/);
    expect(() => assertSecureBaseUrl("not-a-url")).toThrow(/valid absolute URL/);
  });

  test("rejects URL-embedded credentials even over HTTPS", () => {
    expect(() => assertSecureBaseUrl("https://user:secret@api.example.test")).toThrow(
      "must not embed credentials",
    );
  });

  test("allowInsecureBaseUrl opts out but warns loudly", () => {
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => assertSecureBaseUrl("http://api.steward.example", true)).not.toThrow();
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain("not HTTPS");
    } finally {
      warn.mockRestore();
    }
  });

  test("the insecure opt-out permits HTTP only, never arbitrary URL schemes", () => {
    expect(() => assertSecureBaseUrl("ftp://api.steward.example", true)).toThrow(/HTTPS/);
  });
});

describe("SDK constructors enforce HTTPS baseUrl", () => {
  test("StewardClient rejects plaintext non-loopback baseUrl", () => {
    expect(() => new StewardClient({ baseUrl: "http://api.steward.example" })).toThrow(
      /must use HTTPS/,
    );
    expect(() => new StewardClient({ baseUrl: "http://localhost:3200" })).not.toThrow();
    expect(() => new StewardClient({ baseUrl: "https://api.steward.example" })).not.toThrow();
  });

  test("StewardAuth rejects plaintext non-loopback baseUrl", () => {
    expect(() => new StewardAuth({ baseUrl: "http://api.steward.example" })).toThrow(
      /must use HTTPS/,
    );
    expect(() => new StewardAuth({ baseUrl: "http://localhost:3200" })).not.toThrow();
    expect(() => new StewardAuth({ baseUrl: "https://api.steward.example" })).not.toThrow();
  });

  test("AgentClient rejects plaintext non-loopback baseUrl", async () => {
    const { pkcs8Base64 } = await generateMockKeyPair();
    const keypair = await AgentKeypair.fromPkcs8Base64(pkcs8Base64);
    const config = { baseUrl: "http://api.steward.example", agentId: "agent-1", keypair };
    expect(() => new AgentClient(config)).toThrow(/must use HTTPS/);
    expect(() => new AgentClient({ ...config, baseUrl: "http://localhost:3200" })).not.toThrow();
    expect(
      () => new AgentClient({ ...config, baseUrl: "https://api.steward.example" }),
    ).not.toThrow();
  });
});
