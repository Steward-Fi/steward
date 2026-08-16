import { describe, expect, test } from "bun:test";
import {
  assertSecureBaseUrl,
  loadConfig,
  redactConfig,
  redactSecret,
  type StewardMcpConfig,
} from "../config.js";

describe("assertSecureBaseUrl", () => {
  test("accepts https URLs", () => {
    expect(() => assertSecureBaseUrl("https://steward.example.com")).not.toThrow();
  });

  test("accepts http for localhost variants", () => {
    expect(() => assertSecureBaseUrl("http://localhost:7860")).not.toThrow();
    expect(() => assertSecureBaseUrl("http://127.0.0.1:7860")).not.toThrow();
    expect(() => assertSecureBaseUrl("http://[::1]:7860")).not.toThrow();
  });

  test("rejects http for remote hosts", () => {
    expect(() => assertSecureBaseUrl("http://steward.example.com")).toThrow(
      /only allowed for localhost/,
    );
  });

  test("rejects non-http(s) protocols", () => {
    expect(() => assertSecureBaseUrl("ftp://steward.example.com")).toThrow(/only http\(s\)/);
  });

  test("rejects malformed URLs", () => {
    expect(() => assertSecureBaseUrl("not a url")).toThrow(/not a valid URL/);
  });
});

describe("loadConfig", () => {
  test("loads a full config from env", () => {
    const config = loadConfig({
      STEWARD_URL: "https://steward.example.com",
      STEWARD_API_KEY: "sk_live_abcd1234",
      STEWARD_TENANT_ID: "tenant_1",
      STEWARD_AGENT_ID: "agent_1",
    } as NodeJS.ProcessEnv);
    expect(config).toEqual({
      baseUrl: "https://steward.example.com",
      apiKey: "sk_live_abcd1234",
      bearerToken: undefined,
      tenantId: "tenant_1",
      defaultAgentId: "agent_1",
    });
  });

  test("accepts STEWARD_BASE_URL as a fallback for STEWARD_URL", () => {
    const config = loadConfig({
      STEWARD_BASE_URL: "https://steward.example.com",
      STEWARD_API_KEY: "k",
    } as NodeJS.ProcessEnv);
    expect(config.baseUrl).toBe("https://steward.example.com");
  });

  test("accepts a bearer token instead of an api key", () => {
    const config = loadConfig({
      STEWARD_URL: "https://steward.example.com",
      STEWARD_JWT: "jwt-token",
    } as NodeJS.ProcessEnv);
    expect(config.bearerToken).toBe("jwt-token");
    expect(config.apiKey).toBeUndefined();
  });

  test("accepts STEWARD_BEARER_TOKEN as an alias for STEWARD_JWT", () => {
    const config = loadConfig({
      STEWARD_URL: "https://steward.example.com",
      STEWARD_BEARER_TOKEN: "jwt-token",
    } as NodeJS.ProcessEnv);
    expect(config.bearerToken).toBe("jwt-token");
  });

  test("throws when STEWARD_URL is missing", () => {
    expect(() => loadConfig({ STEWARD_API_KEY: "k" } as NodeJS.ProcessEnv)).toThrow(
      /Missing required STEWARD_URL/,
    );
  });

  test("throws when no credentials are provided", () => {
    expect(() =>
      loadConfig({ STEWARD_URL: "https://steward.example.com" } as NodeJS.ProcessEnv),
    ).toThrow(/Missing Steward credentials/);
  });

  test("throws on insecure remote http URLs", () => {
    expect(() =>
      loadConfig({
        STEWARD_URL: "http://steward.example.com",
        STEWARD_API_KEY: "k",
      } as NodeJS.ProcessEnv),
    ).toThrow(/only allowed for localhost/);
  });

  test("treats blank credential strings as absent", () => {
    expect(() =>
      loadConfig({
        STEWARD_URL: "https://steward.example.com",
        STEWARD_API_KEY: "   ",
      } as NodeJS.ProcessEnv),
    ).toThrow(/Missing Steward credentials/);
  });
});

describe("redaction", () => {
  test("redactSecret masks all but the last 4 chars of long secrets", () => {
    expect(redactSecret("sk_live_abcd1234")).toBe("****1234");
  });

  test("redactSecret fully masks short secrets", () => {
    expect(redactSecret("short")).toBe("****");
    expect(redactSecret("12345678")).toBe("****");
  });

  test("redactConfig hides apiKey and bearerToken but keeps non-secret fields", () => {
    const config: StewardMcpConfig = {
      baseUrl: "https://steward.example.com",
      apiKey: "sk_live_abcd1234",
      bearerToken: "jwt-supersecret-token",
      tenantId: "tenant_1",
      defaultAgentId: "agent_1",
    };
    const redacted = redactConfig(config);
    expect(redacted.baseUrl).toBe("https://steward.example.com");
    expect(redacted.tenantId).toBe("tenant_1");
    expect(redacted.defaultAgentId).toBe("agent_1");
    expect(redacted.apiKey).toBe("****1234");
    expect(redacted.bearerToken).toBe("****oken");
    // Ensure the raw secret never appears in the serialized output.
    expect(JSON.stringify(redacted)).not.toContain("sk_live_abcd1234");
    expect(JSON.stringify(redacted)).not.toContain("supersecret");
  });

  test("redactConfig omits undefined fields", () => {
    const redacted = redactConfig({
      baseUrl: "https://steward.example.com",
      apiKey: "sk_abcd1234",
    });
    expect("bearerToken" in redacted).toBe(false);
    expect("tenantId" in redacted).toBe(false);
  });
});
