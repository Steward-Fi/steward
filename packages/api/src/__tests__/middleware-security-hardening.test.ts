import { afterEach, describe, expect, it } from "bun:test";
import app from "../app";

const originalNodeEnv = process.env.NODE_ENV;

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
});

describe("middleware security behavior", () => {
  it("fails closed for unknown production CORS tenants and varies every denial", async () => {
    process.env.NODE_ENV = "production";
    const response = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        origin: "https://untrusted.example",
        "X-Steward-Tenant": `unknown-cors-${Date.now()}`,
        "Access-Control-Request-Method": "GET",
      },
    });

    expect(response.status).toBe(403);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(response.headers.get("Vary")).toBe("Origin, X-Steward-Tenant");
  });

  it("emits API security headers and suppresses HSTS on localhost", async () => {
    const response = await app.request("/health", {
      headers: { host: "api.example.com" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(response.headers.get("Permissions-Policy")).toContain("geolocation=()");
    expect(response.headers.get("Strict-Transport-Security")).toContain("includeSubDomains");

    const localResponse = await app.request("/health", {
      headers: { host: "localhost:8787" },
    });
    expect(localResponse.status).toBe(200);
    expect(localResponse.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(localResponse.headers.get("Strict-Transport-Security")).toBeNull();
  });
});
