import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import app from "../app";

const apiRoot = join(import.meta.dir, "..");
const idempotencySource = readFileSync(join(apiRoot, "middleware", "idempotency.ts"), "utf8");
const redisSource = readFileSync(join(apiRoot, "middleware", "redis.ts"), "utf8");
const redisEnforcementSource = readFileSync(
  join(apiRoot, "middleware", "redis-enforcement.ts"),
  "utf8",
);
const securityHeadersSource = readFileSync(
  join(apiRoot, "middleware", "security-headers.ts"),
  "utf8",
);
const globalRateLimitSource = readFileSync(
  join(apiRoot, "middleware", "global-rate-limit.ts"),
  "utf8",
);
const appSource = readFileSync(join(apiRoot, "app.ts"), "utf8");
const indexSource = readFileSync(join(apiRoot, "index.ts"), "utf8");
const webRoot = join(import.meta.dir, "..", "..", "..", "..", "web", "src");
const webMiddlewareSource = readFileSync(join(webRoot, "middleware.ts"), "utf8");
// The dashboard CSP is constructed in web/src/lib/csp.ts (extracted from
// middleware.ts for unit-testing) and applied by middleware.ts.
const webCspSource = readFileSync(join(webRoot, "lib", "csp.ts"), "utf8");

describe("middleware security hardening", () => {
  it("uses durable production idempotency and avoids broad unauthenticated reservations", () => {
    expect(idempotencySource).toContain("class RedisIdempotencyStore");
    expect(idempotencySource).toContain('throw new Error("Durable idempotency store unavailable")');
    expect(idempotencySource).toContain('redis.set(redisKey, value, "PX", ttlMs, "NX")');
    expect(idempotencySource).toContain("hasIdempotencyAuthMaterial");
    expect(idempotencySource).toContain("hasReplaySafePublicContext");
    expect(idempotencySource).toContain("PUBLIC_AUTH_IDEMPOTENCY_PATHS");
    expect(idempotencySource).toContain('hasCredentialScope ? "" : "public-auth"');
    expect(idempotencySource).toContain('hasCredentialScope ? "" : url.pathname');
    expect(idempotencySource).toContain("if (hasAuthMaterial) {");
    expect(idempotencySource).toContain("} else if (!hasReplaySafePublicContext(c)) {");
  });

  it("fails closed when configured Redis rate-limit enforcement is unavailable", () => {
    expect(redisSource).toContain("function isRedisConfigured");
    expect(redisSource).toContain("Rate limit check failed, denying sensitive request");
    expect(redisSource).toContain("Proxy rate limit check failed, denying request");
    expect(redisSource).toContain("return { allowed: false, remaining: 0, resetMs: 60_000 }");
    expect(redisEnforcementSource).toContain("isRedisConfigured()");
    expect(redisEnforcementSource).toContain("Rate limit enforcement is unavailable");
  });

  it("applies Bun runtime gates before Hono route dispatch", () => {
    expect(indexSource).toContain(
      "function runtimeGate(request: Request, peerAddress: string | null)",
    );
    expect(indexSource).toContain("const peerAddress = server.requestIP(request)?.address ?? null");
    expect(indexSource).toContain("runtimeGate(request, peerAddress)");
    // The runtime gate must run before Hono route dispatch.
    const gateAt = indexSource.indexOf("runtimeGate(request, peerAddress)");
    const fetchAt = indexSource.indexOf("app.fetch(request,");
    expect(gateAt).toBeGreaterThanOrEqual(0);
    expect(fetchAt).toBeGreaterThan(gateAt);
    expect(indexSource).not.toContain('app.use("*", async (c, next) => {');
  });

  it("mounts the shared Redis-backed global limiter on the Workers runtime (SEC-068)", () => {
    expect(appSource).toContain("if (isWorkersRuntime) {");
    expect(appSource).toContain('app.use("*", workersGlobalRateLimit)');
    expect(globalRateLimitSource).toContain("checkAuthRateLimit(");
    expect(globalRateLimitSource).toContain('c.req.path === "/health"');
    expect(globalRateLimitSource).toContain('"Rate limit exceeded"');
  });

  it("trims /ready fingerprint detail unless a probe token is presented (SEC-071)", () => {
    expect(indexSource).toContain("function readyProbeAuthorized(");
    expect(indexSource).toContain("STEWARD_READY_PROBE_TOKEN");
    expect(indexSource).toContain("timingSafeEqual");
    expect(indexSource).toContain('"x-steward-probe-token"');
    expect(indexSource).toContain("checks: verbose ? checks : publicChecks");
  });

  it("documents production security headers and dashboard CSP checks in source", () => {
    expect(securityHeadersSource).toContain('"X-Frame-Options": "DENY"');
    expect(securityHeadersSource).toContain('"Content-Security-Policy"');
    expect(securityHeadersSource).toContain("default-src 'none'");
    expect(securityHeadersSource).toContain("frame-ancestors 'none'");
    expect(securityHeadersSource).toContain('"X-Content-Type-Options": "nosniff"');
    expect(securityHeadersSource).toContain('"Permissions-Policy"');
    expect(securityHeadersSource).toContain("Strict-Transport-Security");
    expect(webMiddlewareSource).toContain("Content-Security-Policy");
    expect(webCspSource).toContain("frame-ancestors 'none'");
    expect(webCspSource).toContain("object-src 'none'");
  });

  it("emits API security headers behaviorally and suppresses HSTS on localhost", async () => {
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
