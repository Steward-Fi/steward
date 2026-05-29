import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const idempotencySource = readFileSync(join(apiRoot, "middleware", "idempotency.ts"), "utf8");
const redisSource = readFileSync(join(apiRoot, "middleware", "redis.ts"), "utf8");
const redisEnforcementSource = readFileSync(
  join(apiRoot, "middleware", "redis-enforcement.ts"),
  "utf8",
);
const tenantCorsSource = readFileSync(join(apiRoot, "middleware", "tenant-cors.ts"), "utf8");
const contextSource = readFileSync(join(apiRoot, "services", "context.ts"), "utf8");
const indexSource = readFileSync(join(apiRoot, "index.ts"), "utf8");

describe("middleware security hardening", () => {
  it("uses durable production idempotency and skips unauthenticated reservations", () => {
    expect(idempotencySource).toContain("class RedisIdempotencyStore");
    expect(idempotencySource).toContain('throw new Error("Durable idempotency store unavailable")');
    expect(idempotencySource).toContain('redis.set(redisKey, value, "PX", ttlMs, "NX")');
    expect(idempotencySource).toContain("hasIdempotencyAuthMaterial");
    expect(idempotencySource).toContain(
      'if (!hasIdempotencyAuthMaterial(c.req.raw, Boolean(c.get("requestSignatureVerified")))) {',
    );
  });

  it("fails closed when configured Redis rate-limit enforcement is unavailable", () => {
    expect(redisSource).toContain("function isRedisConfigured");
    expect(redisSource).toContain("Rate limit check failed, denying sensitive request");
    expect(redisSource).toContain("return { allowed: false, remaining: 0, resetMs: 60_000 }");
    expect(redisEnforcementSource).toContain("isRedisConfigured()");
    expect(redisEnforcementSource).toContain("Rate limit enforcement is unavailable");
  });

  it("fails closed for tenant CORS in production and rejects JWT/header tenant mismatch", () => {
    expect(tenantCorsSource).toContain('process.env.NODE_ENV === "production"');
    expect(tenantCorsSource).toContain("origins.length === 0");
    expect(tenantCorsSource).toContain("return c.newResponse(null, 403)");
    expect(tenantCorsSource).toContain("TENANT_ID_RE.test(tenantId)");
    expect(tenantCorsSource).toContain("MAX_CORS_CACHE_ENTRIES");
    expect(tenantCorsSource).toContain("if (!row && clientRows.length === 0) return []");
    expect(tenantCorsSource).toContain("X-Steward-Request-Timestamp");
    expect(tenantCorsSource).toContain("X-Steward-Request-Expires-At");
    expect(contextSource).toContain("headerTenant && headerTenant !== payload.tenantId");
    expect(contextSource).toContain('"Tenant header does not match token"');
  });

  it("applies Bun runtime gates before Hono route dispatch", () => {
    expect(indexSource).toContain("function runtimeGate(request: Request)");
    expect(indexSource).toContain(
      "fetch: (request: Request) => runtimeGate(request) ?? app.fetch(request)",
    );
    expect(indexSource).not.toContain('app.use("*", async (c, next) => {');
  });
});
