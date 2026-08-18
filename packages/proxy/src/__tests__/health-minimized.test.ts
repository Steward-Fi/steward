/**
 * SEC-174 pinning test: the unauthenticated proxy /health response must stay
 * minimal — exactly { ok, service, serverTime }. The pre-fix body also leaked
 * the service version and the alias list, which are recon details an
 * unauthenticated caller can use to fingerprint the deployment and enumerate
 * proxied upstreams. serverTime stays because the API readiness probe reads
 * it. If a future change adds a field here, this test fails loudly so the
 * exposure is a deliberate review decision, not an accident.
 */
import { describe, expect, test } from "bun:test";

// Bootstrap the entrypoint's boot-time env BEFORE any dynamic import of
// `../index.ts` (it validates the JWT secret and requires a database URL at
// module load), matching the isolation posture of metrics-exposure.test.ts.
process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
process.env.STEWARD_JWT_SECRET ||= "test-proxy-health-jwt-secret-32-characters-min";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL ||= "postgres://steward:steward@127.0.0.1:5432/steward_test";

describe("proxy /health minimized body (SEC-174)", () => {
  test("unauthenticated /health exposes only ok/service/serverTime", async () => {
    const mod = await import("../index.ts");
    const app = mod.default as { fetch: (r: Request) => Promise<Response> };

    const res = await app.fetch(new Request("http://proxy.local/health"));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;

    // Exact key set — any added field (version, aliases, uptime, ...) fails
    // this pin.
    expect(Object.keys(body).sort()).toEqual(["ok", "serverTime", "service"]);
    expect(body.ok).toBe(true);
    expect(body.service).toBe("steward-proxy");
    // serverTime is the API readiness probe's liveness signal: a valid ISO
    // timestamp, nothing else.
    expect(typeof body.serverTime).toBe("string");
    expect(Number.isNaN(Date.parse(body.serverTime as string))).toBe(false);

    // Explicit anti-regression pins for the pre-fix recon fields.
    expect(body).not.toHaveProperty("version");
    expect(body).not.toHaveProperty("aliases");
  });
});
