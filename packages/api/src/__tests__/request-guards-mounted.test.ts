import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

/**
 * SEC-010 / SEC-150 regression: the request-expiry + authorization-signature
 * guards must be MOUNTED on the real app (they were unmounted dead code while
 * /openapi.json and the tenant security checklist claimed enforcement), and
 * the sensitive-path prefix list must cover the key-material / money-movement
 * surfaces that were missing.
 *
 * Default posture is verify-when-present: requests WITHOUT guard headers flow
 * through to route auth, but a request carrying stale freshness or an invalid
 * signature header fails closed.
 */
describe("mounted request guards (SEC-010/SEC-150)", () => {
  let app: Awaited<typeof import("../app")>["app"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "mounted-guards-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "mounted-guards-audit-hmac-key-with-enough-entropy";
    process.env.STEWARD_REQUEST_SIGNING_SECRETS = "mounted-guards-signing-secret";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    ({ app } = await import("../app"));
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_REQUEST_SIGNING_SECRETS;
  });

  function stalePost(path: string, headers: Record<string, string> = {}) {
    return app.request(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-request-timestamp": String(Math.floor(Date.now() / 1000) - 3600),
        ...headers,
      },
      body: "{}",
    });
  }

  it("rejects stale freshness headers on sensitive mutating routes", async () => {
    const response = await stalePost("/vault/agent-1/sign");
    expect(response.status).toBe(408);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: "Request timestamp is stale",
    });
  });

  it("rejects invalid request signatures on sensitive mutating routes", async () => {
    const response = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-request-timestamp": String(Math.floor(Date.now() / 1000)),
        "x-steward-signature": `v1=${"0".repeat(64)}`,
        "idempotency-key": "mounted-guards-invalid-signature",
      },
      body: "{}",
    });
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: "Invalid request signature",
    });
  });

  it("admits unsigned sensitive requests through to route auth (verify-when-present)", async () => {
    const response = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    // Reaches tenantAuth (403), NOT a guard rejection (400/408/401) — unsigned
    // browser/SDK clients keep working until an operator opts into strict mode.
    expect(response.status).toBe(403);
  });

  it("covers every sensitive route prefix", async () => {
    for (const path of [
      "/v1/kms/keys/key-1/decrypt",
      "/v2/provider-actions/action-1/execute",
      "/dashboard/some-mutation",
      "/agent-enroll",
      "/v1/agent-enroll",
    ]) {
      const response = await stalePost(path);
      expect(response.status).toBe(408);
    }
  });
});
