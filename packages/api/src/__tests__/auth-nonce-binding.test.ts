import { afterAll, afterEach, beforeAll, describe, expect, it, mock } from "bun:test";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

process.env.NODE_ENV = "test";
process.env.STEWARD_MASTER_PASSWORD = "nonce-binding-master-password";
process.env.STEWARD_JWT_SECRET = "nonce-binding-jwt-secret-with-enough-entropy";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.SIWE_ALLOWED_DOMAINS = "steward.fi";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";

const originalFetch = globalThis.fetch;
let auth: typeof import("../routes/auth");

function siweMessage(domain: string, address: string, nonce: string) {
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to Steward",
    "",
    `URI: https://${domain}`,
    "Version: 1",
    "Chain ID: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
}

async function nonce(headers: HeadersInit = {}) {
  const response = await auth.authRoutes.request("/nonce", {
    headers: { origin: "https://steward.fi", ...headers },
  });
  return { response, body: (await response.json()) as { nonce?: string; error?: string } };
}

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  auth = await import("../routes/auth");
  await getDb().insert(tenants).values({
    id: "bound-tenant",
    name: "Bound tenant",
    apiKeyHash: "nonce-binding-api-key-hash",
    ownerAddress: "0x0000000000000000000000000000000000000742",
  });
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.APP_URL;
  delete process.env.GOOGLE_CLIENT_ID;
  delete process.env.GOOGLE_CLIENT_SECRET;
  delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
});

afterAll(async () => {
  await closeDb();
});

describe("mounted nonce and OAuth state boundaries", () => {
  it("requires an allowlisted origin and binds a nonce to domain and tenant", async () => {
    const denied = await auth.authRoutes.request("/nonce", {
      headers: { origin: "https://attacker.example" },
    });
    expect(denied.status).toBe(400);
    expect(await denied.json()).toMatchObject({
      ok: false,
      error: "SIWE nonce requests require an allowed Origin or Referer",
    });

    const issued = await nonce({ "x-steward-tenant": "bound-tenant" });
    expect(issued.response.status).toBe(200);
    expect(issued.body.nonce).toMatch(/^[A-Za-z0-9]{8,}$/);
    const mismatch = await auth.authRoutes.request("/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        message: siweMessage(
          "steward.fi",
          "0x0000000000000000000000000000000000000742",
          issued.body.nonce!,
        ),
        signature: `0x${"00".repeat(65)}`,
      }),
    });
    expect(mismatch.status).toBe(401);
    expect(((await mismatch.json()) as { error: string }).error).toContain("tenant");
  });

  it("uses APP_URL for provider callbacks even with a hostile Host", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://app.example.test/callback";
    const response = await auth.authRoutes.request(
      "/oauth/google/authorize?redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFG0123456789-_&code_challenge_method=S256",
      { headers: { host: "attacker.example" } },
    );
    expect(response.status).toBe(302);
    const provider = new URL(response.headers.get("location")!);
    expect(provider.searchParams.get("redirect_uri")).toBe(
      "https://api.example.test/auth/oauth/google/callback",
    );
    expect(provider.searchParams.get("redirect_uri")).not.toContain("attacker.example");
  });

  it("keeps callback state retryable when provider verification fails", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://app.example.test/callback";
    const state = "retryable-provider-state";
    const payload = JSON.stringify({
      provider: "google",
      redirectUri: "https://app.example.test/callback",
    });
    await auth.getAuthChallengeStore().set(`oauth:${state}`, payload);
    globalThis.fetch = mock(async () => new Response("provider rejected code", { status: 401 }));

    const failed = await auth.authRoutes.request(
      `/oauth/google/callback?code=bad-code&state=${state}`,
    );
    expect(failed.status).toBe(502);
    expect(await auth.getAuthChallengeStore().get(`oauth:${state}`)).toBe(payload);
  });

  it("rate-limits challenge allocation without returning an extra nonce", async () => {
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    process.env.NODE_ENV = "production";
    try {
      const blocked = await nonce();
      expect(blocked.response.status).toBe(429);
      expect(blocked.body.nonce).toBeUndefined();
      expect(blocked.body.error).toContain("Too many nonce requests");
    } finally {
      process.env.NODE_ENV = "test";
      process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
    }
  });
});
