import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { getDb, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ─── Test Config ──────────────────────────────────────────────────────────

const TEST_PORT = 3299;
const BASE_URL = `http://localhost:${TEST_PORT}`;
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

const TENANT_WITH_KEY = "test-tenant-with-key";
const TENANT_WITHOUT_KEY = "test-tenant-no-key";
type ErrorBody = { error: string };

let validApiKey: string;
const contextSource = readFileSync(join(import.meta.dir, "..", "services", "context.ts"), "utf8");

// ─── Setup ────────────────────────────────────────────────────────────────

beforeAll(async () => {
  if (!hasDatabaseUrl) {
    return;
  }
  const db = getDb();
  const apiKeyPair = generateApiKey();
  validApiKey = apiKeyPair.key;

  // Create tenant WITH an API key hash
  await db
    .insert(tenants)
    .values({
      id: TENANT_WITH_KEY,
      name: "Tenant With Key",
      apiKeyHash: apiKeyPair.hash,
    })
    .onConflictDoNothing();

  // Create tenant WITHOUT an API key hash (simulating empty STEWARD_DEFAULT_TENANT_KEY)
  await db
    .insert(tenants)
    .values({
      id: TENANT_WITHOUT_KEY,
      name: "Tenant No Key",
      apiKeyHash: "", // Empty — no auth configured
    })
    .onConflictDoNothing();
});

afterAll(async () => {
  if (!hasDatabaseUrl) {
    return;
  }
  const db = getDb();
  await db.delete(tenants).where(eq(tenants.id, TENANT_WITH_KEY));
  await db.delete(tenants).where(eq(tenants.id, TENANT_WITHOUT_KEY));
});

// ─── Tests ────────────────────────────────────────────────────────────────

describeWithDatabase("Tenant API Key Authentication", () => {
  describe("Tenant with API key configured", () => {
    it("allows access with valid API key", async () => {
      const res = await fetch(`${BASE_URL}/agents`, {
        headers: {
          "X-Steward-Tenant": TENANT_WITH_KEY,
          "X-Steward-Key": validApiKey,
        },
      });
      expect(res.status).toBe(200);
    });

    it("rejects access with invalid API key", async () => {
      const res = await fetch(`${BASE_URL}/agents`, {
        headers: {
          "X-Steward-Tenant": TENANT_WITH_KEY,
          "X-Steward-Key": "stw_invalid_key",
        },
      });
      expect(res.status).toBe(403);
    });

    it("rejects access with no API key", async () => {
      const res = await fetch(`${BASE_URL}/agents`, {
        headers: {
          "X-Steward-Tenant": TENANT_WITH_KEY,
        },
      });
      expect(res.status).toBe(403);
    });
  });

  describe("Tenant without API key configured (Bug 3 fix)", () => {
    it("matches missing-tenant failures when no API key is configured and no key is sent", async () => {
      const res = await fetch(`${BASE_URL}/agents`, {
        headers: {
          "X-Steward-Tenant": TENANT_WITHOUT_KEY,
          // No X-Steward-Key
        },
      });

      expect(res.status).toBe(403);
      const json = (await res.json()) as ErrorBody;
      expect(json.error).toBe("Forbidden");
    });

    it("matches missing-tenant failures when no API key is configured and a key is sent", async () => {
      const res = await fetch(`${BASE_URL}/agents`, {
        headers: {
          "X-Steward-Tenant": TENANT_WITHOUT_KEY,
          "X-Steward-Key": "stw_some_key",
        },
      });

      expect(res.status).toBe(403);
      const json = (await res.json()) as ErrorBody;
      expect(json.error).toBe("Forbidden");
    });
  });

  describe("Non-existent tenant", () => {
    it("matches invalid-key failures so tenant IDs cannot be enumerated", async () => {
      const res = await fetch(`${BASE_URL}/agents`, {
        headers: {
          "X-Steward-Tenant": "nonexistent-tenant-12345",
          "X-Steward-Key": "stw_whatever",
        },
      });
      expect(res.status).toBe(403);
      const json = (await res.json()) as ErrorBody;
      expect(json.error).toBe("Forbidden");
    });
  });
});

describe("tenantAuth API-key oracle hardening", () => {
  it("keeps missing, invalid, and disabled tenant API-key failures indistinguishable", () => {
    const apiKeyFallbackStart = contextSource.indexOf(
      'const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID',
    );
    const apiKeyFallbackEnd = contextSource.indexOf("export async function sessionAuth");
    expect(apiKeyFallbackStart).toBeGreaterThanOrEqual(0);
    expect(apiKeyFallbackEnd).toBeGreaterThan(apiKeyFallbackStart);
    const apiKeyFallback = contextSource.slice(apiKeyFallbackStart, apiKeyFallbackEnd);

    expect(apiKeyFallback).toContain(
      "if (!tenant.apiKeyHash || !validateApiKey(apiKey, tenant.apiKeyHash))",
    );
    expect(apiKeyFallback).not.toContain('error: "Tenant not found" }, 404');
    expect(apiKeyFallback).not.toContain("Tenant not configured for API key auth");
    expect(apiKeyFallback).not.toContain("API key required");
  });
});
