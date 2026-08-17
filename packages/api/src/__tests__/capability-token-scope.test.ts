/**
 * SEC-033 regression: a token-mode capability token (scopes `["cap:<manifest>"]`)
 * must NOT authenticate as a general agent credential on the tenant surface.
 *
 * The capability issuance layer (packages/plugin-capabilities) mints short-lived
 * tokens documented as "authorizes EXACTLY this capability and nothing else".
 * Before the fix they also carried the broad `agent` scope, and tenantAuth
 * accepted any HS256 `scope === "agent"` bearer — so the "least-privilege"
 * token worked on every agent-token endpoint (trade-session self-management,
 * token-status reads, policy reads, ...). These tests exercise the REAL app +
 * tenantAuth against an in-memory PGLite db and assert both halves of the fix:
 *
 *   1. tenantAuth refuses any agent token carrying a `cap:` scope (even one
 *      that also stamps the broad `agent` scope — defense in depth).
 *   2. a plain `agent`-scoped token still passes the gate (control).
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { Hono } from "hono";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30000);

const TENANT_ID = `cap-scope-tenant-${Date.now()}`;
const AGENT_ID = `cap-scope-agent-${Date.now()}`;

let app: Hono<{ Variables: AppVariables }>;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "cap-scope-test-master-password";
  process.env.STEWARD_JWT_SECRET ??= "cap-scope-test-jwt-secret-with-enough-entropy-0123456789";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "c".repeat(64);

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const { app: realApp } = await import("../app");
  app = realApp;

  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Cap Scope Tenant", apiKeyHash: "hash" })
    .onConflictDoNothing();
  await getDb()
    .insert(agents)
    .values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: AGENT_ID,
      walletAddress: "0x0000000000000000000000000000000000000c0c",
    })
    .onConflictDoNothing();
});

afterAll(async () => {
  await closeDb();
});

/** Probe an agent-token-gated route (GET /agents/:agentId/policy). */
async function probeAsAgent(token: string): Promise<number> {
  const res = await app.request(`/agents/${AGENT_ID}/policy`, {
    headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": TENANT_ID },
  });
  return res.status;
}

describe("capability-scoped (cap:) tokens are not general agent credentials", () => {
  it("rejects a token carrying ONLY a cap: scope", async () => {
    const token = await signAgentToken(
      { agentId: AGENT_ID, tenantId: TENANT_ID, scopes: ["cap:github:app:org"] },
      "5m",
    );
    expect(await probeAsAgent(token)).toBe(403);
  });

  it("rejects a token carrying cap: alongside the broad agent scope", async () => {
    const token = await signAgentToken(
      { agentId: AGENT_ID, tenantId: TENANT_ID, scopes: ["agent", "cap:github:app:org"] },
      "5m",
    );
    expect(await probeAsAgent(token)).toBe(403);
  });

  it("still accepts a plain agent-scoped token (control)", async () => {
    const token = await signAgentToken(
      { agentId: AGENT_ID, tenantId: TENANT_ID, scopes: ["agent"] },
      "5m",
    );
    // 404 (no policy row) — the point is the tenant auth gate did NOT 403.
    expect(await probeAsAgent(token)).toBe(404);
  });
});
