import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `wallet-batch-alias-${Date.now()}`;

async function makeApp() {
  const { createAgentBatch } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", "wallet-batch-admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.post("/wallets/batch", createAgentBatch);
  app.post("/v1/wallets/batch", createAgentBatch);
  return app;
}

describe("wallet batch aliases", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "wallet-batch-alias-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "wallet-batch-alias-audit-hmac-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Wallet Batch Alias Tenant", apiKeyHash: "hash" });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("creates server wallets through the Privy-style wallets batch alias", async () => {
    const response = await app.request("/wallets/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallets: [{ id: "wallet-ref-1", name: "Treasury Wallet", externalId: "crm-wallet-1" }],
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        created: Array<{ id: string; name: string; platformId?: string }>;
        errors: unknown[];
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.errors).toEqual([]);
    expect(body.data.created).toHaveLength(1);
    expect(body.data.created[0].name).toBe("Treasury Wallet");
    expect(body.data.created[0].platformId).toBe("crm-wallet-1");

    const rows = await getDb()
      .select({ id: agents.id, platformId: agents.platformId })
      .from(agents)
      .where(eq(agents.platformId, "crm-wallet-1"));
    expect(rows).toHaveLength(1);
  });

  it("keeps the v1 wallets batch alias on the same contract", async () => {
    const response = await app.request("/v1/wallets/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallets: [{ id: "wallet-ref-2", name: "Ops Wallet", externalId: "crm-wallet-2" }],
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { created: Array<{ platformId?: string }>; errors: unknown[] };
    };
    expect(body.ok).toBe(true);
    expect(body.data.errors).toEqual([]);
    expect(body.data.created[0].platformId).toBe("crm-wallet-2");
  });
});
