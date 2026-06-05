import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `solana-priority-fee-tenant-${Date.now()}`;
const AGENT_ID = `solana-priority-fee-agent-${Date.now()}`;
const FROM = "7v54NWdBtkjuAFJrLGsS2SXnuk8nKam81mZJeeYxVFi9";
const RECIPIENT = "6TcyBfPdBt1kjsvDZLzmBFnuMaLWiTaAt4RjUr9VA5YD";
const OVER_CAP_V0_TRANSFER =
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQACBGa+fjMsekUzMr2dCn99sFX1xe8aBq2mbZizn7aBDEc6URw0oaLLUh3xa7JGuN6OeZfOI1x+drIqPXUDokgZ3YoDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcDAgAFAsBcFQACAAkDQEIPAAAAAAADAgABDAIAAAB7AAAAAAAAAAA=";
const WITHIN_CAP_V0_TRANSFER =
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAQACBGa+fjMsekUzMr2dCn99sFX1xe8aBq2mbZizn7aBDEc6URw0oaLLUh3xa7JGuN6OeZfOI1x+drIqPXUDokgZ3YoDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcDAgAFAkANAwACAAkD6AMAAAAAAAADAgABDAIAAAB7AAAAAAAAAAA=";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", "solana-priority-fee-admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("sign-solana priority-fee cap", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "sign-solana-priority-fee-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "sign-solana-priority-fee-audit-hmac-key-32chars";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Solana Priority Fee Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Solana Priority Fee Agent",
      walletAddress: FROM,
    });
    await getDb()
      .insert(policies)
      .values([
        {
          id: `${AGENT_ID}-approved-recipient`,
          agentId: AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [RECIPIENT], mode: "whitelist" },
        },
        {
          id: `${AGENT_ID}-auto-approve-threshold`,
          agentId: AGENT_ID,
          type: "auto-approve-threshold",
          enabled: true,
          config: { threshold: "999" },
        },
      ]);
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
  });

  it("rejects a v0 transfer whose priority fee exceeds the cap before signing", async () => {
    const context = await import("../services/context");
    const originalSignSolanaTransaction = context.vault.signSolanaTransaction.bind(context.vault);
    context.vault.signSolanaTransaction = async () => {
      throw new Error("over-cap priority fee should not reach signing");
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          transaction: OVER_CAP_V0_TRANSFER,
          broadcast: false,
        }),
      });

      expect(response.status).toBe(422);
      const body = (await response.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toMatch(/priority fee.*exceeds the allowed maximum/i);
    } finally {
      context.vault.signSolanaTransaction = originalSignSolanaTransaction;
    }
  });

  it("accepts a v0 transfer whose priority fee is within the cap", async () => {
    const context = await import("../services/context");
    const originalSignSolanaTransaction = context.vault.signSolanaTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signSolanaTransaction = async (request) => {
      signCalls += 1;
      expect(request.agentId).toBe(AGENT_ID);
      expect(request.tenantId).toBe(TENANT_ID);
      expect(request.broadcast).toBe(false);
      expect(request.expectedTo).toBeUndefined();
      expect(request.expectedValue).toBeUndefined();
      return { signature: "signed-v0-transfer", broadcast: false, chainId: request.chainId };
    };

    try {
      const response = await app.request(`/vault/${AGENT_ID}/sign-solana`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          transaction: WITHIN_CAP_V0_TRANSFER,
          broadcast: false,
        }),
      });

      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        ok: boolean;
        data?: { signature: string; broadcast: boolean; chainId: number };
      };
      expect(body.ok).toBe(true);
      expect(body.data?.signature).toBe("signed-v0-transfer");
      expect(body.data?.broadcast).toBe(false);
      expect(body.data?.chainId).toBe(101);
      expect(signCalls).toBe(1);
    } finally {
      context.vault.signSolanaTransaction = originalSignSolanaTransaction;
    }
  });
});
