import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `wallet-actions-tenant-${Date.now()}`;
const OTHER_TENANT_ID = `wallet-actions-other-tenant-${Date.now()}`;
const AGENT_ID = `wallet-actions-agent-${Date.now()}`;
const AGENT_WITHOUT_ALLOWLIST_ID = `wallet-actions-no-allowlist-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const BLOCKED = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN = "0x4200000000000000000000000000000000000006";

async function makeApp(tenantId = TENANT_ID) {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("userId", "wallet-actions-admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("wallet transfer actions", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "wallet-actions-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Wallet Actions Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(tenants).values({
      id: OTHER_TENANT_ID,
      name: "Other Wallet Actions Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(agents).values({
      id: AGENT_WITHOUT_ALLOWLIST_ID,
      tenantId: TENANT_ID,
      name: "Wallet Actions Agent Without Allowlist",
      walletAddress: "0x0000000000000000000000000000000000000002",
    });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-recipients",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED, TOKEN], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "approved-token-transfer-selector",
        agentId: AGENT_ID,
        type: "contract-allowlist",
        enabled: true,
        config: {
          contracts: [
            {
              address: TOKEN,
              selectors: ["0xa9059cbb"],
              constraints: {
                "0xa9059cbb": {
                  recipientAllowlist: [ALLOWED],
                  maxAmount: "99",
                },
              },
            },
          ],
        },
      });
    await getDb()
      .insert(policies)
      .values({
        id: "manual-approval-threshold",
        agentId: AGENT_ID,
        type: "auto-approve-threshold",
        enabled: true,
        config: { threshold: "999" },
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("quotes native transfers and records rejected transfer actions for status polling", async () => {
    const quoteResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer/quote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1000", chainId: 8453, broadcast: false }),
    });
    expect(quoteResponse.status).toBe(200);
    const quoteBody = (await quoteResponse.json()) as {
      ok: boolean;
      data: { type: string; token: string; request: { broadcast: boolean } };
    };
    expect(quoteBody.ok).toBe(true);
    expect(quoteBody.data.type).toBe("transfer");
    expect(quoteBody.data.token).toBe("native");
    expect(quoteBody.data.request.broadcast).toBe(false);

    const createResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: BLOCKED, amountWei: "1000", chainId: 8453, broadcast: false }),
    });
    expect(createResponse.status).toBe(403);
    const createBody = (await createResponse.json()) as {
      ok: boolean;
      data: { id: string; type: string; status: string; to: string };
    };
    expect(createBody.ok).toBe(false);
    expect(createBody.data.type).toBe("transfer");
    expect(createBody.data.status).toBe("rejected");
    expect(createBody.data.to).toBe(BLOCKED);

    const [tx] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, createBody.data.id));
    expect(tx.id).toBe(createBody.data.id);
    expect(tx.status).toBe("rejected");
    expect(tx.actionType).toBe("transfer");

    const statusResponse = await app.request(`/vault/${AGENT_ID}/actions/${createBody.data.id}`);
    expect(statusResponse.status).toBe(200);
    const statusBody = (await statusResponse.json()) as {
      ok: boolean;
      data: { id: string; status: string };
    };
    expect(statusBody.ok).toBe(true);
    expect(statusBody.data.id).toBe(createBody.data.id);
    expect(statusBody.data.status).toBe("rejected");

    const otherTenantApp = await makeApp(OTHER_TENANT_ID);
    const otherTenantStatusResponse = await otherTenantApp.request(
      `/vault/${AGENT_ID}/actions/${createBody.data.id}`,
    );
    expect(otherTenantStatusResponse.status).toBe(404);

    await getDb().insert(transactions).values({
      id: "legacy-sign-tx",
      agentId: AGENT_ID,
      status: "signed",
      toAddress: ALLOWED,
      value: "1000",
      chainId: 8453,
    });
    const legacyStatusResponse = await app.request(`/vault/${AGENT_ID}/actions/legacy-sign-tx`);
    expect(legacyStatusResponse.status).toBe(404);

    const pendingResponse = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: ALLOWED, value: "1000", chainId: 8453, broadcast: false }),
    });
    expect(pendingResponse.status).toBe(202);
    const pendingBody = (await pendingResponse.json()) as {
      ok: boolean;
      data: { id: string; status: string };
    };
    expect(pendingBody.ok).toBe(true);
    expect(pendingBody.data.status).toBe("pending_approval");

    const pendingStatusResponse = await app.request(
      `/vault/${AGENT_ID}/actions/${pendingBody.data.id}`,
    );
    expect(pendingStatusResponse.status).toBe(200);
    const pendingStatusBody = (await pendingStatusResponse.json()) as {
      ok: boolean;
      data: { status: string };
    };
    expect(pendingStatusBody.data.status).toBe("pending_approval");

    const signedActionId = "legacy-signed-transfer-action";
    await getDb()
      .insert(transactions)
      .values({
        id: signedActionId,
        agentId: AGENT_ID,
        status: "signed",
        toAddress: ALLOWED,
        value: "1000",
        chainId: 8453,
        actionType: "transfer",
        actionPayload: {
          type: "transfer",
          token: "native",
          broadcast: false,
          signedTx: "0xsigned-bearer-transaction",
        },
      });
    const signedStatusResponse = await app.request(`/vault/${AGENT_ID}/actions/${signedActionId}`);
    expect(signedStatusResponse.status).toBe(200);
    const signedStatusBody = (await signedStatusResponse.json()) as {
      ok: boolean;
      data: { status: string; signedTx?: string };
    };
    expect(signedStatusBody.ok).toBe(true);
    expect(signedStatusBody.data.status).toBe("signed");
    expect(signedStatusBody.data.signedTx).toBeUndefined();
  });

  it("fails ERC20 transfer actions closed until token-aware spend accounting exists", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: ALLOWED,
        token: TOKEN,
        value: "1000",
        chainId: 8453,
        broadcast: false,
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { id: string; token: string; to: string; value: string; status: string };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe(
      "ERC20 transfer actions require token-aware spend accounting before signing",
    );
    expect(body.data).toBeUndefined();
  });

  it("does not persist ERC20 action ids before token-aware accounting is implemented", async () => {
    const response = await app.request(`/vault/${AGENT_WITHOUT_ALLOWLIST_ID}/actions/transfer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: ALLOWED,
        token: TOKEN,
        value: "1",
        chainId: 8453,
        broadcast: false,
      }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { id: string; status: string; token: string };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe(
      "ERC20 transfer actions require token-aware spend accounting before signing",
    );
    expect(body.data).toBeUndefined();
  });
});
