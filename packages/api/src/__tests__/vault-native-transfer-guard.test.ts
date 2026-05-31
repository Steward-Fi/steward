/**
 * REAL behavioral coverage for the native-transfer gas-accounting guard on the
 * vault `/:agentId/sign` money path.
 *
 * The old vault-send-calls-spend.test.ts only `readFileSync`'d vault.ts and
 * asserted the source mentioned `eth_getCode` and "Native transfers to contract
 * recipients" — it never ran the guard. This drives the REAL route and proves
 * the two fail-closed deny branches actually fire:
 *
 *   1. a native transfer that sets `gasLimit` is refused (gas spend is not
 *      policy-accounted), and
 *   2. a native transfer whose recipient has contract code is refused.
 *
 * The recipient-code lookup is the only mocked seam: `Vault.rpcPassthrough` is a
 * read-only JSON-RPC passthrough (it would otherwise hit a public Base RPC),
 * stubbed here to return controlled `eth_getCode` results. Everything else — the
 * route, validation, and the guard logic itself — runs for real. The guard
 * returns BEFORE policy evaluation and signing, so no key material is needed.
 */
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { agents, auditEvents, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `native-guard-tenant-${Date.now()}`;
const AGENT_ID = `native-guard-agent-${Date.now()}`;
// A valid EVM address used as the recipient; its "code" is controlled per-test
// via the rpcPassthrough stub, so the same address can stand in for an EOA or a
// contract.
const RECIPIENT = "0x1234567890123456789012345678901234567890";
const CONTRACT_BYTECODE = "0x60806040523480156100";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "native-guard-owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("native transfer gas-accounting guard (real /sign path)", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "native-guard-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "native-transfer-guard-test-audit-hmac-key-0123456789abcdef";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Native Guard Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Native Guard Agent",
      walletAddress: "0x0000000000000000000000000000000000000abc",
    });
    // Allowlist the recipient so the audit-ordering test below reaches the signer
    // (policy APPROVES). The guard-only / idempotency tests all return BEFORE
    // policy evaluation, so this policy is inert for them.
    await getDb()
      .insert(policies)
      .values({
        id: `${AGENT_ID}-approved`,
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [RECIPIENT], mode: "whitelist" },
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("refuses a native transfer that sets gasLimit (gas spend not policy-accounted)", async () => {
    // The gasLimit branch returns before any RPC lookup, so no stub is needed.
    const res = await app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: RECIPIENT,
        value: "1000",
        chainId: 8453,
        gasLimit: "21000",
        broadcast: false,
      }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe(
      "Native transfers cannot set gasLimit because gas spend is not policy-accounted",
    );
  });

  it("refuses a native transfer whose recipient has contract code", async () => {
    const spy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: CONTRACT_BYTECODE,
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    try {
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: RECIPIENT,
          value: "1000",
          chainId: 8453,
          broadcast: false,
        }),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toContain("Native transfers to contract recipients are disabled");
      // The guard actually consulted the chain for recipient code.
      expect(spy).toHaveBeenCalled();
      const call = spy.mock.calls[0][0] as { method: string; params: unknown[] };
      expect(call.method).toBe("eth_getCode");
      expect(call.params[0]).toBe(RECIPIENT);
    } finally {
      spy.mockRestore();
    }
  });

  it("requires an Idempotency-Key for broadcast signing to a verified EOA (replay protection)", async () => {
    // Recipient verified as an EOA (code "0x"), so the gas-accounting guard PASSES;
    // the broadcast request then fails closed on the missing Idempotency-Key (428)
    // BEFORE any signer-permission check or signing — replay protection is a hard
    // precondition for broadcast, not an optional convenience.
    const spy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    try {
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: RECIPIENT,
          value: "1000",
          chainId: 8453,
          broadcast: true,
        }),
      });
      expect(res.status).toBe(428);
      const body = (await res.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("Broadcast signing requires an Idempotency-Key header");
    } finally {
      spy.mockRestore();
    }
  });

  it("writes the vault.sign.authorized audit BEFORE the irreversible sign (fault-injected)", async () => {
    // Recipient is a verified EOA (code "0x") AND allowlisted, so the request
    // passes the guard + policy and reaches the signer. Fault-inject the sign to
    // throw: the route must already have COMMITTED the authorization audit (which
    // is written before the sign), and must persist NOTHING as signed/broadcast.
    // If the audit were written AFTER the sign, the throw would prevent the row
    // and this test would fail — so presence-after-fault proves the ordering.
    const rpcSpy = spyOn(Vault.prototype, "rpcPassthrough").mockResolvedValue({
      jsonrpc: "2.0",
      id: 1,
      result: "0x",
    } as Awaited<ReturnType<Vault["rpcPassthrough"]>>);
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockRejectedValue(
      new Error("hsm offline"),
    );
    try {
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: RECIPIENT,
          value: "1000",
          chainId: 8453,
          broadcast: false,
        }),
      });
      expect(res.status).toBe(500);
      const body = (await res.json()) as { ok: boolean; data?: unknown };
      expect(body.ok).toBe(false);
      expect(body.data).toBeUndefined();
      expect(signSpy).toHaveBeenCalled();

      // The authorization audit survived the failed sign → it was written first.
      const authorized = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(eq(auditEvents.action, "vault.sign.authorized"), eq(auditEvents.tenantId, TENANT_ID)),
        );
      expect(authorized.length).toBe(1);

      // Fail-closed: nothing persisted as signed for this agent (the row is created
      // inside signTransaction, which threw), and the success audit was NOT written.
      const rows = await getDb()
        .select({ id: transactions.id })
        .from(transactions)
        .where(eq(transactions.agentId, AGENT_ID));
      expect(rows.length).toBe(0);
      const succeeded = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(and(eq(auditEvents.action, "vault.sign"), eq(auditEvents.tenantId, TENANT_ID)));
      expect(succeeded.length).toBe(0);
    } finally {
      rpcSpy.mockRestore();
      signSpy.mockRestore();
    }
  });

  it("fails closed when the recipient-code lookup is unavailable (RPC error)", async () => {
    const spy = spyOn(Vault.prototype, "rpcPassthrough").mockRejectedValue(new Error("rpc down"));
    try {
      const res = await app.request(`/vault/${AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: RECIPIENT,
          value: "1000",
          chainId: 8453,
          broadcast: false,
        }),
      });
      // Cannot prove the recipient is an EOA → must not sign.
      expect(res.status).toBe(502);
      const body = (await res.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toContain("recipient contract code is verified");
    } finally {
      spy.mockRestore();
    }
  });
});
