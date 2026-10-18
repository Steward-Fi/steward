import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { createHash, randomUUID } from "node:crypto";
import {
  agents,
  agentWallets,
  auditEvents,
  closeDb,
  createDb,
  getDb,
  proxyAuditLog,
  tenantContextFromAuthenticatedPrincipal,
  tenants,
  withTenantRlsTransaction,
  writeAuditEvent,
} from "@stwd/db";
import { and, asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { verifyAuditChain } from "../../../api/src/services/audit";

const PLATFORM_KEY = "stw_platform_real_pg_transfer";
const PLATFORM_KEY_HASH = createHash("sha256").update(PLATFORM_KEY).digest("hex");
const HAS_REAL_PG =
  Boolean(process.env.DATABASE_URL) && process.env.STEWARD_PGLITE_MEMORY !== "true";
const submitCalls: unknown[] = [];
let submitError: Error | undefined;
let submitGate: Promise<void> | undefined;
let notifySubmitEntered: (() => void) | undefined;
const restrictedRole = `steward_platform_transfer_${randomUUID().replaceAll("-", "")}`;
const restrictedPassword = randomUUID().replaceAll("-", "");
let adminHandle: ReturnType<typeof createDb> | undefined;
let restrictedHandles: Array<ReturnType<typeof createDb>> = [];

mock.module("@stwd/policy-engine", () => ({
  aggregationLookupFromMap: () => undefined,
  aggregationQueriesForPolicies: () => [],
  aggregationQueryKey: () => "unused",
  assetAllowlistEvaluator: () => ({ passed: true }),
  evaluateTradeOrder: () => ({ approved: true, results: [] }),
  tradeLeverageCapEvaluator: () => ({ passed: true }),
  tradeVenueAllowlistEvaluator: () => ({ passed: true }),
}));

class MockHyperliquidAdapter {
  async signSendAsset(params: Record<string, unknown>) {
    return { action: { type: "sendAsset", ...params }, nonce: 1, signature: { value: "signed" } };
  }

  async submitSendAsset(signed: unknown) {
    submitCalls.push(signed);
    notifySubmitEntered?.();
    if (submitGate) await submitGate;
    if (submitError) throw submitError;
    return { status: "ok", response: { type: "default" } };
  }
}

mock.module("@stwd/venue-hyperliquid", () => ({
  HyperliquidAdapter: MockHyperliquidAdapter,
  getMarketableLimitPx: async () => "1",
  hyperliquidAssetSchema: z.union([
    z.enum(["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP", "NEAR", "HYPE", "ZEC", "XMR"]),
    z.string().regex(/^[a-z0-9]+:[A-Z0-9]+$/),
  ]),
  isBuilderPerpSymbol: (coin: string) => /^[a-z0-9]+:[A-Z0-9]+$/.test(coin),
  validateBuilderFeeEnv: () => undefined,
}));

process.env.STEWARD_AUDIT_HMAC_KEY ??= "operator-transfer-real-pg-audit-hmac-key-0123456789abcdef";

async function seed() {
  const suffix = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const tenantId = `transfer-pg-tenant-${suffix}`;
  const agentId = `transfer-pg-agent-${suffix}`;
  await getDb()
    .insert(tenants)
    .values({
      id: tenantId,
      name: "Transfer real PG",
      apiKeyHash: `hash-${suffix}`,
    });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "Transfer Agent",
    walletAddress: "0x00000000000000000000000000000000000000aa",
  });
  await getDb().insert(agentWallets).values({
    agentId,
    chainFamily: "evm",
    address: "0x00000000000000000000000000000000000000bb",
    venue: "hyperliquid",
    purpose: "perp",
  });
  return { tenantId, agentId };
}

async function buildApp(failAuditAction?: string, routeDb = getDb(), expectedTenantId?: string) {
  const { tradingPlugin } = await import("../index");
  const app = new Hono();
  const ctx = {
    db: routeDb,
    vault: {
      getWallet: async () => ({ address: "0x00000000000000000000000000000000000000bb" }),
    },
    ensureAgentForTenant: async (tenantId: string, agentId: string) =>
      expectedTenantId == null || tenantId === expectedTenantId ? { id: agentId, tenantId } : null,
    getPolicySet: async () => [],
    isValidAnyAddress: () => true,
    policyEngine: { evaluate: async () => ({ approved: true, results: [] }) },
    priceOracle: {
      getNativeUsdPrice: async () => 1,
      weiToUsd: async () => 0,
      usdToWei: async () => "0",
    },
    safeJsonParse: async (c: { req: { json: () => Promise<unknown> } }) => c.req.json(),
    writeAuditEvent: async (event: Parameters<typeof writeAuditEvent>[0]) => {
      if (event.action === failAuditAction) throw new Error("forced terminal audit failure");
      await writeAuditEvent(event);
    },
    verifyAuditChain,
    getRedisClient: () => null,
    requireAgentJwt: async (_c: unknown, next: () => Promise<void>) => next(),
    tenantAuth: async (_c: unknown, next: () => Promise<void>) => next(),
    operatorAuth: async (
      c: {
        req: { header: (name: string) => string | undefined };
        set: (key: string, value: unknown) => void;
        json: (body: unknown, status: number) => Response;
      },
      next: () => Promise<void>,
    ) => {
      c.set("tenantId", c.req.header("X-Steward-Tenant") || "default");
      if (c.req.header("X-Steward-Platform-Key") !== PLATFORM_KEY) {
        return c.json({ ok: false, error: "Invalid platform key" }, 403);
      }
      c.set("authType", "platform");
      c.set("platformKeyHash", PLATFORM_KEY_HASH);
      return next();
    },
  } as never;
  tradingPlugin.register(app as never, ctx);
  return app;
}

function transfer(
  app: Hono,
  tenantId: string,
  agentId: string,
  idempotencyKey: string,
  amountUsdc = "7.5",
) {
  return app.request("/v1/trade/hyperliquid/transfer", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Tenant": tenantId,
      "X-Steward-Platform-Key": PLATFORM_KEY,
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      agentId,
      sourceDex: "xyz",
      destinationDex: "",
      amountUsdc,
    }),
  });
}

async function actions(tenantId: string, agentId: string) {
  const rows = await getDb()
    .select({ action: auditEvents.action, metadata: auditEvents.metadata })
    .from(auditEvents)
    .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.resourceId, agentId)))
    .orderBy(asc(auditEvents.seq));
  return rows.filter(({ action }) => action.includes("recovery.transfer"));
}

describe.skipIf(!HAS_REAL_PG)("collateral transfer durable replay on real PostgreSQL", () => {
  beforeAll(async () => {
    adminHandle = createDb(process.env.DATABASE_URL as string);
    const roleRows = await adminHandle.client`
      SELECT rolsuper FROM pg_roles WHERE rolname = current_user
    `;
    if (!roleRows[0]?.rolsuper) {
      throw new Error("real-PG restricted platform proof requires a bootstrap superuser");
    }
    const databaseRows = await adminHandle.client`SELECT current_database() AS name`;
    const databaseName = String(databaseRows[0]?.name).replaceAll('"', '""');
    await adminHandle.client.unsafe(
      `CREATE ROLE ${restrictedRole} LOGIN PASSWORD '${restrictedPassword}' ` +
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
    );
    await adminHandle.client.unsafe(
      `GRANT CONNECT ON DATABASE "${databaseName}" TO ${restrictedRole}`,
    );
    await adminHandle.client.unsafe(
      `GRANT USAGE ON SCHEMA public, steward_rls TO ${restrictedRole}`,
    );
    await adminHandle.client.unsafe(
      `GRANT EXECUTE ON FUNCTION steward_rls.tenant_id() TO ${restrictedRole}`,
    );
    const platformAuthorization = await adminHandle.client`
      SELECT to_regprocedure('steward_rls.platform_authorized()') AS function
    `;
    // Some local databases may already include the later platform-authority
    // policy topology. Grant its pure GUC predicate when present so this proof
    // still exercises tenant RLS with platform_authorized left unset/false.
    if (platformAuthorization[0]?.function) {
      await adminHandle.client.unsafe(
        `GRANT EXECUTE ON FUNCTION steward_rls.platform_authorized() TO ${restrictedRole}`,
      );
    }
    await adminHandle.client.unsafe(
      `GRANT SELECT, INSERT, UPDATE ON audit_events, audit_chain_heads TO ${restrictedRole}`,
    );
    await adminHandle.client.unsafe(
      `GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO ${restrictedRole}`,
    );
    const restrictedUrl = new URL(process.env.DATABASE_URL as string);
    restrictedUrl.username = restrictedRole;
    restrictedUrl.password = restrictedPassword;
    restrictedHandles = [createDb(restrictedUrl.toString()), createDb(restrictedUrl.toString())];
    for (const handle of restrictedHandles) {
      const restrictedRows = await handle.client`
        SELECT rolsuper, rolbypassrls, rolinherit,
               has_table_privilege(current_user, 'public.proxy_audit_log', 'INSERT') AS proxy_insert
        FROM pg_roles WHERE rolname = current_user
      `;
      expect(restrictedRows[0]).toEqual(
        expect.objectContaining({
          rolsuper: false,
          rolbypassrls: false,
          rolinherit: false,
          proxy_insert: false,
        }),
      );
    }
  });

  afterAll(async () => {
    await Promise.all(restrictedHandles.map(({ client }) => client.end()));
    if (adminHandle) {
      await adminHandle.client.unsafe(`DROP OWNED BY ${restrictedRole}`);
      await adminHandle.client.unsafe(`DROP ROLE IF EXISTS ${restrictedRole}`);
      await adminHandle.client.end();
    }
    await closeDb();
  });

  test("cold workers replay terminal success and ambiguous failure from chained audit evidence", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const success = await seed();
    const first = await transfer(await buildApp(), success.tenantId, success.agentId, "pg-success");
    const replay = await transfer(
      await buildApp(),
      success.tenantId,
      success.agentId,
      "pg-success",
    );
    expect(first.status).toBe(200);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitCalls).toHaveLength(1);
    expect((await actions(success.tenantId, success.agentId)).map(({ action }) => action)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.submitted",
    ]);

    submitCalls.length = 0;
    submitError = new Error("transport status unknown secret marker");
    const ambiguous = await seed();
    const failed = await transfer(
      await buildApp(),
      ambiguous.tenantId,
      ambiguous.agentId,
      "pg-ambiguous",
    );
    const failedReplay = await transfer(
      await buildApp(),
      ambiguous.tenantId,
      ambiguous.agentId,
      "pg-ambiguous",
    );
    expect(failed.status).toBe(502);
    expect(failedReplay.status).toBe(502);
    expect(failedReplay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitCalls).toHaveLength(1);
    const ambiguousAudits = await actions(ambiguous.tenantId, ambiguous.agentId);
    expect(ambiguousAudits.at(-1)?.metadata).toEqual(
      expect.objectContaining({ ambiguousOutcome: true, phase: "submit" }),
    );
    expect(JSON.stringify(ambiguousAudits)).not.toContain("secret marker");
  });

  test("a terminal audit outage leaves durable pending evidence that prevents a cold resubmit", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const seeded = await seed();
    const first = await transfer(
      await buildApp("trade.recovery.transfer.submitted"),
      seeded.tenantId,
      seeded.agentId,
      "pg-audit-outage",
    );
    expect(first.status).toBe(200);
    const coldRetry = await transfer(
      await buildApp("trade.recovery.transfer.submitted"),
      seeded.tenantId,
      seeded.agentId,
      "pg-audit-outage",
    );
    expect(coldRetry.status).toBe(409);
    expect(coldRetry.headers.get("Retry-After")).toBe("60");
    expect(submitCalls).toHaveLength(1);
    expect((await actions(seeded.tenantId, seeded.agentId)).map(({ action }) => action)).toEqual([
      "trade.recovery.transfer.requested",
    ]);
  });

  test("restricted platform pools concurrently replay only their tenant's terminal evidence", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const seeded = await seed();
    const idempotencyKey = `restricted-${randomUUID()}`;
    const first = await transfer(
      await buildApp(undefined, getDb(), seeded.tenantId),
      seeded.tenantId,
      seeded.agentId,
      idempotencyKey,
    );
    expect(first.status).toBe(200);
    expect(submitCalls).toHaveLength(1);
    submitCalls.length = 0;

    const apps = await Promise.all(
      restrictedHandles.map(({ db }) => buildApp(undefined, db as never, seeded.tenantId)),
    );
    const [replayA, replayB] = await Promise.all(
      apps.map((app) => transfer(app, seeded.tenantId, seeded.agentId, idempotencyKey)),
    );
    for (const replay of [replayA, replayB]) {
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    }
    expect(submitCalls).toHaveLength(0);

    const foreignTenantId = `transfer-pg-foreign-${randomUUID()}`;
    await getDb()
      .insert(tenants)
      .values({
        id: foreignTenantId,
        name: "Transfer foreign PG",
        apiKeyHash: `hash-${randomUUID()}`,
      });
    const foreignContext = tenantContextFromAuthenticatedPrincipal({
      tenantId: foreignTenantId,
      method: "operator-recovery-transfer-test",
      subject: "platform-operator",
    });
    const hidden = await withTenantRlsTransaction(
      restrictedHandles[0]!.db as never,
      "postgres-js",
      foreignContext,
      async (tx) =>
        (tx as ReturnType<typeof getDb>)
          .select()
          .from(auditEvents)
          .where(eq(auditEvents.tenantId, seeded.tenantId)),
      { isolationLevel: "repeatable read", readOnly: true },
    );
    expect(hidden).toHaveLength(0);
    const denied = await transfer(apps[0]!, foreignTenantId, seeded.agentId, idempotencyKey);
    expect(denied.status).toBe(404);
    expect(denied.headers.get("Idempotency-Replayed")).toBeNull();
    expect(submitCalls).toHaveLength(0);
  });

  test("two fresh restricted workers serialize first submission before venue execution", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const seeded = await seed();
    const idempotencyKey = `fresh-race-${randomUUID()}`;
    const apps = await Promise.all(
      restrictedHandles.map(({ db }) => buildApp(undefined, db as never, seeded.tenantId)),
    );
    let releaseSubmit = () => undefined;
    submitGate = new Promise<void>((resolve) => {
      releaseSubmit = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      notifySubmitEntered = resolve;
    });
    const requests = apps.map((app) =>
      transfer(app, seeded.tenantId, seeded.agentId, idempotencyKey),
    );
    await entered;
    const peer = await Promise.race(requests);
    expect(peer.status).toBe(409);
    expect(peer.headers.get("Retry-After")).toBe("60");
    releaseSubmit();
    const responses = await Promise.all(requests);
    submitGate = undefined;
    notifySubmitEntered = undefined;
    expect(responses.map(({ status }) => status).sort()).toEqual([200, 409]);
    expect(submitCalls).toHaveLength(1);
    expect((await actions(seeded.tenantId, seeded.agentId)).map(({ action }) => action)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.submitted",
    ]);
    const proxyRows = await getDb()
      .select({ id: proxyAuditLog.id })
      .from(proxyAuditLog)
      .where(eq(proxyAuditLog.tenantId, seeded.tenantId));
    expect(proxyRows).toHaveLength(0);
  });

  test("concurrent conflicting fingerprints serialize on the idempotency identity", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const seeded = await seed();
    const idempotencyKey = `conflict-race-${randomUUID()}`;
    const apps = await Promise.all(
      restrictedHandles.map(({ db }) => buildApp(undefined, db as never, seeded.tenantId)),
    );
    let releaseSubmit = () => undefined;
    submitGate = new Promise<void>((resolve) => {
      releaseSubmit = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      notifySubmitEntered = resolve;
    });
    const requests = [
      transfer(apps[0]!, seeded.tenantId, seeded.agentId, idempotencyKey, "7.5"),
      transfer(apps[1]!, seeded.tenantId, seeded.agentId, idempotencyKey, "8.5"),
    ];
    await entered;
    const peer = await Promise.race(requests);
    expect(peer.status).toBe(409);
    expect(await peer.json()).toEqual({
      ok: false,
      error: "Idempotency key reused with a different body",
    });
    releaseSubmit();
    const responses = await Promise.all(requests);
    submitGate = undefined;
    notifySubmitEntered = undefined;
    expect(responses.map(({ status }) => status).sort()).toEqual([200, 409]);
    expect(submitCalls).toHaveLength(1);
    expect((await actions(seeded.tenantId, seeded.agentId)).map(({ action }) => action)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.submitted",
    ]);
  });
});
