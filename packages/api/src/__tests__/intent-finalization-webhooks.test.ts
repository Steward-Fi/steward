import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditEvents,
  closeDb,
  getDb,
  intents,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

setDefaultTimeout(60_000);

const TENANT_ID = `intent-finalization-${crypto.randomUUID()}`;
const AGENT_ID = `intent-finalization-agent-${crypto.randomUUID()}`;
const ADMIN_USER_ID = crypto.randomUUID();
const OTHER_ADMIN_USER_ID = crypto.randomUUID();
const RECIPIENTS = [
  "0x0000000000000000000000000000000000000001",
  "0x0000000000000000000000000000000000000002",
] as const;
const ENV_KEYS = [
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_PGLITE_MEMORY",
] as const;
const previousEnv = new Map<string, string | undefined>();

type WebhookCall = {
  type: string;
  payload: Record<string, unknown>;
  auditVisible: Promise<boolean> | null;
};

let webhookCalls: WebhookCall[] = [];
let verifyAuditBeforeDispatch = false;
const dispatchWebhookMock = mock(
  (tenantId: string, _agentId: string, type: string, payload: Record<string, unknown>) => {
    const intentId = String(payload.intent_id ?? payload.actionId ?? "");
    webhookCalls.push({
      type,
      payload,
      auditVisible: verifyAuditBeforeDispatch
        ? getDb()
            .select({ id: auditEvents.id })
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.tenantId, tenantId),
                eq(auditEvents.action, "intent.executed"),
                eq(auditEvents.resourceId, intentId),
              ),
            )
            .then((rows) => rows.length === 1)
        : null,
    });
    return Promise.resolve();
  },
);
const enqueueWebhookMock = mock(
  async (
    _tx: unknown,
    tenantId: string,
    _agentId: string,
    type: string,
    payload: Record<string, unknown>,
  ) => {
    const intentId = String(payload.intent_id ?? payload.actionId ?? "");
    webhookCalls.push({
      type,
      payload,
      auditVisible: verifyAuditBeforeDispatch
        ? getDb()
            .select({ id: auditEvents.id })
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.tenantId, tenantId),
                eq(auditEvents.action, "intent.executed"),
                eq(auditEvents.resourceId, intentId),
              ),
            )
            .then((rows) => rows.length === 1)
        : null,
    });
  },
);

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
  enqueueWebhookDurablyWithinTx: enqueueWebhookMock,
}));

async function makeApp(auth: "api-key" | "admin" | "other-admin") {
  const { intentRoutes } = await import("../routes/intents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (auth === "api-key") {
      c.set("authType", "api-key");
    } else {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", auth === "admin" ? ADMIN_USER_ID : OTHER_ADMIN_USER_ID);
      c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.onError(() => Response.json({ ok: false, error: "Internal server error" }, { status: 500 }));
  app.route("/intents", intentRoutes);
  return app;
}

let apiApp: Awaited<ReturnType<typeof makeApp>>;
let adminApp: Awaited<ReturnType<typeof makeApp>>;
let otherAdminApp: Awaited<ReturnType<typeof makeApp>>;
let originalFetch: typeof globalThis.fetch;

async function createAuthorizedIntent(
  kind: "transfer" | "send_calls",
  broadcast = false,
): Promise<string> {
  const payload =
    kind === "transfer"
      ? {
          action: "transfer",
          transfer: {
            to: RECIPIENTS[0],
            value: "1",
            chainId: 84532,
            gasLimit: "21000",
            broadcast,
          },
        }
      : {
          action: "send_calls",
          chainId: 84532,
          broadcast: false,
          calls: [
            { to: RECIPIENTS[0], value: "1" },
            { to: RECIPIENTS[1], value: "2" },
          ],
        };
  const response = await apiApp.request("/intents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      intentType: "wallet_action",
      agentId: AGENT_ID,
      payload,
    }),
  });
  expect(response.status).toBe(201);
  const created = (await response.json()) as { data: { id: string } };
  const authorize = await adminApp.request(`/intents/${created.data.id}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  expect(authorize.status).toBe(200);
  return created.data.id;
}

async function executeIntent(id: string) {
  return otherAdminApp.request(`/intents/${id}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
}

beforeAll(async () => {
  for (const key of ENV_KEYS) previousEnv.set(key, process.env[key]);
  process.env.STEWARD_AUDIT_HMAC_KEY = "intent-finalization-audit-hmac-key-with-enough-entropy";
  process.env.STEWARD_MASTER_PASSWORD = "intent-finalization-master-password";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  __resetAuditHmacKeyCacheForTests();

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Intent finalization tenant",
    apiKeyHash: "intent-finalization-key-hash",
  });
  await getDb()
    .insert(users)
    .values([
      { id: ADMIN_USER_ID, email: `intent-admin-${ADMIN_USER_ID}@example.test` },
      { id: OTHER_ADMIN_USER_ID, email: `intent-other-${OTHER_ADMIN_USER_ID}@example.test` },
    ]);
  await getDb()
    .insert(userTenants)
    .values([
      { userId: ADMIN_USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: OTHER_ADMIN_USER_ID, tenantId: TENANT_ID, role: "admin" },
    ]);
  const { vault } = await import("../services/context");
  await vault.createAgent(TENANT_ID, AGENT_ID, "Intent finalization agent");
  await getDb()
    .insert(policies)
    .values({
      id: `policy-${crypto.randomUUID()}`,
      agentId: AGENT_ID,
      type: "approved-addresses",
      enabled: true,
      config: { mode: "whitelist", addresses: [...RECIPIENTS] },
    });

  apiApp = await makeApp("api-key");
  adminApp = await makeApp("admin");
  otherAdminApp = await makeApp("other-admin");
  originalFetch = globalThis.fetch;
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body ?? "{}")) as { id?: number; method?: string };
    const result =
      request.method === "eth_getTransactionCount"
        ? "0x0"
        : request.method === "eth_gasPrice"
          ? "0x3b9aca00"
          : null;
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id ?? 1, result }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
});

beforeEach(() => {
  webhookCalls = [];
  verifyAuditBeforeDispatch = false;
  dispatchWebhookMock.mockClear();
  enqueueWebhookMock.mockClear();
});

afterAll(async () => {
  globalThis.fetch = originalFetch;
  try {
    await closeDb();
  } finally {
    for (const key of ENV_KEYS) {
      const value = previousEnv.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    __resetAuditHmacKeyCacheForTests();
  }
});

describe("intent finalization webhook hardening", () => {
  it("rolls back the terminal status and emits no success webhook when required audit fails", async () => {
    const id = await createAuthorizedIntent("transfer");
    webhookCalls = [];
    await getDb().execute(
      sql.raw(`
      CREATE FUNCTION fail_intent_executed_audit() RETURNS trigger AS $$
      BEGIN
        IF NEW.action = 'intent.executed' AND NEW.resource_id = '${id}' THEN
          RAISE EXCEPTION 'intent completion audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `),
    );
    await getDb().execute(
      sql.raw(`
      CREATE TRIGGER fail_intent_executed_audit_trigger
      BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION fail_intent_executed_audit();
    `),
    );

    try {
      const response = await executeIntent(id);
      expect(response.status).toBe(500);
      const [stored] = await getDb().select().from(intents).where(eq(intents.id, id));
      expect(stored.status).toBe("executing");
      expect(stored.executionResult).toMatchObject({
        recoveryVersion: 1,
        state: "completed",
        result: {
          handler: "wallet_action.transfer",
          actionId: id,
        },
      });
      expect(webhookCalls).toHaveLength(0);
      const completionAudits = await getDb()
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, "intent.executed"), eq(auditEvents.resourceId, id)));
      expect(completionAudits).toHaveLength(0);
    } finally {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS fail_intent_executed_audit_trigger ON audit_events"),
      );
      await getDb().execute(sql.raw("DROP FUNCTION IF EXISTS fail_intent_executed_audit()"));
    }

    verifyAuditBeforeDispatch = true;
    const recovered = await executeIntent(id);
    expect(recovered.status).toBe(200);
    expect(webhookCalls.map((call) => call.type)).toEqual([
      "wallet_action.transfer.succeeded",
      "intent.executed",
    ]);
    expect(await Promise.all(webhookCalls.map((call) => call.auditVisible))).toEqual([true, true]);
  });

  for (const kind of ["transfer", "send_calls"] as const) {
    it(`commits ${kind} audit before exactly ordered success webhooks and does not replay them`, async () => {
      const id = await createAuthorizedIntent(kind);
      webhookCalls = [];
      verifyAuditBeforeDispatch = true;

      const response = await executeIntent(id);
      expect(response.status).toBe(200);
      expect(webhookCalls.map((call) => call.type)).toEqual([
        `wallet_action.${kind}.succeeded`,
        "intent.executed",
      ]);
      expect(await Promise.all(webhookCalls.map((call) => call.auditVisible))).toEqual([
        true,
        true,
      ]);

      webhookCalls = [];
      const replay = await executeIntent(id);
      expect(replay.status).toBe(409);
      expect(webhookCalls).toHaveLength(0);
    });
  }

  it("allows only one concurrent finalizer to emit success effects", async () => {
    const id = await createAuthorizedIntent("transfer");
    webhookCalls = [];
    const responses = await Promise.all([executeIntent(id), executeIntent(id)]);

    expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
    expect(webhookCalls.map((call) => call.type)).toEqual([
      "wallet_action.transfer.succeeded",
      "intent.executed",
    ]);
    const completionAudits = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.action, "intent.executed"), eq(auditEvents.resourceId, id)));
    expect(completionAudits).toHaveLength(1);
  });

  it("fails closed when mounted PGLite cannot create an autonomous reservation", async () => {
    const id = await createAuthorizedIntent("transfer");
    webhookCalls = [];
    const { withAuthenticatedTenantDatabase } = await import("../services/context");

    const response = await withAuthenticatedTenantDatabase(
      TENANT_ID,
      "session-jwt",
      OTHER_ADMIN_USER_ID,
      () => executeIntent(id),
      OTHER_ADMIN_USER_ID,
    );

    expect(response.status).toBe(500);
    const [stored] = await getDb().select().from(intents).where(eq(intents.id, id));
    expect(stored).toMatchObject({ status: "authorized", executionResult: null });
    expect(webhookCalls).toHaveLength(0);
  });

  it("retains an ambiguous broadcast and never sends it again", async () => {
    const id = await createAuthorizedIntent("transfer", true);
    webhookCalls = [];
    const suiteFetch = globalThis.fetch;
    let rawSends = 0;
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const rpc = JSON.parse(String(init?.body ?? "{}")) as {
        id?: number;
        method?: string;
      };
      let result: unknown;
      if (rpc.method === "eth_chainId") result = "0x14a34";
      else if (rpc.method === "eth_getTransactionCount") result = "0x0";
      else if (rpc.method === "eth_estimateGas") result = "0x5208";
      else if (rpc.method === "eth_gasPrice") result = "0x3b9aca00";
      else if (rpc.method === "eth_maxPriorityFeePerGas") result = "0x3b9aca00";
      else if (rpc.method === "eth_getBlockByNumber") {
        result = {
          baseFeePerGas: "0x3b9aca00",
          difficulty: "0x0",
          extraData: "0x",
          gasLimit: "0x1c9c380",
          gasUsed: "0x0",
          hash: `0x${"11".repeat(32)}`,
          logsBloom: `0x${"00".repeat(256)}`,
          miner: `0x${"00".repeat(20)}`,
          mixHash: `0x${"22".repeat(32)}`,
          nonce: "0x0000000000000000",
          number: "0x1",
          parentHash: `0x${"33".repeat(32)}`,
          receiptsRoot: `0x${"44".repeat(32)}`,
          sha3Uncles: `0x${"55".repeat(32)}`,
          size: "0x1",
          stateRoot: `0x${"66".repeat(32)}`,
          timestamp: "0x1",
          totalDifficulty: "0x0",
          transactions: [],
          transactionsRoot: `0x${"77".repeat(32)}`,
          uncles: [],
        };
      } else if (rpc.method === "eth_sendRawTransaction") {
        rawSends++;
        throw new Error("response lost after accepted raw transaction");
      } else if (rpc.method === "eth_getTransactionByHash") result = null;
      else throw new Error(`unexpected RPC method ${rpc.method}`);
      return Response.json({ jsonrpc: "2.0", id: rpc.id ?? 1, result });
    }) as typeof fetch;

    try {
      const first = await executeIntent(id);
      expect(first.status).toBe(202);
      const firstBody = (await first.json()) as {
        data: { executionState: string; recoveryRequired: boolean };
      };
      expect(firstBody.data).toMatchObject({
        executionState: "outcome_unknown",
        recoveryRequired: true,
      });
      expect(rawSends).toBe(1);

      const [stored] = await getDb().select().from(intents).where(eq(intents.id, id));
      expect(stored).toMatchObject({
        status: "executing",
        executionResult: {
          recoveryVersion: 1,
          state: "outcome_unknown",
          executionDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
          outcomeHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
          outcomeDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        },
      });
      expect(
        await getDb().select().from(transactions).where(eq(transactions.id, id)),
      ).toMatchObject([
        { status: "outcome_unknown", txHash: expect.stringMatching(/^0x[0-9a-f]{64}$/) },
      ]);

      const retry = await executeIntent(id);
      expect(retry.status).toBe(202);
      expect(rawSends).toBe(1);
      expect(webhookCalls).toHaveLength(0);
    } finally {
      globalThis.fetch = suiteFetch;
    }
  });
});
