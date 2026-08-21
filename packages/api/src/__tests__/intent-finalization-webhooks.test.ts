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

async function createAuthorizedIntent(kind: "transfer" | "send_calls"): Promise<string> {
  const payload =
    kind === "transfer"
      ? {
          action: "transfer",
          transfer: {
            to: RECIPIENTS[0],
            value: "1",
            chainId: 84532,
            broadcast: false,
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
        handler: "wallet_action.transfer",
        actionId: id,
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
});
