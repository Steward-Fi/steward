import { and, eq, gte, sql } from "drizzle-orm";
import { Hono, type Context, type Next } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";

import { hashApiKey, validateApiKey } from "@steward/auth";
import {
  agents,
  approvalQueue,
  closeDb,
  getDb,
  policies,
  tenants,
  toPolicyRule,
  toSignRequest,
  toTxRecord,
  transactions,
} from "@steward/db";
import { PolicyEngine } from "@steward/policy-engine";
import type {
  AgentIdentity,
  ApiResponse,
  PolicyRule,
  SignRequest,
  Tenant,
  TenantConfig,
} from "@steward/shared";
import { Vault } from "@steward/vault";
import { WebhookDispatcher } from "@steward/webhooks";

const API_VERSION = process.env.API_VERSION || "0.1.0";
const startTime = Date.now();
const PORT = parseInt(process.env.PORT || "3200", 10);
const DEFAULT_TENANT_ID = "default";
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 100;

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

const DATABASE_URL = requireEnv("DATABASE_URL");
const MASTER_PASSWORD = requireEnv("STEWARD_MASTER_PASSWORD");

if (!Number.isInteger(PORT) || PORT <= 0) {
  throw new Error("PORT must be a positive integer");
}

process.env.DATABASE_URL = DATABASE_URL;

const db = getDb();
const vault = new Vault({
  masterPassword: MASTER_PASSWORD,
  rpcUrl: process.env.RPC_URL || "https://mainnet.base.org",
  chainId: 8453,
});
const policyEngine = new PolicyEngine();
const webhookDispatcher = new WebhookDispatcher();

const defaultTenantConfig: TenantConfig = {
  id: DEFAULT_TENANT_ID,
  name: "Default Tenant",
};

const tenantConfigs = new Map<string, TenantConfig>([[defaultTenantConfig.id, defaultTenantConfig]]);

const defaultTenantReady = db
  .insert(tenants)
  .values({
    id: DEFAULT_TENANT_ID,
    name: "Default Tenant",
    apiKeyHash: process.env.STEWARD_DEFAULT_TENANT_KEY || "",
  })
  .onConflictDoNothing();

type AppVariables = {
  tenant: Tenant;
  tenantConfig: TenantConfig;
  tenantId: string;
};

const app = new Hono<{ Variables: AppVariables }>();
const requestLog = new Map<string, { count: number; resetAt: number }>();
let isShuttingDown = false;

app.use("*", cors());
app.use("*", logger());
app.use("*", async (c, next) => {
  if (c.req.path === "/health") {
    return next();
  }

  if (isShuttingDown) {
    return c.json<ApiResponse>({ ok: false, error: "Server is shutting down" }, 503);
  }

  const forwardedFor = c.req.header("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || c.req.header("x-real-ip") || "unknown";
  const now = Date.now();
  const current = requestLog.get(ip);

  if (!current || current.resetAt <= now) {
    requestLog.set(ip, {
      count: 1,
      resetAt: now + RATE_LIMIT_WINDOW_MS,
    });
    return next();
  }

  if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
    c.header("Retry-After", Math.ceil((current.resetAt - now) / 1000).toString());
    return c.json<ApiResponse>({ ok: false, error: "Rate limit exceeded" }, 429);
  }

  current.count += 1;
  requestLog.set(ip, current);

  return next();
});

const requestLogCleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [ip, entry] of requestLog.entries()) {
    if (entry.resetAt <= now) {
      requestLog.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

function getTenantPayload(tenant: Tenant): Tenant & TenantConfig {
  const config = tenantConfigs.get(tenant.id);
  return {
    ...tenant,
    name: config?.name || tenant.name,
    webhookUrl: config?.webhookUrl,
    defaultPolicies: config?.defaultPolicies,
  };
}

async function findTenant(tenantId: string): Promise<Tenant | undefined> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.id, tenantId));
  return tenant;
}

async function ensureAgentForTenant(
  tenantId: string,
  agentId: string
): Promise<AgentIdentity | undefined> {
  return vault.getAgent(tenantId, agentId);
}

async function tenantAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
  options?: { requireTenantMatch?: string }
) {
  await defaultTenantReady;

  const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
  const tenant = await findTenant(tenantId);

  if (!tenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  }

  if (options?.requireTenantMatch && tenantId !== options.requireTenantMatch) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  const apiKey = c.req.header("X-Steward-Key") || "";
  if (tenant.apiKeyHash && !validateApiKey(apiKey, tenant.apiKeyHash)) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  c.set("tenantId", tenantId);
  c.set("tenant", tenant);
  c.set("tenantConfig", tenantConfigs.get(tenantId) || { id: tenant.id, name: tenant.name });

  await next();
}

async function getPolicySet(tenantId: string, agentId: string): Promise<PolicyRule[]> {
  const storedPolicies = await db
    .select()
    .from(policies)
    .where(eq(policies.agentId, agentId));

  if (storedPolicies.length > 0) {
    return storedPolicies.map(toPolicyRule);
  }

  return tenantConfigs.get(tenantId)?.defaultPolicies || [];
}

async function getTransactionStats(agentId: string) {
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 3600_000);
  const oneDayAgo = new Date(now.getTime() - 86400_000);
  const oneWeekAgo = new Date(now.getTime() - 604800_000);

  // ISO strings for raw sql`` templates (postgres.js can't serialize Date objects)
  const oneHourAgoStr = oneHourAgo.toISOString();
  const oneDayAgoStr = oneDayAgo.toISOString();

  const [stats] = await db
    .select({
      recentTxCount1h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneHourAgoStr}::timestamptz)`,
      recentTxCount24h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneDayAgoStr}::timestamptz)`,
      spentToday: sql<string>`
        coalesce(
          sum(
            case
              when ${transactions.createdAt} >= ${oneDayAgoStr}::timestamptz then (${transactions.value})::numeric
              else 0
            end
          ),
          0
        )::text
      `,
      spentThisWeek: sql<string>`coalesce(sum((${transactions.value})::numeric), 0)::text`,
    })
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        gte(transactions.createdAt, oneWeekAgo),
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`
      )
    );

  return {
    recentTxCount1h: Number(stats?.recentTxCount1h ?? 0),
    recentTxCount24h: Number(stats?.recentTxCount24h ?? 0),
    spentToday: BigInt(stats?.spentToday ?? "0"),
    spentThisWeek: BigInt(stats?.spentThisWeek ?? "0"),
  };
}

app.use("/agents", (c, next) => tenantAuth(c, next));
app.use("/agents/*", (c, next) => tenantAuth(c, next));
app.use("/vault/*", (c, next) => tenantAuth(c, next));
app.use("/tenants/:id", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") })
);
app.use("/tenants/:id/webhook", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") })
);

app.get("/", (c) => c.json({ name: "steward", version: API_VERSION, status: "running" }));
app.get("/health", (c) =>
  c.json({
    status: "ok",
    version: API_VERSION,
    uptime: Math.floor((Date.now() - startTime) / 1000),
  })
);

app.post("/tenants", async (c) => {
  const body = await c.req.json<{
    id: string;
    name: string;
    apiKeyHash: string;
    webhookUrl?: string;
    defaultPolicies?: PolicyRule[];
  }>();

  const existingTenant = await findTenant(body.id);
  if (existingTenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant already exists" }, 400);
  }

  // If caller passes a raw key (stw_…) instead of a hash, hash it now
  const apiKeyHash =
    body.apiKeyHash && !body.apiKeyHash.match(/^[0-9a-f]{64}$/)
      ? hashApiKey(body.apiKeyHash)
      : body.apiKeyHash;

  const [tenant] = await db
    .insert(tenants)
    .values({
      id: body.id,
      name: body.name,
      apiKeyHash,
    })
    .returning();

  tenantConfigs.set(body.id, {
    id: body.id,
    name: body.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies,
  });

  return c.json<ApiResponse<Tenant & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

app.get("/tenants/:id", (c) => {
  const tenant = c.get("tenant");
  return c.json<ApiResponse<Tenant & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

app.put("/tenants/:id/webhook", async (c) => {
  const tenant = c.get("tenant");
  const tenantConfig = c.get("tenantConfig");
  const body = await c.req.json<{ webhookUrl?: string; defaultPolicies?: PolicyRule[] }>();

  const updatedConfig: TenantConfig = {
    ...tenantConfig,
    id: tenant.id,
    name: tenant.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies ?? tenantConfig.defaultPolicies,
  };

  tenantConfigs.set(tenant.id, updatedConfig);

  return c.json<ApiResponse<TenantConfig>>({
    ok: true,
    data: updatedConfig,
  });
});

app.post("/agents", async (c) => {
  const tenantId = c.get("tenantId");
  const body = await c.req.json<{ id: string; name: string; platformId?: string }>();

  try {
    const identity = await vault.createAgent(tenantId, body.id, body.name, body.platformId);
    return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: identity });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

app.get("/agents", async (c) => {
  const tenantId = c.get("tenantId");
  const tenantAgents = await vault.listAgentsByTenant(tenantId);
  return c.json<ApiResponse<AgentIdentity[]>>({ ok: true, data: tenantAgents });
});

app.get("/agents/:agentId", async (c) => {
  const tenantId = c.get("tenantId");
  const agent = await vault.getAgent(tenantId, c.req.param("agentId"));
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: agent });
});

app.get("/agents/:agentId/policies", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const agentPolicies = await db
    .select()
    .from(policies)
    .where(eq(policies.agentId, agentId));

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: agentPolicies.map(toPolicyRule),
  });
});

app.put("/agents/:agentId/policies", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const nextPolicies = await c.req.json<PolicyRule[]>();

  await db.delete(policies).where(eq(policies.agentId, agentId));

  if (nextPolicies.length > 0) {
    await db.insert(policies).values(
      nextPolicies.map((policy) => ({
        id: policy.id || crypto.randomUUID(),
        agentId,
        type: policy.type,
        enabled: policy.enabled,
        config: policy.config,
      }))
    );
  }

  const storedPolicies = await db
    .select()
    .from(policies)
    .where(eq(policies.agentId, agentId));

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: storedPolicies.map(toPolicyRule),
  });
});

app.post("/vault/:agentId/sign", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const request = await c.req.json<Omit<SignRequest, "agentId" | "tenantId">>();
  const signRequest: SignRequest = { ...request, tenantId, agentId };
  const policySet = await getPolicySet(tenantId, agentId);
  const stats = await getTransactionStats(agentId);

  const evaluation = policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "pending",
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
      });

      await db.insert(approvalQueue).values({
        id: crypto.randomUUID(),
        txId,
        agentId,
        status: "pending",
      });

      const webhookUrlApproval = tenantConfigs.get(tenantId)?.webhookUrl;
      if (webhookUrlApproval) {
        webhookDispatcher
          .dispatch(
            { type: "approval_required", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
            webhookUrlApproval
          )
          .catch(console.error);
      }

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: { txId, results: evaluation.results, status: "pending_approval" },
        },
        202
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress: signRequest.to,
      value: signRequest.value,
      data: signRequest.data,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
    });

    const webhookUrlRejected = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlRejected) {
      webhookDispatcher
        .dispatch(
          { type: "tx_rejected", tenantId, agentId, data: { txId, results: evaluation.results }, timestamp: new Date() },
          webhookUrlRejected
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403
    );
  }

  try {
    const txId = crypto.randomUUID();
    const txHash = await vault.signTransaction(signRequest, {
      txId,
      policyResults: evaluation.results,
      status: "signed",
    });

    await db
      .update(transactions)
      .set({
        status: "signed",
        txHash,
        policyResults: evaluation.results,
        signedAt: new Date(),
      })
      .where(eq(transactions.id, txId));

    const webhookUrlSigned = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlSigned) {
      webhookDispatcher
        .dispatch(
          { type: "tx_signed", tenantId, agentId, data: { txId, txHash }, timestamp: new Date() },
          webhookUrlSigned
        )
        .catch(console.error);
    }

    return c.json<ApiResponse<{ txId: string; txHash: string }>>({
      ok: true,
      data: { txId, txHash },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";

    const webhookUrlFailed = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlFailed) {
      webhookDispatcher
        .dispatch(
          { type: "tx_failed", tenantId, agentId, data: { error: message }, timestamp: new Date() },
          webhookUrlFailed
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>({ ok: false, error: message }, 500);
  }
});

app.post("/vault/:agentId/approve/:txId", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [transaction] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
  if (!transaction) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const [queueEntry] = await db
    .select()
    .from(approvalQueue)
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending")
      )
    );

  if (!queueEntry) {
    return c.json<ApiResponse>({ ok: false, error: "Pending approval not found" }, 404);
  }

  try {
    const txHash = await vault.signTransaction(
      { ...toSignRequest(transaction), tenantId },
      {
        txId,
        policyResults: transaction.policyResults,
        status: "signed",
      }
    );

    const resolvedAt = new Date();

    await db
      .update(approvalQueue)
      .set({
        status: "approved",
        resolvedAt,
        resolvedBy: tenantId,
      })
      .where(eq(approvalQueue.id, queueEntry.id));

    await db
      .update(transactions)
      .set({
        status: "signed",
        txHash,
        signedAt: resolvedAt,
      })
      .where(eq(transactions.id, txId));

    const webhookUrlApproved = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlApproved) {
      webhookDispatcher
        .dispatch(
          { type: "tx_signed", tenantId, agentId, data: { txId, txHash }, timestamp: new Date() },
          webhookUrlApproved
        )
        .catch(console.error);
    }

    return c.json<ApiResponse<{ txId: string; txHash: string }>>({
      ok: true,
      data: { txId, txHash },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";

    const webhookUrlFailed = tenantConfigs.get(tenantId)?.webhookUrl;
    if (webhookUrlFailed) {
      webhookDispatcher
        .dispatch(
          { type: "tx_failed", tenantId, agentId, data: { txId, error: message }, timestamp: new Date() },
          webhookUrlFailed
        )
        .catch(console.error);
    }

    return c.json<ApiResponse>({ ok: false, error: message }, 500);
  }
});

app.post("/vault/:agentId/reject/:txId", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [queueEntry] = await db
    .select()
    .from(approvalQueue)
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending")
      )
    );

  if (!queueEntry) {
    return c.json<ApiResponse>({ ok: false, error: "Pending approval not found" }, 404);
  }

  const resolvedAt = new Date();

  await db
    .update(approvalQueue)
    .set({
      status: "rejected",
      resolvedAt,
      resolvedBy: tenantId,
    })
    .where(eq(approvalQueue.id, queueEntry.id));

  await db
    .update(transactions)
    .set({
      status: "rejected",
    })
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));

  return c.json<ApiResponse>({ ok: true });
});

app.get("/vault/:agentId/pending", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const pendingTransactions = await db
    .select({
      queueId: approvalQueue.id,
      status: approvalQueue.status,
      requestedAt: approvalQueue.requestedAt,
      transaction: transactions,
    })
    .from(approvalQueue)
    .innerJoin(transactions, eq(transactions.id, approvalQueue.txId))
    .where(
      and(
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
        eq(transactions.agentId, agentId)
      )
    );

  return c.json<ApiResponse>({
    ok: true,
    data: pendingTransactions.map((entry) => ({
      queueId: entry.queueId,
      status: entry.status,
      requestedAt: entry.requestedAt,
      transaction: toTxRecord(entry.transaction),
    })),
  });
});

app.get("/vault/:agentId/history", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const history = await db
    .select()
    .from(transactions)
    .where(eq(transactions.agentId, agentId));

  return c.json<ApiResponse>({
    ok: true,
    data: history.map(toTxRecord),
  });
});

const server = Bun.serve({
  port: PORT,
  fetch: (request) => app.fetch(request),
  idleTimeout: 30,
});

const shutdown = async (signal: string) => {
  if (isShuttingDown) {
    return;
  }

  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down Steward API`);

  server.stop(true);
  clearInterval(requestLogCleanupTimer);
  requestLog.clear();

  try {
    await closeDb();
  } catch (error) {
    console.error("Failed to close database connection cleanly", error);
  }

  process.exit(0);
};

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

console.log(`Steward API running on :${server.port}`);
