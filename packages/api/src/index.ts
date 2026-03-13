import { Hono, type Context, type Next } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { Vault } from "@steward/vault";
import { PolicyEngine } from "@steward/policy-engine";
import type {
  SignRequest,
  PolicyRule,
  ApiResponse,
  AgentIdentity,
  Tenant,
  TenantConfig,
} from "@steward/shared";

// ─── Config ───

const MASTER_PASSWORD = process.env.STEWARD_MASTER_PASSWORD || "steward-dev-password";
const PORT = parseInt(process.env.PORT || "3200");
const DEFAULT_TENANT_ID = "default";

// ─── Init ───

const vault = new Vault({
  masterPassword: MASTER_PASSWORD,
  rpcUrl: process.env.RPC_URL || "https://mainnet.base.org",
  chainId: 8453,
});

const policyEngine = new PolicyEngine();

const defaultTenant: Tenant = {
  id: DEFAULT_TENANT_ID,
  name: "Default Tenant",
  apiKeyHash: process.env.STEWARD_DEFAULT_TENANT_KEY || "",
  createdAt: new Date(),
};

const defaultTenantConfig: TenantConfig = {
  id: DEFAULT_TENANT_ID,
  name: defaultTenant.name,
};

// In-memory tenant store (replace with DB)
const tenants = new Map<string, Tenant>([[defaultTenant.id, defaultTenant]]);
const tenantConfigs = new Map<string, TenantConfig>([[defaultTenantConfig.id, defaultTenantConfig]]);

// In-memory policy store (replace with DB)
const agentPolicies = new Map<string, PolicyRule[]>();

// In-memory tx tracking (replace with DB)
const txHistory = new Map<string, { timestamp: number; value: bigint }[]>();

type AppVariables = {
  tenant: Tenant;
  tenantConfig: TenantConfig;
  tenantId: string;
};

const app = new Hono<{ Variables: AppVariables }>();

app.use("*", cors());
app.use("*", logger());

// ─── Helpers ───

function getScopedKey(tenantId: string, agentId: string): string {
  return `${tenantId}:${agentId}`;
}

function getTenantPayload(tenant: Tenant): Tenant & TenantConfig {
  const config = tenantConfigs.get(tenant.id);
  return {
    ...tenant,
    name: config?.name || tenant.name,
    webhookUrl: config?.webhookUrl,
    defaultPolicies: config?.defaultPolicies,
  };
}

async function tenantAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
  options?: { requireTenantMatch?: string }
) {
  const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
  const tenant = tenants.get(tenantId);

  if (!tenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  }

  if (options?.requireTenantMatch && tenantId !== options.requireTenantMatch) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  const apiKey = c.req.header("X-Steward-Key") || "";
  if (tenant.apiKeyHash && apiKey !== tenant.apiKeyHash) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }

  c.set("tenantId", tenantId);
  c.set("tenant", tenant);
  c.set("tenantConfig", tenantConfigs.get(tenantId) || { id: tenant.id, name: tenant.name });

  await next();
}

// ─── Middleware ───

app.use("/agents", (c, next) => tenantAuth(c, next));
app.use("/agents/*", (c, next) => tenantAuth(c, next));
app.use("/vault/*", (c, next) => tenantAuth(c, next));
app.use("/tenants/:id", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") })
);
app.use("/tenants/:id/webhook", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") })
);

// ─── Health ───

app.get("/", (c) => c.json({ name: "steward", version: "0.1.0", status: "running" }));
app.get("/health", (c) => c.json({ ok: true }));

// ─── Tenant Management ───

app.post("/tenants", async (c) => {
  const body = await c.req.json<{
    id: string;
    name: string;
    apiKeyHash: string;
    webhookUrl?: string;
    defaultPolicies?: PolicyRule[];
  }>();

  if (tenants.has(body.id)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant already exists" }, 400);
  }

  const tenant: Tenant = {
    id: body.id,
    name: body.name,
    apiKeyHash: body.apiKeyHash,
    createdAt: new Date(),
  };

  const tenantConfig: TenantConfig = {
    id: body.id,
    name: body.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies,
  };

  tenants.set(tenant.id, tenant);
  tenantConfigs.set(tenantConfig.id, tenantConfig);

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

// ─── Agent Management ───

app.post("/agents", async (c) => {
  const tenantId = c.get("tenantId");
  const body = await c.req.json<{ id: string; name: string; platformId?: string }>();
  try {
    const identity = vault.createAgent(tenantId, body.id, body.name, body.platformId);
    return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: identity });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

app.get("/agents", (c) => {
  const tenantId = c.get("tenantId");
  const agents = vault.listAgentsByTenant(tenantId);
  return c.json<ApiResponse<AgentIdentity[]>>({ ok: true, data: agents });
});

app.get("/agents/:agentId", (c) => {
  const tenantId = c.get("tenantId");
  const agent = vault.getAgent(tenantId, c.req.param("agentId"));
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: agent });
});

// ─── Policy Management ───

app.get("/agents/:agentId/policies", (c) => {
  const scopedKey = getScopedKey(c.get("tenantId"), c.req.param("agentId"));
  const policies = agentPolicies.get(scopedKey) || [];
  return c.json<ApiResponse<PolicyRule[]>>({ ok: true, data: policies });
});

app.put("/agents/:agentId/policies", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const scopedKey = getScopedKey(tenantId, agentId);
  const policies = await c.req.json<PolicyRule[]>();
  agentPolicies.set(scopedKey, policies);
  return c.json<ApiResponse>({ ok: true });
});

// ─── Signing ───

app.post("/vault/:agentId/sign", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const scopedKey = getScopedKey(tenantId, agentId);
  const request = await c.req.json<Omit<SignRequest, "agentId" | "tenantId">>();
  const signRequest: SignRequest = { ...request, tenantId, agentId };

  const policies = agentPolicies.get(scopedKey) || tenantConfigs.get(tenantId)?.defaultPolicies || [];

  const history = txHistory.get(scopedKey) || [];
  const now = Date.now();
  const oneHourAgo = now - 3600_000;
  const oneDayAgo = now - 86400_000;
  const oneWeekAgo = now - 604800_000;

  const recentTxCount1h = history.filter((t) => t.timestamp > oneHourAgo).length;
  const recentTxCount24h = history.filter((t) => t.timestamp > oneDayAgo).length;
  const spentToday = history
    .filter((t) => t.timestamp > oneDayAgo)
    .reduce((sum, t) => sum + t.value, 0n);
  const spentThisWeek = history
    .filter((t) => t.timestamp > oneWeekAgo)
    .reduce((sum, t) => sum + t.value, 0n);

  const evaluation = policyEngine.evaluate(policies, {
    request: signRequest,
    recentTxCount1h,
    recentTxCount24h,
    spentToday,
    spentThisWeek,
  });

  if (!evaluation.approved) {
    if (evaluation.requiresManualApproval) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: { results: evaluation.results, status: "pending_approval" },
        },
        202
      );
    }
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { results: evaluation.results },
      },
      403
    );
  }

  try {
    const txHash = await vault.signTransaction(signRequest);

    if (!txHistory.has(scopedKey)) txHistory.set(scopedKey, []);
    txHistory.get(scopedKey)?.push({ timestamp: now, value: BigInt(request.value) });

    return c.json<ApiResponse<{ txHash: string }>>({
      ok: true,
      data: { txHash },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 500);
  }
});

// ─── Transaction History ───

app.get("/vault/:agentId/history", (c) => {
  const scopedKey = getScopedKey(c.get("tenantId"), c.req.param("agentId"));
  const history = txHistory.get(scopedKey) || [];
  return c.json<ApiResponse>({
    ok: true,
    data: history.map((t) => ({ timestamp: t.timestamp, value: t.value.toString() })),
  });
});

// ─── Start ───

console.log(`Steward API running on :${PORT}`);
export default { port: PORT, fetch: app.fetch };
