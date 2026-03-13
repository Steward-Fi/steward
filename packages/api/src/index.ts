import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { Vault } from "@steward/vault";
import { PolicyEngine } from "@steward/policy-engine";
import type { SignRequest, PolicyRule, ApiResponse, AgentIdentity } from "@steward/shared";

// ─── Config ───

const MASTER_PASSWORD = process.env.STEWARD_MASTER_PASSWORD || "steward-dev-password";
const PORT = parseInt(process.env.PORT || "3200");

// ─── Init ───

const vault = new Vault({
  masterPassword: MASTER_PASSWORD,
  rpcUrl: process.env.RPC_URL || "https://mainnet.base.org",
  chainId: 8453,
});

const policyEngine = new PolicyEngine();

// In-memory policy store (replace with DB)
const agentPolicies = new Map<string, PolicyRule[]>();

// In-memory tx tracking (replace with DB)
const txHistory = new Map<string, { timestamp: number; value: bigint }[]>();

const app = new Hono();

app.use("*", cors());
app.use("*", logger());

// ─── Health ───

app.get("/", (c) => c.json({ name: "steward", version: "0.1.0", status: "running" }));
app.get("/health", (c) => c.json({ ok: true }));

// ─── Agent Management ───

app.post("/agents", async (c) => {
  const body = await c.req.json<{ id: string; name: string; platformId?: string }>();
  try {
    const identity = vault.createAgent(body.id, body.name, body.platformId);
    return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: identity });
  } catch (e: any) {
    return c.json<ApiResponse>({ ok: false, error: e.message }, 400);
  }
});

app.get("/agents", (c) => {
  const agents = vault.listAgents();
  return c.json<ApiResponse<AgentIdentity[]>>({ ok: true, data: agents });
});

app.get("/agents/:agentId", (c) => {
  const agent = vault.getAgent(c.req.param("agentId"));
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: agent });
});

// ─── Policy Management ───

app.get("/agents/:agentId/policies", (c) => {
  const policies = agentPolicies.get(c.req.param("agentId")) || [];
  return c.json<ApiResponse<PolicyRule[]>>({ ok: true, data: policies });
});

app.put("/agents/:agentId/policies", async (c) => {
  const policies = await c.req.json<PolicyRule[]>();
  agentPolicies.set(c.req.param("agentId"), policies);
  return c.json<ApiResponse>({ ok: true });
});

// ─── Signing ───

app.post("/vault/:agentId/sign", async (c) => {
  const agentId = c.req.param("agentId");
  const request = await c.req.json<Omit<SignRequest, "agentId">>();
  const signRequest: SignRequest = { ...request, agentId };

  // Get policies
  const policies = agentPolicies.get(agentId) || [];

  // Build evaluation context from tx history
  const history = txHistory.get(agentId) || [];
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

  // Evaluate policies
  const evaluation = policyEngine.evaluate(policies, {
    request: signRequest,
    recentTxCount1h,
    recentTxCount24h,
    spentToday,
    spentThisWeek,
  });

  if (!evaluation.approved) {
    if (evaluation.requiresManualApproval) {
      return c.json<ApiResponse>({
        ok: false,
        error: "Transaction requires manual approval",
        data: { results: evaluation.results, status: "pending_approval" },
      }, 202);
    }
    return c.json<ApiResponse>({
      ok: false,
      error: "Transaction rejected by policy",
      data: { results: evaluation.results },
    }, 403);
  }

  // Sign and broadcast
  try {
    const txHash = await vault.signTransaction(signRequest);

    // Record in history
    if (!txHistory.has(agentId)) txHistory.set(agentId, []);
    txHistory.get(agentId)!.push({ timestamp: now, value: BigInt(request.value) });

    return c.json<ApiResponse<{ txHash: string }>>({
      ok: true,
      data: { txHash },
    });
  } catch (e: any) {
    return c.json<ApiResponse>({ ok: false, error: e.message }, 500);
  }
});

// ─── Transaction History ───

app.get("/vault/:agentId/history", (c) => {
  const history = txHistory.get(c.req.param("agentId")) || [];
  return c.json<ApiResponse>({
    ok: true,
    data: history.map((t) => ({ timestamp: t.timestamp, value: t.value.toString() })),
  });
});

// ─── Start ───

console.log(`🏦 Steward API running on :${PORT}`);
export default { port: PORT, fetch: app.fetch };
