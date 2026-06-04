/**
 * Aggregated dashboard endpoint — single API call for widget rendering.
 *
 * Mount: app.route("/dashboard", dashboardRoutes)
 */

import type { AgentDashboardResponse } from "@stwd/shared";
import { and, desc, eq, gte, sql } from "drizzle-orm";
import {
  createOpenAPIApp,
  createRoute,
  err,
  errorEnvelope,
  jsonContent,
  ok,
  okEnvelope,
  z,
} from "../openapi";
import {
  approvalQueue,
  db,
  ensureAgentForTenant,
  getPolicySet,
  getTransactionStats,
  requireTenantLevel,
  setNoStoreHeaders,
  toTxRecord,
  transactions,
  vault,
} from "../services/context";

export const dashboardRoutes = createOpenAPIApp();

// Top-level dashboard shape is documented precisely; the deeply-nested shared
// types (PolicyRule, TxRecord) are referenced as opaque arrays rather than
// hand-mirrored — mirroring them here would duplicate @stwd/shared and create a
// second source of truth. The authoritative source for those nested shapes
// remains the shared TS types until @stwd/shared is made zod-first (z.infer).
const balanceLegSchema = z.object({
  native: z.string(),
  nativeFormatted: z.string(),
  chainId: z.number(),
  symbol: z.string(),
});

const dashboardData = z
  .object({
    agent: z
      .object({
        id: z.string(),
        tenantId: z.string(),
        name: z.string(),
        walletAddress: z.string(),
      })
      .openapi("AgentIdentitySummary"),
    balances: z.object({ evm: balanceLegSchema.optional(), solana: balanceLegSchema.optional() }),
    spend: z.object({
      today: z.string(),
      thisWeek: z.string(),
      thisMonth: z.string(),
      todayFormatted: z.string(),
      thisWeekFormatted: z.string(),
      thisMonthFormatted: z.string(),
    }),
    policies: z.array(z.unknown()),
    pendingApprovals: z.number(),
    recentTransactions: z.array(z.unknown()),
  })
  .openapi("AgentDashboard");

const dashboardRoute = createRoute({
  method: "get",
  // OpenAPI path templating uses {param}; @hono/zod-openapi maps it to Hono's
  // :param for routing, so GET /dashboard/:agentId still matches at runtime.
  path: "/{agentId}",
  tags: ["dashboard"],
  summary:
    "Aggregated agent dashboard (identity, balances, spend, policies, approvals, recent txs)",
  request: {
    params: z.object({
      agentId: z.string().openapi({ param: { name: "agentId", in: "path" }, example: "agt_123" }),
    }),
  },
  responses: {
    200: jsonContent(okEnvelope(dashboardData), "Aggregated dashboard for the agent"),
    403: jsonContent(errorEnvelope, "Tenant-level auth or recent MFA required"),
    404: jsonContent(errorEnvelope, "Agent not found"),
  },
});

function hasRecentSessionMfa(c: Parameters<typeof requireTenantLevel>[0], maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

// ─── GET /dashboard/:agentId — aggregated agent dashboard ─────────────────────

dashboardRoutes.openapi(dashboardRoute, async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!requireTenantLevel(c)) {
    return c.json(err("Tenant-level auth required"), 403);
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json(err("Dashboard data requires recent MFA verification"), 403);
  }
  setNoStoreHeaders(c);

  // Get agent identity
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json(err("Agent not found"), 404);
  }

  // Run queries in parallel
  const [policyRules, txStats, recentTxRows, pendingApprovalsResult, balanceResult] =
    await Promise.all([
      // Policies
      getPolicySet(tenantId, agentId),

      // Spend stats
      getTransactionStats(agentId),

      // Recent transactions (last 5)
      db
        .select()
        .from(transactions)
        .where(eq(transactions.agentId, agentId))
        .orderBy(desc(transactions.createdAt))
        .limit(5),

      // Pending approvals count
      db
        .select({ count: sql<number>`count(*)` })
        .from(approvalQueue)
        .where(and(eq(approvalQueue.agentId, agentId), eq(approvalQueue.status, "pending"))),

      // Balance — try to get from vault
      vault.getBalance(tenantId, agentId).catch(() => null),
    ]);

  // Get monthly spend
  const oneMonthAgo = new Date(Date.now() - 30 * 86400_000);
  const [monthlyStats] = await db
    .select({
      spentThisMonth: sql<string>`coalesce(sum((${transactions.value})::numeric), 0)::text`,
    })
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        gte(transactions.createdAt, oneMonthAgo),
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`,
      ),
    );

  const spentToday = txStats.spentToday.toString();
  const spentThisWeek = txStats.spentThisWeek.toString();
  const spentThisMonth = monthlyStats?.spentThisMonth ?? "0";

  const formatWei = (wei: string): string => {
    const n = Number(BigInt(wei)) / 1e18;
    return n.toFixed(6);
  };

  const dashboard: AgentDashboardResponse = {
    agent,
    balances: {
      evm: balanceResult
        ? {
            native: balanceResult.native.toString(),
            nativeFormatted: balanceResult.nativeFormatted,
            chainId: balanceResult.chainId,
            symbol: balanceResult.symbol,
          }
        : undefined,
    },
    spend: {
      today: spentToday,
      thisWeek: spentThisWeek,
      thisMonth: spentThisMonth,
      todayFormatted: formatWei(spentToday),
      thisWeekFormatted: formatWei(spentThisWeek),
      thisMonthFormatted: formatWei(spentThisMonth),
    },
    policies: policyRules,
    pendingApprovals: Number(pendingApprovalsResult[0]?.count ?? 0),
    recentTransactions: recentTxRows.map(toTxRecord),
  };

  return c.json(ok(dashboard), 200);
});
