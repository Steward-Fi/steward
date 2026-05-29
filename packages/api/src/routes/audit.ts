/**
 * Audit routes — read-only endpoints for querying transaction history,
 * proxy audit logs, and approval queue data across all agents for a tenant.
 *
 * Mount: app.route("/audit", auditRoutes)
 */

import { proxyAuditLog } from "@stwd/db";
import { and, count, desc, eq, gte, inArray, lte, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { verifyAuditChain } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  agents,
  approvalQueue,
  db,
  transactions,
} from "../services/context";

export const auditRoutes = new Hono<{ Variables: AppVariables }>();

const MAX_AUDIT_PAGE = 5_000;
const MAX_AUDIT_OFFSET = 1_000_000;
const MAX_AUDIT_VERIFY_RANGE = 10_000;
const MAX_AUDIT_EXPORT_RANGE_MS = 31 * 24 * 60 * 60 * 1000;
const AUDIT_READ_MFA_MAX_AGE_MS = 5 * 60_000;

function hasRecentSessionMfa(
  c: Context<{ Variables: AppVariables }>,
  maxAgeMs = AUDIT_READ_MFA_MAX_AGE_MS,
) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

auditRoutes.use("*", async (c, next) => {
  const role = c.get("tenantRole");
  if (c.get("authType") !== "session-jwt" || (role !== "owner" && role !== "admin")) {
    return c.json<ApiResponse>(
      { ok: false, error: "Audit routes require owner or admin session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Audit routes require recent MFA verification" },
      403,
    );
  }
  return next();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

type ParsedParam<T> = { ok: true; value: T } | { ok: false; error: string };

function parsePositiveIntegerParam(
  raw: string | undefined,
  name: string,
  defaultValue: number,
  maxValue: number,
): ParsedParam<number> {
  if (raw === undefined || raw === "") return { ok: true, value: defaultValue };
  if (!/^\d+$/.test(raw)) {
    return { ok: false, error: `${name} must be a positive integer` };
  }
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1 || n > maxValue) {
    return { ok: false, error: `${name} must be between 1 and ${maxValue}` };
  }
  return { ok: true, value: n };
}

function parseDateParam(raw: string | undefined, name: string): ParsedParam<Date | undefined> {
  if (!raw) return { ok: true, value: undefined };
  const date = new Date(raw);
  if (!Number.isFinite(date.getTime())) {
    return { ok: false, error: `${name} must be a valid date` };
  }
  return { ok: true, value: date };
}

function parsePagination(
  rawPage: string | undefined,
  rawLimit: string | undefined,
): ParsedParam<{ page: number; limit: number; offset: number }> {
  const page = parsePositiveIntegerParam(rawPage, "page", 1, MAX_AUDIT_PAGE);
  if (!page.ok) return page;
  const limit = parsePositiveIntegerParam(rawLimit, "limit", 50, 200);
  if (!limit.ok) return limit;
  const offset = (page.value - 1) * limit.value;
  if (offset > MAX_AUDIT_OFFSET) {
    return { ok: false, error: `offset must not exceed ${MAX_AUDIT_OFFSET}` };
  }
  return { ok: true, value: { page: page.value, limit: limit.value, offset } };
}

function parseAuditDateRange(
  rawDateFrom: string | undefined,
  rawDateTo: string | undefined,
): ParsedParam<{ dateFrom: Date | undefined; dateTo: Date | undefined }> {
  const dateFrom = parseDateParam(rawDateFrom, "dateFrom");
  if (!dateFrom.ok) return dateFrom;
  const dateTo = parseDateParam(rawDateTo, "dateTo");
  if (!dateTo.ok) return dateTo;
  if (dateFrom.value && dateTo.value && dateFrom.value > dateTo.value) {
    return { ok: false, error: "dateFrom must be before dateTo" };
  }
  return { ok: true, value: { dateFrom: dateFrom.value, dateTo: dateTo.value } };
}

function validateAuditExportRange(
  dateFrom: Date | undefined,
  dateTo: Date | undefined,
): string | null {
  if (!dateFrom || !dateTo) {
    return "audit export requires dateFrom and dateTo";
  }
  if (dateTo.getTime() - dateFrom.getTime() > MAX_AUDIT_EXPORT_RANGE_MS) {
    return "audit export range must not exceed 31 days";
  }
  return null;
}

/** Resolve the set of agentIds belonging to the authenticated tenant. */
async function tenantAgentIds(tenantId: string): Promise<string[]> {
  const rows = await db.select({ id: agents.id }).from(agents).where(eq(agents.tenantId, tenantId));
  return rows.map((r) => r.id);
}

// ─── GET /audit/log ───────────────────────────────────────────────────────────

auditRoutes.get("/log", async (c) => {
  const tenantId = c.get("tenantId");
  const pagination = parsePagination(c.req.query("page"), c.req.query("limit"));
  if (!pagination.ok) return c.json<ApiResponse>({ ok: false, error: pagination.error }, 400);
  const { page, limit, offset } = pagination.value;

  const filterAgentId = c.req.query("agentId");
  const filterAction = c.req.query("action"); // sign, approve, reject, proxy
  const filterStatus = c.req.query("status");
  const dateRange = parseAuditDateRange(c.req.query("dateFrom"), c.req.query("dateTo"));
  if (!dateRange.ok) return c.json<ApiResponse>({ ok: false, error: dateRange.error }, 400);
  const { dateFrom, dateTo } = dateRange.value;

  // Get all agent IDs for this tenant (for tenant isolation)
  const agentIds = await tenantAgentIds(tenantId);

  if (agentIds.length === 0) {
    return c.json<ApiResponse>({
      ok: true,
      data: {
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      },
    });
  }

  // Narrow to a single agent if filter provided
  const relevantAgentIds = filterAgentId
    ? agentIds.includes(filterAgentId)
      ? [filterAgentId]
      : []
    : agentIds;

  if (relevantAgentIds.length === 0) {
    return c.json<ApiResponse>({
      ok: true,
      data: {
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      },
    });
  }

  type AuditEntry = {
    id: string;
    timestamp: string;
    agentId: string;
    action: string;
    status: string;
    details: Record<string, unknown>;
    policyResults?: unknown;
    value?: string;
    to?: string;
  };

  const entries: AuditEntry[] = [];
  let totalCount = 0;

  const wantTx = !filterAction || ["sign", "approve", "reject"].includes(filterAction);
  const wantProxy = !filterAction || filterAction === "proxy";
  const combinedFetchLimit = wantTx && wantProxy ? offset + limit : limit;

  // ── Transactions + approval_queue ────────────────────────────────────────

  if (wantTx) {
    const txConditions = [inArray(transactions.agentId, relevantAgentIds)];

    if (filterStatus) {
      txConditions.push(eq(transactions.status, filterStatus as any));
    }
    if (dateFrom) {
      txConditions.push(gte(transactions.createdAt, dateFrom));
    }
    if (dateTo) {
      txConditions.push(lte(transactions.createdAt, dateTo));
    }

    const txWhere = and(...txConditions);

    // Count
    const [txCount] = await db.select({ count: count() }).from(transactions).where(txWhere);

    // Fetch with left join to approval_queue
    const txRows = await db
      .select({
        id: transactions.id,
        agentId: transactions.agentId,
        status: transactions.status,
        toAddress: transactions.toAddress,
        value: transactions.value,
        chainId: transactions.chainId,
        txHash: transactions.txHash,
        policyResults: transactions.policyResults,
        createdAt: transactions.createdAt,
        signedAt: transactions.signedAt,
        aqStatus: approvalQueue.status,
        aqRequestedAt: approvalQueue.requestedAt,
        aqResolvedAt: approvalQueue.resolvedAt,
        aqResolvedBy: approvalQueue.resolvedBy,
      })
      .from(transactions)
      .leftJoin(approvalQueue, eq(approvalQueue.txId, transactions.id))
      .where(txWhere)
      .orderBy(desc(transactions.createdAt))
      .limit(wantProxy ? combinedFetchLimit : limit)
      .offset(wantProxy ? 0 : offset);

    for (const row of txRows) {
      let action: string;
      if (row.aqStatus === "approved") action = "approve";
      else if (row.aqStatus === "rejected" || row.status === "rejected") action = "reject";
      else if (row.status === "signed" || row.status === "broadcast" || row.status === "confirmed")
        action = "sign";
      else action = "sign"; // pending, failed, etc.

      if (filterAction && action !== filterAction) continue;

      entries.push({
        id: row.id,
        timestamp: (row.createdAt as Date).toISOString(),
        agentId: row.agentId,
        action,
        status: row.status,
        details: {
          chainId: row.chainId,
          txHash: row.txHash ?? undefined,
          approvalStatus: row.aqStatus ?? undefined,
          resolvedBy: row.aqResolvedBy ?? undefined,
          resolvedAt: row.aqResolvedAt ? (row.aqResolvedAt as Date).toISOString() : undefined,
        },
        policyResults: row.policyResults,
        value: row.value,
        to: row.toAddress,
      });
    }

    if (!wantProxy) {
      totalCount = Number(txCount?.count ?? 0);
    } else {
      totalCount += Number(txCount?.count ?? 0);
    }
  }

  // ── Proxy audit log ─────────────────────────────────────────────────────

  if (wantProxy) {
    const proxyConditions = [eq(proxyAuditLog.tenantId, tenantId)];

    if (filterAgentId) {
      proxyConditions.push(eq(proxyAuditLog.agentId, filterAgentId));
    }
    if (dateFrom) {
      proxyConditions.push(gte(proxyAuditLog.createdAt, dateFrom));
    }
    if (dateTo) {
      proxyConditions.push(lte(proxyAuditLog.createdAt, dateTo));
    }

    const proxyWhere = and(...proxyConditions);

    const [proxyCount] = await db.select({ count: count() }).from(proxyAuditLog).where(proxyWhere);

    const proxyRows = await db
      .select()
      .from(proxyAuditLog)
      .where(proxyWhere)
      .orderBy(desc(proxyAuditLog.createdAt))
      .limit(wantTx ? combinedFetchLimit : limit)
      .offset(wantTx ? 0 : offset);

    for (const row of proxyRows) {
      if (filterStatus) {
        const statusStr = String(row.statusCode);
        if (statusStr !== filterStatus) continue;
      }

      entries.push({
        id: row.id,
        timestamp: (row.createdAt as Date).toISOString(),
        agentId: row.agentId,
        action: "proxy",
        status: row.statusCode < 400 ? "success" : "error",
        details: {
          targetHost: row.targetHost,
          targetPath: row.targetPath,
          method: row.method,
          statusCode: row.statusCode,
          latencyMs: row.latencyMs,
        },
      });
    }

    totalCount += Number(proxyCount?.count ?? 0);
  }

  // Sort merged entries by timestamp descending, then paginate
  entries.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const needsClientPagination = wantTx && wantProxy;
  const paginatedEntries = needsClientPagination
    ? entries.slice(offset, offset + limit)
    : entries.slice(0, limit);

  const totalPages = Math.ceil(totalCount / limit);

  return c.json<ApiResponse>({
    ok: true,
    data: {
      data: paginatedEntries,
      pagination: { page, limit, total: totalCount, totalPages },
    },
  });
});

// ─── GET /audit/summary ───────────────────────────────────────────────────────

auditRoutes.get("/summary", async (c) => {
  const tenantId = c.get("tenantId");
  const range = c.req.query("range") || "30d";

  let since: Date | null = null;
  const now = new Date();

  switch (range) {
    case "24h":
      since = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case "7d":
      since = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case "30d":
      since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    case "all":
      if (process.env.STEWARD_ALLOW_UNBOUNDED_AUDIT_SUMMARY !== "true") {
        return c.json<ApiResponse>(
          { ok: false, error: "range=all requires STEWARD_ALLOW_UNBOUNDED_AUDIT_SUMMARY=true" },
          400,
        );
      }
      since = null;
      break;
    default:
      since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  }

  const agentIds = await tenantAgentIds(tenantId);

  if (agentIds.length === 0) {
    return c.json<ApiResponse>({
      ok: true,
      data: {
        totalTransactions: 0,
        totalApprovals: 0,
        totalRejections: 0,
        totalProxyRequests: 0,
        policyViolations: 0,
        topAgents: [],
        dailyActivity: [],
      },
    });
  }

  // Transaction stats
  const txConditions = [inArray(transactions.agentId, agentIds)];
  if (since) txConditions.push(gte(transactions.createdAt, since));

  const [txStats] = await db
    .select({
      total: count(),
      approvals: sql<number>`count(*) filter (where ${transactions.status} in ('signed', 'broadcast', 'confirmed'))`,
      rejections: sql<number>`count(*) filter (where ${transactions.status} = 'rejected')`,
      policyViolations: sql<number>`count(*) filter (where ${transactions.status} = 'rejected' and jsonb_array_length(${transactions.policyResults}::jsonb) > 0)`,
    })
    .from(transactions)
    .where(and(...txConditions));

  // Proxy request count
  const proxyConditions: ReturnType<typeof eq>[] = [eq(proxyAuditLog.tenantId, tenantId)];
  if (since) proxyConditions.push(gte(proxyAuditLog.createdAt, since));

  const [proxyStats] = await db
    .select({ total: count() })
    .from(proxyAuditLog)
    .where(and(...proxyConditions));

  // Top agents by tx count
  const topAgentsRows = await db
    .select({
      agentId: transactions.agentId,
      txCount: count(),
    })
    .from(transactions)
    .where(and(...txConditions))
    .groupBy(transactions.agentId)
    .orderBy(desc(count()))
    .limit(10);

  // Look up agent names
  const agentNameMap = new Map<string, string>();
  if (topAgentsRows.length > 0) {
    const agentRows = await db
      .select({ id: agents.id, name: agents.name })
      .from(agents)
      .where(
        inArray(
          agents.id,
          topAgentsRows.map((r) => r.agentId),
        ),
      );
    for (const a of agentRows) agentNameMap.set(a.id, a.name);
  }

  const topAgents = topAgentsRows.map((r) => ({
    agentId: r.agentId,
    name: agentNameMap.get(r.agentId) || r.agentId,
    txCount: Number(r.txCount),
  }));

  // Daily activity (transactions only, last 30 days max)
  const dailyCutoff = since || new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const dailyRows = await db
    .select({
      date: sql<string>`date_trunc('day', ${transactions.createdAt})::date::text`,
      txCount: count(),
    })
    .from(transactions)
    .where(and(inArray(transactions.agentId, agentIds), gte(transactions.createdAt, dailyCutoff)))
    .groupBy(sql`date_trunc('day', ${transactions.createdAt})`)
    .orderBy(sql`date_trunc('day', ${transactions.createdAt})`);

  const dailyActivity = dailyRows.map((r) => ({
    date: r.date,
    txCount: Number(r.txCount),
  }));

  return c.json<ApiResponse>({
    ok: true,
    data: {
      totalTransactions: Number(txStats?.total ?? 0),
      totalApprovals: Number(txStats?.approvals ?? 0),
      totalRejections: Number(txStats?.rejections ?? 0),
      totalProxyRequests: Number(proxyStats?.total ?? 0),
      policyViolations: Number(txStats?.policyViolations ?? 0),
      topAgents,
      dailyActivity,
    },
  });
});

// ─── GET /audit/export ────────────────────────────────────────────────────────

auditRoutes.get("/export", async (c) => {
  const tenantId = c.get("tenantId");
  const filterAgentId = c.req.query("agentId");
  const filterAction = c.req.query("action");
  const filterStatus = c.req.query("status");
  const dateRange = parseAuditDateRange(c.req.query("dateFrom"), c.req.query("dateTo"));
  if (!dateRange.ok) return c.json<ApiResponse>({ ok: false, error: dateRange.error }, 400);
  const { dateFrom, dateTo } = dateRange.value;
  const exportRangeError = validateAuditExportRange(dateFrom, dateTo);
  if (exportRangeError) return c.json<ApiResponse>({ ok: false, error: exportRangeError }, 400);

  const agentIds = await tenantAgentIds(tenantId);

  if (agentIds.length === 0) {
    c.header("Content-Type", "text/csv");
    c.header("Content-Disposition", 'attachment; filename="audit-export.csv"');
    return c.body("id,timestamp,agentId,action,status,to,value,details\n");
  }

  const relevantAgentIds = filterAgentId
    ? agentIds.includes(filterAgentId)
      ? [filterAgentId]
      : []
    : agentIds;

  const rows: string[] = [];
  rows.push("id,timestamp,agentId,action,status,to,value,details");

  const wantTx = !filterAction || ["sign", "approve", "reject"].includes(filterAction);
  const wantProxy = !filterAction || filterAction === "proxy";

  if (wantTx && relevantAgentIds.length > 0) {
    const txConditions = [inArray(transactions.agentId, relevantAgentIds)];
    if (filterStatus) txConditions.push(eq(transactions.status, filterStatus as any));
    if (dateFrom) txConditions.push(gte(transactions.createdAt, dateFrom));
    if (dateTo) txConditions.push(lte(transactions.createdAt, dateTo));

    const txRows = await db
      .select({
        id: transactions.id,
        agentId: transactions.agentId,
        status: transactions.status,
        toAddress: transactions.toAddress,
        value: transactions.value,
        chainId: transactions.chainId,
        txHash: transactions.txHash,
        createdAt: transactions.createdAt,
        aqStatus: approvalQueue.status,
        aqResolvedAt: approvalQueue.resolvedAt,
        aqResolvedBy: approvalQueue.resolvedBy,
      })
      .from(transactions)
      .leftJoin(approvalQueue, eq(approvalQueue.txId, transactions.id))
      .where(and(...txConditions))
      .orderBy(desc(transactions.createdAt))
      .limit(10000);

    for (const row of txRows) {
      let action = "sign";
      if (row.aqStatus === "approved") action = "approve";
      else if (row.aqStatus === "rejected" || row.status === "rejected") action = "reject";
      if (filterAction && action !== filterAction) continue;

      rows.push(
        csvRow([
          row.id,
          (row.createdAt as Date).toISOString(),
          row.agentId,
          action,
          row.status,
          row.toAddress,
          row.value,
          [
            `chainId=${row.chainId}`,
            row.txHash ? `txHash=${row.txHash}` : "",
            row.aqStatus ? `approvalStatus=${row.aqStatus}` : "",
            row.aqResolvedBy ? `resolvedBy=${row.aqResolvedBy}` : "",
            row.aqResolvedAt ? `resolvedAt=${(row.aqResolvedAt as Date).toISOString()}` : "",
          ]
            .filter(Boolean)
            .join(" "),
        ]),
      );
    }
  }

  if (wantProxy) {
    const proxyConditions: ReturnType<typeof eq>[] = [eq(proxyAuditLog.tenantId, tenantId)];
    if (filterAgentId) proxyConditions.push(eq(proxyAuditLog.agentId, filterAgentId));
    if (dateFrom) proxyConditions.push(gte(proxyAuditLog.createdAt, dateFrom));
    if (dateTo) proxyConditions.push(lte(proxyAuditLog.createdAt, dateTo));

    const proxyRows = await db
      .select()
      .from(proxyAuditLog)
      .where(and(...proxyConditions))
      .orderBy(desc(proxyAuditLog.createdAt))
      .limit(10000);

    for (const row of proxyRows) {
      rows.push(
        csvRow([
          row.id,
          (row.createdAt as Date).toISOString(),
          row.agentId,
          "proxy",
          row.statusCode < 400 ? "success" : "error",
          `${row.targetHost}${row.targetPath}`,
          "",
          `method=${row.method} status=${row.statusCode} latency=${row.latencyMs}ms`,
        ]),
      );
    }
  }

  c.header("Content-Type", "text/csv");
  c.header("Content-Disposition", 'attachment; filename="audit-export.csv"');
  return c.body(`${rows.join("\n")}\n`);
});

// ─── GET /audit/events ────────────────────────────────────────────────────────
//
// Read raw tamper-evident audit events for the calling tenant. Returns only
// the calling tenant's chain (enforced by tenantId filter); operators with
// platform-level access should query directly.
auditRoutes.get("/events", async (c) => {
  const tenantId = c.get("tenantId");
  const pagination = parsePagination(c.req.query("page"), c.req.query("limit"));
  if (!pagination.ok) return c.json<ApiResponse>({ ok: false, error: pagination.error }, 400);
  const { page, limit, offset } = pagination.value;
  const action = c.req.query("action");

  const rows = (await db.execute(
    action
      ? sql`SELECT id, seq, actor_type, actor_id, action, resource_type, resource_id, metadata, ip_address, user_agent, request_id, created_at
            FROM audit_events
            WHERE tenant_id = ${tenantId} AND action = ${action}
            ORDER BY seq DESC LIMIT ${limit} OFFSET ${offset}`
      : sql`SELECT id, seq, actor_type, actor_id, action, resource_type, resource_id, metadata, ip_address, user_agent, request_id, created_at
            FROM audit_events
            WHERE tenant_id = ${tenantId}
            ORDER BY seq DESC LIMIT ${limit} OFFSET ${offset}`,
  )) as Array<Record<string, unknown>>;

  const [{ total } = { total: 0 }] = (await db.execute(
    sql`SELECT COUNT(*)::int AS total FROM audit_events WHERE tenant_id = ${tenantId}`,
  )) as Array<{ total: number }>;

  return c.json<ApiResponse>({
    ok: true,
    data: {
      data: rows.map((r) => ({
        ...r,
        seq: Number(r.seq),
        created_at:
          r.created_at instanceof Date
            ? (r.created_at as Date).toISOString()
            : String(r.created_at),
      })),
      pagination: {
        page,
        limit,
        total: Number(total),
        totalPages: Math.ceil(Number(total) / limit),
      },
    },
  });
});

// ─── POST /audit/verify ───────────────────────────────────────────────────────
//
// Walk the tenant's audit chain and verify every HMAC. A break here means
// either (a) the HMAC key has rotated without a documented re-keying or
// (b) somebody with DB write access has tampered with historical rows.
// Tenant-level auth required — agent tokens cannot verify.
auditRoutes.post("/verify", async (c) => {
  const tenantId = c.get("tenantId");
  const parsedFromSeq = parsePositiveIntegerParam(
    c.req.query("fromSeq"),
    "fromSeq",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  if (!parsedFromSeq.ok) {
    return c.json<ApiResponse>({ ok: false, error: parsedFromSeq.error }, 400);
  }
  const fromSeq = parsedFromSeq.value;
  const toSeqRaw = c.req.query("toSeq");
  const parsedToSeq = toSeqRaw
    ? parsePositiveIntegerParam(toSeqRaw, "toSeq", fromSeq, Number.MAX_SAFE_INTEGER)
    : ({ ok: true, value: undefined } as const);
  if (!parsedToSeq.ok) {
    return c.json<ApiResponse>({ ok: false, error: parsedToSeq.error }, 400);
  }
  const requestedToSeq = parsedToSeq.value;
  const toSeq = requestedToSeq ?? fromSeq + MAX_AUDIT_VERIFY_RANGE - 1;
  if (toSeq !== undefined && toSeq < fromSeq) {
    return c.json<ApiResponse>({ ok: false, error: "toSeq must be greater than fromSeq" }, 400);
  }
  if (toSeq - fromSeq + 1 > MAX_AUDIT_VERIFY_RANGE) {
    return c.json<ApiResponse>(
      { ok: false, error: `audit verify range must not exceed ${MAX_AUDIT_VERIFY_RANGE}` },
      400,
    );
  }

  const result = await verifyAuditChain(tenantId, { fromSeq, toSeq });
  const verifiedToSeq = result.valid
    ? fromSeq + result.count - 1
    : Math.max(fromSeq - 1, result.brokenAt - 1);
  return c.json<ApiResponse>({
    ok: true,
    data: {
      ...result,
      anchored: fromSeq === 1,
      verifiedFromSeq: fromSeq,
      verifiedToSeq,
      warning:
        fromSeq === 1
          ? undefined
          : "Partial verification is anchored to the stored predecessor hash and is not proof that earlier audit rows are intact.",
    },
  });
});

function csvRow(fields: string[]): string {
  return fields
    .map((f) => {
      const raw = String(f ?? "");
      const s = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
      if (s.includes(",") || s.includes('"') || s.includes("\n")) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    })
    .join(",");
}
