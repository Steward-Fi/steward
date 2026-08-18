/**
 * Audit routes — read-only endpoints for querying transaction history,
 * proxy audit logs, and approval queue data across all agents for a tenant.
 *
 * Mount: app.route("/audit", auditRoutes)
 */

import { auditChainHeads, auditCheckpoints, proxyAuditLog } from "@stwd/db";
import { shouldUsePGLite } from "@stwd/db/pglite";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { and, count, desc, eq, gte, inArray, lte, type SQL, sql } from "drizzle-orm";
import { Hono } from "hono";
import { auditOwnerAdminMfaGate } from "../middleware/audit-gate";
import {
  type AuditBundleData,
  readAuditBundleData,
  signAuditBundle,
  verifyAuditChain,
} from "../services/audit";
import {
  beginAuditArchiveRestore,
  completeAuditArchiveRestore,
  createAuditArchive,
  getAuditArchiveChunk,
  getAuditArchiveManifest,
  getAuditRetentionPolicy,
  listAuditArchives,
  MAX_ARCHIVE_CHUNK_SIZE,
  MAX_AUDIT_RETENTION_DAYS,
  MIN_ARCHIVE_CHUNK_SIZE,
  MIN_AUDIT_RETENTION_DAYS,
  putAuditArchiveRestoreChunk,
  recordAuditArchiveDurabilityAcknowledgement,
  runTenantAuditRetention,
  setAuditRetentionPolicy,
} from "../services/audit-archive";
import {
  AuditSigningKeyError,
  isCheckpointSigningConfigured,
  type SignedCheckpoint,
  verifyCheckpoint,
} from "../services/audit-checkpoint";
import { AuditCheckpointAnchorError } from "../services/audit-checkpoint-anchor";
import {
  type ApiResponse,
  type AppVariables,
  agents,
  approvalQueue,
  db,
  safeJsonParse,
  transactions,
} from "../services/context";
import { inspectGovernedRoutes } from "../services/governed-route-inventory";

export const auditRoutes = new Hono<{ Variables: AppVariables }>();

const MAX_AUDIT_PAGE = 5_000;
const MAX_AUDIT_OFFSET = 1_000_000;
const MAX_AUDIT_VERIFY_RANGE = 10_000;
// An evidence bundle inlines every event in the range as JSON; cap it so a
// single request can't materialize an unbounded chain in memory.
const MAX_AUDIT_BUNDLE_EVENTS = 10_000;
// BUNDLE_CANONICALIZATION_SPEC now lives in services/audit (single source of
// truth, spec §6.2) and is imported above.
const MAX_AUDIT_EXPORT_RANGE_MS = 31 * 24 * 60 * 60 * 1000;
const MAX_AUDIT_METADATA_FILTERS = 5;
const AUDIT_ACTION_FILTER_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const AUDIT_METADATA_PATH_PART_PATTERN = /^[A-Za-z0-9_]{1,64}$/;
const MAX_AUDIT_METADATA_VALUE_LENGTH = 256;

// Owner/admin + recent-MFA gate, shared with the PR5 case/evidence routes so
// both surfaces enforce an IDENTICAL posture (spec §6.3).
auditRoutes.use("*", auditOwnerAdminMfaGate);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

function parseAuditActionFilter(raw: string | undefined, name: string): ParsedParam<string | null> {
  if (!raw) return { ok: true, value: null };
  if (!AUDIT_ACTION_FILTER_PATTERN.test(raw)) {
    return { ok: false, error: `${name} contains unsupported characters` };
  }
  return { ok: true, value: raw };
}

function escapeAuditLikePrefix(raw: string): string {
  return raw.replace(/([%_\\])/g, "\\$1");
}

function parseAuditMetadataFilters(
  query: URLSearchParams,
): ParsedParam<Array<{ path: string[]; value: string }>> {
  const filters: Array<{ path: string[]; value: string }> = [];
  for (const [key, value] of query.entries()) {
    if (!key.startsWith("metadata.")) continue;
    if (filters.length >= MAX_AUDIT_METADATA_FILTERS) {
      return {
        ok: false,
        error: `metadata filters cannot exceed ${MAX_AUDIT_METADATA_FILTERS}`,
      };
    }
    const path = key.slice("metadata.".length).split(".");
    if (
      path.length === 0 ||
      path.length > 5 ||
      path.some(
        (part) =>
          !AUDIT_METADATA_PATH_PART_PATTERN.test(part) ||
          part === "__proto__" ||
          part === "prototype" ||
          part === "constructor",
      )
    ) {
      return {
        ok: false,
        error:
          "metadata filter keys must use dot-separated alphanumeric/underscore paths up to depth 5",
      };
    }
    if (value.length === 0 || value.length > MAX_AUDIT_METADATA_VALUE_LENGTH) {
      return {
        ok: false,
        error: `metadata filter values must be 1-${MAX_AUDIT_METADATA_VALUE_LENGTH} characters`,
      };
    }
    filters.push({ path, value });
  }
  return { ok: true, value: filters };
}

function auditMetadataPathLiteral(path: string[]): SQL {
  // Safe because parseAuditMetadataFilters restricts every segment to
  // [A-Za-z0-9_]{1,64}; keep this as the only raw interpolation for JSON paths.
  return sql.raw(`'{${path.join(",")}}'`);
}

function rowsFromExecute<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object" && Array.isArray((result as { rows?: unknown }).rows)) {
    return (result as { rows: T[] }).rows;
  }
  return [];
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
  const dateRange = parseAuditDateRange(c.req.query("dateFrom"), c.req.query("dateTo"));
  if (!dateRange.ok) return c.json<ApiResponse>({ ok: false, error: dateRange.error }, 400);
  const actionFilter = parseAuditActionFilter(c.req.query("action"), "action");
  if (!actionFilter.ok) return c.json<ApiResponse>({ ok: false, error: actionFilter.error }, 400);
  const actionPrefixFilter = parseAuditActionFilter(c.req.query("actionPrefix"), "actionPrefix");
  if (!actionPrefixFilter.ok) {
    return c.json<ApiResponse>({ ok: false, error: actionPrefixFilter.error }, 400);
  }
  const metadataFilters = parseAuditMetadataFilters(new URL(c.req.url).searchParams);
  if (!metadataFilters.ok) {
    return c.json<ApiResponse>({ ok: false, error: metadataFilters.error }, 400);
  }
  const action = actionFilter.value;
  const actionPrefix = actionPrefixFilter.value;
  const actorType = c.req.query("actorType");
  const actorId = c.req.query("actorId");
  const resourceType = c.req.query("resourceType");
  const resourceId = c.req.query("resourceId");
  const requestId = c.req.query("requestId");

  const conditions: SQL[] = [sql`tenant_id = ${tenantId}`];
  if (action) conditions.push(sql`action = ${action}`);
  if (actionPrefix) {
    conditions.push(sql`action LIKE ${`${escapeAuditLikePrefix(actionPrefix)}%`} ESCAPE '\\'`);
  }
  if (actorType) conditions.push(sql`actor_type = ${actorType}`);
  if (actorId) conditions.push(sql`actor_id = ${actorId}`);
  if (resourceType) conditions.push(sql`resource_type = ${resourceType}`);
  if (resourceId) conditions.push(sql`resource_id = ${resourceId}`);
  if (requestId) conditions.push(sql`request_id = ${requestId}`);
  for (const filter of metadataFilters.value) {
    conditions.push(sql`metadata #>> ${auditMetadataPathLiteral(filter.path)} = ${filter.value}`);
  }
  if (dateRange.value.dateFrom) conditions.push(sql`created_at >= ${dateRange.value.dateFrom}`);
  if (dateRange.value.dateTo) conditions.push(sql`created_at <= ${dateRange.value.dateTo}`);
  const where = sql.join(conditions, sql` AND `);

  const rows = rowsFromExecute<Record<string, unknown>>(
    await db.execute(sql`
      SELECT id, seq, actor_type, actor_id, action, resource_type, resource_id, metadata, ip_address, user_agent, request_id, created_at
      FROM audit_events
      WHERE ${where}
      ORDER BY seq DESC LIMIT ${limit} OFFSET ${offset}
    `),
  );

  const [{ total } = { total: 0 }] = rowsFromExecute<{ total: number }>(
    await db.execute(sql`SELECT COUNT(*)::int AS total FROM audit_events WHERE ${where}`),
  );

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

  const requireHead = c.req.query("requireHead") === "true";
  const result = await verifyAuditChain(tenantId, { fromSeq, toSeq, requireHead });
  const verifiedToSeq = result.valid
    ? fromSeq + result.count - 1
    : Math.max(fromSeq - 1, result.brokenAt - 1);
  return c.json<ApiResponse>({
    ok: true,
    data: {
      ...result,
      anchored: fromSeq === 1,
      requireHead,
      verifiedFromSeq: fromSeq,
      verifiedToSeq,
      warning:
        fromSeq === 1
          ? undefined
          : "Partial verification is anchored to the stored predecessor hash and is not proof that earlier audit rows are intact.",
    },
  });
});

// ─── GET /audit/integrity ───────────────────────────────────────────────────
//
// A bounded operator diagnostic: verify the full live HMAC chain, then verify
// the newest persisted Ed25519 checkpoint and require it to commit to the
// current chain head. The normal audit owner/admin + recent-MFA gate above
// applies; no HMAC key or private signing material is returned.
auditRoutes.get("/integrity", async (c) => {
  const tenantId = c.get("tenantId");
  const configuredLimit = Number(process.env.STEWARD_DOCTOR_AUDIT_MAX_EVENTS ?? "100000");
  const maxEvents =
    Number.isSafeInteger(configuredLimit) && configuredLimit > 0 ? configuredLimit : 100_000;
  const data = await db.transaction(async (tx) => {
    if (!shouldUsePGLite()) {
      await tx.execute(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`);
    }
    const [head] = await tx
      .select({ seq: auditChainHeads.expectedSeq, hmac: auditChainHeads.headHmac })
      .from(auditChainHeads)
      .where(eq(auditChainHeads.tenantId, tenantId))
      .limit(1);
    const chain = await verifyAuditChain(tenantId, {
      requireHead: true,
      maxRows: maxEvents,
      executor: tx,
    });
    const [row] = await tx
      .select()
      .from(auditCheckpoints)
      .where(eq(auditCheckpoints.tenantId, tenantId))
      .orderBy(desc(auditCheckpoints.seq), desc(auditCheckpoints.id))
      .limit(1);
    const governedRoutes = await inspectGovernedRoutes(tenantId, tx);

    let checkpointValid = false;
    let checkpointAtHead = false;
    if (row && head && !("limitExceeded" in chain && chain.limitExceeded)) {
      const checkpoint: SignedCheckpoint = {
        payload: row.payload as unknown as SignedCheckpoint["payload"],
        signature: row.signature,
        publicKey: row.publicKey,
      };
      checkpointValid = verifyCheckpoint(checkpoint);
      checkpointAtHead =
        row.seq === Number(head.seq) &&
        Buffer.from(row.headHmac).toString("hex") === Buffer.from(head.hmac).toString("hex") &&
        checkpoint.payload.seq === Number(head.seq) &&
        checkpoint.payload.headHmac === Buffer.from(head.hmac).toString("hex");
    }
    const limitExceeded = "limitExceeded" in chain && chain.limitExceeded === true;
    return {
      valid: chain.valid && checkpointValid && checkpointAtHead,
      chainValid: chain.valid,
      checkpointPresent: Boolean(row),
      checkpointValid,
      checkpointAtHead,
      checkpointSeq: row?.seq ?? null,
      chainHeadSeq: head ? Number(head.seq) : null,
      bounded: true,
      eventsInspected: chain.valid ? chain.count : maxEvents,
      maxEvents,
      governedRoutes,
      ...(limitExceeded
        ? {
            error:
              "audit chain exceeds the bounded doctor verification limit; use an offline export",
          }
        : {}),
    };
  });

  return c.json<ApiResponse>({
    ok: true,
    data,
  });
});

// ─── Tenant retention + durable archive control plane ─────────────────────

auditRoutes.get("/retention-policy", async (c) => {
  const policy = await getAuditRetentionPolicy(c.get("tenantId"));
  return c.json({ ok: true, data: policy });
});

auditRoutes.put("/retention-policy", async (c) => {
  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  const allowed = new Set(["enabled", "retentionDays", "archiveChunkSize"]);
  if (Object.keys(body).some((key) => !allowed.has(key))) {
    return c.json<ApiResponse>({ ok: false, error: "Unsupported retention policy field" }, 400);
  }
  if (
    typeof body.enabled !== "boolean" ||
    !Number.isSafeInteger(body.retentionDays) ||
    !Number.isSafeInteger(body.archiveChunkSize)
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "enabled, retentionDays, and archiveChunkSize are required" },
      400,
    );
  }
  const retentionDays = body.retentionDays as number;
  const archiveChunkSize = body.archiveChunkSize as number;
  if (retentionDays < MIN_AUDIT_RETENTION_DAYS || retentionDays > MAX_AUDIT_RETENTION_DAYS) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `retentionDays must be ${MIN_AUDIT_RETENTION_DAYS}-${MAX_AUDIT_RETENTION_DAYS}`,
      },
      400,
    );
  }
  if (archiveChunkSize < MIN_ARCHIVE_CHUNK_SIZE || archiveChunkSize > MAX_ARCHIVE_CHUNK_SIZE) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `archiveChunkSize must be ${MIN_ARCHIVE_CHUNK_SIZE}-${MAX_ARCHIVE_CHUNK_SIZE}`,
      },
      400,
    );
  }
  const tenantId = c.get("tenantId");
  const policy = await setAuditRetentionPolicy({
    tenantId,
    enabled: body.enabled,
    retentionDays,
    archiveChunkSize,
    updatedBy: c.get("userId") ?? null,
  });
  return c.json({ ok: true, data: policy });
});

auditRoutes.post("/archives", async (c) => {
  if (!isCheckpointSigningConfigured()) {
    return c.json<ApiResponse>({ ok: false, error: "Audit signing key is required" }, 503);
  }
  const body = await safeJsonParse<Record<string, unknown>>(c);
  const allowed = new Set(["fromSeq", "toSeq", "chunkSize"]);
  if (
    !body ||
    Object.keys(body).some((key) => !allowed.has(key)) ||
    !Number.isSafeInteger(body.fromSeq) ||
    !Number.isSafeInteger(body.toSeq) ||
    (body.chunkSize !== undefined && !Number.isSafeInteger(body.chunkSize))
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "fromSeq and toSeq are required safe integers" },
      400,
    );
  }
  try {
    const policy = await getAuditRetentionPolicy(c.get("tenantId"));
    const archive = await createAuditArchive({
      tenantId: c.get("tenantId"),
      fromSeq: body.fromSeq as number,
      toSeq: body.toSeq as number,
      chunkSize: (body.chunkSize as number | undefined) ?? policy.archiveChunkSize,
    });
    return c.json({ ok: true, data: archive }, archive.reused ? 200 : 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Audit archive failed";
    return c.json<ApiResponse>({ ok: false, error: message }, 409);
  }
});

auditRoutes.get("/archives", async (c) => {
  const limit = parsePositiveIntegerParam(c.req.query("limit"), "limit", 50, 200);
  if (!limit.ok) return c.json<ApiResponse>({ ok: false, error: limit.error }, 400);
  const beforeRaw = c.req.query("before");
  const before = beforeRaw ? new Date(beforeRaw) : undefined;
  if (before && !Number.isFinite(before.getTime())) {
    return c.json<ApiResponse>({ ok: false, error: "before must be a valid timestamp" }, 400);
  }
  try {
    const archives = await listAuditArchives(c.get("tenantId"), {
      limit: limit.value,
      before,
    });
    return c.json({ ok: true, data: archives });
  } catch (error) {
    console.error("[audit] archive list failed", redactedThrownDiagnostics(error));
    return c.json<ApiResponse>({ ok: false, error: "Failed to list audit archives" }, 500);
  }
});

auditRoutes.post("/archives/restore", async (c) => {
  const body = await safeJsonParse<Record<string, unknown>>(c);
  const allowed = new Set(["manifest", "manifestSha256", "signature"]);
  if (
    !body ||
    Object.keys(body).some((key) => !allowed.has(key)) ||
    !body.manifest ||
    typeof body.manifest !== "object" ||
    typeof body.manifestSha256 !== "string" ||
    typeof body.signature !== "string"
  ) {
    return c.json<ApiResponse>({ ok: false, error: "Signed archive manifest is required" }, 400);
  }
  try {
    const result = await beginAuditArchiveRestore({
      tenantId: c.get("tenantId"),
      manifest: body.manifest as never,
      manifestSha256: body.manifestSha256,
      signature: body.signature,
      actorId: c.get("userId") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return c.json({ ok: true, data: result }, result.reused ? 200 : 201);
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Restore failed" },
      409,
    );
  }
});

auditRoutes.put("/archives/:archiveId/restore/chunks/:index", async (c) => {
  const archiveId = c.req.param("archiveId");
  const indexRaw = c.req.param("index");
  if (!UUID_PATTERN.test(archiveId) || !/^\d{1,6}$/.test(indexRaw)) {
    return c.json<ApiResponse>({ ok: false, error: "Restore session not found" }, 404);
  }
  if (!(c.req.header("content-type") ?? "").toLowerCase().startsWith("application/x-ndjson")) {
    return c.json<ApiResponse>({ ok: false, error: "application/x-ndjson is required" }, 415);
  }
  try {
    const result = await putAuditArchiveRestoreChunk({
      tenantId: c.get("tenantId"),
      archiveId,
      index: Number(indexRaw),
      jsonl: await c.req.text(),
    });
    return c.json({ ok: true, data: result });
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Restore failed" },
      409,
    );
  }
});

auditRoutes.post("/archives/:archiveId/restore/complete", async (c) => {
  const archiveId = c.req.param("archiveId");
  if (!UUID_PATTERN.test(archiveId)) {
    return c.json<ApiResponse>({ ok: false, error: "Restore session not found" }, 404);
  }
  try {
    const result = await completeAuditArchiveRestore({
      tenantId: c.get("tenantId"),
      archiveId,
      actorId: c.get("userId") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return c.json({ ok: true, data: result });
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Restore failed" },
      409,
    );
  }
});

auditRoutes.post("/archives/:archiveId/durability-ack", async (c) => {
  const archiveId = c.req.param("archiveId");
  if (!UUID_PATTERN.test(archiveId)) {
    return c.json<ApiResponse>({ ok: false, error: "Archive not found" }, 404);
  }
  const body = await safeJsonParse<Record<string, unknown>>(c);
  const allowed = new Set(["payload", "keyId", "signature"]);
  if (
    !body ||
    Object.keys(body).some((key) => !allowed.has(key)) ||
    !body.payload ||
    typeof body.payload !== "object" ||
    typeof body.keyId !== "string" ||
    typeof body.signature !== "string"
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signed durability acknowledgement is required" },
      400,
    );
  }
  try {
    const result = await recordAuditArchiveDurabilityAcknowledgement({
      tenantId: c.get("tenantId"),
      archiveId,
      payload: body.payload as never,
      keyId: body.keyId,
      signature: body.signature,
      actorId: c.get("userId") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return c.json({ ok: true, data: result });
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Acknowledgement failed" },
      409,
    );
  }
});

auditRoutes.get("/archives/:archiveId", async (c) => {
  const archiveId = c.req.param("archiveId");
  if (!UUID_PATTERN.test(archiveId)) {
    return c.json<ApiResponse>({ ok: false, error: "Archive not found" }, 404);
  }
  const manifest = await getAuditArchiveManifest(c.get("tenantId"), archiveId);
  if (!manifest) return c.json<ApiResponse>({ ok: false, error: "Archive not found" }, 404);
  return c.json({ ok: true, data: manifest });
});

auditRoutes.get("/archives/:archiveId/chunks/:index", async (c) => {
  const archiveId = c.req.param("archiveId");
  const indexRaw = c.req.param("index");
  if (!UUID_PATTERN.test(archiveId) || !/^\d{1,6}$/.test(indexRaw)) {
    return c.json<ApiResponse>({ ok: false, error: "Archive chunk not found" }, 404);
  }
  const chunk = await getAuditArchiveChunk(c.get("tenantId"), archiveId, Number(indexRaw));
  if (!chunk) return c.json<ApiResponse>({ ok: false, error: "Archive chunk not found" }, 404);
  return new Response(chunk.jsonl, {
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "X-Content-SHA256": chunk.sha256,
      "X-Content-Type-Options": "nosniff",
    },
  });
});

auditRoutes.post("/retention/run", async (c) => {
  if (!isCheckpointSigningConfigured()) {
    return c.json<ApiResponse>({ ok: false, error: "Audit signing key is required" }, 503);
  }
  const tenantId = c.get("tenantId");
  try {
    const result = await runTenantAuditRetention(tenantId, {
      actorId: c.get("userId") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    const verification = await verifyAuditChain(tenantId, { requireHead: true });
    if (!verification.valid) {
      throw new Error(`Post-retention audit verification failed at seq ${verification.brokenAt}`);
    }
    return c.json({ ok: true, data: result });
  } catch (error) {
    console.error(
      `[audit] retention run failed for tenant ${tenantId}`,
      redactedThrownDiagnostics(error),
    );
    return c.json<ApiResponse>({ ok: false, error: "Audit retention failed" }, 500);
  }
});

// ─── GET /audit/bundle ────────────────────────────────────────────────────
//
// Offline-verifiable evidence bundle. Returns the tenant's audit events in the
// requested seq range plus an Ed25519-signed checkpoint over the chain head, so
// an third-party auditor can verify the export offline (no Steward access, no
// secret) with scripts/verify-evidence-bundle.mjs. The signature commits to the
// head HMAC; the event list lets the verifier confirm linkage and that the head
// row matches the signed checkpoint.
auditRoutes.get("/bundle", async (c) => {
  const tenantId = c.get("tenantId");

  if (!isCheckpointSigningConfigured()) {
    if (process.env.NODE_ENV === "production") {
      return c.json<ApiResponse>(
        {
          ok: false,
          error:
            "Offline evidence bundles require STEWARD_AUDIT_SIGNING_KEY. Generate an " +
            "Ed25519 key (openssl genpkey -algorithm ed25519) and configure it.",
        },
        503,
      );
    }
    console.warn(
      "⚠️ [audit] STEWARD_AUDIT_SIGNING_KEY not set — /audit/bundle disabled. " +
        "Set it to produce offline-verifiable evidence bundles.",
    );
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Offline evidence bundles are disabled: STEWARD_AUDIT_SIGNING_KEY is not " +
          "configured (development).",
      },
      503,
    );
  }

  const parsedFromSeq = parsePositiveIntegerParam(
    c.req.query("from"),
    "from",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  if (!parsedFromSeq.ok) {
    return c.json<ApiResponse>({ ok: false, error: parsedFromSeq.error }, 400);
  }
  const fromSeq = parsedFromSeq.value;
  const toRaw = c.req.query("to");
  const parsedToSeq = toRaw
    ? parsePositiveIntegerParam(toRaw, "to", fromSeq, Number.MAX_SAFE_INTEGER)
    : ({ ok: true, value: undefined } as const);
  if (!parsedToSeq.ok) {
    return c.json<ApiResponse>({ ok: false, error: parsedToSeq.error }, 400);
  }
  const requestedToSeq = parsedToSeq.value;
  const toSeq = requestedToSeq ?? fromSeq + MAX_AUDIT_BUNDLE_EVENTS - 1;
  if (toSeq < fromSeq) {
    return c.json<ApiResponse>({ ok: false, error: "to must be greater than from" }, 400);
  }
  if (toSeq - fromSeq + 1 > MAX_AUDIT_BUNDLE_EVENTS) {
    return c.json<ApiResponse>(
      { ok: false, error: `audit bundle range must not exceed ${MAX_AUDIT_BUNDLE_EVENTS} events` },
      400,
    );
  }

  let bundleData: AuditBundleData;
  try {
    bundleData = await readAuditBundleData(tenantId, fromSeq, toSeq);
  } catch (err) {
    console.error(
      `[audit] bundle read failed for tenant ${tenantId}`,
      redactedThrownDiagnostics(err),
    );
    return c.json<ApiResponse>({ ok: false, error: "Failed to read audit chain" }, 500);
  }

  // Single source of signing truth (spec §6.2): the checkpoint sign + content
  // digest + best-effort persistence live in services/audit.signAuditBundle, so
  // /audit/bundle and /v2/provider-actions/:id/evidence produce byte-identical
  // envelopes. No behavior change to this route.
  try {
    const bundle = await signAuditBundle(tenantId, fromSeq, toSeq, bundleData);
    return c.json(bundle);
  } catch (err) {
    if (err instanceof AuditSigningKeyError) {
      return c.json<ApiResponse>({ ok: false, error: err.message }, 503);
    }
    if (err instanceof AuditCheckpointAnchorError) {
      return c.json<ApiResponse>({ ok: false, error: "Required checkpoint anchoring failed" }, 503);
    }
    console.error(
      `[audit] checkpoint signing failed for tenant ${tenantId}`,
      redactedThrownDiagnostics(err),
    );
    return c.json<ApiResponse>({ ok: false, error: "Failed to sign checkpoint" }, 500);
  }
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
