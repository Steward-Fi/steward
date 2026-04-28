/**
 * Dashboard-side adapter for the `@stwd/sdk` audit responses.
 *
 * The dashboard historically consumed flattened shapes that differ from the
 * raw API envelopes. Keep the mapping here so the published SDK stays in
 * lock-step with the HTTP contract and the UI stays legible.
 */

import type { AuditLogEntry, AuditSummaryResponse } from "@stwd/sdk";

export type AuditResult = "allow" | "deny" | "error";

/** Flattened audit entry consumed by `dashboard/audit`. */
export interface AuditEntry {
  id: string;
  tenantId: string;
  agentId: string;
  agentName?: string;
  action: string;
  result: AuditResult;
  details?: Record<string, unknown>;
  cost?: string;
  timestamp: string;
}

export interface AuditQueryParams {
  agentId?: string;
  action?: string;
  result?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

/** Per-agent audit roll-up consumed by `dashboard/audit`. */
export interface AuditSummary {
  agentId: string;
  agentName?: string;
  totalActions: number;
  totalCost: string;
  allowCount: number;
  denyCount: number;
}

const DENY_STATUSES = new Set(["rejected", "denied", "deny", "violation", "policy_violation"]);
const ERROR_STATUSES = new Set(["error", "failed", "failure"]);

/** Map a raw audit log entry to the dashboard's flattened shape. */
export function toAuditEntry(entry: AuditLogEntry): AuditEntry {
  const status = (entry.status ?? "").toLowerCase();
  let result: AuditResult = "allow";
  if (ERROR_STATUSES.has(status)) result = "error";
  else if (DENY_STATUSES.has(status)) result = "deny";

  return {
    id: entry.id,
    tenantId: "",
    agentId: entry.agentId,
    action: entry.action,
    result,
    details: entry.details,
    cost: entry.value,
    timestamp: entry.timestamp,
  };
}

/** Translate dashboard `AuditQueryParams` into the SDK's query shape. */
export function toAuditLogQuery(params?: AuditQueryParams) {
  if (!params) return undefined;
  const limit = params.limit;
  const page =
    params.offset !== undefined && limit ? Math.floor(params.offset / limit) + 1 : undefined;
  return {
    agentId: params.agentId,
    action: params.action,
    status: params.result,
    dateFrom: params.from,
    dateTo: params.to,
    limit,
    page,
  };
}

/** Collapse the API summary into the per-agent rows the dashboard expects. */
export function toAuditSummaryRows(summary: AuditSummaryResponse): AuditSummary[] {
  return summary.topAgents.map((a) => ({
    agentId: a.agentId,
    agentName: a.name,
    totalActions: a.txCount,
    totalCost: "0",
    allowCount: a.txCount,
    denyCount: 0,
  }));
}
