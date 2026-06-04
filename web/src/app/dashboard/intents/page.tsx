"use client";

import type { Intent, IntentStatus, IntentType } from "@stwd/sdk";
import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/components/auth-provider";
import { steward } from "@/lib/api";
import { cn, formatDate, shortenAddress } from "@/lib/utils";

const STATUS_FILTERS = [
  "all",
  "pending",
  "authorized",
  "executing",
  "executed",
  "failed",
  "rejected",
  "canceled",
  "expired",
] as const;

const TYPE_FILTERS = [
  "all",
  "rpc",
  "transfer",
  "wallet_action",
  "wallet_update",
  "policy_update",
  "policy_rule_update",
  "quorum_update",
] as const;

const statusStyles: Record<string, string> = {
  pending: "bg-amber-400/10 text-amber-400",
  authorized: "bg-sky-400/10 text-sky-400",
  executing: "bg-blue-400/10 text-blue-400",
  executed: "bg-emerald-400/10 text-emerald-400",
  failed: "bg-orange-400/10 text-orange-400",
  rejected: "bg-red-400/10 text-red-400",
  canceled: "bg-text-tertiary/10 text-text-tertiary",
  expired: "bg-violet-400/10 text-violet-400",
};

type StatusFilter = (typeof STATUS_FILTERS)[number];
type TypeFilter = (typeof TYPE_FILTERS)[number];
type Toast = { id: string; message: string; kind: "success" | "error" };
type IntentAction = "authorize" | "reject" | "cancel" | "execute" | "fail";

function readable(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function jsonPreview(value: unknown) {
  if (value === null || value === undefined) return "{}";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function displayDate(value: Date | string | number | null | undefined) {
  return value ? formatDate(typeof value === "number" ? new Date(value) : value) : "—";
}

function intentId(intent: Intent) {
  return intent.intent_id || intent.id;
}

function actorLabel(intent: Intent) {
  return intent.createdByDisplayName || intent.created_by_display_name || intent.createdById || "—";
}

function resourceLabel(intent: Intent) {
  const id = intent.resourceId || intent.resource_id;
  if (!intent.resourceType && !id) return "—";
  return [intent.resourceType, id].filter(Boolean).join(":");
}

function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 text-xs font-medium",
        statusStyles[status] || "bg-bg-surface text-text-tertiary",
      )}
    >
      {readable(status)}
    </span>
  );
}

function JsonBlock({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="min-w-0">
      <div className="mb-2 text-xs uppercase tracking-wider text-text-tertiary">{label}</div>
      <pre className="max-h-80 overflow-auto border border-border-subtle bg-bg p-3 font-mono text-xs leading-relaxed text-text-secondary">
        {jsonPreview(value)}
      </pre>
    </div>
  );
}

export default function IntentsPage() {
  useAuth();
  const [intents, setIntents] = useState<Intent[]>([]);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const loadIntents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await steward.listIntents({
        limit: 200,
        status: statusFilter === "all" ? undefined : (statusFilter as IntentStatus),
        intentType: typeFilter === "all" ? undefined : (typeFilter as IntentType),
      });
      setIntents(response.intents);
      setSelectedId((current) => {
        if (current && response.intents.some((intent) => intentId(intent) === current)) {
          return current;
        }
        return response.intents[0] ? intentId(response.intents[0]) : null;
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load intents");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, typeFilter]);

  useEffect(() => {
    loadIntents();
  }, [loadIntents]);

  function addToast(message: string, kind: Toast["kind"]) {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev, { id, message, kind }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 3000);
  }

  async function runAction(intent: Intent, action: IntentAction) {
    const id = intentId(intent);
    const key = `${id}-${action}`;
    let reason: string | null = null;

    if (action === "reject" || action === "cancel" || action === "fail") {
      reason = window.prompt(`${readable(action)} reason`);
      if (reason === null) return;
    }

    setActionLoading(key);
    try {
      let updated: Intent;
      if (action === "authorize") {
        updated = await steward.authorizeIntent(id, { reason: "Reviewed from dashboard" });
      } else if (action === "reject") {
        updated = await steward.rejectIntent(id, { reason: reason || "Rejected from dashboard" });
      } else if (action === "cancel") {
        updated = await steward.cancelIntent(id, { reason: reason || "Canceled from dashboard" });
      } else if (action === "execute") {
        updated = await steward.executeIntent(id, {
          executionResult: { reviewedFrom: "dashboard", executedAt: new Date().toISOString() },
        });
      } else {
        updated = await steward.failIntent(id, {
          reason: reason || "Failed from dashboard",
          executionResult: { reviewedFrom: "dashboard", failedAt: new Date().toISOString() },
        });
      }

      setIntents((prev) => prev.map((item) => (intentId(item) === id ? updated : item)));
      setSelectedId(intentId(updated));
      addToast(`${readable(action)} updated`, "success");
    } catch (e: unknown) {
      addToast(e instanceof Error ? e.message : `Failed to ${action}`, "error");
    } finally {
      setActionLoading(null);
    }
  }

  const selectedIntent = useMemo(
    () => intents.find((intent) => intentId(intent) === selectedId) ?? null,
    [intents, selectedId],
  );

  const counts = useMemo(
    () =>
      intents.reduce<Record<string, number>>((acc, intent) => {
        acc[intent.status] = (acc[intent.status] || 0) + 1;
        return acc;
      }, {}),
    [intents],
  );

  if (loading) {
    return (
      <div className="space-y-8">
        <div className="h-8 w-40 animate-pulse bg-bg-surface" />
        <div className="h-10 animate-pulse bg-bg-surface" />
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_420px]">
          <div className="h-96 animate-pulse bg-bg-surface" />
          <div className="h-96 animate-pulse bg-bg-surface" />
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Intents</h1>
          <p className="mt-1 text-sm text-text-tertiary">Reviewable tenant actions</p>
        </div>
        <button
          onClick={loadIntents}
          className="w-fit bg-bg-surface px-4 py-2 text-xs font-medium text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text"
        >
          Refresh
        </button>
      </div>

      <div className="pointer-events-none fixed right-6 bottom-6 z-50 flex flex-col gap-2">
        <AnimatePresence>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.96 }}
              transition={{ duration: 0.22, ease: [0.25, 1, 0.5, 1] }}
              className={cn(
                "pointer-events-auto border bg-bg-elevated px-4 py-3 text-sm font-medium",
                toast.kind === "success"
                  ? "border-emerald-400/30 text-emerald-400"
                  : "border-red-400/30 text-red-400",
              )}
            >
              {toast.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {error && (
        <div className="border border-red-400/20 bg-red-400/5 py-16 text-center">
          <p className="mb-1 text-sm text-text-secondary">Failed to load intents</p>
          <p className="mb-4 font-mono text-xs text-text-tertiary">{error}</p>
          <button
            onClick={loadIntents}
            className="bg-accent px-4 py-2 text-sm text-bg transition-colors hover:bg-accent-hover"
          >
            Retry
          </button>
        </div>
      )}

      <div className="space-y-3">
        <div className="flex flex-wrap gap-1">
          {STATUS_FILTERS.map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={cn(
                "px-3 py-1.5 text-xs transition-colors",
                statusFilter === status
                  ? "bg-bg-surface text-text"
                  : "text-text-tertiary hover:bg-bg-elevated hover:text-text-secondary",
              )}
            >
              {status === "all" ? "All" : readable(status)}
              <span className="ml-1 tabular-nums">
                {status === "all" ? intents.length : counts[status] || 0}
              </span>
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1">
          {TYPE_FILTERS.map((type) => (
            <button
              key={type}
              onClick={() => setTypeFilter(type)}
              className={cn(
                "px-3 py-1.5 text-xs transition-colors",
                typeFilter === type
                  ? "bg-bg-surface text-text"
                  : "text-text-tertiary hover:bg-bg-elevated hover:text-text-secondary",
              )}
            >
              {type === "all" ? "All types" : readable(type)}
            </button>
          ))}
        </div>
      </div>

      {error ? null : intents.length === 0 ? (
        <div className="border border-border-subtle py-20 text-center">
          <p className="font-display text-lg font-600 text-text-secondary">No intents</p>
          <p className="mx-auto mt-2 max-w-sm text-sm text-text-tertiary">
            Matching review requests will appear here.
          </p>
        </div>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_440px]">
          <div className="min-w-0 border-t border-border-subtle">
            <div className="hidden items-center border-b border-border px-2 py-2 text-xs tracking-wider text-text-tertiary uppercase md:flex">
              <span className="w-28">Status</span>
              <span className="w-36">Type</span>
              <span className="flex-1">Agent</span>
              <span className="w-44">Resource</span>
              <span className="w-32 text-right">Created</span>
            </div>

            {intents.map((intent, index) => {
              const id = intentId(intent);
              const isSelected = selectedId === id;

              return (
                <motion.div
                  key={id}
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelectedId(id)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setSelectedId(id);
                    }
                  }}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: Math.min(index * 0.03, 0.5), duration: 0.3 }}
                  className={cn(
                    "flex w-full flex-col gap-2 border-b border-border-subtle px-2 py-3.5 text-left transition-colors md:flex-row md:items-center md:gap-0",
                    isSelected ? "bg-bg-elevated" : "hover:bg-bg-elevated/30",
                  )}
                >
                  <div className="w-28">
                    <StatusPill status={intent.status} />
                  </div>
                  <div className="w-36">
                    <span className="text-sm text-text-secondary">
                      {readable(String(intent.intentType || intent.intent_type))}
                    </span>
                  </div>
                  <div className="min-w-0 flex-1">
                    {intent.agentId ? (
                      <Link
                        href={`/dashboard/agents/${intent.agentId}`}
                        onClick={(event) => event.stopPropagation()}
                        className="text-sm text-text transition-colors hover:text-accent"
                      >
                        {shortenAddress(intent.agentId, 6)}
                      </Link>
                    ) : (
                      <span className="text-sm text-text-tertiary">Tenant</span>
                    )}
                  </div>
                  <div className="w-44 min-w-0">
                    <span className="block truncate font-mono text-xs text-text-tertiary">
                      {resourceLabel(intent)}
                    </span>
                  </div>
                  <div className="w-32 text-right">
                    <span className="text-xs text-text-tertiary">
                      {displayDate(intent.createdAt || intent.created_at)}
                    </span>
                  </div>
                </motion.div>
              );
            })}
          </div>

          <aside className="min-w-0 border border-border-subtle bg-bg-elevated/30">
            {selectedIntent ? (
              <div className="space-y-6 p-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="mb-2">
                      <StatusPill status={selectedIntent.status} />
                    </div>
                    <h2 className="truncate font-display text-lg font-600 text-text">
                      {readable(String(selectedIntent.intentType || selectedIntent.intent_type))}
                    </h2>
                    <p className="mt-1 truncate font-mono text-xs text-text-tertiary">
                      {intentId(selectedIntent)}
                    </p>
                  </div>
                  <span className="font-mono text-xs text-text-tertiary">
                    {displayDate(selectedIntent.updatedAt)}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-x-4 gap-y-3 border-y border-border-subtle py-4 text-xs">
                  <span className="text-text-tertiary">Created by</span>
                  <span className="truncate text-right text-text-secondary">
                    {actorLabel(selectedIntent)}
                  </span>
                  <span className="text-text-tertiary">Agent</span>
                  <span className="truncate text-right font-mono text-text-secondary">
                    {selectedIntent.agentId || "—"}
                  </span>
                  <span className="text-text-tertiary">Wallet</span>
                  <span className="truncate text-right font-mono text-text-secondary">
                    {selectedIntent.wallet_id || "—"}
                  </span>
                  <span className="text-text-tertiary">Resource</span>
                  <span className="truncate text-right font-mono text-text-secondary">
                    {resourceLabel(selectedIntent)}
                  </span>
                  <span className="text-text-tertiary">Expires</span>
                  <span className="text-right text-text-secondary">
                    {displayDate(selectedIntent.expiresAt)}
                  </span>
                </div>

                <div className="flex flex-wrap gap-2">
                  {selectedIntent.status === "pending" && (
                    <>
                      <button
                        onClick={() => runAction(selectedIntent, "authorize")}
                        disabled={actionLoading !== null}
                        className="bg-emerald-400/10 px-3 py-2 text-xs font-medium text-emerald-400 transition-colors hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {actionLoading === `${intentId(selectedIntent)}-authorize`
                          ? "..."
                          : "Authorize"}
                      </button>
                      <button
                        onClick={() => runAction(selectedIntent, "reject")}
                        disabled={actionLoading !== null}
                        className="bg-red-400/10 px-3 py-2 text-xs font-medium text-red-400 transition-colors hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {actionLoading === `${intentId(selectedIntent)}-reject` ? "..." : "Reject"}
                      </button>
                    </>
                  )}
                  {(selectedIntent.status === "pending" ||
                    selectedIntent.status === "authorized") && (
                    <button
                      onClick={() => runAction(selectedIntent, "cancel")}
                      disabled={actionLoading !== null}
                      className="bg-text-tertiary/10 px-3 py-2 text-xs font-medium text-text-secondary transition-colors hover:bg-bg-surface disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {actionLoading === `${intentId(selectedIntent)}-cancel` ? "..." : "Cancel"}
                    </button>
                  )}
                  {selectedIntent.status === "authorized" && (
                    <>
                      <button
                        onClick={() => runAction(selectedIntent, "execute")}
                        disabled={actionLoading !== null}
                        className="bg-sky-400/10 px-3 py-2 text-xs font-medium text-sky-400 transition-colors hover:bg-sky-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {actionLoading === `${intentId(selectedIntent)}-execute`
                          ? "..."
                          : "Execute"}
                      </button>
                      <button
                        onClick={() => runAction(selectedIntent, "fail")}
                        disabled={actionLoading !== null}
                        className="bg-orange-400/10 px-3 py-2 text-xs font-medium text-orange-400 transition-colors hover:bg-orange-400/20 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        {actionLoading === `${intentId(selectedIntent)}-fail` ? "..." : "Fail"}
                      </button>
                    </>
                  )}
                </div>

                <div className="space-y-4">
                  <JsonBlock label="Payload" value={selectedIntent.payload} />
                  <JsonBlock
                    label="Authorization"
                    value={
                      selectedIntent.authorizationDetails || selectedIntent.authorization_details
                    }
                  />
                  <JsonBlock
                    label="Execution"
                    value={
                      selectedIntent.executionResult ||
                      selectedIntent.execution_result || {
                        authorizedBy: selectedIntent.authorizedBy || selectedIntent.authorized_by,
                        rejectedBy: selectedIntent.rejectedBy || selectedIntent.rejected_by,
                        cancellationReason:
                          selectedIntent.cancellationReason || selectedIntent.cancellation_reason,
                        failureReason:
                          selectedIntent.failureReason || selectedIntent.failure_reason,
                      }
                    }
                  />
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-sm text-text-tertiary">Select an intent</div>
            )}
          </aside>
        </div>
      )}
    </motion.div>
  );
}
