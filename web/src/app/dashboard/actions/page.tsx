"use client";

import { motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import { steward } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import {
  sortWalletActionHistory,
  toWalletActionHistoryItem,
  type WalletActionHistoryItem,
  type WalletActionStatus,
  type WalletAuditEventEntry,
} from "@/lib/wallet-action-history";

type LoadState = "idle" | "loading" | "ready" | "error";
type StatusFilter = WalletActionStatus | "all";

const statusFilters: StatusFilter[] = [
  "all",
  "queued",
  "authorized",
  "signed",
  "succeeded",
  "broadcast",
  "confirmed",
  "replaced",
  "rejected",
  "failed",
  "canceled",
  "expired",
];

function statusTone(status: WalletActionStatus): string {
  switch (status) {
    case "succeeded":
    case "signed":
    case "broadcast":
    case "confirmed":
      return "border-success/30 text-success";
    case "queued":
    case "authorized":
      return "border-info/30 text-info";
    case "replaced":
    case "canceled":
    case "expired":
    case "rejected":
      return "border-warning/30 text-warning";
    case "failed":
      return "border-red-400/30 text-red-300";
    default:
      return "border-border text-text-tertiary";
  }
}

function labelStatus(status: StatusFilter): string {
  return status === "all"
    ? "All"
    : status
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
}

export default function WalletActionsPage() {
  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<WalletAuditEventEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState<StatusFilter>("all");
  const [adapterOnly, setAdapterOnly] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    void loadHistory();
  }, [adapterOnly]);

  async function loadHistory() {
    try {
      setState("loading");
      setError(null);
      const [walletActions, adapterActions] = await Promise.all([
        adapterOnly
          ? Promise.resolve({ data: [], pagination: { total: 0 } })
          : steward.getAuditEvents({
              resourceType: "wallet_action",
              actionPrefix: "wallet_action.",
              limit: 50,
            }),
        steward.getAuditEvents({
          resourceType: "account",
          actionPrefix: "wallet.action.",
          limit: 50,
        }),
      ]);
      const merged = [...walletActions.data, ...adapterActions.data];
      setEvents(merged);
      setTotal(walletActions.pagination.total + adapterActions.pagination.total);
      setState("ready");
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : "Failed to load wallet action history");
    }
  }

  const items = useMemo(
    () => sortWalletActionHistory(events.map(toWalletActionHistoryItem)),
    [events],
  );
  const filtered = useMemo(
    () =>
      items.filter((item) => {
        if (status !== "all" && item.status !== status) return false;
        const normalizedQuery = query.trim().toLowerCase();
        if (!normalizedQuery) return true;
        const searchable = [
          item.event.action,
          item.actionId,
          item.walletId,
          item.chain,
          item.value,
          item.requestId,
          item.txHash,
          item.lifecycleStatus,
          item.adapter?.kind,
          item.adapter?.provider,
          item.adapter?.lifecycleStatus,
          item.adapter?.sessionId,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return searchable.includes(normalizedQuery);
      }),
    [items, query, status],
  );
  const statusCounts = useMemo(
    () =>
      items.reduce<Record<WalletActionStatus, number>>(
        (counts, item) => {
          counts[item.status] += 1;
          return counts;
        },
        {
          authorized: 0,
          queued: 0,
          signed: 0,
          succeeded: 0,
          broadcast: 0,
          confirmed: 0,
          replaced: 0,
          rejected: 0,
          failed: 0,
          canceled: 0,
          expired: 0,
          unknown: 0,
        },
      ),
    [items],
  );
  const adapterCount = items.filter((item) => item.adapter).length;
  const activeCount = items.filter((item) =>
    ["authorized", "queued", "signed", "broadcast"].includes(item.status),
  ).length;
  const terminalCount = items.filter((item) =>
    ["succeeded", "confirmed", "replaced", "rejected", "failed", "canceled", "expired"].includes(
      item.status,
    ),
  ).length;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Wallet Actions</h1>
          <p className="text-sm text-text-tertiary mt-1">
            Dedicated action history across wallet actions and adapter lifecycle audit markers.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadHistory()}
          className="px-4 py-2 text-sm border border-border text-text-secondary hover:text-text hover:border-text-tertiary transition-colors"
        >
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border">
        <Metric label="Loaded Events" value={items.length} detail={`${total} indexed total`} />
        <Metric label="Active Actions" value={activeCount} detail="queued, signed, broadcast" />
        <Metric label="Adapter Markers" value={adapterCount} detail={`${terminalCount} terminal`} />
      </div>

      <section className="border border-border bg-bg-elevated p-5 space-y-5">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
          <div>
            <h2 className="font-display text-sm font-600">Action History</h2>
            <p className="text-xs text-text-tertiary mt-1">
              Uses server-side action-prefix and adapter metadata filters over audit events.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search action, wallet, hash"
              aria-label="Search wallet actions"
              className="min-h-9 w-full sm:w-64 border border-border-subtle bg-bg px-3 py-1.5 text-xs text-text-secondary outline-none transition-colors placeholder:text-text-tertiary focus:border-accent"
            />
            <div className="flex flex-wrap gap-2">
              {statusFilters.map((filter) => (
                <button
                  key={filter}
                  type="button"
                  onClick={() => setStatus(filter)}
                  className={`px-3 py-1.5 text-xs border transition-colors ${
                    status === filter
                      ? "border-accent text-accent bg-accent/5"
                      : "border-border-subtle text-text-tertiary hover:text-text-secondary"
                  }`}
                >
                  {labelStatus(filter)}
                  {filter !== "all" && statusCounts[filter] > 0 ? ` ${statusCounts[filter]}` : ""}
                </button>
              ))}
            </div>
            <label className="inline-flex items-center gap-2 text-xs text-text-secondary">
              <input
                type="checkbox"
                checked={adapterOnly}
                onChange={(event) => setAdapterOnly(event.target.checked)}
                className="accent-current"
              />
              Adapter metadata only
            </label>
          </div>
        </div>

        {state === "loading" ? (
          <div className="space-y-2">
            {[...Array(5)].map((_, index) => (
              <div key={index} className="h-20 bg-bg animate-pulse border border-border-subtle" />
            ))}
          </div>
        ) : state === "error" ? (
          <div className="border border-red-400/20 bg-red-400/5 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center border border-border-subtle">
            <p className="font-display text-lg font-600 text-text-secondary">
              No wallet actions found
            </p>
            <p className="text-sm text-text-tertiary mt-2">
              Adjust filters or search terms, or wait for wallet action audit events to be indexed.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-xs text-text-tertiary">
              Showing {filtered.length} of {items.length} loaded events
            </div>
            {filtered.map((item) => (
              <WalletActionRow key={`${item.event.id}-${item.event.seq}`} item={item} />
            ))}
          </div>
        )}
      </section>
    </motion.div>
  );
}

function Metric({ label, value, detail }: { label: string; value: number; detail: string }) {
  return (
    <div className="bg-bg-elevated p-5 min-h-24">
      <div className="text-xs text-text-tertiary tracking-wider uppercase">{label}</div>
      <div className="font-display text-2xl font-700 mt-2 tabular-nums">{value}</div>
      <div className="text-xs text-text-tertiary mt-1">{detail}</div>
    </div>
  );
}

function WalletActionRow({ item }: { item: WalletActionHistoryItem }) {
  const adapterParts = item.adapter
    ? [item.adapter.kind, item.adapter.provider, item.adapter.lifecycleStatus]
        .filter(Boolean)
        .join(" / ")
    : null;

  return (
    <article className="border border-border-subtle px-4 py-4">
      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-medium text-text">{item.actionKind}</h3>
            <span
              className={`text-[11px] uppercase tracking-[0.12em] border px-2 py-0.5 ${statusTone(
                item.status,
              )}`}
            >
              {labelStatus(item.status)}
            </span>
            {item.adapter && (
              <span className="text-[11px] uppercase tracking-[0.12em] border border-accent/30 text-accent px-2 py-0.5">
                Adapter
              </span>
            )}
          </div>
          <div className="text-xs text-text-tertiary mt-2 font-mono break-all">
            {item.event.action}
          </div>
        </div>
        <div className="text-xs text-text-tertiary font-mono flex-shrink-0">
          seq {item.event.seq}
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2 text-xs">
        <Fact label="Action ID" value={item.actionId} mono />
        <Fact label="Wallet" value={item.walletId} mono />
        <Fact label="Chain" value={item.chain} />
        <Fact label="Value" value={item.value} mono />
        <Fact label="Lifecycle" value={item.lifecycleStatus} />
        <Fact label="Tx Hash" value={item.txHash} mono />
        <Fact label="Request" value={item.requestId} mono />
      </div>

      {adapterParts && (
        <div className="mt-3 border border-border-subtle bg-bg px-3 py-3">
          <div className="text-[11px] uppercase tracking-[0.12em] text-text-tertiary">
            Adapter Lifecycle
          </div>
          <div className="text-sm text-text-secondary mt-1">{adapterParts}</div>
          {item.adapter?.sessionId && (
            <div className="text-xs text-text-tertiary font-mono mt-1">
              session {item.adapter.sessionId}
            </div>
          )}
        </div>
      )}

      <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-xs text-text-tertiary">
        <span>{formatDate(item.event.created_at)}</span>
        <span>{item.event.actor_type}</span>
        {item.event.actor_id && <span className="font-mono">{item.event.actor_id}</span>}
        {item.requestId && <span className="font-mono">request {item.requestId}</span>}
        {item.event.resource_type && <span>{item.event.resource_type}</span>}
      </div>
    </article>
  );
}

function Fact({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string | null;
  mono?: boolean;
}) {
  return (
    <div className="border border-border-subtle bg-bg px-3 py-2 min-w-0">
      <div className="text-[11px] uppercase tracking-[0.12em] text-text-tertiary">{label}</div>
      <div className={`mt-1 truncate text-text-secondary ${mono ? "font-mono" : ""}`}>
        {value ?? "—"}
      </div>
    </div>
  );
}
