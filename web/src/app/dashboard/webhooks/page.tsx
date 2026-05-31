"use client";

import { WEBHOOK_EVENT_TYPES, type WebhookConfig, type WebhookDelivery } from "@stwd/sdk";
import { AnimatePresence, motion } from "framer-motion";
import type { FormEvent } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { steward } from "@/lib/api";
import { formatDate } from "@/lib/utils";

const ease: [number, number, number, number] = [0.25, 1, 0.5, 1];

function statusClass(status: WebhookDelivery["status"]) {
  const map: Record<WebhookDelivery["status"], string> = {
    pending: "text-amber-400 bg-amber-400/10",
    processing: "text-sky-300 bg-sky-300/10",
    delivered: "text-emerald-400 bg-emerald-400/10",
    failed: "text-orange-400 bg-orange-400/10",
    dead: "text-red-400 bg-red-400/10",
  };
  return map[status] ?? "text-text-tertiary bg-bg-surface";
}

function canRetry(delivery: WebhookDelivery) {
  return delivery.status !== "delivered" && delivery.attempts < delivery.maxAttempts;
}

function canReplay(delivery: WebhookDelivery) {
  return (
    (delivery.status === "delivered" ||
      delivery.status === "failed" ||
      delivery.status === "dead") &&
    delivery.eventType !== "webhook.test"
  );
}

function parseEventList(value: string) {
  return value
    .split(/[\n,]/)
    .map((event) => event.trim())
    .filter(Boolean);
}

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [deliveryLoading, setDeliveryLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [retryingId, setRetryingId] = useState<string | null>(null);
  const [replayingId, setReplayingId] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [deliveryStatusFilter, setDeliveryStatusFilter] = useState<string>("all");
  const [deliveryEventFilter, setDeliveryEventFilter] = useState("");
  const [deliveryErrorFilter, setDeliveryErrorFilter] = useState<string>("all");
  const [newWebhook, setNewWebhook] = useState({
    url: "",
    description: "",
    events: "user.created\nuser.authenticated\ntransaction.confirmed",
  });

  const deliveryQuery = useMemo(
    () => ({
      limit: 100,
      ...(deliveryStatusFilter !== "all"
        ? { status: deliveryStatusFilter as WebhookDelivery["status"] }
        : {}),
      ...(deliveryEventFilter.trim() ? { eventType: deliveryEventFilter.trim() } : {}),
      ...(deliveryErrorFilter !== "all" ? { hasError: deliveryErrorFilter === "with_error" } : {}),
    }),
    [deliveryErrorFilter, deliveryEventFilter, deliveryStatusFilter],
  );

  const selectedWebhook = useMemo(
    () => webhooks.find((webhook) => webhook.id === selectedId),
    [selectedId, webhooks],
  );

  const loadDeliveries = useCallback(
    async (webhookId: string) => {
      setDeliveryLoading(true);
      try {
        const rows = await steward.getWebhookDeliveries(webhookId, deliveryQuery);
        setDeliveries(rows);
      } finally {
        setDeliveryLoading(false);
      }
    },
    [deliveryQuery],
  );

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const configs = await steward.listWebhooks();
      setWebhooks(configs);
      const nextSelectedId = selectedId || configs[0]?.id || "";
      setSelectedId(nextSelectedId);
      if (nextSelectedId) {
        await loadDeliveries(nextSelectedId);
      } else {
        setDeliveries([]);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load webhooks");
    } finally {
      setLoading(false);
    }
  }, [loadDeliveries, selectedId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  async function selectWebhook(webhookId: string) {
    setSelectedId(webhookId);
    setExpanded(null);
    setError(null);
    try {
      await loadDeliveries(webhookId);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load webhook deliveries");
    }
  }

  async function retryDelivery(deliveryId: string) {
    if (!selectedId) return;
    setRetryingId(deliveryId);
    setError(null);
    try {
      const updated = await steward.retryDelivery(deliveryId);
      setDeliveries((rows) => rows.map((row) => (row.id === updated.id ? updated : row)));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to retry webhook delivery");
    } finally {
      setRetryingId(null);
    }
  }

  async function replayDelivery(delivery: WebhookDelivery) {
    if (!window.confirm("Replay this event as a new signed webhook delivery?")) return;
    setReplayingId(delivery.id);
    setError(null);
    try {
      const replayed = await steward.replayDelivery(delivery.id);
      const matchesFilters =
        (deliveryStatusFilter === "all" || replayed.status === deliveryStatusFilter) &&
        (!deliveryEventFilter.trim() || replayed.eventType === deliveryEventFilter.trim()) &&
        (deliveryErrorFilter === "all" ||
          (deliveryErrorFilter === "with_error" ? replayed.hasError : !replayed.hasError));
      setDeliveries((rows) =>
        matchesFilters
          ? [replayed, ...rows.filter((row) => row.id !== replayed.id)]
          : rows.filter((row) => row.id !== replayed.id),
      );
      setExpanded(matchesFilters ? replayed.id : null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to replay webhook delivery");
    } finally {
      setReplayingId(null);
    }
  }

  async function sendTest(webhook: WebhookConfig) {
    setTestingId(webhook.id);
    setError(null);
    try {
      const delivery = await steward.testWebhook(webhook.id);
      if (selectedId !== webhook.id) {
        setSelectedId(webhook.id);
      }
      const matchesFilters =
        (deliveryStatusFilter === "all" || delivery.status === deliveryStatusFilter) &&
        (!deliveryEventFilter.trim() || delivery.eventType === deliveryEventFilter.trim()) &&
        (deliveryErrorFilter === "all" ||
          (deliveryErrorFilter === "with_error" ? delivery.hasError : !delivery.hasError));
      setDeliveries((rows) =>
        matchesFilters
          ? [delivery, ...rows.filter((row) => row.id !== delivery.id)]
          : rows.filter((row) => row.id !== delivery.id),
      );
      setExpanded(matchesFilters ? delivery.id : null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to send test webhook");
    } finally {
      setTestingId(null);
    }
  }

  async function exportDeliveries() {
    if (!selectedId) return;
    setExporting(true);
    setError(null);
    try {
      const csv = await steward.exportWebhookDeliveriesCsv(selectedId, {
        ...deliveryQuery,
        limit: 1000,
      });
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `webhook-deliveries-${selectedId}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to export webhook deliveries");
    } finally {
      setExporting(false);
    }
  }

  async function createEndpoint(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreating(true);
    setError(null);
    setCreatedSecret(null);
    try {
      const created = await steward.createWebhook({
        url: newWebhook.url.trim(),
        description: newWebhook.description.trim() || undefined,
        events: parseEventList(newWebhook.events),
      });
      setWebhooks((rows) => [created, ...rows.filter((row) => row.id !== created.id)]);
      setSelectedId(created.id);
      setDeliveries([]);
      setNewWebhook({
        url: "",
        description: "",
        events: "user.created\nuser.authenticated\ntransaction.confirmed",
      });
      setCreatedSecret(created.secret ?? null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to create webhook endpoint");
    } finally {
      setCreating(false);
    }
  }

  async function setEndpointEnabled(webhook: WebhookConfig, enabled: boolean) {
    setUpdatingId(webhook.id);
    setError(null);
    try {
      const updated = await steward.updateWebhook(webhook.id, { enabled });
      setWebhooks((rows) => rows.map((row) => (row.id === updated.id ? updated : row)));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to update webhook endpoint");
    } finally {
      setUpdatingId(null);
    }
  }

  async function deleteEndpoint(webhook: WebhookConfig) {
    if (!window.confirm(`Delete webhook endpoint ${webhook.url}?`)) return;
    setDeletingId(webhook.id);
    setError(null);
    try {
      await steward.deleteWebhook(webhook.id);
      const remaining = webhooks.filter((row) => row.id !== webhook.id);
      setWebhooks(remaining);
      const nextSelected = remaining[0]?.id ?? "";
      setSelectedId(nextSelected);
      setDeliveries([]);
      if (nextSelected) await loadDeliveries(nextSelected);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to delete webhook endpoint");
    } finally {
      setDeletingId(null);
    }
  }

  const deliveredCount = deliveries.filter((delivery) => delivery.status === "delivered").length;
  const failedCount = deliveries.filter(
    (delivery) => delivery.status === "failed" || delivery.status === "dead",
  ).length;
  const retryableCount = deliveries.filter(canRetry).length;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Webhooks</h1>
          <p className="text-sm text-text-tertiary mt-1">
            Endpoint subscriptions, delivery attempts, and manual retries
          </p>
        </div>
        <button
          type="button"
          onClick={loadData}
          className="px-4 py-2 text-sm border border-border text-text-tertiary hover:text-text hover:border-accent transition-colors"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="border border-red-400/20 bg-red-400/5 p-4 text-sm">
          <div className="text-red-300">Failed to load webhook data</div>
          <div className="text-text-tertiary font-mono text-xs mt-1">{error}</div>
        </div>
      )}

      {createdSecret && (
        <div className="border border-amber-400/20 bg-amber-400/5 p-4 text-sm">
          <div className="text-amber-300">Webhook signing secret</div>
          <div className="text-text-tertiary mt-1">
            Copy this secret now. It is only returned when the endpoint is created.
          </div>
          <code className="block mt-3 font-mono text-xs text-text-secondary break-all">
            {createdSecret}
          </code>
        </div>
      )}

      {loading ? (
        <div className="space-y-px bg-border">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="bg-bg h-16 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid lg:grid-cols-[360px_1fr] gap-6">
          <section className="space-y-3">
            <h2 className="text-xs text-text-tertiary uppercase tracking-wider">Endpoints</h2>
            <form
              onSubmit={createEndpoint}
              className="border border-border bg-bg-elevated p-4 space-y-3"
            >
              <div className="text-sm font-600 text-text-secondary">Add endpoint</div>
              <label className="block space-y-1.5">
                <span className="text-xs text-text-tertiary">URL</span>
                <input
                  value={newWebhook.url}
                  onChange={(event) =>
                    setNewWebhook((value) => ({ ...value, url: event.target.value }))
                  }
                  placeholder="https://api.example.com/webhooks/steward"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
                  required
                />
              </label>
              <label className="block space-y-1.5">
                <span className="text-xs text-text-tertiary">Description</span>
                <input
                  value={newWebhook.description}
                  onChange={(event) =>
                    setNewWebhook((value) => ({ ...value, description: event.target.value }))
                  }
                  placeholder="Production event sink"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                />
              </label>
              <label className="block space-y-1.5">
                <span className="text-xs text-text-tertiary">Events</span>
                <textarea
                  value={newWebhook.events}
                  onChange={(event) =>
                    setNewWebhook((value) => ({ ...value, events: event.target.value }))
                  }
                  rows={4}
                  placeholder="user.created&#10;user.authenticated&#10;transaction.confirmed"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                />
              </label>
              <datalist id="webhook-events">
                {WEBHOOK_EVENT_TYPES.map((eventType) => (
                  <option key={eventType} value={eventType} />
                ))}
              </datalist>
              <button
                type="submit"
                disabled={creating}
                className="w-full px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-50 font-medium"
              >
                {creating ? "Creating..." : "Add Endpoint"}
              </button>
            </form>
            <div className="border border-border bg-bg-elevated divide-y divide-border-subtle">
              {webhooks.length === 0 ? (
                <div className="p-5 text-sm text-text-tertiary">
                  No endpoints configured. Add one to receive signed event deliveries.
                </div>
              ) : (
                webhooks.map((webhook) => (
                  <div
                    key={webhook.id}
                    className={`transition-colors ${
                      selectedId === webhook.id ? "bg-bg-surface" : "hover:bg-bg-surface/50"
                    }`}
                  >
                    <button
                      type="button"
                      onClick={() => selectWebhook(webhook.id)}
                      className="w-full text-left p-4"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="font-mono text-sm text-text-secondary truncate">
                          {webhook.url}
                        </div>
                        <span
                          className={`text-xs px-1.5 py-0.5 ${
                            webhook.enabled
                              ? "text-emerald-400 bg-emerald-400/10"
                              : "text-text-tertiary bg-bg"
                          }`}
                        >
                          {webhook.enabled ? "enabled" : "disabled"}
                        </span>
                      </div>
                      <div className="text-xs text-text-tertiary mt-2 flex items-center gap-3">
                        <span>{webhook.events.length || "all"} events</span>
                        <span>{webhook.maxRetries} retries</span>
                        <span>{formatDate(webhook.createdAt)}</span>
                      </div>
                    </button>
                    <div className="flex items-center gap-3 px-4 pb-4">
                      <button
                        type="button"
                        onClick={() => setEndpointEnabled(webhook, !webhook.enabled)}
                        disabled={updatingId === webhook.id}
                        className="text-xs text-text-tertiary hover:text-accent transition-colors disabled:opacity-50"
                      >
                        {webhook.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        onClick={() => sendTest(webhook)}
                        disabled={testingId === webhook.id || !webhook.enabled}
                        className="text-xs text-text-tertiary hover:text-accent transition-colors disabled:opacity-50"
                      >
                        {testingId === webhook.id ? "Sending..." : "Send Test"}
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteEndpoint(webhook)}
                        disabled={deletingId === webhook.id}
                        className="text-xs text-text-tertiary hover:text-red-400 transition-colors disabled:opacity-50"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="space-y-5">
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "Delivered", value: deliveredCount, className: "text-emerald-400" },
                { label: "Failed", value: failedCount, className: "text-red-400" },
                { label: "Retryable", value: retryableCount, className: "text-amber-400" },
              ].map((item) => (
                <div key={item.label} className="border border-border bg-bg-elevated p-4">
                  <div className="text-xs text-text-tertiary">{item.label}</div>
                  <div className={`font-display text-xl font-700 ${item.className}`}>
                    {item.value.toLocaleString()}
                  </div>
                </div>
              ))}
            </div>

            {selectedWebhook && (
              <div className="border border-border-subtle bg-bg-elevated p-4 space-y-2">
                <div className="text-xs text-text-tertiary uppercase tracking-wider">
                  Selected endpoint
                </div>
                <div className="font-mono text-sm text-text-secondary break-all">
                  {selectedWebhook.url}
                </div>
                <div className="text-xs text-text-tertiary">
                  {selectedWebhook.events.length
                    ? selectedWebhook.events.join(", ")
                    : "All configured events"}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
                <div className="flex items-center gap-3">
                  <h2 className="text-xs text-text-tertiary uppercase tracking-wider">
                    Delivery History
                  </h2>
                  <button
                    type="button"
                    onClick={exportDeliveries}
                    disabled={!selectedId || exporting}
                    className="text-xs text-text-tertiary hover:text-accent transition-colors disabled:opacity-50"
                  >
                    {exporting ? "Exporting..." : "Export CSV"}
                  </button>
                </div>
                <div className="grid gap-2 sm:grid-cols-3 lg:w-[560px]">
                  <select
                    value={deliveryStatusFilter}
                    onChange={(event) => setDeliveryStatusFilter(event.target.value)}
                    className="bg-bg border border-border px-3 py-2 text-xs text-text-secondary"
                    aria-label="Delivery status"
                  >
                    <option value="all">All statuses</option>
                    <option value="pending">Pending</option>
                    <option value="processing">Processing</option>
                    <option value="delivered">Delivered</option>
                    <option value="failed">Failed</option>
                    <option value="dead">Dead</option>
                  </select>
                  <input
                    value={deliveryEventFilter}
                    onChange={(event) => setDeliveryEventFilter(event.target.value)}
                    list="webhook-event-filter-options"
                    placeholder="Event type"
                    className="bg-bg border border-border px-3 py-2 text-xs text-text-secondary"
                    aria-label="Delivery event type"
                  />
                  <datalist id="webhook-event-filter-options">
                    <option value="webhook.test" />
                    {WEBHOOK_EVENT_TYPES.map((eventType) => (
                      <option key={eventType} value={eventType} />
                    ))}
                  </datalist>
                  <select
                    value={deliveryErrorFilter}
                    onChange={(event) => setDeliveryErrorFilter(event.target.value)}
                    className="bg-bg border border-border px-3 py-2 text-xs text-text-secondary"
                    aria-label="Delivery error state"
                  >
                    <option value="all">All errors</option>
                    <option value="with_error">With error</option>
                    <option value="without_error">Without error</option>
                  </select>
                </div>
              </div>
              {deliveryLoading ? (
                <div className="space-y-px bg-border">
                  {[...Array(4)].map((_, i) => (
                    <div key={i} className="bg-bg h-14 animate-pulse" />
                  ))}
                </div>
              ) : deliveries.length === 0 ? (
                <div className="py-16 text-center border border-border-subtle">
                  <p className="text-sm text-text-secondary">No deliveries yet</p>
                  <p className="text-xs text-text-tertiary mt-1">
                    Events will appear here after Steward dispatches to this endpoint.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <div className="grid grid-cols-[1fr_auto_auto_auto] gap-4 px-3 py-2 text-xs text-text-tertiary uppercase tracking-wider border-b border-border-subtle min-w-[720px]">
                    <span>Event</span>
                    <span>Status</span>
                    <span>Attempts</span>
                    <span>Time</span>
                  </div>
                  <AnimatePresence initial={false}>
                    {deliveries.map((delivery, i) => (
                      <motion.div
                        key={delivery.id}
                        initial={{ opacity: 0, y: 4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ delay: i * 0.015, duration: 0.2, ease }}
                      >
                        <button
                          type="button"
                          onClick={() => setExpanded(expanded === delivery.id ? null : delivery.id)}
                          className="w-full text-left"
                        >
                          <div
                            className={`grid grid-cols-[1fr_auto_auto_auto] gap-4 px-3 py-3.5 border-b border-border-subtle transition-colors items-center min-w-[720px] ${
                              expanded === delivery.id
                                ? "bg-bg-elevated"
                                : "hover:bg-bg-elevated/30"
                            }`}
                          >
                            <div className="font-mono text-sm text-text-secondary truncate">
                              {delivery.eventType}
                            </div>
                            <span
                              className={`text-xs px-1.5 py-0.5 font-medium ${statusClass(
                                delivery.status,
                              )}`}
                            >
                              {delivery.status}
                            </span>
                            <div className="text-xs font-mono text-text-tertiary tabular-nums whitespace-nowrap">
                              {delivery.attempts}/{delivery.maxAttempts}
                            </div>
                            <div className="text-xs text-text-tertiary whitespace-nowrap tabular-nums">
                              {formatDate(delivery.createdAt)}
                            </div>
                          </div>
                        </button>
                        <AnimatePresence>
                          {expanded === delivery.id && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.2, ease }}
                              className="overflow-hidden"
                            >
                              <div className="px-3 py-4 bg-bg-elevated border-b border-border-subtle space-y-3">
                                <div className="grid md:grid-cols-2 gap-3 text-xs">
                                  <div>
                                    <div className="text-text-tertiary">Delivery ID</div>
                                    <div className="font-mono text-text-secondary break-all">
                                      {delivery.id}
                                    </div>
                                  </div>
                                  {delivery.replayedFromDeliveryId && (
                                    <div>
                                      <div className="text-text-tertiary">Replayed from</div>
                                      <div className="font-mono text-text-secondary break-all">
                                        {delivery.replayedFromDeliveryId}
                                      </div>
                                    </div>
                                  )}
                                  <div>
                                    <div className="text-text-tertiary">Next retry</div>
                                    <div className="font-mono text-text-secondary">
                                      {delivery.nextRetryAt
                                        ? formatDate(delivery.nextRetryAt)
                                        : "--"}
                                    </div>
                                  </div>
                                  <div>
                                    <div className="text-text-tertiary">Delivered at</div>
                                    <div className="font-mono text-text-secondary">
                                      {delivery.deliveredAt
                                        ? formatDate(delivery.deliveredAt)
                                        : "--"}
                                    </div>
                                  </div>
                                  <div>
                                    <div className="text-text-tertiary">Last error</div>
                                    <div className="font-mono text-text-secondary">
                                      {delivery.hasError ? "redacted" : "--"}
                                    </div>
                                  </div>
                                </div>
                                {canRetry(delivery) && (
                                  <button
                                    type="button"
                                    onClick={() => retryDelivery(delivery.id)}
                                    disabled={retryingId === delivery.id}
                                    className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-50"
                                  >
                                    {retryingId === delivery.id ? "Retrying..." : "Retry Delivery"}
                                  </button>
                                )}
                                {canReplay(delivery) && (
                                  <button
                                    type="button"
                                    onClick={() => replayDelivery(delivery)}
                                    disabled={replayingId === delivery.id}
                                    className="text-xs text-text-tertiary hover:text-accent transition-colors disabled:opacity-50"
                                  >
                                    {replayingId === delivery.id
                                      ? "Replaying..."
                                      : "Replay Delivery"}
                                  </button>
                                )}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </motion.div>
  );
}
