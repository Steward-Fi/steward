export type WalletActionStatus =
  | "authorized"
  | "queued"
  | "signed"
  | "succeeded"
  | "broadcast"
  | "confirmed"
  | "replaced"
  | "rejected"
  | "failed"
  | "canceled"
  | "expired"
  | "unknown";

export type AdapterLifecycle = {
  kind?: string;
  provider?: string;
  lifecycleStatus?: string;
  sessionId?: string;
};

export type WalletAuditEventEntry = {
  id: number | string;
  seq: number;
  actor_type: string;
  actor_id?: string | null;
  action: string;
  resource_type?: string | null;
  resource_id?: string | null;
  metadata: Record<string, unknown>;
  request_id?: string | null;
  created_at: string;
};

export type WalletActionHistoryItem = {
  event: WalletAuditEventEntry;
  actionId: string | null;
  walletId: string | null;
  status: WalletActionStatus;
  actionKind: string;
  adapter: AdapterLifecycle | null;
  chain: string | null;
  value: string | null;
  requestId: string | null;
  txHash: string | null;
  lifecycleStatus: string | null;
};

const STATUS_WORDS: Array<[WalletActionStatus, string[]]> = [
  ["queued", ["queued_for_approval", "pending_approval", "pending", "queued", "reserved"]],
  ["authorized", ["authorized"]],
  ["signed", ["signed"]],
  ["broadcast", ["broadcast", "broadcasted", "submitted"]],
  ["confirmed", ["confirmed", "settled", "finalized"]],
  ["replaced", ["replaced"]],
  ["succeeded", ["succeeded", "success", "completed"]],
  ["rejected", ["rejected", "denied"]],
  ["failed", ["failed", "error", "provider_error", "execution_reverted", "reverted"]],
  ["canceled", ["canceled", "cancelled"]],
  ["expired", ["expired"]],
];

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function inferStatus(action: string, metadata: Record<string, unknown>): WalletActionStatus {
  const explicit = stringValue(metadata.status)?.toLowerCase();
  const nextStatus = stringValue(metadata.nextStatus)?.toLowerCase();
  const lifecycleType = stringValue(metadata.type)?.toLowerCase();
  const adapterStatus = stringValue(asRecord(metadata.adapter)?.lifecycleStatus)?.toLowerCase();
  const haystack = [action.toLowerCase(), explicit, nextStatus, lifecycleType, adapterStatus]
    .filter(Boolean)
    .join(" ");
  for (const [status, words] of STATUS_WORDS) {
    if (words.some((word) => haystack.includes(word))) return status;
  }
  return "unknown";
}

function actionKind(action: string): string {
  if (action.startsWith("wallet_action.")) {
    const [, kind] = action.split(".");
    return kind ? kind.replaceAll("_", " ") : "wallet action";
  }
  if (action.startsWith("wallet.action.")) return "adapter action";
  if (action.startsWith("transaction.lifecycle.")) return "transaction lifecycle";
  return action.replaceAll("_", " ");
}

function adapterLifecycle(metadata: Record<string, unknown>): AdapterLifecycle | null {
  const adapter = asRecord(metadata.adapter);
  if (!adapter) return null;
  const lifecycle: AdapterLifecycle = {
    kind: stringValue(adapter.kind) ?? undefined,
    provider: stringValue(adapter.provider) ?? undefined,
    lifecycleStatus: stringValue(adapter.lifecycleStatus) ?? undefined,
    sessionId: stringValue(adapter.sessionId) ?? undefined,
  };
  return Object.values(lifecycle).some(Boolean) ? lifecycle : null;
}

function chainLabel(metadata: Record<string, unknown>): string | null {
  const caip2 = stringValue(metadata.caip2);
  if (caip2) return caip2;
  const chainId = metadata.chainId;
  if (typeof chainId === "number" || typeof chainId === "string") return String(chainId);
  return null;
}

export function toWalletActionHistoryItem(event: WalletAuditEventEntry): WalletActionHistoryItem {
  const metadata = event.metadata ?? {};
  return {
    event,
    actionId: stringValue(metadata.walletActionId) ?? stringValue(event.resource_id),
    walletId: stringValue(metadata.agentId) ?? stringValue(event.actor_id),
    status: inferStatus(event.action, metadata),
    actionKind: actionKind(event.action),
    adapter: adapterLifecycle(metadata),
    chain: chainLabel(metadata),
    value: stringValue(metadata.value) ?? stringValue(metadata.totalValue),
    requestId: stringValue(event.request_id),
    txHash:
      stringValue(metadata.txHash) ??
      stringValue(metadata.replacementTxHash) ??
      stringValue(metadata.signature),
    lifecycleStatus:
      stringValue(metadata.nextStatus) ??
      stringValue(metadata.status) ??
      stringValue(metadata.type) ??
      stringValue(adapterLifecycle(metadata)?.lifecycleStatus),
  };
}

export function sortWalletActionHistory(
  items: WalletActionHistoryItem[],
): WalletActionHistoryItem[] {
  return [...items].sort((a, b) => {
    if (b.event.seq !== a.event.seq) return Number(b.event.seq) - Number(a.event.seq);
    return new Date(b.event.created_at).getTime() - new Date(a.event.created_at).getTime();
  });
}
