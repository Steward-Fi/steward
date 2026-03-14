export function shortenAddress(addr: string, chars = 4): string {
  if (!addr) return "";
  return `${addr.slice(0, chars + 2)}...${addr.slice(-chars)}`;
}

export function formatWei(wei: string): string {
  if (!wei) return "0";
  try {
    const eth = Number(BigInt(wei)) / 1e18;
    if (eth === 0) return "0";
    if (eth < 0.0001) return "<0.0001";
    return eth.toFixed(4);
  } catch {
    const eth = Number(wei) / 1e18;
    if (eth === 0) return "0";
    if (eth < 0.0001) return "<0.0001";
    return eth.toFixed(4);
  }
}

export function formatDate(date: Date | string): string {
  return new Date(date).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    pending: "text-amber-400",
    approved: "text-emerald-400",
    rejected: "text-red-400",
    signed: "text-emerald-400",
    broadcast: "text-violet-400",
    confirmed: "text-emerald-300",
    failed: "text-orange-400",
  };
  return map[status] || "text-text-tertiary";
}

export function policyTypeLabel(type: string): string {
  const map: Record<string, string> = {
    "spending-limit": "Spending Limit",
    "approved-addresses": "Approved Addresses",
    "auto-approve-threshold": "Auto-Approve Threshold",
    "time-window": "Time Window",
    "rate-limit": "Rate Limit",
  };
  return map[type] || type;
}

export function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(" ");
}
