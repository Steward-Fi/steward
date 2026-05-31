export function shortenAddress(addr: string, chars = 4): string {
  if (!addr) return "";
  return `${addr.slice(0, chars + 2)}...${addr.slice(-chars)}`;
}

export function formatWei(wei: string, symbol?: string): string {
  if (!wei) return "0";
  try {
    const eth = Number(BigInt(wei)) / 1e18;
    const formatted = eth === 0 ? "0" : eth < 0.0001 ? "<0.0001" : eth.toFixed(4);
    return symbol ? `${formatted} ${symbol}` : formatted;
  } catch {
    const eth = Number(wei) / 1e18;
    const formatted = eth === 0 ? "0" : eth < 0.0001 ? "<0.0001" : eth.toFixed(4);
    return symbol ? `${formatted} ${symbol}` : formatted;
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

export function policyTypeLabel(type: string): string {
  const map: Record<string, string> = {
    "spending-limit": "Spending Limit",
    "approved-addresses": "Approved Addresses",
    "auto-approve-threshold": "Auto-Approve Threshold",
    "time-window": "Time Window",
    "rate-limit": "Rate Limit",
    "allowed-chains": "Allowed Chains",
  };
  return map[type] || type;
}

export function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(" ");
}
