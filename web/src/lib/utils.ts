export function shortenAddress(addr: string, chars = 4): string {
  if (!addr) return "";
  return `${addr.slice(0, chars + 2)}...${addr.slice(-chars)}`;
}

const WEI_PER_ETH = 10n ** 18n;

function formatWeiValue(value: bigint): string {
  if (value === 0n) return "0";

  const sign = value < 0n ? "-" : "";
  const absolute = value < 0n ? -value : value;

  if (absolute > 0n && absolute < 100_000_000_000_000n) {
    return `${sign}<0.0001`;
  }

  const scale = WEI_PER_ETH / 10_000n;
  const scaled = absolute / scale;
  const whole = scaled / 10_000n;
  const fraction = (scaled % 10_000n).toString().padStart(4, "0");
  return `${sign}${whole}.${fraction}`;
}

export function formatWei(wei: string, symbol?: string): string {
  if (!wei) return "0";
  try {
    const formatted = formatWeiValue(BigInt(wei));
    return symbol ? `${formatted} ${symbol}` : formatted;
  } catch {
    return symbol ? `0 ${symbol}` : "0";
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
