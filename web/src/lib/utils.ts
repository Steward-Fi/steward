import { getNativeDecimals, getNativeSymbol } from "@stwd/shared/client";

export function shortenAddress(addr: string, chars = 4): string {
  if (!addr) return "";
  return `${addr.slice(0, chars + 2)}...${addr.slice(-chars)}`;
}

function formatAtomicValue(value: bigint, decimals: number): string {
  if (value === 0n) return "0";

  const sign = value < 0n ? "-" : "";
  const absolute = value < 0n ? -value : value;
  const unit = 10n ** BigInt(decimals);

  if (absolute * 10_000n < unit) {
    return `${sign}<0.0001`;
  }

  const scale = unit / 10_000n;
  const scaled = absolute / scale;
  const whole = scaled / 10_000n;
  const fraction = (scaled % 10_000n).toString().padStart(4, "0");
  return `${sign}${whole}.${fraction}`;
}

export function formatWei(wei: string, symbol?: string): string {
  if (!wei) return "0";
  try {
    const formatted = formatAtomicValue(BigInt(wei), 18);
    return symbol ? `${formatted} ${symbol}` : formatted;
  } catch {
    return symbol ? `0 ${symbol}` : "0";
  }
}

/**
 * Format a native-asset amount using the chain's own atomic decimals
 * (wei 10^18, lamports 10^9, piconero 10^12, …) plus its symbol.
 */
export function formatNativeAmount(value: string, chainId: number): string {
  if (!value) return `0 ${getNativeSymbol(chainId)}`;
  try {
    const formatted = formatAtomicValue(BigInt(value), getNativeDecimals(chainId));
    return `${formatted} ${getNativeSymbol(chainId)}`;
  } catch {
    return `0 ${getNativeSymbol(chainId)}`;
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
