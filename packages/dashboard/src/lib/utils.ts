import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function shortenAddress(address: string, chars = 4): string {
  return `${address.slice(0, chars + 2)}...${address.slice(-chars)}`;
}

export function formatWei(wei: string): string {
  const num = Number(BigInt(wei)) / 1e18;
  if (num === 0) return "0 ETH";
  if (num < 0.0001) return "<0.0001 ETH";
  return `${num.toFixed(4)} ETH`;
}

export function formatDate(date: Date | string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function statusColor(status: string): string {
  switch (status) {
    case "confirmed":
    case "signed":
    case "approved":
      return "badge-success";
    case "pending":
      return "badge-warning";
    case "rejected":
    case "failed":
      return "badge-danger";
    case "broadcast":
      return "badge-info";
    default:
      return "badge-neutral";
  }
}

export function policyTypeLabel(type: string): string {
  switch (type) {
    case "spending-limit":
      return "Spending Limit";
    case "approved-addresses":
      return "Approved Addresses";
    case "auto-approve-threshold":
      return "Auto-Approve Threshold";
    case "time-window":
      return "Time Window";
    case "rate-limit":
      return "Rate Limit";
    default:
      return type;
  }
}
