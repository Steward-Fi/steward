interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  trend?: "up" | "down" | "neutral";
}

export function StatCard({ label, value, subtext, trend }: StatCardProps) {
  return (
    <div className="card p-5">
      <div className="text-xs text-zinc-500 uppercase tracking-wider mb-2">{label}</div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      {subtext && (
        <div className={`text-xs mt-1 ${
          trend === "up" ? "text-green-400" :
          trend === "down" ? "text-red-400" :
          "text-zinc-500"
        }`}>
          {subtext}
        </div>
      )}
    </div>
  );
}
