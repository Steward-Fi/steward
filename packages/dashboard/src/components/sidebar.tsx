"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const navigation = [
  { name: "Overview", href: "/", icon: "◆" },
  { name: "Agents", href: "/agents", icon: "◈" },
  { name: "Approvals", href: "/approvals", icon: "◉" },
  { name: "Transactions", href: "/transactions", icon: "◎" },
  { name: "Settings", href: "/settings", icon: "◇" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-60 border-r border-[#262626] bg-[#0a0a0a] flex flex-col">
      <div className="p-5 border-b border-[#262626]">
        <Link href="/" className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-green-600 flex items-center justify-center text-white font-bold text-sm">
            S
          </div>
          <span className="font-semibold text-lg tracking-tight">Steward</span>
        </Link>
      </div>

      <nav className="flex-1 p-3 space-y-1">
        {navigation.map((item) => {
          const isActive = item.href === "/"
            ? pathname === "/"
            : pathname.startsWith(item.href);

          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
                isActive
                  ? "bg-white/5 text-white"
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.02]"
              )}
            >
              <span className="text-xs">{item.icon}</span>
              {item.name}
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-[#262626]">
        <div className="text-xs text-zinc-600">
          Steward v0.1.0
        </div>
      </div>
    </aside>
  );
}
