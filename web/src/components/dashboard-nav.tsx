"use client";

import { motion } from "framer-motion";
import Image from "next/image";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/components/auth-provider";

const links = [
  { href: "/dashboard", label: "Overview", exact: true },
  { href: "/dashboard/agents", label: "Agents" },
  { href: "/dashboard/approvals", label: "Approvals" },
  { href: "/dashboard/transactions", label: "Transactions" },
  { href: "/dashboard/secrets", label: "Secrets" },
  { href: "/dashboard/policies", label: "Policies" },
  { href: "/dashboard/audit", label: "Audit" },
  { href: "/dashboard/settings", label: "Settings" },
];

function shortenAddr(addr: string | undefined): string {
  if (!addr) return "";
  return `${addr.slice(0, 6)}\u2026${addr.slice(-4)}`;
}

export function DashboardNav() {
  const pathname = usePathname();
  const router = useRouter();
  const { address, tenant, signOut } = useAuth();

  function isActive(href: string, exact?: boolean) {
    if (exact) return pathname === href;
    return pathname?.startsWith(href) ?? false;
  }

  async function handleDisconnect() {
    await signOut();
    router.push("/login");
  }

  return (
    <header className="border-b border-border sticky top-0 z-40 bg-bg/90 backdrop-blur-sm">
      <div className="max-w-[1400px] mx-auto px-6 md:px-10">
        <div className="flex items-center justify-between h-14 gap-4">
          <div className="flex items-center gap-4 md:gap-10 min-w-0 flex-1">
            <Link
              href="/"
              className="flex items-center gap-2 hover:opacity-80 transition-opacity flex-shrink-0"
            >
              <Image
                src="/logo.png"
                alt="Steward"
                width={20}
                height={20}
                className="w-5 h-5"
              />
              <span className="font-display text-base font-bold tracking-tight text-text">
                steward
              </span>
            </Link>

            <nav className="flex items-center gap-1 overflow-x-auto scrollbar-hide">
              {links.map((link) => {
                const active = isActive(link.href, link.exact);
                return (
                  <Link
                    key={link.href}
                    href={link.href}
                    className={`relative px-3 py-1.5 text-sm transition-colors whitespace-nowrap flex-shrink-0 ${
                      active
                        ? "text-text"
                        : "text-text-tertiary hover:text-text-secondary"
                    }`}
                  >
                    {link.label}
                    {active && (
                      <motion.div
                        layoutId="dashboard-nav-indicator"
                        className="absolute bottom-0 left-0 right-0 h-[2px] bg-accent"
                        transition={{
                          type: "tween",
                          duration: 0.25,
                          ease: [0.25, 1, 0.5, 1],
                        }}
                      />
                    )}
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="flex items-center gap-4">
            {tenant && (
              <span className="text-xs text-text-tertiary hidden md:inline font-mono">
                {tenant.tenantName}
              </span>
            )}
            {address && (
              <span className="text-xs text-text-tertiary hidden md:inline font-mono">
                {shortenAddr(address)}
              </span>
            )}
            <button
              onClick={handleDisconnect}
              className="text-xs text-text-tertiary hover:text-text-secondary transition-colors"
            >
              Disconnect
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
