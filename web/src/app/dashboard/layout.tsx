"use client";

import { DashboardNav } from "@/components/dashboard-nav";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-bg">
      <DashboardNav />
      <main className="max-w-[1400px] mx-auto px-6 md:px-10 py-8 md:py-12">
        {children}
      </main>
    </div>
  );
}
