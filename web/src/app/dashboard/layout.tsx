"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardNav } from "@/components/dashboard-nav";
import { useAuth } from "@/components/auth-provider";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated) {
      router.push("/login");
      return;
    }
    setReady(true);
  }, [isAuthenticated, isLoading, router]);

  if (isLoading || !ready) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <div className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg">
      <DashboardNav />
      <main className="max-w-[1400px] mx-auto px-6 md:px-10 py-8 md:py-12">
        {children}
      </main>
    </div>
  );
}
