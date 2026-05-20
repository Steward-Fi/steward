"use client";

import { StewardLogin } from "@stwd/react";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { SelfHostPrompt } from "@/components/self-host-prompt";
import { useApiReachability } from "@/lib/api-reachability";

const Logo = (
  <div className="flex items-center justify-center gap-2.5">
    <Image src="/logo.png" alt="" width={28} height={28} className="w-7 h-7 opacity-70" />
    <span className="font-display text-xl font-bold tracking-tight">steward</span>
  </div>
);

function LoginLoading() {
  return (
    <div className="min-h-screen bg-bg flex items-center justify-center">
      <div className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin" />
    </div>
  );
}

export default function LoginPage() {
  const router = useRouter();
  // Same gate as dashboard: if the API is unreachable the public demo
  // doesn’t have a control plane to log into. Surface the self-host CTA
  // instead of rendering a login form whose every action will fail.
  const api = useApiReachability();

  if (api.status === "checking") return <LoginLoading />;

  if (api.status === "unreachable") {
    return (
      <div className="min-h-screen bg-bg">
        <SelfHostPrompt detail={api.detail} onRetry={api.refresh} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-4 sm:px-6">
      <div className="w-full max-w-sm">
        <StewardLogin
          variant="card"
          title="Sign in to Steward"
          subtitle="Manage your agents, wallets, and policies"
          logo={Logo}
          showPasskey
          showEmail
          showGoogle
          showDiscord
          showWallets
          onSuccess={() => router.push("/dashboard")}
          onError={(err) => console.error("Login error:", err)}
        />
      </div>
    </div>
  );
}
