"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import Image from "next/image";
import { createClient } from "@/lib/supabase";

export default function OnboardPage() {
  const [status, setStatus] = useState<"checking" | "provisioning" | "done" | "error">("checking");
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  const supabase = createClient();
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    onboard();
  }, []);

  async function onboard() {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        router.push("/login");
        return;
      }

      // Check if user already has a tenant
      const { data: existing } = await supabase
        .from("steward_tenants")
        .select("tenant_id")
        .eq("user_id", user.id)
        .limit(1)
        .single();

      if (existing) {
        router.push("/dashboard");
        return;
      }

      // Provision a new tenant
      setStatus("provisioning");
      
      const tenantId = `t-${user.id.slice(0, 8)}`;
      const tenantName = user.user_metadata?.full_name || user.email?.split("@")[0] || "My Workspace";
      
      // Call our API route to provision the tenant server-side
      const res = await fetch("/api/provision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId, tenantName }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to provision tenant");
      }

      const { apiKey } = await res.json();

      // Store in Supabase
      const { error: insertError } = await supabase
        .from("steward_tenants")
        .insert({
          user_id: user.id,
          tenant_id: tenantId,
          tenant_name: tenantName,
          api_key: apiKey,
          role: "owner",
        });

      if (insertError) throw insertError;

      setStatus("done");
      setTimeout(() => router.push("/dashboard"), 800);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Provisioning failed");
      setStatus("error");
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-6">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="text-center max-w-sm"
      >
        <Image
          src="/logo.png"
          alt=""
          width={40}
          height={40}
          className="w-10 h-10 opacity-60 mx-auto mb-6"
        />

        {status === "checking" && (
          <>
            <div className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin mx-auto mb-4" />
            <p className="text-sm text-text-tertiary">Checking account...</p>
          </>
        )}

        {status === "provisioning" && (
          <>
            <div className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin mx-auto mb-4" />
            <p className="text-sm text-text">Setting up your workspace</p>
            <p className="text-xs text-text-tertiary mt-1">
              Creating tenant, generating API key...
            </p>
          </>
        )}

        {status === "done" && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
          >
            <div className="w-8 h-8 border-2 border-emerald-400 flex items-center justify-center mx-auto mb-4">
              <span className="text-emerald-400 text-sm">✓</span>
            </div>
            <p className="text-sm text-text">Workspace ready</p>
            <p className="text-xs text-text-tertiary mt-1">
              Redirecting to dashboard...
            </p>
          </motion.div>
        )}

        {status === "error" && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <p className="text-sm text-red-400 mb-2">Setup failed</p>
            <p className="text-xs text-text-tertiary mb-6 font-mono">{error}</p>
            <button
              onClick={() => {
                ran.current = false;
                setError(null);
                setStatus("checking");
                onboard();
              }}
              className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
            >
              Retry
            </button>
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}
