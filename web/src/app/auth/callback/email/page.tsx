"use client";

import React, { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { motion } from "framer-motion";

import { useAuth } from "@/components/auth-provider";
import { verifyMagicLink } from "@/lib/auth-api";

type State = "verifying" | "success" | "error";

// Inner component — needs Suspense because useSearchParams() suspends on the
// initial server render when the search params aren't yet available.
function EmailCallbackInner() {
  const router = useRouter();
  const params = useSearchParams();
  const { completeEmailAuth } = useAuth();

  const [state, setState] = useState<State>("verifying");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const verifiedRef = useRef(false);

  useEffect(() => {
    if (verifiedRef.current) return;
    verifiedRef.current = true;

    const token = params?.get("token") ?? null;
    const email = params?.get("email") ?? null;

    if (!token || !email) {
      setState("error");
      setErrorMsg("Invalid magic link — missing token or email.");
      return;
    }

    verifyMagicLink(token, email)
      .then((result) => {
        completeEmailAuth(result);
        setState("success");
        // Short delay so the success state is visible before redirect
        setTimeout(() => {
          router.replace("/dashboard");
        }, 800);
      })
      .catch((e) => {
        setState("error");
        setErrorMsg(
          e instanceof Error ? e.message : "This link is invalid or has expired.",
        );
      });
  }, []);

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-6">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: [0.25, 1, 0.5, 1] }}
        className="w-full max-w-xs text-center"
      >
        {state === "verifying" && (
          <div className="space-y-4">
            <div className="flex justify-center">
              <span className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin" />
            </div>
            <p className="text-sm text-text-secondary">Signing you in…</p>
          </div>
        )}

        {state === "success" && (
          <div className="space-y-3">
            <div className="flex justify-center">
              <span className="text-2xl">✓</span>
            </div>
            <p className="text-sm text-text-secondary">
              Signed in — redirecting…
            </p>
          </div>
        )}

        {state === "error" && (
          <div className="space-y-5">
            <div className="space-y-2">
              <p className="text-sm font-medium text-text">Link expired</p>
              <p className="text-xs text-text-tertiary">
                {errorMsg ?? "This magic link is no longer valid."}
              </p>
            </div>
            <button
              onClick={() => router.replace("/login")}
              className="px-4 py-2 text-xs bg-accent text-bg hover:bg-accent-hover transition-colors font-medium"
            >
              Back to sign in
            </button>
          </div>
        )}
      </motion.div>
    </div>
  );
}

export default function EmailCallbackPage() {
  const SuspenseAny = Suspense as React.ComponentType<{
    fallback: React.ReactNode;
    children: React.ReactNode;
  }>;
  return (
    <SuspenseAny
      fallback={
        <div className="min-h-screen bg-bg flex items-center justify-center">
          <span className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin" />
        </div>
      }
    >
      <EmailCallbackInner />
    </SuspenseAny>
  );
}
