"use client";

import { useAuth } from "@stwd/react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import type React from "react";
import { Suspense, useEffect, useState } from "react";
import { API_URL } from "@/lib/api";

type AcceptState = "idle" | "accepting" | "accepted" | "error";

async function acceptInvitation(tenantId: string, token: string, sessionToken: string) {
  const response = await fetch(
    `${API_URL}/user/me/tenants/${encodeURIComponent(tenantId)}/invitations/accept`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${sessionToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token }),
    },
  );
  const body = (await response.json()) as {
    ok: boolean;
    data?: { tenantId: string; role: string; invitationId: string; alreadyMember?: boolean };
    error?: string;
  };
  if (!response.ok || !body.ok) {
    throw new Error(body.error || `Request failed with ${response.status}`);
  }
  return body.data;
}

function AcceptInvitationInner() {
  const auth = useAuth();
  const params = useSearchParams();
  const tenantId = params?.get("tenantId") ?? "";
  const token = params?.get("token") ?? "";
  const [state, setState] = useState<AcceptState>("idle");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const sessionToken = auth.getToken();
    if (!tenantId || !token || !sessionToken || state !== "idle") return;

    let cancelled = false;
    setState("accepting");
    acceptInvitation(tenantId, token, sessionToken)
      .then((result) => {
        if (cancelled) return;
        setState("accepted");
        setMessage(
          result?.alreadyMember
            ? `You're already a member of ${tenantId}.`
            : `You've joined ${tenantId} as ${result?.role ?? "member"}.`,
        );
      })
      .catch((error) => {
        if (cancelled) return;
        setState("error");
        setMessage(error instanceof Error ? error.message : "Failed to accept invitation");
      });

    return () => {
      cancelled = true;
    };
  }, [auth, tenantId, token, state]);

  const missingParams = !tenantId || !token;
  const needsLogin = !missingParams && !auth.getToken();

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-4">
      <div className="w-full max-w-sm border border-border-subtle bg-bg p-6">
        <div className="text-lg font-semibold text-text">Accept invitation</div>
        <div className="mt-3 text-sm leading-6 text-text-secondary">
          {missingParams
            ? "This invitation link is missing required fields."
            : needsLogin
              ? "Sign in with the invited email, then reopen this invitation link."
              : state === "accepting"
                ? "Accepting invitation..."
                : message}
        </div>
        <div className="mt-6 flex gap-3">
          {needsLogin ? (
            <Link
              href="/login"
              className="bg-accent px-4 py-2 text-sm font-medium text-bg hover:bg-accent-hover transition-colors"
            >
              Sign in
            </Link>
          ) : null}
          {state === "accepted" ? (
            <Link
              href="/dashboard"
              className="bg-accent px-4 py-2 text-sm font-medium text-bg hover:bg-accent-hover transition-colors"
            >
              Open dashboard
            </Link>
          ) : null}
          {state === "error" || missingParams ? (
            <Link
              href="/dashboard"
              className="border border-border px-4 py-2 text-sm text-text-secondary hover:text-text transition-colors"
            >
              Back to dashboard
            </Link>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export default function AcceptInvitationPage() {
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
      <AcceptInvitationInner />
    </SuspenseAny>
  );
}
