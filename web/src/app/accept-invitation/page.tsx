"use client";

import { useAuth } from "@stwd/react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import type React from "react";
import { Suspense, useEffect, useRef, useState } from "react";
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
    // Do not reflect server/provider details into this public invitation page.
    throw new Error("The invitation could not be accepted. Please verify the link and try again.");
  }
  return body.data;
}

function AcceptInvitationInner() {
  const auth = useAuth();
  const params = useSearchParams();
  const tenantId = params?.get("tenantId") ?? "";
  const token = params?.get("token") ?? "";
  const invitationKey = `${tenantId}\u0000${token}`;
  const [state, setState] = useState<AcceptState>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [activeInvitationKey, setActiveInvitationKey] = useState(invitationKey);
  const acceptingRef = useRef(false);
  const requestGeneration = useRef(0);

  // App-router query navigation can retain this component instance. Reset the
  // confirmation and invalidate any old completion before exposing controls
  // for a different invitation.
  useEffect(() => {
    if (activeInvitationKey === invitationKey) return;
    requestGeneration.current += 1;
    acceptingRef.current = false;
    setState("idle");
    setMessage(null);
    setActiveInvitationKey(invitationKey);
  }, [activeInvitationKey, invitationKey]);

  // SEC-075: never auto-accept on page load. Joining a tenant is a
  // security-relevant account change and must require an explicit click from
  // the signed-in user — merely opening a crafted link must not fire the POST.
  function handleAccept() {
    const sessionToken = auth.getToken();
    if (
      !tenantId ||
      !token ||
      !sessionToken ||
      activeInvitationKey !== invitationKey ||
      state !== "idle" ||
      acceptingRef.current
    )
      return;

    // Ref fencing closes the same-event-loop double-click window before React
    // commits the accepting state and removes the button.
    acceptingRef.current = true;
    const generation = requestGeneration.current;
    setState("accepting");
    acceptInvitation(tenantId, token, sessionToken)
      .then((result) => {
        if (requestGeneration.current !== generation) return;
        setState("accepted");
        setMessage(
          result?.alreadyMember
            ? `You're already a member of ${tenantId}.`
            : `You've joined ${tenantId} as ${result?.role ?? "member"}.`,
        );
      })
      .catch((error) => {
        if (requestGeneration.current !== generation) return;
        acceptingRef.current = false;
        setState("error");
        setMessage(error instanceof Error ? error.message : "Failed to accept invitation");
      });
  }

  const missingParams = !tenantId || !token;
  const needsLogin = !missingParams && !auth.getToken();
  const showConfirm =
    activeInvitationKey === invitationKey && !missingParams && !needsLogin && state === "idle";

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
                : showConfirm
                  ? `You've been invited to join ${tenantId}. Review the tenant before accepting — only continue if you expected this invitation.`
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
          {showConfirm ? (
            <>
              <button
                type="button"
                onClick={handleAccept}
                className="bg-accent px-4 py-2 text-sm font-medium text-bg hover:bg-accent-hover transition-colors"
              >
                Accept invitation
              </button>
              <Link
                href="/dashboard"
                className="border border-border px-4 py-2 text-sm text-text-secondary hover:text-text transition-colors"
              >
                Decline
              </Link>
            </>
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
