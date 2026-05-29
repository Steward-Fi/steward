import { useEffect, useRef, useState } from "react";
import { useAuth } from "../hooks/useAuth.js";
import type { StewardEmailCallbackProps } from "../types.js";

type CallbackStep = "loading" | "success" | "error";

/**
 * Remove the magic-link `token` (and `email`) from the visible URL so the
 * one-time token does not linger in browser history, bookmarks, or the
 * Referer header sent to subsequently-loaded resources. We rewrite the
 * current history entry in place via `history.replaceState`; this does not
 * trigger navigation or reload.
 */
function scrubTokenFromUrl(): void {
  if (typeof window === "undefined" || !window.history?.replaceState) return;
  try {
    const url = new URL(window.location.href);
    if (!url.searchParams.has("token") && !url.searchParams.has("email")) return;
    url.searchParams.delete("token");
    url.searchParams.delete("email");
    window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash);
  } catch {
    // Best effort — never block sign-in on URL cleanup.
  }
}

/**
 * StewardEmailCallback — Mount on your `/auth/callback` route.
 *
 * Reads `token` and `email` from the URL search params, then calls
 * `verifyEmailCallback` from the auth context to exchange the magic link
 * token for a session.
 *
 * @example
 * // In your router:
 * <Route path="/auth/callback" element={
 *   <StewardEmailCallback
 *     onSuccess={() => navigate("/dashboard")}
 *     redirectTo="/dashboard"
 *   />
 * } />
 */
export function StewardEmailCallback({
  onSuccess,
  onError,
  redirectTo,
}: StewardEmailCallbackProps) {
  const { verifyEmailCallback, isAuthenticated } = useAuth();
  const [step, setStep] = useState<CallbackStep>("loading");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const attemptedRef = useRef(false);
  // Captured at mount before we scrub the URL, so Retry can re-attempt the
  // exchange even though token/email are no longer in window.location.
  const credsRef = useRef<{ token: string; email: string } | null>(null);

  useEffect(() => {
    // Prevent double-fire in React strict mode
    if (attemptedRef.current) return;
    attemptedRef.current = true;

    // Already authenticated, skip verification
    if (isAuthenticated) {
      setStep("success");
      if (redirectTo && typeof window !== "undefined") {
        window.location.href = redirectTo;
      }
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const email = params.get("email");

    if (!token || !email) {
      const msg = "Missing token or email in callback URL.";
      setErrorMsg(msg);
      setStep("error");
      onError?.(new Error(msg));
      return;
    }

    // Capture before scrubbing so the Retry button can re-run the exchange.
    credsRef.current = { token, email };
    // Strip the one-time token/email from the URL immediately after reading
    // them so they don't persist in history or leak via Referer.
    scrubTokenFromUrl();

    void (async () => {
      try {
        const result = await verifyEmailCallback(token, email);
        setStep("success");
        onSuccess?.(result);

        if (redirectTo && typeof window !== "undefined") {
          window.location.href = redirectTo;
        }
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setErrorMsg(error.message);
        setStep("error");
        onError?.(error);
      }
    })();
  }, [onError, verifyEmailCallback, redirectTo, onSuccess, isAuthenticated]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRetry = () => {
    attemptedRef.current = false;
    setStep("loading");
    setErrorMsg(null);

    // The URL was scrubbed on the first attempt, so read from the captured
    // credentials rather than the (now token-less) location.
    const token = credsRef.current?.token ?? null;
    const email = credsRef.current?.email ?? null;

    if (!token || !email) {
      setErrorMsg("Missing token or email in callback URL.");
      setStep("error");
      return;
    }

    void (async () => {
      try {
        const result = await verifyEmailCallback(token, email);
        setStep("success");
        onSuccess?.(result);

        if (redirectTo && typeof window !== "undefined") {
          window.location.href = redirectTo;
        }
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setErrorMsg(error.message);
        setStep("error");
        onError?.(error);
      }
    })();
  };

  if (step === "loading") {
    return (
      <div className="stwd-callback stwd-callback__loading">
        <div className="stwd-loading">Verifying your sign-in link…</div>
      </div>
    );
  }

  if (step === "success") {
    return (
      <div className="stwd-callback stwd-callback__success">
        <p>✅ Signed in successfully.</p>
        {redirectTo && <p className="stwd-muted-text">Redirecting…</p>}
      </div>
    );
  }

  return (
    <div className="stwd-callback stwd-callback__error">
      <p className="stwd-error-text">{errorMsg ?? "Verification failed."}</p>
      <button className="stwd-btn stwd-btn-secondary" onClick={handleRetry} type="button">
        Retry
      </button>
    </div>
  );
}
