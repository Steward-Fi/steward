import React, { useState, useContext } from "react";
import { StewardAuthContext } from "../provider.js";
import type { StewardLoginProps } from "../types.js";

type LoginStep = "idle" | "loading" | "email-sent" | "error";

/**
 * StewardLogin — Drop-in auth widget for Steward-powered apps.
 *
 * Must be used inside a <StewardProvider auth={{ baseUrl: "..." }}>.
 *
 * Supports:
 *   - Passkey (WebAuthn) — browser only
 *   - Email magic link
 *   - SIWE (Sign-In With Ethereum) — requires caller to wire in a wallet
 *
 * @example
 * <StewardProvider client={client} agentId="..." auth={{ baseUrl: "https://api.steward.fi" }}>
 *   <StewardLogin onSuccess={({ token }) => console.log("token:", token)} />
 * </StewardProvider>
 */
export function StewardLogin({
  onSuccess,
  onError,
  showPasskey = true,
  showEmail = true,
  showSIWE = false,
  className,
}: StewardLoginProps) {
  const ctx = useContext(StewardAuthContext);

  const [email, setEmail] = useState("");
  const [step, setStep] = useState<LoginStep>("idle");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!ctx) {
    return (
      <div className={`stwd-login stwd-login--error ${className ?? ""}`}>
        <p className="stwd-login__error">
          StewardLogin must be used inside a &lt;StewardProvider&gt; with an{" "}
          <code>auth</code> prop.
        </p>
      </div>
    );
  }

  // Already signed in — render nothing (parent should guard with isAuthenticated)
  if (ctx.isAuthenticated) {
    return null;
  }

  const handleError = (err: unknown) => {
    const error = err instanceof Error ? err : new Error(String(err));
    setErrorMsg(error.message);
    setStep("error");
    onError?.(error);
  };

  const handlePasskey = async () => {
    if (!email.trim()) {
      setErrorMsg("Enter your email address first.");
      setStep("error");
      return;
    }
    setStep("loading");
    setErrorMsg(null);
    try {
      const result = await ctx.signInWithPasskey(email.trim());
      onSuccess?.(result);
    } catch (err) {
      handleError(err);
    }
  };

  const handleEmail = async () => {
    if (!email.trim()) {
      setErrorMsg("Enter your email address.");
      setStep("error");
      return;
    }
    setStep("loading");
    setErrorMsg(null);
    try {
      await ctx.signInWithEmail(email.trim());
      setStep("email-sent");
    } catch (err) {
      handleError(err);
    }
  };

  const isLoading = step === "loading" || ctx.isLoading;

  if (step === "email-sent") {
    return (
      <div className={`stwd-login stwd-login--sent ${className ?? ""}`}>
        <p className="stwd-login__notice">
          ✉️ Magic link sent to <strong>{email}</strong>. Check your inbox.
        </p>
        <button
          className="stwd-login__back"
          onClick={() => setStep("idle")}
          type="button"
        >
          ← Back
        </button>
      </div>
    );
  }

  return (
    <div className={`stwd-login ${className ?? ""}`}>
      <div className="stwd-login__fields">
        <input
          className="stwd-login__input"
          type="email"
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              if (showPasskey) void handlePasskey();
              else if (showEmail) void handleEmail();
            }
          }}
          disabled={isLoading}
          autoComplete="email webauthn"
          aria-label="Email address"
        />
      </div>

      <div className="stwd-login__actions">
        {showPasskey && (
          <button
            className="stwd-login__btn stwd-login__btn--passkey"
            onClick={() => void handlePasskey()}
            disabled={isLoading}
            type="button"
          >
            {isLoading ? "Signing in…" : "🔑 Sign in with Passkey"}
          </button>
        )}

        {showEmail && (
          <button
            className="stwd-login__btn stwd-login__btn--email"
            onClick={() => void handleEmail()}
            disabled={isLoading}
            type="button"
          >
            {isLoading ? "Sending…" : "✉️ Send Magic Link"}
          </button>
        )}

        {showSIWE && (
          <button
            className="stwd-login__btn stwd-login__btn--siwe"
            disabled={true}
            type="button"
            title="Connect your wallet to sign in with Ethereum"
          >
            🦊 Sign in with Ethereum
          </button>
        )}
      </div>

      {step === "error" && errorMsg && (
        <p className="stwd-login__error" role="alert">
          {errorMsg}
        </p>
      )}
    </div>
  );
}
