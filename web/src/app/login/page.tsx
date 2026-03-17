"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAccount } from "wagmi";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { motion, AnimatePresence } from "framer-motion";
import Image from "next/image";

import { useAuth } from "@/components/auth-provider";

// ─── Animation variants ───────────────────────────────────────────────────────

const container = {
  hidden: { opacity: 0, y: 16 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.35, ease: [0.25, 1, 0.5, 1] as const },
  },
};

const fadeIn = {
  hidden: { opacity: 0, y: -6 },
  show: { opacity: 1, y: 0, transition: { duration: 0.2 } },
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const { isConnected } = useAccount();
  const { isAuthenticated, isLoading, signIn, signInWithPasskey, signInWithEmail } =
    useAuth();
  const router = useRouter();

  const [emailInput, setEmailInput] = useState("");
  const [status, setStatus] = useState<
    "idle" | "passkey" | "email" | "wallet" | "sent"
  >("idle");
  const [error, setError] = useState<string | null>(null);
  const [sentExpiry, setSentExpiry] = useState<string | null>(null);

  // Redirect when authenticated
  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      router.push("/dashboard");
    }
  }, [isAuthenticated, isLoading, router]);

  // Auto-trigger SIWE when wallet connects
  useEffect(() => {
    if (isConnected && !isAuthenticated && !isLoading && status !== "wallet") {
      handleWalletSignIn();
    }
  }, [isConnected, isAuthenticated, isLoading]);

  // ── Handlers ─────────────────────────────────────────────────────────────────

  function validateEmail(value: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
  }

  async function handlePasskey() {
    if (!validateEmail(emailInput)) {
      setError("Enter a valid email first.");
      return;
    }
    setStatus("passkey");
    setError(null);
    try {
      await signInWithPasskey(emailInput.trim());
      // redirect handled by the effect above
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Passkey sign-in failed.";
      setError(msg.includes("AbortError") ? "Passkey prompt was dismissed." : msg);
      setStatus("idle");
    }
  }

  async function handleMagicLink() {
    if (!validateEmail(emailInput)) {
      setError("Enter a valid email first.");
      return;
    }
    setStatus("email");
    setError(null);
    try {
      const result = await signInWithEmail(emailInput.trim());
      setSentExpiry(result.expiresAt ?? null);
      setStatus("sent");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Failed to send magic link.",
      );
      setStatus("idle");
    }
  }

  async function handleWalletSignIn() {
    setStatus("wallet");
    setError(null);
    try {
      await signIn();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Wallet sign-in failed.",
      );
      setStatus("idle");
    }
  }

  // ── Loading state ─────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <span className="w-4 h-4 border border-text-tertiary border-t-accent animate-spin" />
      </div>
    );
  }

  // ── Magic link sent ───────────────────────────────────────────────────────────

  if (status === "sent") {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center px-6">
        <motion.div
          variants={container}
          initial="hidden"
          animate="show"
          className="w-full max-w-sm text-center"
        >
          <Logo />
          <div className="mt-12 space-y-3">
            <div className="w-10 h-10 mx-auto flex items-center justify-center border border-border bg-bg-elevated">
              <span className="text-xl">✉</span>
            </div>
            <h2 className="font-display text-xl font-bold tracking-tight">
              Check your inbox
            </h2>
            <p className="text-sm text-text-secondary">
              We sent a sign-in link to{" "}
              <span className="text-text">{emailInput}</span>
            </p>
            {sentExpiry && (
              <p className="text-xs text-text-tertiary">
                Link expires in 10 minutes.
              </p>
            )}
          </div>
          <button
            onClick={() => {
              setStatus("idle");
              setError(null);
            }}
            className="mt-8 text-xs text-text-tertiary hover:text-text transition-colors underline underline-offset-2"
          >
            Use a different method
          </button>
        </motion.div>
      </div>
    );
  }

  // ── Main login form ───────────────────────────────────────────────────────────

  const busy = status === "passkey" || status === "email" || status === "wallet";

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-6">
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="w-full max-w-sm"
      >
        {/* Logo */}
        <div className="flex items-center justify-center gap-2.5 mb-12">
          <Logo />
        </div>

        <h1 className="font-display text-2xl font-bold tracking-tight mb-1 text-center">
          Sign in to Steward
        </h1>
        <p className="text-sm text-text-tertiary mb-8 text-center">
          Manage agent wallets and policies.
        </p>

        {/* Email input */}
        <div className="mb-4">
          <input
            type="email"
            placeholder="you@example.com"
            value={emailInput}
            onChange={(e) => {
              setEmailInput(e.target.value);
              if (error) setError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") handlePasskey();
            }}
            disabled={busy}
            className={[
              "w-full px-3 py-2.5 bg-bg-elevated border text-sm",
              "text-text placeholder:text-text-tertiary",
              "focus:outline-none focus:border-accent/60",
              "transition-colors disabled:opacity-50",
              error
                ? "border-red-500/60"
                : "border-border hover:border-border-subtle",
            ].join(" ")}
          />
        </div>

        {/* Passkey button (primary) */}
        <button
          onClick={handlePasskey}
          disabled={busy}
          className={[
            "w-full flex items-center justify-center gap-2.5",
            "px-4 py-2.5 text-sm font-medium",
            "bg-accent text-bg",
            "hover:bg-accent-hover active:scale-[0.99]",
            "transition-all duration-150",
            "disabled:opacity-50 disabled:cursor-not-allowed",
          ].join(" ")}
        >
          {status === "passkey" ? (
            <>
              <span className="w-3.5 h-3.5 border border-bg/40 border-t-bg animate-spin" />
              <span>Checking passkey…</span>
            </>
          ) : (
            <>
              <FingerprintIcon />
              <span>Continue with passkey</span>
            </>
          )}
        </button>

        {/* Magic link button (secondary) */}
        <button
          onClick={handleMagicLink}
          disabled={busy}
          className={[
            "w-full flex items-center justify-center gap-2.5 mt-2",
            "px-4 py-2.5 text-sm font-medium",
            "bg-transparent border border-border text-text-secondary",
            "hover:border-border-subtle hover:text-text",
            "active:scale-[0.99] transition-all duration-150",
            "disabled:opacity-50 disabled:cursor-not-allowed",
          ].join(" ")}
        >
          {status === "email" ? (
            <>
              <span className="w-3.5 h-3.5 border border-text-tertiary border-t-text animate-spin" />
              <span>Sending link…</span>
            </>
          ) : (
            <>
              <span className="text-base leading-none">✉</span>
              <span>Send magic link</span>
            </>
          )}
        </button>

        {/* Error */}
        <AnimatePresence>
          {error && (
            <motion.p
              key="error"
              variants={fadeIn}
              initial="hidden"
              animate="show"
              exit="hidden"
              className="mt-3 text-xs text-red-400 text-center"
            >
              {error}
            </motion.p>
          )}
        </AnimatePresence>

        {/* Divider */}
        <div className="flex items-center gap-3 my-6">
          <div className="flex-1 h-px bg-border" />
          <span className="text-xs text-text-tertiary tracking-wider">or</span>
          <div className="flex-1 h-px bg-border" />
        </div>

        {/* Wallet connect (tertiary) */}
        <div className="flex flex-col items-center gap-3">
          <ConnectButton
            showBalance={false}
            chainStatus="none"
            accountStatus="address"
          />
          {status === "wallet" && (
            <motion.div
              variants={fadeIn}
              initial="hidden"
              animate="show"
              className="flex items-center gap-2 text-xs text-text-tertiary"
            >
              <span className="w-3 h-3 border border-text-tertiary border-t-accent animate-spin" />
              Sign the message in your wallet…
            </motion.div>
          )}
        </div>

        <p className="mt-10 text-center text-xs text-text-tertiary">
          No password needed. Your keys, your wallet.
        </p>
      </motion.div>
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Logo() {
  return (
    <div className="flex items-center justify-center gap-2.5">
      <Image
        src="/logo.png"
        alt=""
        width={28}
        height={28}
        className="w-7 h-7 opacity-70"
      />
      <span className="font-display text-xl font-bold tracking-tight">
        steward
      </span>
    </div>
  );
}

function FingerprintIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
      <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
      <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
      <path d="M2 12a10 10 0 0 1 18-6" />
      <path d="M2 17c1 .5 2.5 1 4 1" />
      <path d="M22 6c0 2-.5 3.5-1.3 5" />
      <path d="M6 10a6 6 0 0 1 11.4-2.1" />
      <path d="M8.65 22c.21-.66.45-1.32.57-2" />
      <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
    </svg>
  );
}
