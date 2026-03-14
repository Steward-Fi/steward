"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAccount } from "wagmi";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { motion } from "framer-motion";
import Image from "next/image";
import { useAuth } from "@/components/auth-provider";

export default function LoginPage() {
  const { isConnected } = useAccount();
  const { isAuthenticated, isLoading, signIn } = useAuth();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [signing, setSigning] = useState(false);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      router.push("/dashboard");
    }
  }, [isAuthenticated, isLoading, router]);

  // Auto-trigger SIWE sign-in when wallet connects
  useEffect(() => {
    if (isConnected && !isAuthenticated && !isLoading && !signing) {
      handleSignIn();
    }
  }, [isConnected, isAuthenticated, isLoading]);

  async function handleSignIn() {
    setSigning(true);
    setError(null);
    try {
      await signIn();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Sign-in failed. Try again."
      );
    } finally {
      setSigning(false);
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <div className="w-5 h-5 border border-text-tertiary border-t-accent animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-6">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.25, 1, 0.5, 1] }}
        className="w-full max-w-sm text-center"
      >
        {/* Logo */}
        <div className="flex items-center justify-center gap-2.5 mb-12">
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

        <h1 className="font-display text-2xl font-700 tracking-tight mb-2">
          Connect your wallet
        </h1>
        <p className="text-sm text-text-tertiary mb-10 max-w-xs mx-auto">
          Sign in with your Ethereum wallet to manage agent wallets and
          policies.
        </p>

        {/* Connect Button */}
        <div className="flex justify-center mb-6">
          <ConnectButton
            showBalance={false}
            chainStatus="none"
            accountStatus="address"
          />
        </div>

        {/* Signing state */}
        {signing && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-center gap-3 mt-6"
          >
            <div className="w-4 h-4 border border-text-tertiary border-t-accent animate-spin" />
            <span className="text-xs text-text-tertiary">
              Sign the message in your wallet...
            </span>
          </motion.div>
        )}

        {/* Error */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-6 space-y-3"
          >
            <p className="text-xs text-red-400">{error}</p>
            {isConnected && (
              <button
                onClick={handleSignIn}
                className="px-4 py-2 text-xs bg-accent text-bg hover:bg-accent-hover transition-colors font-medium"
              >
                Try again
              </button>
            )}
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}
