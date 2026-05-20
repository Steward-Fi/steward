"use client";

import { motion } from "framer-motion";
import { API_URL } from "@/lib/api";

const DOCS_URL = "https://docs.steward.fi";
const REPO_URL = "https://github.com/Steward-Fi/steward";

interface SelfHostPromptProps {
  /** Optional underlying failure detail for ops/debug. Hidden in `<details>`. */
  detail?: string;
  /** Show a "Retry connection" button (e.g. when user spun up an instance). */
  onRetry?: () => void;
  /** Tighter layout for use inside an existing dashboard frame. */
  variant?: "page" | "inline";
}

/**
 * Renders the canonical "Steward is self-hostable; this demo doesn't run a
 * control plane" prompt. Used by both the dashboard error fallback and the
 * login page when the configured API origin is unreachable.
 *
 * WHY: steward.fi is a marketing site. The Steward API + dashboard are
 * meant to run inside each org's own infrastructure. We want users who
 * land on the public dashboard to understand that immediately, with a
 * clear path to docs/source, not see a generic "Failed to connect" error.
 */
export function SelfHostPrompt({ detail, onRetry, variant = "page" }: SelfHostPromptProps) {
  const wrapper =
    variant === "page"
      ? "min-h-[calc(100vh-6rem)] flex items-center justify-center px-6"
      : "py-12 flex items-center justify-center px-6";

  return (
    <div className={wrapper}>
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
        className="max-w-xl w-full"
      >
        <p className="text-xs text-text-tertiary tracking-widest uppercase mb-6">
          Self-hosted by design
        </p>
        <h2 className="font-display text-3xl md:text-4xl font-700 tracking-tight leading-[1.1]">
          Steward runs on your infrastructure.
        </h2>
        <p className="mt-5 text-text-secondary leading-relaxed">
          This public site doesn&apos;t host a Steward control plane. Each organization runs its own
          instance to keep credentials, policies, and audit logs in its own perimeter. Spin one up,
          point your dashboard at it, and you&apos;re done.
        </p>

        <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-px bg-border-subtle">
          <a
            href={DOCS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="bg-bg p-5 hover:bg-bg-elevated transition-colors group"
          >
            <div className="text-sm font-display font-600 group-hover:text-accent transition-colors">
              Read the deploy guide
            </div>
            <div className="text-xs text-text-tertiary mt-1">
              Docker, Kubernetes, or any Node.js host
            </div>
          </a>
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="bg-bg p-5 hover:bg-bg-elevated transition-colors group"
          >
            <div className="text-sm font-display font-600 group-hover:text-accent transition-colors">
              Browse the source
            </div>
            <div className="text-xs text-text-tertiary mt-1">
              MIT-licensed. No per-transaction fee.
            </div>
          </a>
        </div>

        <div className="mt-8 border border-border-subtle bg-bg-elevated/40 px-5 py-4">
          <p className="text-xs text-text-tertiary tracking-wide uppercase mb-2">
            Already self-hosted?
          </p>
          <p className="text-sm text-text-secondary leading-relaxed">
            Point your dashboard at your instance by setting{" "}
            <code className="font-mono text-xs text-text bg-bg px-1.5 py-0.5">
              NEXT_PUBLIC_STEWARD_API_URL
            </code>{" "}
            before building, or run the dashboard locally alongside your API. Configured to reach{" "}
            <code className="font-mono text-xs text-text bg-bg px-1.5 py-0.5 break-all">
              {API_URL}
            </code>{" "}
            and the API didn&apos;t respond.
          </p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-4 text-xs px-3 py-1.5 border border-border text-text-secondary hover:text-text hover:border-text-tertiary transition-colors"
            >
              Retry connection
            </button>
          )}
        </div>

        {detail && (
          <details className="mt-6 text-xs text-text-tertiary">
            <summary className="cursor-pointer hover:text-text-secondary transition-colors">
              Connection detail
            </summary>
            <pre className="mt-2 font-mono text-[11px] whitespace-pre-wrap break-words border border-border-subtle bg-bg-elevated/40 p-3">
              {detail}
            </pre>
          </details>
        )}
      </motion.div>
    </div>
  );
}
