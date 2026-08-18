"use client";

/**
 * Provider-action case and evidence surface (U5).
 *
 * Consumes the evidence GET /v2/provider-actions/:id/case + /evidence routes.
 * Invariants enforced here:
 *   - Renders evidence `completeness` (complete/incomplete/unknown) VERBATIM and
 *     surfaces `incompletenessReasons`. NEVER renders "verified/complete" when
 *     evidence says otherwise (honest completeness).
 *   - States the operator-key trust limit (evidence E7): a signed bundle proves the
 *     audit chain is internally consistent under the OPERATOR's signing key; it
 *     is NOT an operator-integrity proof.
 *   - Offers the signed bundle download + the EXACT offline verify command with
 *     the out-of-band `--expected-key-fingerprint` flag.
 *   - Never displays a credential or canonical bytes (only IDs/hashes/safe
 *     summary).
 *   - Accessibility: labeled regions, keyboard-operable, screen-reader landmarks.
 */

import { useAuth } from "@stwd/react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  type CaseManifest,
  getCase,
  getEvidence,
  ProviderActionError,
} from "@/lib/provider-actions";

type LoadState = "loading" | "ready" | "error";

function completenessTone(c: string): string {
  // Honest: only `complete` reads as success; incomplete/unknown are warnings.
  if (c === "complete") return "border-success/40 bg-success/5 text-success";
  return "border-warning/40 bg-warning/5 text-warning";
}

export default function ProviderActionCasePage() {
  const auth = useAuth();
  const params = useParams<{ id: string }>();
  const id = params?.id ?? "";

  const [state, setState] = useState<LoadState>("loading");
  const [manifest, setManifest] = useState<CaseManifest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const m = await getCase(id, auth.getToken?.() ?? null, auth.activeTenantId ?? null);
      setManifest(m);
      setState("ready");
    } catch (e) {
      setError(e instanceof ProviderActionError ? e.code : "Failed to load case");
      setState("error");
    }
  }, [id, auth]);

  useEffect(() => {
    if (id) void load();
  }, [id, load]);

  async function downloadBundle() {
    setDownloading(true);
    setDownloadError(null);
    try {
      const bundle = await getEvidence(id, auth.getToken?.() ?? null, auth.activeTenantId ?? null);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `provider-evidence-${id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setDownloadError(
        e instanceof ProviderActionError ? e.code : "Evidence export failed (signing key required)",
      );
    } finally {
      setDownloading(false);
    }
  }

  const verifyCommand = `node scripts/verify-evidence-bundle.mjs provider-evidence-${id}.json --expected-key-fingerprint <YOUR_TRUSTED_KEY_FINGERPRINT>`;

  return (
    <main className="max-w-3xl mx-auto p-6" aria-labelledby="case-heading">
      <nav aria-label="Breadcrumb" className="mb-4 text-sm">
        <Link href="/dashboard/actions" className="text-accent hover:underline">
          ← Back to actions
        </Link>
      </nav>

      <h1 id="case-heading" className="font-display text-2xl font-600 mb-1">
        Provider action case
      </h1>
      <p className="text-text-secondary text-xs font-mono mb-6 break-all">{id}</p>

      {state === "loading" && (
        <p role="status" className="text-text-secondary">
          Loading case…
        </p>
      )}

      {state === "error" && (
        <div role="alert" className="border border-border p-6 bg-bg-elevated">
          <p className="text-text-secondary text-sm mb-1">Not found or not authorized</p>
          <p className="text-text-tertiary text-xs font-mono">{error}</p>
        </div>
      )}

      {state === "ready" && manifest && (
        <>
          {/* Honest completeness banner (verbatim). */}
          <div
            role="status"
            className={`border px-4 py-3 mb-6 ${completenessTone(manifest.completeness)}`}
          >
            <p className="font-600">
              Completeness: <span className="font-mono">{manifest.completeness}</span>
            </p>
            <p className="text-sm mt-1">
              Terminal state: <span className="font-mono">{manifest.terminalState}</span>
            </p>
            {manifest.incompletenessReasons.length > 0 && (
              <ul className="mt-2 list-disc list-inside text-sm">
                {manifest.incompletenessReasons.map((r) => (
                  <li key={r} className="font-mono">
                    {r}
                  </li>
                ))}
              </ul>
            )}
            {manifest.missingRequiredRoles.length > 0 && (
              <p className="text-sm mt-2">
                Missing required roles:{" "}
                <span className="font-mono">{manifest.missingRequiredRoles.join(", ")}</span>
              </p>
            )}
          </div>

          {/* Commitments (hashes only, never canonical bytes / credentials). */}
          <section aria-labelledby="commitments-heading" className="mb-6">
            <h2 id="commitments-heading" className="font-display text-lg font-600 mb-3">
              Commitments
            </h2>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-text-secondary">Operation</dt>
              <dd className="font-mono break-all">
                {manifest.operation.key} (rev {manifest.operation.revision},{" "}
                {manifest.operation.riskClass})
              </dd>
              <dt className="text-text-secondary">Action digest</dt>
              <dd className="font-mono break-all">{manifest.actionDigest}</dd>
              <dt className="text-text-secondary">Request hash</dt>
              <dd className="font-mono break-all">{manifest.requestHash}</dd>
              <dt className="text-text-secondary">Idempotency key hash</dt>
              <dd className="font-mono break-all">{manifest.idempotencyKeyHash}</dd>
              {manifest.execution && (
                <>
                  <dt className="text-text-secondary">Dispatch state</dt>
                  <dd className="font-mono">{manifest.execution.dispatchState}</dd>
                  <dt className="text-text-secondary">Upstream status</dt>
                  <dd className="font-mono">{manifest.execution.upstreamStatusCode ?? "n/a"}</dd>
                  <dt className="text-text-secondary">Reconciled</dt>
                  <dd className="font-mono">{String(manifest.execution.reconciled)}</dd>
                  <dt className="text-text-secondary">Provider idempotency (hash)</dt>
                  <dd className="font-mono break-all">
                    {manifest.execution.providerIdempotencyKeyHash ?? "n/a"}
                  </dd>
                </>
              )}
            </dl>
          </section>

          {/* Evidence export + offline verification. */}
          <section aria-labelledby="evidence-heading" className="mb-6">
            <h2 id="evidence-heading" className="font-display text-lg font-600 mb-3">
              Signed evidence
            </h2>
            <button
              type="button"
              onClick={downloadBundle}
              disabled={downloading}
              aria-label="Download the signed evidence bundle"
              className="px-4 py-2 text-sm font-600 border border-border bg-bg-elevated hover:bg-bg-surface transition-colors focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-40"
            >
              {downloading ? "Exporting…" : "Download signed bundle"}
            </button>
            {downloadError && (
              <p role="alert" className="text-danger text-xs mt-2 font-mono">
                {downloadError}
              </p>
            )}

            <h3 className="text-text-secondary text-xs uppercase tracking-wide mt-4 mb-2">
              Verify offline (bind trust to your out-of-band key fingerprint)
            </h3>
            <div
              role="region"
              // biome-ignore lint/a11y/noNoninteractiveTabindex: WCAG requires keyboard focus for a scrollable region.
              tabIndex={0}
              aria-label="Offline evidence verification command"
              className="overflow-x-auto"
            >
              <pre className="bg-bg-surface border border-border-subtle p-3 text-xs min-w-max">
                {verifyCommand}
              </pre>
            </div>

            {/* Operator-key trust limit (E7). */}
            <p className="text-text-secondary text-xs mt-3 leading-relaxed">
              Trust limit: a valid signature proves this evidence chain is internally consistent
              under the <strong>operator&apos;s</strong> audit signing key. It is NOT an
              operator-integrity proof, NOT MPC, and NOT exactly-once. Always verify against a
              signing-key fingerprint you obtained out-of-band; verifying against the embedded key
              proves self-consistency only.
            </p>
          </section>
        </>
      )}
    </main>
  );
}
