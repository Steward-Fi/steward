"use client";

/**
 * Provider-action approval detail surface.
 *
 * Consumes the governed GET/POST /v2/provider-actions/:id/approval routes, not the
 * legacy transaction-approval endpoints, G4). Invariants enforced here:
 *   - Approve and Deny are EQUAL-WEIGHT controls (same size, same emphasis).
 *   - A typed reason is REQUIRED for BOTH decisions (client-side block; the
 *     server also enforces APPROVAL_REASON_REQUIRED).
 *   - Shows the exact action via the SAFE SUMMARY + operation/account labels +
 *     digests. Never canonical bytes or comment body text.
 *   - There is NO one-click bulk approval; a decision requires opening this
 *     detail and entering a reason.
 *   - A terminal/expired/denied case renders its state honestly and DISABLES
 *     the decision controls.
 *   - Accessibility: labeled controls, keyboard-operable, screen-reader
 *     landmarks, sufficient contrast (WCAG 2.1 AA target).
 */

import { useAuth } from "@stwd/react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  type ApprovalDetail,
  decideApproval,
  getApprovalDetail,
  isDecidableStatus,
  ProviderActionError,
} from "@/lib/provider-actions";

type LoadState = "loading" | "ready" | "error";

export default function ProviderApprovalDetailPage() {
  const auth = useAuth();
  const params = useParams<{ id: string }>();
  const id = params?.id ?? "";

  const [state, setState] = useState<LoadState>("loading");
  const [detail, setDetail] = useState<ApprovalDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState<"approve" | "deny" | null>(null);
  const [decisionResult, setDecisionResult] = useState<string | null>(null);
  const [reasonError, setReasonError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const d = await getApprovalDetail(id, auth.getToken?.() ?? null, auth.activeTenantId ?? null);
      setDetail(d);
      setState("ready");
    } catch (e) {
      setError(e instanceof ProviderActionError ? e.code : "Failed to load approval");
      setState("error");
    }
  }, [id, auth]);

  useEffect(() => {
    if (id) void load();
  }, [id, load]);

  async function decide(decision: "approve" | "deny") {
    // Client-side reason gate; the server enforces the same requirement.
    if (reason.trim().length === 0) {
      setReasonError("A typed reason is required for both approve and deny.");
      return;
    }
    if (!detail) return;
    setReasonError(null);
    setSubmitting(decision);
    setDecisionResult(null);
    try {
      await decideApproval(
        id,
        {
          decision,
          reason: reason.trim(),
          expectedVersion: detail.version,
          expectedRequestHash: detail.requestHash,
          expectedActionDigest: detail.actionDigest,
        },
        auth.getToken?.() ?? null,
        auth.activeTenantId ?? null,
      );
      setDecisionResult(`Decision recorded: ${decision}`);
      await load();
    } catch (e) {
      setDecisionResult(e instanceof ProviderActionError ? `Error: ${e.code}` : "Decision failed");
    } finally {
      setSubmitting(null);
    }
  }

  const decidable = detail ? isDecidableStatus(detail.status) : false;

  return (
    <main className="max-w-3xl mx-auto p-6" aria-labelledby="approval-detail-heading">
      <nav aria-label="Breadcrumb" className="mb-4 text-sm">
        <Link href="/dashboard/approvals" className="text-accent hover:underline">
          ← Back to approvals
        </Link>
      </nav>

      <h1 id="approval-detail-heading" className="font-display text-2xl font-600 mb-1">
        Provider action approval
      </h1>
      <p className="text-text-secondary text-xs font-mono mb-6 break-all">{id}</p>

      {state === "loading" && (
        <p role="status" className="text-text-secondary">
          Loading approval…
        </p>
      )}

      {state === "error" && (
        <div role="alert" className="border border-border p-6 bg-bg-elevated">
          <p className="text-text-secondary text-sm mb-1">Not found or not authorized</p>
          <p className="text-text-tertiary text-xs font-mono">{error}</p>
        </div>
      )}

      {state === "ready" && detail && (
        <>
          {/* Honest terminal-state banner. */}
          {!decidable && (
            <div
              role="status"
              className="border border-warning/40 bg-warning/5 text-warning px-4 py-3 mb-6"
            >
              This action is <strong>{detail.status}</strong>. Decision controls are disabled; its
              lifecycle is already terminal.
            </div>
          )}

          {/* The exact action: safe summary + labels + digests ONLY. */}
          <section aria-labelledby="action-summary-heading" className="mb-6">
            <h2 id="action-summary-heading" className="font-display text-lg font-600 mb-3">
              Exact action
            </h2>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
              <dt className="text-text-secondary">Status</dt>
              <dd className="font-mono">{detail.status}</dd>
              <dt className="text-text-secondary">Operation</dt>
              <dd className="font-mono break-all">{detail.operationId}</dd>
              <dt className="text-text-secondary">Provider account</dt>
              <dd className="font-mono break-all">{detail.providerAccountId}</dd>
              <dt className="text-text-secondary">Workspace</dt>
              <dd className="font-mono break-all">{detail.workspaceId}</dd>
              <dt className="text-text-secondary">Action digest</dt>
              <dd className="font-mono break-all">{detail.actionDigest}</dd>
              <dt className="text-text-secondary">Request hash</dt>
              <dd className="font-mono break-all">{detail.requestHash}</dd>
              <dt className="text-text-secondary">Expires</dt>
              <dd className="font-mono">{detail.expiresAt ?? "n/a"}</dd>
            </dl>

            {detail.safeSummary && (
              <div className="mt-4">
                <h3 className="text-text-secondary text-xs uppercase tracking-wide mb-2">
                  Safe summary (redacted, never full request bytes)
                </h3>
                <div
                  role="region"
                  // biome-ignore lint/a11y/noNoninteractiveTabindex: WCAG requires keyboard focus for a scrollable region.
                  tabIndex={0}
                  aria-label="Redacted safe summary"
                  className="overflow-x-auto"
                >
                  <pre className="bg-bg-surface border border-border-subtle p-3 text-xs min-w-max">
                    {JSON.stringify(detail.safeSummary, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </section>

          {/* Equal-weight decision controls with a REQUIRED typed reason. */}
          <section aria-labelledby="decision-heading">
            <h2 id="decision-heading" className="font-display text-lg font-600 mb-3">
              Decision
            </h2>
            <label htmlFor="decision-reason" className="block text-sm text-text-secondary mb-1">
              Reason (required for approve and deny)
            </label>
            <textarea
              id="decision-reason"
              name="decision-reason"
              value={reason}
              onChange={(e) => {
                setReason(e.target.value);
                if (reasonError) setReasonError(null);
              }}
              disabled={!decidable || submitting !== null}
              aria-required="true"
              aria-invalid={reasonError !== null}
              aria-describedby={reasonError ? "reason-error" : undefined}
              rows={3}
              className="w-full bg-bg-surface border border-border p-3 text-sm mb-1 focus:outline-none focus:ring-2 focus:ring-accent"
              placeholder="Explain why you are approving or denying this action…"
            />
            {reasonError && (
              <p id="reason-error" role="alert" className="text-danger text-xs mb-2">
                {reasonError}
              </p>
            )}

            {/* Both buttons: identical sizing/typography = EQUAL WEIGHT (U4). */}
            <div className="flex gap-3 mt-3">
              <button
                type="button"
                onClick={() => decide("approve")}
                disabled={!decidable || submitting !== null}
                aria-label="Approve this provider action"
                className="flex-1 px-4 py-2 text-sm font-600 border border-border bg-bg-elevated hover:bg-bg-surface transition-colors focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {submitting === "approve" ? "Approving…" : "Approve"}
              </button>
              <button
                type="button"
                onClick={() => decide("deny")}
                disabled={!decidable || submitting !== null}
                aria-label="Deny this provider action"
                className="flex-1 px-4 py-2 text-sm font-600 border border-border bg-bg-elevated hover:bg-bg-surface transition-colors focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {submitting === "deny" ? "Denying…" : "Deny"}
              </button>
            </div>

            {decisionResult && (
              <p role="status" className="mt-4 text-sm font-mono text-text-secondary">
                {decisionResult}
              </p>
            )}
          </section>
        </>
      )}
    </main>
  );
}
