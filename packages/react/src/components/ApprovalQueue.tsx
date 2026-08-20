import { useEffect, useId, useRef, useState } from "react";
import { useApprovals } from "../hooks/useApprovals.js";
import { useStewardContext } from "../provider.js";
import type { ApprovalQueueProps } from "../types.js";
import { formatRelativeTime, formatWei, getStatusColor, truncateAddress } from "../utils/format.js";

/**
 * Pending transactions awaiting human review.
 */
export function ApprovalQueue({
  refreshInterval,
  onResolve,
  showPolicyReason = true,
  className,
}: ApprovalQueueProps) {
  const { features } = useStewardContext();
  const { pending, isLoading, error, approve, reject, isResolving } = useApprovals(refreshInterval);
  type ConfirmAction = {
    txId: string;
    action: "approve" | "reject";
  };
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const confirmActionRef = useRef<ConfirmAction | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const cancelButtonRef = useRef<HTMLButtonElement | null>(null);
  const confirmationOpenerRef = useRef<HTMLButtonElement | null>(null);
  const dialogTitleId = useId();
  const dialogDescriptionId = useId();
  const dialogErrorId = useId();

  useEffect(() => {
    if (!confirmAction) return;
    cancelButtonRef.current?.focus();
    return () => {
      const opener = confirmationOpenerRef.current;
      confirmationOpenerRef.current = null;
      if (opener?.isConnected) opener.focus();
    };
  }, [confirmAction]);

  useEffect(() => {
    if (!confirmAction) return;
    const handleDialogKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (isResolving) return;
        closeConfirmation();
        return;
      }
      if (event.key !== "Tab") return;

      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = [
        ...dialog.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ].filter(
        (element) =>
          element.getAttribute("aria-hidden") !== "true" &&
          element.getAttribute("aria-disabled") !== "true",
      );
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !dialog.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleDialogKeyDown, true);
    return () => document.removeEventListener("keydown", handleDialogKeyDown, true);
  }, [confirmAction, isResolving]);

  if (!features.showApprovalQueue) return null;

  const handleConfirm = async () => {
    if (!confirmAction) return;
    const submittedAction = confirmAction;
    setActionError(null);
    try {
      if (submittedAction.action === "approve") {
        await approve(submittedAction.txId);
      } else {
        await reject(submittedAction.txId);
      }
    } catch {
      if (confirmActionRef.current === submittedAction) {
        setActionError(
          `We couldn't ${submittedAction.action} this transaction. Check your connection and try again.`,
        );
      }
      return;
    }
    if (confirmActionRef.current === submittedAction) {
      confirmActionRef.current = null;
      setConfirmAction(null);
    }
    onResolve?.(
      submittedAction.txId,
      submittedAction.action === "approve" ? "approved" : "rejected",
    );
  };

  const closeConfirmation = () => {
    confirmActionRef.current = null;
    setActionError(null);
    setConfirmAction(null);
  };

  const openConfirmation = (
    txId: string,
    action: "approve" | "reject",
    opener: HTMLButtonElement,
  ) => {
    const nextAction = { txId, action };
    confirmationOpenerRef.current = opener;
    confirmActionRef.current = nextAction;
    setActionError(null);
    setConfirmAction(nextAction);
  };

  if (isLoading) {
    return (
      <div className={`stwd-card stwd-approval-queue ${className || ""}`}>
        <div className="stwd-loading">Loading approvals...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`stwd-card stwd-approval-queue ${className || ""}`}>
        <div className="stwd-error-text">Failed to load approvals: {error.message}</div>
      </div>
    );
  }

  return (
    <div className={`stwd-card stwd-approval-queue ${className || ""}`}>
      <div className="stwd-approval-header">
        <h3 className="stwd-heading">Pending Approvals</h3>
        {pending.length > 0 && (
          <span className="stwd-badge stwd-badge-warning">{pending.length}</span>
        )}
      </div>

      {pending.length === 0 ? (
        <div className="stwd-empty-state">
          <div className="stwd-empty-icon">✅</div>
          <div className="stwd-empty-text">No pending approvals</div>
        </div>
      ) : (
        <div className="stwd-approval-list">
          {pending.map((entry) => (
            <div key={entry.id} className="stwd-approval-item">
              <div className="stwd-approval-main">
                <div className="stwd-approval-to">
                  To: <code>{truncateAddress(entry.to)}</code>
                </div>
                <div className="stwd-approval-value">{formatWei(entry.value)} ETH</div>
                <div className="stwd-approval-meta">
                  <span className="stwd-badge stwd-badge-muted">Chain {entry.chainId}</span>
                  <span className="stwd-approval-time">{formatRelativeTime(entry.createdAt)}</span>
                </div>
              </div>

              {showPolicyReason && entry.policyResults.length > 0 && (
                <div className="stwd-approval-reasons">
                  <div className="stwd-approval-reasons-label">Triggered policies:</div>
                  {entry.policyResults
                    .filter((pr) => !pr.passed)
                    .map((pr, i) => (
                      <div key={i} className={`stwd-badge ${getStatusColor("rejected")}`}>
                        {pr.type}: {pr.reason || "failed"}
                      </div>
                    ))}
                </div>
              )}

              <div className="stwd-approval-actions">
                <button
                  className="stwd-btn stwd-btn-error"
                  disabled={isResolving}
                  onClick={(event) => openConfirmation(entry.txId, "reject", event.currentTarget)}
                >
                  Deny
                </button>
                <button
                  className="stwd-btn stwd-btn-success"
                  disabled={isResolving}
                  onClick={(event) => openConfirmation(entry.txId, "approve", event.currentTarget)}
                >
                  Approve
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Confirmation Dialog */}
      {confirmAction && (
        <div
          className="stwd-modal-overlay"
          onClick={() => {
            if (!isResolving) closeConfirmation();
          }}
        >
          <div
            ref={dialogRef}
            className="stwd-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby={dialogTitleId}
            aria-describedby={
              actionError ? `${dialogDescriptionId} ${dialogErrorId}` : dialogDescriptionId
            }
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 id={dialogTitleId} className="stwd-heading">
              {confirmAction.action === "approve" ? "Approve Transaction?" : "Deny Transaction?"}
            </h3>
            <p id={dialogDescriptionId} className="stwd-muted-text">
              {confirmAction.action === "approve"
                ? "This transaction will be signed and broadcast."
                : "This transaction will be rejected and will not be executed."}
            </p>
            {actionError && (
              <div id={dialogErrorId} className="stwd-error-text" role="alert">
                {actionError}
              </div>
            )}
            <div className="stwd-modal-actions">
              <button
                ref={cancelButtonRef}
                className="stwd-btn stwd-btn-secondary"
                onClick={closeConfirmation}
                disabled={isResolving}
              >
                Cancel
              </button>
              <button
                className={`stwd-btn ${confirmAction.action === "approve" ? "stwd-btn-success" : "stwd-btn-error"}`}
                onClick={handleConfirm}
                disabled={isResolving}
              >
                {isResolving
                  ? "Processing..."
                  : confirmAction.action === "approve"
                    ? "Approve"
                    : "Deny"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
