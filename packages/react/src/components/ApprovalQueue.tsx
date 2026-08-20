import { useRef, useState } from "react";
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

  const openConfirmation = (txId: string, action: "approve" | "reject") => {
    const nextAction = { txId, action };
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
                  onClick={() => openConfirmation(entry.txId, "reject")}
                >
                  Deny
                </button>
                <button
                  className="stwd-btn stwd-btn-success"
                  disabled={isResolving}
                  onClick={() => openConfirmation(entry.txId, "approve")}
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
        <div className="stwd-modal-overlay" onClick={closeConfirmation}>
          <div className="stwd-modal" onClick={(e) => e.stopPropagation()}>
            <h3 className="stwd-heading">
              {confirmAction.action === "approve" ? "Approve Transaction?" : "Deny Transaction?"}
            </h3>
            <p className="stwd-muted-text">
              {confirmAction.action === "approve"
                ? "This transaction will be signed and broadcast."
                : "This transaction will be rejected and will not be executed."}
            </p>
            {actionError && (
              <div className="stwd-error-text" role="alert">
                {actionError}
              </div>
            )}
            <div className="stwd-modal-actions">
              <button className="stwd-btn stwd-btn-secondary" onClick={closeConfirmation}>
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
