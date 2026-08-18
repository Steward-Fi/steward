export const MFA_TIMESTAMP_MAX_FUTURE_SKEW_MS = 30_000;

/** Validate an MFA timestamp against both staleness and bounded clock skew. */
export function isRecentMfaTimestamp(
  verifiedAt: unknown,
  maxAgeMs: number,
  nowMs = Date.now(),
  maxFutureSkewMs = MFA_TIMESTAMP_MAX_FUTURE_SKEW_MS,
): boolean {
  if (
    typeof verifiedAt !== "number" ||
    !Number.isFinite(verifiedAt) ||
    !Number.isFinite(maxAgeMs) ||
    maxAgeMs < 0 ||
    !Number.isFinite(nowMs) ||
    !Number.isFinite(maxFutureSkewMs) ||
    maxFutureSkewMs < 0
  ) {
    return false;
  }
  const ageMs = nowMs - verifiedAt;
  return ageMs >= -maxFutureSkewMs && ageMs <= maxAgeMs;
}
