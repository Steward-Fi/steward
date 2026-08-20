const GOOGLE_CONNECT_MFA_MAX_AGE_MS = 5 * 60_000;

/** Provider credentials authorize durable agent actions, so every connect
 * lifecycle operation requires a freshly stepped-up human session. */
export function hasRecentGoogleConnectMfa(
  verifiedAt: unknown,
  now = Date.now(),
): verifiedAt is number {
  if (typeof verifiedAt !== "number" || !Number.isFinite(verifiedAt)) return false;
  const ageMs = now - verifiedAt;
  return ageMs >= 0 && ageMs <= GOOGLE_CONNECT_MFA_MAX_AGE_MS;
}
