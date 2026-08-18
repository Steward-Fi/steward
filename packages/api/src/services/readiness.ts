import { createHash, timingSafeEqual } from "node:crypto";

export interface ReadinessCheck {
  ok: boolean;
  required?: boolean;
  error?: string;
  source?: string;
  detail?: unknown;
}

function readinessProbeAuthorized(expected: string | undefined, presented: string | undefined) {
  if (!expected || !presented) return false;
  const expectedDigest = createHash("sha256").update(expected).digest();
  const presentedDigest = createHash("sha256").update(presented).digest();
  return timingSafeEqual(expectedDigest, presentedDigest);
}

/**
 * Return readiness details appropriate for the caller. The public response
 * exposes only health booleans; an operator token unlocks backend identities,
 * migration details, timing data, and diagnostic errors.
 */
export function readinessChecksForResponse(
  checks: Record<string, ReadinessCheck>,
  expectedToken: string | undefined,
  presentedToken: string | undefined,
): Record<string, ReadinessCheck> {
  if (readinessProbeAuthorized(expectedToken, presentedToken)) return checks;
  return Object.fromEntries(
    Object.entries(checks).map(([name, check]) => [
      name,
      { ok: check.ok, ...(check.required === false ? { required: false } : {}) },
    ]),
  );
}
