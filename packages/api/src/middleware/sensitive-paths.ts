/**
 * Single source of truth for the set of request paths considered
 * "sensitive" — i.e. money-, key-, auth-, or tenant-administration surfaces
 * that are freshness-checked and signature-checked according to the resolved
 * request posture. Public authentication and verified user-session requests
 * have a narrow browser exemption because they cannot safely hold a shared
 * server HMAC root; agent and other machine credentials remain fail-closed in
 * production. Adding or removing a prefix changes both middleware guards.
 */

/** Path prefixes whose mutating requests are treated as sensitive. */
export const SENSITIVE_PATH_PREFIXES: readonly string[] = [
  "/vault",
  "/agents",
  "/v1/agents",
  "/wallets/batch",
  "/v1/wallets/batch",
  "/accounts",
  "/v1/accounts",
  "/adapters",
  "/v1/adapters",
  "/policies",
  "/v1/policies",
  "/secrets",
  "/trade",
  "/v1/trade",
  "/approvals",
  "/intents",
  "/audit",
  "/auth",
  "/global-wallet",
  "/user",
  "/v1/users",
  "/webhooks",
  "/tenants",
  "/platform",
  "/condition-sets",
  "/v1/condition-sets",
  "/condition_sets",
  "/v1/condition_sets",
  "/v2/workspaces",
  "/v2/provider-accounts",
  "/v2/provider-role-bindings",
  "/v2/provider-grants",
  // KMS key operations, provider action execution and approval, dashboard
  // session mutations, and agent enrollment remain sensitive surfaces.
  "/v1/kms",
  "/v2/provider-actions",
  "/dashboard",
  "/agent-enroll",
  "/v1/agent-enroll",
];

/**
 * True when `path` falls under a sensitive surface. Matched by prefix so both
 * a collection route (`/agents`) and its sub-resources (`/agents/:id/...`) are
 * covered.
 */
export function isSensitivePath(path: string): boolean {
  return SENSITIVE_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}
