# Session revocation design

Steward uses a hybrid session invalidation model:

- **User sessions:** access tokens are short-lived (15 minutes) and refresh tokens keep the existing 30-day rotation flow. Logout also records the current access token JTI in a revocation store until its natural expiry, but the short TTL is the primary risk reducer for ordinary user sessions.
- **Agent tokens:** agent tokens are higher-value and keep their existing default 30-day TTL for compatibility. They therefore use server-side revocation for true invalidation: each JWT carries a unique `jti`, and platform operators can set an agent-wide revocation line so all tokens issued before it fail verification.

Revocation state is Redis-backed when `REDIS_URL` is configured. This is required for multi-instance deployments so all API/auth workers share the same blacklist/cutoff state. If Redis is not configured or becomes unavailable, the auth package falls back to an in-memory store intended only for single-instance or embedded mode.

Redis keys:

- `revoked:<jti>` — set until the revoked token's `exp`.
- `revoked-agent:<agentId>:<issuedBefore>` — marker for an agent token revocation event.
- `revoked-agent:<agentId>:issued-before` — latest cutoff used during verification.
