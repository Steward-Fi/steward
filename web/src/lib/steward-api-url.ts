/**
 * Single source of truth for the dashboard's Steward API origin.
 *
 * Steward is self-host-first: there is no shared hosted API. When
 * `NEXT_PUBLIC_STEWARD_API_URL` is unset (local dev), we fall back to the local
 * compose profile, which exposes the API on port 3200.
 *
 * This module deliberately has NO dependencies (no `@stwd/sdk`, no Next imports)
 * so it can be consumed by both the client bundle (`lib/api.ts`, providers) and
 * the edge middleware (`middleware.ts`). Keeping the fallback here ensures the
 * runtime request origin and the CSP `connect-src` allowlist stay in sync. If
 * the default changes, both places change together.
 *
 * Note on the local-dev default: the plain-http compose API cannot answer https,
 * so `middleware.ts` recognizes an http loopback API origin and omits
 * `upgrade-insecure-requests` for it (production sets an https origin via
 * NEXT_PUBLIC_STEWARD_API_URL, where HTTPS enforcement stays fully on).
 */
export const DEFAULT_STEWARD_API_URL = "http://localhost:3200";

/** Resolved Steward API base URL: env override or the self-host default. */
export const STEWARD_API_URL = process.env.NEXT_PUBLIC_STEWARD_API_URL || DEFAULT_STEWARD_API_URL;
