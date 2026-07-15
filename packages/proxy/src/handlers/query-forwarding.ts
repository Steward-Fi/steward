/**
 * Governed query-string forwarding.
 *
 * The proxy resolves the upstream target from the request *path* only (route
 * matching must never be influenced by the query — see `applyGovernedQuery`
 * invariants below). This module is the single, audited chokepoint that
 * composes the client's query string onto the already-pinned upstream URL.
 *
 * Security invariants (all enforced or asserted here):
 *   - The outbound scheme, host, port, and path are pinned by target
 *     resolution and MUST be identical before and after applying the query.
 *     If applying the query changes any of them, we fail closed.
 *   - The query is applied via `URL.search`, which preserves the exact
 *     percent-encoding and the ordered, possibly-duplicated key/value pairs of
 *     the original request-target. We never round-trip through
 *     `URLSearchParams` entries / `Object.fromEntries`, which would collapse
 *     duplicate keys and normalize encoding.
 *   - userinfo (username/password) and fragment must be empty on the final URL.
 *   - The configured upstream target must not itself already carry a query. The
 *     current contract builds targets as bare `https://host/path` with no base
 *     query, so a pre-existing query is unexpected; we reject fail-closed rather
 *     than guess a merge semantics that could enable parameter smuggling.
 */

export interface GovernedQueryResult {
  ok: true;
  url: URL;
}

export interface GovernedQueryError {
  ok: false;
  reason: string;
}

/**
 * Extract the raw query string (including the leading "?", or "" when absent)
 * from an incoming request URL, using WHATWG URL parsing so that any fragment
 * is stripped and the exact percent-encoding / ordered duplicate pairs of the
 * request-target are preserved.
 *
 * Returns "" for a missing or empty ("?") query.
 */
export function extractRawQuery(requestUrl: string): string {
  try {
    return new URL(requestUrl).search;
  } catch {
    // A request URL Hono handed us should always parse; fail closed to "no
    // query" rather than throwing, so a parse hiccup can never smuggle data.
    return "";
  }
}

/**
 * Compose the governed client query onto the pinned upstream target URL.
 *
 * `targetUrl` is the fully-resolved, host/scheme/path-pinned upstream URL built
 * from the request path (no query). `rawQuery` is the value returned by
 * `extractRawQuery` for the same request. The returned URL is a fresh clone with
 * the query applied; the input is not mutated.
 *
 * Fails closed (returns `{ ok: false }`) if applying the query would alter the
 * pinned authority/path, if the target already carried a query, or if the
 * result exposes userinfo or a fragment.
 */
export function applyGovernedQuery(
  targetUrl: URL,
  rawQuery: string,
): GovernedQueryResult | GovernedQueryError {
  // The pinned target must never itself carry a query, userinfo, or fragment.
  if (targetUrl.search !== "") {
    return { ok: false, reason: "target-carries-base-query" };
  }
  if (targetUrl.username !== "" || targetUrl.password !== "") {
    return { ok: false, reason: "target-carries-userinfo" };
  }
  if (targetUrl.hash !== "") {
    return { ok: false, reason: "target-carries-fragment" };
  }

  // Snapshot the pinned authority + path so we can prove they are unchanged.
  const pinned = {
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: targetUrl.port,
    pathname: targetUrl.pathname,
  };

  const composed = new URL(targetUrl.toString());
  // Setting `.search` preserves the exact bytes of the query (encoding + order
  // + duplicate keys). Normalize a bare "?" (empty query) to no query at all.
  const normalizedQuery =
    rawQuery === "" || rawQuery === "?" ? "" : rawQuery.startsWith("?") ? rawQuery : `?${rawQuery}`;
  composed.search = normalizedQuery;

  // Re-validate: the query must not have influenced the pinned authority/path,
  // and must not have introduced userinfo or a fragment. WHATWG URL parsing
  // treats `.search` content as opaque query data, so this should always hold —
  // the assertion exists so any future regression fails closed instead of
  // silently forwarding a confused target.
  if (
    composed.protocol !== pinned.protocol ||
    composed.hostname !== pinned.hostname ||
    composed.port !== pinned.port ||
    composed.pathname !== pinned.pathname ||
    composed.username !== "" ||
    composed.password !== "" ||
    composed.hash !== ""
  ) {
    return { ok: false, reason: "query-altered-pinned-target" };
  }

  return { ok: true, url: composed };
}
