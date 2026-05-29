/**
 * Pure route-matching functions.
 *
 * Extracted from proxy.ts so they can be unit-tested without DB dependencies.
 */

/**
 * Match a host pattern against a hostname.
 * Supports exact match and wildcard prefix: *.example.com
 */
export function matchHost(pattern: string, host: string): boolean {
  if (pattern === host) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return false;
}

/**
 * Match a path pattern against a request path.
 * Supports exact match and wildcard suffix: /v1/*
 * The pattern "/*" matches everything.
 */
export function matchPath(pattern: string, path: string): boolean {
  if (pattern === "/*" || pattern === "*") return true;
  if (pattern === path) return true;
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -1); // "/v1/"
    return path.startsWith(prefix);
  }
  return false;
}

export interface RouteMatchPattern {
  hostPattern: string;
  pathPattern?: string | null;
  method?: string | null;
  priority?: number | null;
  createdAt?: Date | string | null;
  id?: string | null;
}

function hostSpecificity(pattern: string): number {
  if (pattern === "*") return 0;
  if (pattern.startsWith("*.")) return 100 + pattern.length;
  return 1_000 + pattern.length;
}

function pathSpecificity(pattern: string | null | undefined): number {
  const value = pattern ?? "/*";
  if (value === "*" || value === "/*") return 0;
  if (value.endsWith("/*")) return 100 + value.length;
  return 1_000 + value.length;
}

function methodSpecificity(method: string | null | undefined): number {
  return method && method !== "*" ? 1 : 0;
}

function createdAtMs(value: Date | string | null | undefined): number {
  if (!value) return 0;
  const time = value instanceof Date ? value.getTime() : Date.parse(value);
  return Number.isFinite(time) ? time : 0;
}

/**
 * Deterministic route ordering for equally valid matches.
 *
 * Priority is still the operator override. Ties prefer the narrowest route:
 * exact host over wildcard host, exact/longer path over broad wildcard path,
 * exact method over method wildcard, then stable age/id ordering.
 */
export function compareRouteMatchSpecificity(
  a: RouteMatchPattern,
  b: RouteMatchPattern,
): number {
  const priorityDelta = (b.priority ?? 0) - (a.priority ?? 0);
  if (priorityDelta !== 0) return priorityDelta;

  const hostDelta = hostSpecificity(b.hostPattern) - hostSpecificity(a.hostPattern);
  if (hostDelta !== 0) return hostDelta;

  const pathDelta = pathSpecificity(b.pathPattern) - pathSpecificity(a.pathPattern);
  if (pathDelta !== 0) return pathDelta;

  const methodDelta = methodSpecificity(b.method) - methodSpecificity(a.method);
  if (methodDelta !== 0) return methodDelta;

  const createdDelta = createdAtMs(a.createdAt) - createdAtMs(b.createdAt);
  if (createdDelta !== 0) return createdDelta;

  return String(a.id ?? "").localeCompare(String(b.id ?? ""));
}
