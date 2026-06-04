/**
 * Named alias resolution.
 *
 * Resolves proxy request paths to target URLs:
 *   - Named alias:  /openai/v1/chat/completions → https://api.openai.com/v1/chat/completions
 *   - Direct proxy: /proxy/custom.api.com/endpoint → https://custom.api.com/endpoint
 *
 * Returns null if the path doesn't match any known pattern.
 */

import { isIP } from "node:net";
import { DEFAULT_ALIASES } from "../config";

export interface ResolvedTarget {
  /** Full target URL including protocol */
  url: string;
  /** Just the hostname (for route matching) */
  host: string;
  /** Path on the target host */
  path: string;
}

function configuredDirectProxyHosts(): Set<string> {
  return new Set(
    [
      ...Object.values(DEFAULT_ALIASES),
      ...(process.env.STEWARD_PROXY_ALLOWED_HOSTS ?? "")
        .split(",")
        .map((host) => host.trim().toLowerCase())
        .filter(Boolean),
    ].map((host) => host.toLowerCase()),
  );
}

function isBlockedHost(host: string): boolean {
  const normalized = host.toLowerCase();
  if (isIP(normalized)) return true;
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal")
  ) {
    return true;
  }
  return false;
}

function isAllowedDirectProxyHost(host: string): boolean {
  const normalized = host.toLowerCase();
  if (!normalized.includes(".") || isBlockedHost(normalized)) return false;
  return configuredDirectProxyHosts().has(normalized);
}

function hasUnsafePath(path: string): boolean {
  if (/[\u0000-\u001f\u007f]/.test(path)) return true;
  const lowered = path.toLowerCase();
  if (
    lowered.includes("%2e") ||
    lowered.includes("%2f") ||
    lowered.includes("%5c") ||
    lowered.includes("\\")
  ) {
    return true;
  }
  return path.split("/").some((segment) => segment === "." || segment === "..");
}

/**
 * Resolve a proxy request path to a target URL.
 *
 * @param requestPath - The path from the incoming request (e.g. "/openai/v1/chat/completions")
 * @returns Resolved target or null if path doesn't match any alias or proxy pattern
 */
export function resolveTarget(requestPath: string): ResolvedTarget | null {
  // Strip leading slash and split into segments
  const cleaned = requestPath.startsWith("/") ? requestPath.slice(1) : requestPath;
  if (!cleaned) return null;

  const slashIdx = cleaned.indexOf("/");
  const firstSegment = slashIdx === -1 ? cleaned : cleaned.slice(0, slashIdx);
  const remainder = slashIdx === -1 ? "" : cleaned.slice(slashIdx);

  // 1. Check named aliases: /openai/... → api.openai.com/...
  const aliasHost = resolveAliasHost(firstSegment);
  if (aliasHost) {
    const path = remainder || "/";
    if (hasUnsafePath(path)) return null;
    // Defense-in-depth: even though current aliases are hardcoded public hosts,
    // run the alias target through the same SSRF host guard used for direct
    // proxying. This ensures any future DB-driven / configurable alias can never
    // resolve to localhost, a private/internal domain, or a bare IP without
    // being rejected here (in addition to the runtime DNS resolution check).
    const host = aliasHost.toLowerCase();
    if (!host.includes(".") || isBlockedHost(host)) return null;
    return {
      url: `https://${host}${path}`,
      host,
      path,
    };
  }

  // 2. Direct proxy: /proxy/custom.api.com/endpoint → custom.api.com/endpoint
  if (firstSegment === "proxy") {
    const afterProxy = remainder.startsWith("/") ? remainder.slice(1) : remainder;
    if (!afterProxy) return null;

    const hostSlashIdx = afterProxy.indexOf("/");
    const rawHost = hostSlashIdx === -1 ? afterProxy : afterProxy.slice(0, hostSlashIdx);
    const host = rawHost.toLowerCase();
    const path = hostSlashIdx === -1 ? "/" : afterProxy.slice(hostSlashIdx);

    if (!isAllowedDirectProxyHost(host)) return null;
    if (hasUnsafePath(path)) return null;

    return {
      url: `https://${host}${path}`,
      host,
      path,
    };
  }

  return null;
}

/**
 * Resolve a named alias to its target host.
 *
 * Single chokepoint for alias → host resolution. When aliases become
 * configurable (e.g. DB-driven), extend this function rather than reading
 * DEFAULT_ALIASES directly elsewhere — the SSRF host guard in resolveTarget()
 * is applied to whatever this returns.
 */
function resolveAliasHost(name: string): string | undefined {
  return DEFAULT_ALIASES[name];
}

/**
 * Get all registered alias names.
 */
export function getAliasNames(): string[] {
  return Object.keys(DEFAULT_ALIASES);
}

/**
 * Check if a given name is a registered alias.
 */
export function isAlias(name: string): boolean {
  return name in DEFAULT_ALIASES;
}
