"use client";

/**
 * API reachability check.
 *
 * The public demo at https://steward.fi does NOT run a Steward control plane.
 * Steward is self-hosted: each org runs their own instance and points their
 * own dashboard at it. When the configured API base is unreachable (DNS
 * NXDOMAIN, network error, refused connection, 5xx with no body), we surface
 * a "self-host" prompt instead of an "internal error" UI.
 *
 * This module is a single source of truth for that detection so dashboard,
 * login, and any other consumer treat the failure mode identically.
 */

import { useEffect, useState } from "react";
import { API_URL } from "@/lib/api";

export type ApiReachability =
  | { status: "checking" }
  | { status: "reachable" }
  | { status: "unreachable"; reason: "network" | "server"; detail?: string };

/**
 * Lightweight probe — hits a no-auth public endpoint with a short timeout.
 * Treats network errors and 5xx as unreachable; 2xx/4xx as reachable
 * (a 4xx still means the server is up and routing correctly).
 */
export async function probeApi(baseUrl: string = API_URL): Promise<ApiReachability> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/health`, {
      method: "GET",
      cache: "no-store",
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (res.status >= 500) {
      return {
        status: "unreachable",
        reason: "server",
        detail: `${res.status} ${res.statusText || ""}`.trim(),
      };
    }
    return { status: "reachable" };
  } catch (err) {
    return {
      status: "unreachable",
      reason: "network",
      detail: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * React hook variant. Re-checks on mount and whenever `baseUrl` changes.
 * Does NOT poll on a timer — callers can re-invoke `refresh()` from a
 * retry button.
 */
export function useApiReachability(baseUrl: string = API_URL): ApiReachability & {
  refresh: () => void;
} {
  const [state, setState] = useState<ApiReachability>({ status: "checking" });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState({ status: "checking" });
    probeApi(baseUrl).then((result) => {
      if (!cancelled) setState(result);
    });
    return () => {
      cancelled = true;
    };
  }, [baseUrl, tick]);

  return { ...state, refresh: () => setTick((t) => t + 1) };
}
