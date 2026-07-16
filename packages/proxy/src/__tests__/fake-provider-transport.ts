/**
 * PR6 deterministic in-process fake provider transport (TEST-ONLY).
 *
 * WHAT THIS IS
 * ------------
 * A drop-in replacement for the terminal proxy forwarder `forwardWithVettedDns`
 * (`proxy.ts`), matching the `ProxyForwarder` signature EXACTLY. It is injected
 * ONLY through the existing test-only seam `__setForwardProxyRequestForTests`
 * (`proxy.ts`), which is a module-private mutable binding exported behind a
 * `__`-prefixed test-only name. There is NO env var, request header, config
 * row, or `NODE_ENV` branch that selects it in production (U1). A static
 * inventory test (`fake-provider-transport-inventory.test.ts`) asserts this
 * module is imported ONLY by test files / the CI harness, never by any `src/`
 * production module.
 *
 * WHERE IT SITS IN THE PIPELINE
 * -----------------------------
 * The proxy invokes `forwardProxyRequestForHandler(...)` as the FINAL step,
 * AFTER: SSRF/public-DNS vetting (`verifyProxyHostResolvesPublicly`), hop-by-hop
 * header stripping, credential decryption + injection, and (for governed routes)
 * the atomic single-winner execution claim. The fake therefore proves the FULL
 * governed path end-to-end; it replaces ONLY the terminal network I/O and
 * weakens NO guard (U1). By the time the fake is called, the injected credential
 * header is already present — the fake ASSERTS the credential header is present
 * at this layer but NEVER logs, records, or returns its value (canary
 * discipline).
 *
 * DETERMINISM
 * -----------
 * The fake keys its scripted response on the outbound
 * `(method, url.pathname, url.search, canonical-body-hash)` tuple, so a given
 * governed action always yields the same response. No wall-clock, no randomness.
 * A per-key "mode" (ok / timeout / server-error / client-error) lets a test
 * script post-dispatch failure semantics (M08 outcome_unknown, M-failed, etc.)
 * against a controllable barrier rather than a sleep.
 *
 * This module is `packages/proxy/src/__tests__/` on purpose: it lives under
 * `__tests__/` so the inventory scan and tsconfig test-exclusion both treat it
 * as test-only, and it never ships in a production build artifact.
 */

import { createHash } from "node:crypto";
import type { LookupAddress } from "node:dns";

/** The EXACT terminal-forwarder signature (mirrors `ProxyForwarder` in proxy.ts). */
export type FakeForwarder = (
  url: URL,
  method: string,
  headers: Headers,
  body: ReadableStream<Uint8Array> | null,
  records: LookupAddress[],
) => Promise<Response>;

/** How the fake resolves a given scripted key. */
export type FakeMode =
  | "ok"
  | "timeout" // reject after the barrier: models a post-dispatch network timeout (outcome_unknown)
  | "server-error" // unambiguous 5xx: models `failed`
  | "client-error"; // 4xx: models a classified upstream client error

/** A scripted response entry keyed by the canonical outbound tuple. */
export interface FakeScript {
  mode: FakeMode;
  /** Response status for the `ok` / error modes (default 200 for ok). */
  status?: number;
  /** JSON body returned for `ok` (GitHub-shaped). Ignored for error/timeout. */
  json?: unknown;
  /** Optional response headers (content-type defaults to application/json). */
  headers?: Record<string, string>;
}

/** A single recorded outbound call. NEVER records header VALUES (canary). */
export interface FakeCallRecord {
  key: string;
  method: string;
  /** pathname + search only; no host credentials ever appear here. */
  path: string;
  /** Header NAMES only, lowercased, sorted. Values are never recorded. */
  headerNames: string[];
  /** True iff SOME credential-bearing header (authorization / injected key) was present. */
  credentialHeaderPresent: boolean;
  bodyHash: string | null;
  at: number; // monotonic call ordinal, not wall-clock
}

const CREDENTIAL_HEADER_NAMES = new Set([
  "authorization",
  "x-api-key",
  "x-goog-api-key",
  "private-token",
]);

/**
 * The deterministic fake. Construct one per test, script it, then
 * `__setForwardProxyRequestForTests(fake.forwarder)`.
 */
export class FakeProviderTransport {
  private scripts = new Map<string, FakeScript>();
  private records: FakeCallRecord[] = [];
  private callOrdinal = 0;
  /**
   * Optional barrier a "timeout"/"ok" script awaits before resolving/rejecting.
   * Lets a test hold the terminal I/O open to interleave a concurrent claim or
   * a crash injection (never a sleep as an oracle).
   */
  private barrier: Promise<void> | null = null;
  private releaseBarrier: (() => void) | null = null;

  /** Script a response for a canonical outbound tuple. */
  script(match: { method: string; path: string; bodyHash?: string | null }, entry: FakeScript): this {
    this.scripts.set(this.keyOf(match.method, match.path, match.bodyHash ?? null), entry);
    return this;
  }

  /** Script by exact key (as recorded). */
  scriptKey(key: string, entry: FakeScript): this {
    this.scripts.set(key, entry);
    return this;
  }

  /** A fallback used when no exact script matches (default: an empty 200 JSON array). */
  private fallback: FakeScript = { mode: "ok", status: 200, json: [] };
  setFallback(entry: FakeScript): this {
    this.fallback = entry;
    return this;
  }

  /** Install a barrier the next matching call will await before completing. */
  arm(): this {
    this.barrier = new Promise<void>((resolve) => {
      this.releaseBarrier = resolve;
    });
    return this;
  }

  /** Release an armed barrier (lets the pending forwarder call complete). */
  release(): void {
    this.releaseBarrier?.();
    this.releaseBarrier = null;
    this.barrier = null;
  }

  /** All recorded calls (header VALUES never present). */
  calls(): readonly FakeCallRecord[] {
    return this.records;
  }

  /** Count of recorded outbound dispatches. */
  dispatchCount(): number {
    return this.records.length;
  }

  reset(): void {
    this.scripts.clear();
    this.records = [];
    this.callOrdinal = 0;
    this.barrier = null;
    this.releaseBarrier = null;
    this.fallback = { mode: "ok", status: 200, json: [] };
  }

  private keyOf(method: string, path: string, bodyHash: string | null): string {
    return `${method.toUpperCase()} ${path}${bodyHash ? ` #${bodyHash}` : ""}`;
  }

  /** The forwarder to hand to `__setForwardProxyRequestForTests`. */
  get forwarder(): FakeForwarder {
    return async (url, method, headers, body, _records) => {
      const path = `${url.pathname}${url.search}`;
      const bodyHash = await hashBody(body);
      const key = this.keyOf(method, path, bodyHash);

      // Record header NAMES only. Never a value.
      const headerNames: string[] = [];
      let credentialHeaderPresent = false;
      headers.forEach((_value, name) => {
        const lower = name.toLowerCase();
        headerNames.push(lower);
        if (CREDENTIAL_HEADER_NAMES.has(lower)) credentialHeaderPresent = true;
      });
      headerNames.sort();

      this.records.push({
        key,
        method: method.toUpperCase(),
        path,
        headerNames,
        credentialHeaderPresent,
        bodyHash,
        at: this.callOrdinal++,
      });

      const entry =
        this.scripts.get(key) ??
        this.scripts.get(this.keyOf(method, path, null)) ??
        this.fallback;

      if (this.barrier) {
        // Hold until released; models a controllable post-dispatch stall.
        await this.barrier;
      }

      if (entry.mode === "timeout") {
        throw new Error("Proxy upstream request timed out");
      }
      if (entry.mode === "server-error") {
        return jsonResponse(entry.status ?? 502, { error: "upstream_error" }, entry.headers);
      }
      if (entry.mode === "client-error") {
        return jsonResponse(entry.status ?? 422, { error: "unprocessable" }, entry.headers);
      }
      // ok
      return jsonResponse(entry.status ?? 200, entry.json ?? {}, entry.headers);
    };
  }
}

function jsonResponse(
  status: number,
  json: unknown,
  headers?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(json), {
    status,
    headers: { "content-type": "application/json", ...(headers ?? {}) },
  });
}

/** Deterministic canonical body hash (sha256 hex) or null for empty bodies. */
async function hashBody(body: ReadableStream<Uint8Array> | null): Promise<string | null> {
  if (!body) return null;
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  if (chunks.length === 0) return null;
  const hash = createHash("sha256");
  for (const chunk of chunks) hash.update(chunk);
  return hash.digest("hex");
}

/** Canonical GitHub-shaped fixtures used by the golden path (deterministic). */
export const GITHUB_FIXTURES = {
  issueList: [
    { id: 1, number: 101, title: "sandbox issue A", state: "open" },
    { id: 2, number: 102, title: "sandbox issue B", state: "open" },
  ],
  prCommentCreated: {
    id: 424242,
    node_id: "IC_kwDOFAKENODEID",
    body: "governed comment (steward-marker)",
    html_url: "https://github.com/steward-sandbox/hello/pull/1#issuecomment-424242",
  },
} as const;

/**
 * Canonical X-shaped fixtures (spec predates the live X provider; PR6 adds an X
 * leg to the fake matrix — see the drift note in the PR body).
 */
export const X_FIXTURES = {
  usersMe: { data: { id: "999", name: "Sandbox", username: "sandbox" } },
  tweetCreated: { data: { id: "1888000000000000000", text: "governed tweet" } },
} as const;
