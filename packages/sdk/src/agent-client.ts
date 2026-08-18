/**
 * agent-client.ts — @stwd/sdk agent-side capability client (lane A3).
 *
 * The sovereign-custody client: an Eliza/agent process boots holding NOTHING but
 * its P-256 identity keypair (+ the Steward base URL) and obtains everything else
 * at runtime:
 *
 *     boot(keypair)                       ← no token, no API key, no secret
 *       └─ enroll()                       ← challenge/response → short-lived agent token
 *            └─ manifest()               ← what capabilities may I request?
 *                 ├─ issue()/renew()     ← token-mode: short-lived scoped token
 *                 └─ invoke()            ← broker-mode: Steward performs the call
 *       └─ renewal loop                   ← re-enroll before expiry (fail-closed)
 *
 * Contrast with the OLD flow (`POST /agents/:id/token`, ≤30d operator-minted
 * token baked into the container env): the operator's ONE job here is to register
 * the agent's PUBLIC key once (`agent_signers`, keyType=p256). No secret ever
 * lands in a cloud env var, and revocation (flip the signer to revoked, or
 * revoke a grant) takes effect within one short renewal cycle — the client
 * fails closed to unauthenticated on any renewal failure and never reuses a
 * stale token.
 *
 * This file layers on the A1 API surface documented in the receipt:
 *   POST /agent-enroll/challenge, /agent-enroll/verify          (public)
 *   GET  /capabilities/manifest                                  (agent-jwt)
 *   POST /capabilities/manifest/:id/issue|renew                  (agent-jwt)
 *   POST /capabilities/:name/invoke                              (agent-jwt)
 *
 * It uses only WebCrypto + fetch (vendor-neutral, browser+Node+Bun). The private
 * key never leaves `AgentKeypair` and is never logged.
 */

import { AgentKeypair } from "./agent-keypair.ts";
import { assertSecureBaseUrl } from "./base-url.ts";

// ─── Errors ───────────────────────────────────────────────────────────────────

/** A typed error carrying the HTTP status + machine-readable code from Steward. */
export class AgentClientError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly data?: unknown;
  constructor(message: string, status: number, opts?: { code?: string; data?: unknown }) {
    super(message);
    this.name = "AgentClientError";
    this.status = status;
    this.code = opts?.code;
    this.data = opts?.data;
  }
}

/**
 * Thrown when the client is asked to do something requiring a live agent token
 * but it has none (never enrolled, or it fail-closed after a renewal failure /
 * revocation). Distinct from a server 401 so callers can branch on it.
 */
export class NotEnrolledError extends AgentClientError {
  constructor(message = "agent is not enrolled (no live token)") {
    super(message, 0, { code: "not_enrolled" });
    this.name = "NotEnrolledError";
  }
}

// ─── Public shapes ──────────────────────────────────────────────────────────

export interface EnrollResult {
  agentId: string;
  tenantId: string;
  scopes: string[];
  /** epoch ms at which the current agent token expires (best-effort, from JWT exp). */
  expiresAt: number | null;
}

/** One manifest entry the agent may request (mirrors A1 `ManifestListing`). */
export interface ManifestEntry {
  manifest: string;
  provider: string;
  kind: string;
  capabilityName: string;
  capabilityId: string;
  grantExpiresAt: string | null;
}

/** Result of a token-mode issue/renew: a short-lived scoped token. */
export interface TokenCapability {
  mode: "token";
  token: string;
  /** Upstream lease identity. Present for real provider-token mode. */
  leaseId?: string;
  issuer?: string;
  /** Upstream leases remain delivery-pending until the holder proves receipt. */
  acknowledgementRequired?: boolean;
  acknowledgementDeadlineSeconds?: number;
  resource?: { repositories: string[]; permissions: Record<string, "read" | "write" | "admin"> };
  /** @deprecated legacy Steward-JWT fields; not present on upstream leases. */
  jti?: string;
  ttlSeconds?: number;
  scopes?: string[];
  manifest: string;
  capabilityId: string;
  /** epoch ms at which this capability token expires. */
  expiresAt: number;
}

/** Result of a broker-mode issue: how to exercise the capability via invoke(). */
export interface BrokerCapability {
  mode: "broker";
  delegation: { capabilityName: string; method: string; note: string };
  manifest: string;
  capabilityId: string;
}

export type IssuedCapability = TokenCapability | BrokerCapability;

export interface CapabilityIssueOptions {
  ttlSeconds?: number;
  /** Required by upstream token-mode providers. */
  workspaceId?: string;
  resource?: TokenCapability["resource"];
  /** Required for one-time provider-token delivery; never reused for renewal. */
  idempotencyKey?: string;
}

/**
 * 202 approval-pending is a FIRST-CLASS state, not an exception: a broker invoke
 * that hits a require-approval policy returns this instead of throwing. Callers
 * poll or await out-of-band approval, then re-invoke.
 */
export interface InvokePendingApproval {
  status: "pending_approval";
  approvalId: string | null;
}

/** A successful broker invoke: the scrubbed upstream body Steward returned. */
export interface InvokeSuccess<T = unknown> {
  status: "ok";
  httpStatus: number;
  data: T;
}

export type InvokeResult<T = unknown> = InvokeSuccess<T> | InvokePendingApproval;

// ─── Config + events ──────────────────────────────────────────────────────────

/** Lifecycle events surfaced honestly (no silent failures). */
export type AgentClientEvent =
  | { type: "enrolled"; agentId: string; tenantId: string; expiresAt: number | null }
  | { type: "renewed"; agentId: string; expiresAt: number | null }
  | { type: "renew_failed"; error: AgentClientError; willRetry: boolean }
  | { type: "unauthenticated"; reason: string };

export type AgentClientListener = (event: AgentClientEvent) => void;

export interface AgentClientConfig {
  /** Steward base URL, e.g. https://steward.example / http://localhost:3200. */
  baseUrl: string;
  /** the agent's id (matches an `agent_signers` row with an active p256 key). */
  agentId: string;
  /** the identity keypair — the only long-lived secret the agent holds. */
  keypair: AgentKeypair;
  /**
   * Renew this many ms BEFORE the token actually expires, so a request is never
   * made with an about-to-die token. Default 60s. Clamped to < token lifetime.
   */
  renewLeadMs?: number;
  /**
   * Max jitter (ms) subtracted from the renewal delay so a fleet of agents does
   * not stampede Steward at the same instant. Default 5000ms.
   */
  renewJitterMs?: number;
  /** injectable clock (tests). */
  now?: () => number;
  /** injectable fetch (tests / custom transport). */
  fetchImpl?: typeof fetch;
  /** Per-header and per-body transport deadline in ms. Default 10000. */
  requestTimeoutMs?: number;
  /**
   * Tolerance (seconds) applied when reading a token's `exp` claim, to absorb
   * modest client/server clock skew when scheduling renewal. Default 30s.
   */
  clockSkewToleranceSeconds?: number;
  /**
   * Permit a plaintext non-loopback baseUrl (warns at construction). HTTPS is
   * required by default so enrollment proofs and agent tokens never travel
   * cleartext off-loopback.
   */
  allowInsecureBaseUrl?: boolean;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Decode a JWT's `exp` (seconds) without verifying — for renewal scheduling
 * only; the SERVER is the authority on validity. Returns null if unparseable. */
function readJwtExpMs(token: string): number | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payloadB64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const json = JSON.parse(atob(padded)) as { exp?: unknown };
    if (typeof json.exp !== "number") return null;
    return json.exp * 1000;
  } catch {
    return null;
  }
}

// ─── The client ─────────────────────────────────────────────────────────────

export class AgentClient {
  private readonly baseUrl: string;
  private readonly agentId: string;
  private readonly keypair: AgentKeypair;
  private readonly renewLeadMs: number;
  private readonly renewJitterMs: number;
  private readonly now: () => number;
  private readonly fetchImpl: typeof fetch;
  private readonly clockSkewToleranceMs: number;
  private readonly requestTimeoutMs: number;

  private token: string | null = null;
  private tenantId: string | null = null;
  private scopes: string[] = [];
  private tokenExpiresAt: number | null = null;

  private renewTimer: ReturnType<typeof setTimeout> | null = null;
  private renewing = false;
  private stopped = false;

  private readonly listeners = new Set<AgentClientListener>();

  constructor(config: AgentClientConfig) {
    if (!config.baseUrl) throw new Error("baseUrl required");
    if (!config.agentId) throw new Error("agentId required");
    if (!(config.keypair instanceof AgentKeypair)) {
      throw new Error("keypair must be an AgentKeypair (the private key never leaves it)");
    }
    assertSecureBaseUrl(config.baseUrl, config.allowInsecureBaseUrl);
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.agentId = config.agentId;
    this.keypair = config.keypair;
    this.renewLeadMs = config.renewLeadMs ?? 60_000;
    this.renewJitterMs = config.renewJitterMs ?? 5_000;
    this.now = config.now ?? (() => Date.now());
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.clockSkewToleranceMs = (config.clockSkewToleranceSeconds ?? 30) * 1000;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 10_000;
    if (
      !Number.isSafeInteger(this.requestTimeoutMs) ||
      this.requestTimeoutMs < 10 ||
      this.requestTimeoutMs > 60_000
    ) {
      throw new Error("requestTimeoutMs must be an integer from 10 to 60000");
    }
  }

  // ── observability ───────────────────────────────────────────────────────────
  on(listener: AgentClientListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  private emit(event: AgentClientEvent): void {
    for (const l of this.listeners) {
      try {
        l(event);
      } catch {
        // a listener throwing must never break the client.
      }
    }
  }

  /** Whether the client currently holds a token it believes is live. The SERVER
   * remains the authority — this is a local best-effort view for callers. */
  isEnrolled(): boolean {
    if (!this.token) return false;
    if (this.tokenExpiresAt === null) return true;
    return this.now() < this.tokenExpiresAt;
  }

  getTenantId(): string | null {
    return this.tenantId;
  }
  getScopes(): readonly string[] {
    return this.scopes;
  }
  getTokenExpiresAt(): number | null {
    return this.tokenExpiresAt;
  }

  // ── enrollment (keypair-only boot) ────────────────────────────────────────────
  /**
   * Enroll: fetch a single-use challenge, sign its canonical string with the
   * identity key, exchange the signature for a short-lived agent token. This is
   * the ONLY authentication step; everything downstream rides the resulting
   * token. Idempotent to call again (re-enroll / manual refresh).
   */
  async enroll(): Promise<EnrollResult> {
    const challenge = await this.postPublic<{
      agentId: string;
      nonce: string;
      canonicalString: string;
      expiresAt: number;
    }>("/agent-enroll/challenge", { agentId: this.agentId });

    // Sign EXACTLY the server-provided canonical string (never reconstruct it —
    // any drift fails closed at verify).
    const signature = await this.keypair.sign(challenge.canonicalString);

    const verified = await this.postPublic<{
      token: string;
      agentId: string;
      tenantId: string;
      scope: string;
      scopes: string[];
      expiresIn: string;
    }>("/agent-enroll/verify", {
      agentId: this.agentId,
      nonce: challenge.nonce,
      signature,
    });

    this.token = verified.token;
    this.tenantId = verified.tenantId;
    this.scopes = verified.scopes ?? (verified.scope ? [verified.scope] : []);
    this.tokenExpiresAt = readJwtExpMs(verified.token);

    const result: EnrollResult = {
      agentId: verified.agentId,
      tenantId: verified.tenantId,
      scopes: this.scopes,
      expiresAt: this.tokenExpiresAt,
    };
    this.emit({
      type: "enrolled",
      agentId: result.agentId,
      tenantId: result.tenantId,
      expiresAt: result.expiresAt,
    });
    return result;
  }

  /**
   * Start the background renewal loop: re-enroll (fresh challenge/response) a
   * lead-time before the current token expires, with jitter. On success emits
   * `renewed`; on failure emits `renew_failed` AND fails closed (drops the token,
   * emits `unauthenticated`) — a revoked signer stops enrolling, and we never
   * keep serving with a token that may have been revoked. The loop keeps trying
   * (a transient network blip should self-heal) but every attempt in the failed
   * window operates from the unauthenticated state, so no stale token is reused.
   */
  startRenewalLoop(): void {
    this.stopped = false;
    this.scheduleRenew();
  }

  /** Stop the renewal loop (does NOT drop the current token). */
  stopRenewalLoop(): void {
    this.stopped = true;
    if (this.renewTimer) {
      clearTimeout(this.renewTimer);
      this.renewTimer = null;
    }
  }

  private scheduleRenew(): void {
    if (this.stopped) return;
    if (this.renewTimer) clearTimeout(this.renewTimer);

    // If we have no expiry known, retry soon; otherwise renew lead-time early.
    let delay: number;
    if (this.tokenExpiresAt === null) {
      delay = Math.max(0, this.renewLeadMs);
    } else {
      const untilExpiry = this.tokenExpiresAt - this.now();
      const lead = Math.min(this.renewLeadMs, Math.max(0, untilExpiry - 1));
      delay = Math.max(0, untilExpiry - lead);
    }
    // Subtract jitter (never below 0) to de-synchronize a fleet.
    const jitter = this.renewJitterMs > 0 ? Math.floor(Math.random() * this.renewJitterMs) : 0;
    delay = Math.max(0, delay - jitter);

    this.renewTimer = setTimeout(() => {
      void this.renewOnce();
    }, delay);
    // Do not keep the process alive purely for renewal (Node/Bun).
    (this.renewTimer as unknown as { unref?: () => void })?.unref?.();
  }

  private async renewOnce(): Promise<void> {
    if (this.stopped || this.renewing) return;
    this.renewing = true;
    try {
      await this.enroll();
      this.emit({ type: "renewed", agentId: this.agentId, expiresAt: this.tokenExpiresAt });
    } catch (err) {
      const error =
        err instanceof AgentClientError
          ? err
          : new AgentClientError(err instanceof Error ? err.message : "renewal failed", 0);
      // FAIL CLOSED: drop the token so no revoked/stale token is ever reused.
      this.failClosed(`renewal failed: ${error.message}`);
      this.emit({ type: "renew_failed", error, willRetry: !this.stopped });
    } finally {
      this.renewing = false;
      this.scheduleRenew();
    }
  }

  /** Drop all authenticated state; subsequent authed calls throw NotEnrolledError
   * until a successful (re-)enroll. */
  private failClosed(reason: string): void {
    this.token = null;
    this.tenantId = null;
    this.scopes = [];
    this.tokenExpiresAt = null;
    this.emit({ type: "unauthenticated", reason });
  }

  // ── manifest ──────────────────────────────────────────────────────────────────
  /** Fetch this agent's capability manifest (typed entries). */
  async manifest(): Promise<ManifestEntry[]> {
    const data = await this.getAuthed<{ manifest: ManifestEntry[] }>("/capabilities/manifest");
    return data.manifest;
  }

  // ── issuance ──────────────────────────────────────────────────────────────────
  /**
   * Issue a capability by manifest id. token-mode returns a short-lived scoped
   * token; broker-mode returns a delegation descriptor (exercise via invoke()).
   */
  async issue(manifestId: string, opts?: CapabilityIssueOptions): Promise<IssuedCapability> {
    return this.issueOrRenew(manifestId, false, opts);
  }

  /** Renew a capability (identical security path; refreshes a token-mode token,
   * re-checks a broker grant). Revocation lands here: a revoked grant → 403. */
  async renew(manifestId: string, opts?: CapabilityIssueOptions): Promise<IssuedCapability> {
    return this.issueOrRenew(manifestId, true, opts);
  }

  private async issueOrRenew(
    manifestId: string,
    isRenewal: boolean,
    opts?: CapabilityIssueOptions,
  ): Promise<IssuedCapability> {
    const path = `/capabilities/manifest/${encodeURIComponent(manifestId)}/${
      isRenewal ? "renew" : "issue"
    }`;
    const raw = await this.postAuthed<
      | {
          ok: true;
          mode: "token";
          token: string;
          jti: string;
          ttlSeconds: number;
          scopes: string[];
          manifest: string;
          capabilityId: string;
          leaseId?: string;
          issuer?: string;
          acknowledgementRequired?: boolean;
          acknowledgementDeadlineSeconds?: number;
          expiresAt?: string;
          resource?: TokenCapability["resource"];
        }
      | {
          ok: true;
          mode: "broker";
          delegation: { capabilityName: string; method: string; note: string };
          manifest: string;
          capabilityId: string;
        }
    >(
      path,
      opts
        ? { ttlSeconds: opts.ttlSeconds, workspaceId: opts.workspaceId, resource: opts.resource }
        : {},
      opts?.idempotencyKey ? { "Idempotency-Key": opts.idempotencyKey } : undefined,
    );

    if (raw.mode === "token") {
      const expFromJwt = readJwtExpMs(raw.token);
      const upstreamExpiry = raw.expiresAt ? Date.parse(raw.expiresAt) : Number.NaN;
      const expiresAt = Number.isFinite(upstreamExpiry)
        ? upstreamExpiry
        : (expFromJwt ?? this.now() + raw.ttlSeconds * 1000);
      return {
        mode: "token",
        token: raw.token,
        jti: raw.jti,
        ttlSeconds: raw.ttlSeconds,
        scopes: raw.scopes,
        leaseId: raw.leaseId,
        issuer: raw.issuer,
        acknowledgementRequired: raw.acknowledgementRequired,
        acknowledgementDeadlineSeconds: raw.acknowledgementDeadlineSeconds,
        resource: raw.resource,
        manifest: raw.manifest,
        capabilityId: raw.capabilityId,
        expiresAt,
      };
    }
    return {
      mode: "broker",
      delegation: raw.delegation,
      manifest: raw.manifest,
      capabilityId: raw.capabilityId,
    };
  }

  /** Revoke a one-time upstream lease. The token is supplied as proof because
   * Steward deliberately persists only its digest. */
  async revokeLease(leaseId: string, token: string): Promise<void> {
    await this.postAuthed(`/capabilities/manifest/leases/${encodeURIComponent(leaseId)}/revoke`, {
      token,
    });
  }

  /** Confirm that a one-time upstream token reached its intended holder. Call
   * only after the caller has accepted custody; unacknowledged deliveries are
   * revoked by Steward's bounded recovery sweep. */
  async acknowledgeLease(leaseId: string, token: string): Promise<void> {
    await this.postAuthed(`/capabilities/manifest/leases/${encodeURIComponent(leaseId)}/ack`, {
      token,
    });
  }

  // ── broker invoke ─────────────────────────────────────────────────────────────
  /**
   * Invoke a broker-mode capability: Steward performs the outbound call with the
   * credential injected server-side; the agent only ever gets a scrubbed body.
   * 202 approval-pending is returned as a first-class `InvokePendingApproval`
   * state, NOT thrown. Gate denials (401/403/429/400/…) throw AgentClientError.
   */
  async invoke<T = unknown>(
    name: string,
    payload?: { args?: Record<string, unknown>; body?: unknown; query?: Record<string, string> },
  ): Promise<InvokeResult<T>> {
    if (!this.isEnrolled() || !this.token) {
      throw new NotEnrolledError();
    }
    const res = await this.request(
      `${this.baseUrl}/capabilities/${encodeURIComponent(name)}/invoke`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify(payload ?? {}),
      },
    );

    // 202 approval-pending: A1 returns { ok:true, data:{ approvalId, status:"pending" } }.
    if (res.status === 202) {
      const body = await this.safeJson(res);
      const data = (body?.data ?? {}) as { approvalId?: unknown };
      return {
        status: "pending_approval",
        approvalId: typeof data.approvalId === "string" ? data.approvalId : null,
      };
    }

    if (res.status === 401) {
      // The server rejected our token (revoked / expired mid-flight): fail closed.
      this.failClosed("invoke rejected with 401 (token revoked or expired)");
    }

    if (!res.ok) {
      const body = await this.safeJson(res);
      const errField: unknown = body?.error;
      const message =
        (typeof errField === "string" && errField) ||
        (isRecord(errField) && typeof errField.message === "string" && errField.message) ||
        `capability invoke failed with status ${res.status}`;
      throw new AgentClientError(message, res.status, { data: body });
    }

    // Success. The proxy passes the (scrubbed) upstream body through verbatim; A1
    // gate successes use the { ok, data } envelope. Prefer `data` when present.
    const body = await this.safeJson(res);
    const data = (body && "ok" in body ? (body.data as T) : (body as unknown as T)) ?? (null as T);
    return { status: "ok", httpStatus: res.status, data };
  }

  // ── transport ─────────────────────────────────────────────────────────────────
  private async postPublic<T>(path: string, body: unknown): Promise<T> {
    const res = await this.request(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
    return this.unwrap<T>(res);
  }

  private async getAuthed<T>(path: string): Promise<T> {
    return this.authed<T>(path, "GET");
  }
  private async postAuthed<T>(
    path: string,
    body: unknown,
    headers?: Record<string, string>,
  ): Promise<T> {
    return this.authed<T>(path, "POST", body, headers);
  }

  private async authed<T>(
    path: string,
    method: "GET" | "POST",
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    if (!this.isEnrolled() || !this.token) throw new NotEnrolledError();
    const res = await this.request(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${this.token}`,
        ...extraHeaders,
      },
      body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
    });
    if (res.status === 401) {
      this.failClosed("authed request rejected with 401 (token revoked or expired)");
    }
    return this.unwrap<T>(res);
  }

  private async unwrap<T>(res: Response): Promise<T> {
    const body = await this.safeJson(res);
    if (!res.ok || body?.ok === false) {
      const message =
        (typeof body?.error === "string" && body.error) ||
        `request failed with status ${res.status}`;
      throw new AgentClientError(message, res.status, { data: body?.data });
    }
    return (body?.data ?? body) as T;
  }

  private async safeJson(res: Response): Promise<Record<string, unknown> | null> {
    const maxBytes = 1024 * 1024;
    const declared = res.headers.get("content-length");
    if (declared !== null) {
      const length = Number(declared);
      if (!Number.isSafeInteger(length) || length < 0 || length > maxBytes) {
        void res.body?.cancel().catch(() => undefined);
        throw new AgentClientError("response exceeded maximum size", res.status);
      }
    }
    if (!res.body) return null;
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new AgentClientError("response body timed out", 0));
        void Promise.resolve(reader.cancel()).catch(() => undefined);
      }, this.requestTimeoutMs);
    });
    try {
      while (true) {
        const { done, value } = await Promise.race([reader.read(), deadline]);
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          void Promise.resolve(reader.cancel()).catch(() => undefined);
          throw new AgentClientError("response exceeded maximum size", res.status);
        }
        chunks.push(value);
      }
    } catch (error) {
      if (error instanceof AgentClientError) throw error;
      throw new AgentClientError("response body could not be read", 0);
    } finally {
      if (timer) clearTimeout(timer);
      try {
        reader.releaseLock();
      } catch {
        // Cancellation must not replace the fixed transport error.
      }
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder().decode(bytes);
    if (!text) return null;
    try {
      const parsed = JSON.parse(text);
      return isRecord(parsed) ? parsed : { data: parsed };
    } catch {
      return null;
    }
  }

  private async request(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new AgentClientError("network request timed out", 0));
        controller.abort();
      }, this.requestTimeoutMs);
    });
    try {
      return await Promise.race([
        this.fetchImpl(url, { ...init, redirect: "error", signal: controller.signal }),
        deadline,
      ]);
    } catch (error) {
      if (error instanceof AgentClientError) throw error;
      throw new AgentClientError("network request failed", 0);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * One-liner boot helper: construct → enroll → start renewal loop, returning a
 * ready client. This is the whole "boot with keypair only" story in one call.
 */
export async function bootAgentClient(config: AgentClientConfig): Promise<AgentClient> {
  const client = new AgentClient(config);
  await client.enroll();
  client.startRenewalLoop();
  return client;
}
