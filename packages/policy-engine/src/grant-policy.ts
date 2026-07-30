/**
 * grant-policy.ts — per-GRANT invoke-time policy (Sovereign Custody, lane C1).
 *
 * WHAT THIS GATES
 * ---------------
 * Today a capability grant is BINARY: "agent X may use capability Y until
 * expiresAt". Steward's pitch is authorization ABOVE execution — which agent,
 * how much, which venue/method, what approval threshold. A `GrantPolicy` is the
 * per-grant constraint document evaluated at INVOKE time, layered UNDER the
 * tenant-level `capability-intent` policy set:
 *
 *   grant resolution (fail-closed)          — existing
 *   -> GRANT POLICY (this module)           — per-grant constraints
 *   -> capability-intent composition        — existing tenant policy set
 *   -> proxy delegation                     — existing
 *
 * BOTH layers must allow; a deny from EITHER is a deny; an approval from either
 * (with no deny) is a 202. The grant policy can only NARROW what the tenant
 * policy set would allow, never widen it.
 *
 * RULE VOCABULARY (v1)
 * --------------------
 *   - `rate`    — N invokes per trailing window (windowSeconds, counted from the
 *                 append-only capability_invocations audit rows).
 *   - `amount`  — value-bearing caps: a declared invoke-arg field carrying
 *                 INTEGER micros (no floats), a per-invoke cap, a rolling-window
 *                 cumulative cap, and an approval threshold (over X -> 202).
 *   - `venue`   — allowlist of upstream hosts / methods / path prefixes the
 *                 grant may exercise (can only narrow the capability's already
 *                 narrow route surface).
 *   - `time`    — notBefore / notAfter instants + a UTC minute-of-day allowed
 *                 window (wrap across midnight supported).
 *   - `approval`— `always: true` routes EVERY invoke to human approval.
 *
 * CLASSES + FAIL-CLOSED DEFAULTS
 * ------------------------------
 * Every policy declares a capability `class`:
 *   - `"value-bearing"` — moves money/value. MUST carry an `amount` block with
 *     at least one bound; a value-bearing policy without amount limits is a
 *     config error (deny). A missing/malformed policy on the grant is a DENY for
 *     this class (the invoke layer enforces via strict mode / parse failure).
 *   - `"plain-secret"`  — exercises a non-value credential (e.g. read API). A
 *     bare `{version:1, class:"plain-secret"}` allows iff the grant is valid —
 *     this is the EXPLICIT permissive default existing grants are migrated to,
 *     so nothing breaks at rollout.
 *
 * DETERMINISM + FAIL-CLOSED EVERYWHERE
 * ------------------------------------
 * `evaluateGrantPolicy` is a PURE function of (policy, input): the caller
 * supplies `now` and the trailing-window counters (fetched per
 * `grantPolicySignals`), so the same inputs always produce the same verdict.
 * Any ambiguity denies: unknown keys, a bad window, a missing counter the
 * policy needs, a missing/non-integer amount arg, an invalid time bound. The
 * module NEVER throws on hostile config — parse failures are values.
 *
 * Every verdict names the RULE that fired (`verdict.rule`) so the audit row can
 * record exactly why an invoke was allowed, denied, or queued.
 */

import { MAX_AGGREGATE_WINDOW_SECONDS } from "./capability-intent";

/** Grant policy schema version this module understands. */
export const GRANT_POLICY_VERSION = 1 as const;

/** The capability class a grant policy declares. Fail-closed: value-bearing
 *  requires amount limits; a missing policy denies value-bearing exercise. */
export type GrantCapabilityClass = "value-bearing" | "plain-secret";

/** N invokes per trailing window. Counted from the append-only invocation rows
 *  (ALL attempts consume rate — a denied probe is not free). */
export interface GrantRateLimit {
  readonly maxInvokes: number;
  readonly windowSeconds: number;
}

/** Rolling cumulative amount cap over a trailing window (integer micros). */
export interface GrantAmountWindowCap {
  readonly maxMicros: number;
  readonly windowSeconds: number;
}

/** Amount limits for a value-bearing capability. `argField` names the invoke
 *  arg that carries the operation's value as a NON-NEGATIVE SAFE INTEGER in
 *  micros (minor units). A missing/non-integer arg DENIES — an operation whose
 *  value cannot be read can never pass an amount-constrained policy. */
export interface GrantAmountPolicy {
  readonly argField: string;
  /** per-invoke hard cap: amount > perInvokeMaxMicros => deny. */
  readonly perInvokeMaxMicros?: number;
  /** rolling-window cumulative cap: windowSum + amount > maxMicros => deny. */
  readonly window?: GrantAmountWindowCap;
  /** approval threshold: amount > approvalOverMicros (and under the hard caps)
   *  => 202 pending human approval. */
  readonly approvalOverMicros?: number;
}

/** Venue/method allowlists. Each list, when present, is a non-empty allowlist
 *  the resolved capability surface must match. Hosts support a leading `*.`
 *  wildcard (mirrors the proxy's host matching); path prefixes match on segment
 *  boundaries. */
export interface GrantVenuePolicy {
  readonly hosts?: readonly string[];
  readonly methods?: readonly string[];
  readonly pathPrefixes?: readonly string[];
}

/** UTC minute-of-day window in which invokes are ALLOWED (outside => deny).
 *  start > end wraps across midnight. start === end is a config error. */
export interface GrantAllowedWindowUtc {
  readonly startMinuteUtc: number;
  readonly endMinuteUtc: number;
}

/** Time bounds: absolute instants + an allowed minute-of-day window. */
export interface GrantTimePolicy {
  readonly notBefore?: string;
  readonly notAfter?: string;
  readonly allowedWindowUtc?: GrantAllowedWindowUtc;
}

/** Approval quorum block. v1: `always` routes every invoke to human approval. */
export interface GrantApprovalPolicy {
  readonly always?: boolean;
}

/** The v1 grant policy document (the `policy` jsonb on capability_grants). */
export interface GrantPolicyV1 {
  readonly version: typeof GRANT_POLICY_VERSION;
  readonly class: GrantCapabilityClass;
  readonly rate?: GrantRateLimit;
  readonly amount?: GrantAmountPolicy;
  readonly venue?: GrantVenuePolicy;
  readonly time?: GrantTimePolicy;
  readonly approval?: GrantApprovalPolicy;
}

/**
 * The EXPLICIT permissive default existing grants are migrated to (and new
 * grants receive when created without a policy): plain-secret exercise, no
 * constraints — exactly the pre-policy behavior, but written down so every
 * grant's authorization is explicit rather than implied by a NULL.
 */
export const LEGACY_DEFAULT_GRANT_POLICY: GrantPolicyV1 = Object.freeze({
  version: GRANT_POLICY_VERSION,
  class: "plain-secret",
});

/** The verdict effects. `approval_required` reuses the existing 202 flow. */
export type GrantPolicyEffect = "allow" | "deny" | "approval_required";

/** Verdict + WHICH rule fired (audited verbatim). `amountMicros` carries the
 *  extracted per-invoke amount (when an amount block evaluated) so the invoke
 *  layer can record it for future rolling-window sums. */
export interface GrantPolicyVerdict {
  readonly effect: GrantPolicyEffect;
  readonly rule: string;
  readonly reason: string;
  readonly amountMicros?: number;
}

/** The trailing-window signals a parsed policy needs the caller to fetch
 *  before evaluation. Absent-but-required signals DENY at evaluation. */
export interface GrantPolicySignals {
  /** rate.windowSeconds, when a rate block is present. */
  readonly rateWindowSeconds?: number;
  /** amount.window.windowSeconds, when an amount window cap is present. */
  readonly amountWindowSeconds?: number;
}

/** The pure evaluation input. `now` is supplied (never read from the clock)
 *  so the verdict is a deterministic function of its inputs. */
export interface GrantPolicyInput {
  readonly now: Date;
  readonly capability: {
    readonly name: string;
    readonly host: string;
    readonly path: string;
    readonly method: string;
  };
  readonly args: Record<string, unknown>;
  /** count of this agent+capability's invocation rows in the rate window. */
  readonly invokesInWindow?: number;
  /** sum of recorded allow-row amountMicros in the amount window. */
  readonly allowedAmountMicrosInWindow?: number;
}

// ─── parse (fail-closed) ─────────────────────────────────────────────────────

const ALLOWED_POLICY_KEYS: ReadonlySet<string> = new Set([
  "version",
  "class",
  "rate",
  "amount",
  "venue",
  "time",
  "approval",
]);
const ALLOWED_RATE_KEYS: ReadonlySet<string> = new Set(["maxInvokes", "windowSeconds"]);
const ALLOWED_AMOUNT_KEYS: ReadonlySet<string> = new Set([
  "argField",
  "perInvokeMaxMicros",
  "window",
  "approvalOverMicros",
]);
const ALLOWED_AMOUNT_WINDOW_KEYS: ReadonlySet<string> = new Set(["maxMicros", "windowSeconds"]);
const ALLOWED_VENUE_KEYS: ReadonlySet<string> = new Set(["hosts", "methods", "pathPrefixes"]);
const ALLOWED_TIME_KEYS: ReadonlySet<string> = new Set([
  "notBefore",
  "notAfter",
  "allowedWindowUtc",
]);
const ALLOWED_WINDOW_UTC_KEYS: ReadonlySet<string> = new Set(["startMinuteUtc", "endMinuteUtc"]);
const ALLOWED_APPROVAL_KEYS: ReadonlySet<string> = new Set(["always"]);
const GRANT_CLASSES: ReadonlySet<string> = new Set(["value-bearing", "plain-secret"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isPosInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v > 0;
}
function isNonNegInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}
function isMinuteOfDay(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 1439;
}
function isNonEmptyStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.length > 0 && v.every((s) => typeof s === "string" && s.length > 0);
}

function unknownKeys(obj: Record<string, unknown>, allowed: ReadonlySet<string>): string[] {
  return Object.keys(obj).filter((k) => !allowed.has(k));
}

/** A window must be a positive integer of seconds within aggregate-store
 *  retention (an over-retention window would silently under-enforce). */
function isValidWindowSeconds(v: unknown): v is number {
  return isPosInt(v) && v <= MAX_AGGREGATE_WINDOW_SECONDS;
}

export type GrantPolicyParseResult =
  | { readonly ok: true; readonly policy: GrantPolicyV1 }
  | { readonly ok: false; readonly error: string };

/**
 * Validate an untrusted jsonb value into a typed {@link GrantPolicyV1}, or
 * return an error string (the caller DENIES on error — a malformed policy on a
 * grant can never be silently ignored). Never throws.
 */
export function parseGrantPolicy(raw: unknown): GrantPolicyParseResult {
  // Hostile values (throwing Proxy traps / getters, e.g. a hostile jsonb
  // deserializer) must not unwind past this function: a throw from a POLICY
  // gate would surface as a raw 500 upstream instead of a fail-closed deny.
  // The inner body does the actual validation; ANY escape is a parse error.
  try {
    return parseGrantPolicyInner(raw);
  } catch {
    return { ok: false, error: "grant-policy: policy is unreadable (hostile or invalid value)" };
  }
}

function parseGrantPolicyInner(raw: unknown): GrantPolicyParseResult {
  if (!isPlainObject(raw)) return { ok: false, error: "grant-policy: policy must be an object" };
  const unknown = unknownKeys(raw, ALLOWED_POLICY_KEYS);
  if (unknown.length > 0) {
    return { ok: false, error: `grant-policy: unknown key(s): ${unknown.join(", ")}` };
  }
  if (raw.version !== GRANT_POLICY_VERSION) {
    return { ok: false, error: "grant-policy: `version` must be 1" };
  }
  if (typeof raw.class !== "string" || !GRANT_CLASSES.has(raw.class)) {
    return { ok: false, error: 'grant-policy: `class` must be "value-bearing"|"plain-secret"' };
  }
  const cls = raw.class as GrantCapabilityClass;

  // rate
  let rate: GrantRateLimit | undefined;
  if (raw.rate !== undefined) {
    if (!isPlainObject(raw.rate))
      return { ok: false, error: "grant-policy: `rate` must be an object" };
    const u = unknownKeys(raw.rate, ALLOWED_RATE_KEYS);
    if (u.length > 0)
      return { ok: false, error: `grant-policy: unknown rate key(s): ${u.join(", ")}` };
    if (!isPosInt(raw.rate.maxInvokes)) {
      return { ok: false, error: "grant-policy: `rate.maxInvokes` must be a positive integer" };
    }
    if (!isValidWindowSeconds(raw.rate.windowSeconds)) {
      return {
        ok: false,
        error: `grant-policy: \`rate.windowSeconds\` must be a positive integer <= ${MAX_AGGREGATE_WINDOW_SECONDS}`,
      };
    }
    rate = { maxInvokes: raw.rate.maxInvokes, windowSeconds: raw.rate.windowSeconds };
  }

  // amount
  let amount: GrantAmountPolicy | undefined;
  if (raw.amount !== undefined) {
    if (!isPlainObject(raw.amount)) {
      return { ok: false, error: "grant-policy: `amount` must be an object" };
    }
    const u = unknownKeys(raw.amount, ALLOWED_AMOUNT_KEYS);
    if (u.length > 0) {
      return { ok: false, error: `grant-policy: unknown amount key(s): ${u.join(", ")}` };
    }
    if (typeof raw.amount.argField !== "string" || raw.amount.argField.length === 0) {
      return { ok: false, error: "grant-policy: `amount.argField` must be a non-empty string" };
    }
    let perInvokeMaxMicros: number | undefined;
    if (raw.amount.perInvokeMaxMicros !== undefined) {
      if (!isNonNegInt(raw.amount.perInvokeMaxMicros)) {
        return {
          ok: false,
          error: "grant-policy: `amount.perInvokeMaxMicros` must be a non-negative integer",
        };
      }
      perInvokeMaxMicros = raw.amount.perInvokeMaxMicros;
    }
    let window: GrantAmountWindowCap | undefined;
    if (raw.amount.window !== undefined) {
      if (!isPlainObject(raw.amount.window)) {
        return { ok: false, error: "grant-policy: `amount.window` must be an object" };
      }
      const wu = unknownKeys(raw.amount.window, ALLOWED_AMOUNT_WINDOW_KEYS);
      if (wu.length > 0) {
        return { ok: false, error: `grant-policy: unknown amount.window key(s): ${wu.join(", ")}` };
      }
      if (!isNonNegInt(raw.amount.window.maxMicros)) {
        return {
          ok: false,
          error: "grant-policy: `amount.window.maxMicros` must be a non-negative integer",
        };
      }
      if (!isValidWindowSeconds(raw.amount.window.windowSeconds)) {
        return {
          ok: false,
          error: `grant-policy: \`amount.window.windowSeconds\` must be a positive integer <= ${MAX_AGGREGATE_WINDOW_SECONDS}`,
        };
      }
      window = {
        maxMicros: raw.amount.window.maxMicros,
        windowSeconds: raw.amount.window.windowSeconds,
      };
    }
    let approvalOverMicros: number | undefined;
    if (raw.amount.approvalOverMicros !== undefined) {
      if (!isNonNegInt(raw.amount.approvalOverMicros)) {
        return {
          ok: false,
          error: "grant-policy: `amount.approvalOverMicros` must be a non-negative integer",
        };
      }
      approvalOverMicros = raw.amount.approvalOverMicros;
    }
    if (
      perInvokeMaxMicros === undefined &&
      window === undefined &&
      approvalOverMicros === undefined
    ) {
      return {
        ok: false,
        error:
          "grant-policy: `amount` must declare at least one bound (perInvokeMaxMicros, window, approvalOverMicros)",
      };
    }
    amount = { argField: raw.amount.argField, perInvokeMaxMicros, window, approvalOverMicros };
  }

  // A value-bearing capability class without amount limits is unauthorized by
  // construction: the whole point of the class is that value movement is bounded.
  if (cls === "value-bearing" && amount === undefined) {
    return {
      ok: false,
      error: 'grant-policy: class "value-bearing" requires an `amount` block',
    };
  }

  // venue
  let venue: GrantVenuePolicy | undefined;
  if (raw.venue !== undefined) {
    if (!isPlainObject(raw.venue)) {
      return { ok: false, error: "grant-policy: `venue` must be an object" };
    }
    const u = unknownKeys(raw.venue, ALLOWED_VENUE_KEYS);
    if (u.length > 0) {
      return { ok: false, error: `grant-policy: unknown venue key(s): ${u.join(", ")}` };
    }
    const venueOut: { hosts?: string[]; methods?: string[]; pathPrefixes?: string[] } = {};
    if (raw.venue.hosts !== undefined) {
      if (!isNonEmptyStringArray(raw.venue.hosts)) {
        return {
          ok: false,
          error: "grant-policy: `venue.hosts` must be a non-empty array of non-empty strings",
        };
      }
      venueOut.hosts = raw.venue.hosts.map((h) => h.toLowerCase());
    }
    if (raw.venue.methods !== undefined) {
      if (!isNonEmptyStringArray(raw.venue.methods)) {
        return {
          ok: false,
          error: "grant-policy: `venue.methods` must be a non-empty array of non-empty strings",
        };
      }
      venueOut.methods = raw.venue.methods.map((m) => m.toUpperCase());
    }
    if (raw.venue.pathPrefixes !== undefined) {
      if (!isNonEmptyStringArray(raw.venue.pathPrefixes)) {
        return {
          ok: false,
          error:
            "grant-policy: `venue.pathPrefixes` must be a non-empty array of non-empty strings",
        };
      }
      const bad = raw.venue.pathPrefixes.find((p) => !p.startsWith("/"));
      if (bad !== undefined) {
        return {
          ok: false,
          error: "grant-policy: every `venue.pathPrefixes` entry must start with /",
        };
      }
      venueOut.pathPrefixes = [...raw.venue.pathPrefixes];
    }
    if (
      venueOut.hosts === undefined &&
      venueOut.methods === undefined &&
      venueOut.pathPrefixes === undefined
    ) {
      return { ok: false, error: "grant-policy: `venue` must declare at least one allowlist" };
    }
    venue = venueOut;
  }

  // time
  let time: GrantTimePolicy | undefined;
  if (raw.time !== undefined) {
    if (!isPlainObject(raw.time)) {
      return { ok: false, error: "grant-policy: `time` must be an object" };
    }
    const u = unknownKeys(raw.time, ALLOWED_TIME_KEYS);
    if (u.length > 0) {
      return { ok: false, error: `grant-policy: unknown time key(s): ${u.join(", ")}` };
    }
    const timeOut: {
      notBefore?: string;
      notAfter?: string;
      allowedWindowUtc?: GrantAllowedWindowUtc;
    } = {};
    let notBeforeMs: number | undefined;
    let notAfterMs: number | undefined;
    if (raw.time.notBefore !== undefined) {
      if (
        typeof raw.time.notBefore !== "string" ||
        !Number.isFinite(Date.parse(raw.time.notBefore))
      ) {
        return { ok: false, error: "grant-policy: `time.notBefore` must be an ISO-8601 instant" };
      }
      timeOut.notBefore = raw.time.notBefore;
      notBeforeMs = Date.parse(raw.time.notBefore);
    }
    if (raw.time.notAfter !== undefined) {
      if (
        typeof raw.time.notAfter !== "string" ||
        !Number.isFinite(Date.parse(raw.time.notAfter))
      ) {
        return { ok: false, error: "grant-policy: `time.notAfter` must be an ISO-8601 instant" };
      }
      timeOut.notAfter = raw.time.notAfter;
      notAfterMs = Date.parse(raw.time.notAfter);
    }
    if (notBeforeMs !== undefined && notAfterMs !== undefined && notBeforeMs >= notAfterMs) {
      return { ok: false, error: "grant-policy: `time.notBefore` must be before `time.notAfter`" };
    }
    if (raw.time.allowedWindowUtc !== undefined) {
      const w = raw.time.allowedWindowUtc;
      if (!isPlainObject(w)) {
        return { ok: false, error: "grant-policy: `time.allowedWindowUtc` must be an object" };
      }
      const wu = unknownKeys(w, ALLOWED_WINDOW_UTC_KEYS);
      if (wu.length > 0) {
        return {
          ok: false,
          error: `grant-policy: unknown time.allowedWindowUtc key(s): ${wu.join(", ")}`,
        };
      }
      if (!isMinuteOfDay(w.startMinuteUtc) || !isMinuteOfDay(w.endMinuteUtc)) {
        return {
          ok: false,
          error: "grant-policy: `time.allowedWindowUtc` minutes must be integers in 0..1439",
        };
      }
      if (w.startMinuteUtc === w.endMinuteUtc) {
        return {
          ok: false,
          error:
            "grant-policy: `time.allowedWindowUtc` start and end must differ (an empty/full window is ambiguous)",
        };
      }
      timeOut.allowedWindowUtc = { startMinuteUtc: w.startMinuteUtc, endMinuteUtc: w.endMinuteUtc };
    }
    if (
      timeOut.notBefore === undefined &&
      timeOut.notAfter === undefined &&
      timeOut.allowedWindowUtc === undefined
    ) {
      return { ok: false, error: "grant-policy: `time` must declare at least one bound" };
    }
    time = timeOut;
  }

  // approval
  let approval: GrantApprovalPolicy | undefined;
  if (raw.approval !== undefined) {
    if (!isPlainObject(raw.approval)) {
      return { ok: false, error: "grant-policy: `approval` must be an object" };
    }
    const u = unknownKeys(raw.approval, ALLOWED_APPROVAL_KEYS);
    if (u.length > 0) {
      return { ok: false, error: `grant-policy: unknown approval key(s): ${u.join(", ")}` };
    }
    if (raw.approval.always !== undefined && typeof raw.approval.always !== "boolean") {
      return { ok: false, error: "grant-policy: `approval.always` must be a boolean" };
    }
    approval = { always: raw.approval.always };
  }

  return {
    ok: true,
    policy: { version: GRANT_POLICY_VERSION, class: cls, rate, amount, venue, time, approval },
  };
}

/** The trailing-window counters a parsed policy requires the caller to fetch. */
export function grantPolicySignals(policy: GrantPolicyV1): GrantPolicySignals {
  return {
    rateWindowSeconds: policy.rate?.windowSeconds,
    amountWindowSeconds: policy.amount?.window?.windowSeconds,
  };
}

// ─── evaluate (pure, deterministic, deny-first) ──────────────────────────────

/** host allowlist entry match: exact, or `*.suffix` subdomain wildcard
 *  (mirrors the proxy's host matching; a bare `*.x` never matches `x` itself). */
function hostEntryMatches(entry: string, host: string): boolean {
  if (entry === host) return true;
  if (entry.startsWith("*.")) {
    const suffix = entry.slice(1); // ".example.com"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return false;
}

/** path prefix match on segment boundaries: `/a/b` matches `/a/b` and
 *  `/a/b/c`, never `/a/bc`. */
function pathPrefixMatches(prefix: string, path: string): boolean {
  if (prefix === path) return true;
  const p = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return path.startsWith(p);
}

function deny(rule: string, reason: string, amountMicros?: number): GrantPolicyVerdict {
  return { effect: "deny", rule, reason, amountMicros };
}

/**
 * Evaluate a PARSED grant policy against a single invoke. Pure + deterministic:
 * no clock reads, no I/O, never throws. Deny-first precedence:
 *
 *   venue -> time -> rate -> amount hard caps -> approval routing -> allow
 *
 * A deny can never be softened into an approval; approvals are only reachable
 * once every hard constraint has passed.
 */
export function evaluateGrantPolicy(
  policy: GrantPolicyV1,
  input: GrantPolicyInput,
): GrantPolicyVerdict {
  const cap = input.capability;

  // venue allowlists (narrowing only: the capability surface must be inside).
  if (policy.venue) {
    const host = cap.host.toLowerCase();
    if (policy.venue.hosts && !policy.venue.hosts.some((h) => hostEntryMatches(h, host))) {
      return deny("venue.host", `grant-policy: host "${host}" not in grant venue allowlist`);
    }
    const method = cap.method.toUpperCase();
    if (policy.venue.methods && !policy.venue.methods.includes(method)) {
      return deny("venue.method", `grant-policy: method "${method}" not in grant venue allowlist`);
    }
    if (
      policy.venue.pathPrefixes &&
      !policy.venue.pathPrefixes.some((p) => pathPrefixMatches(p, cap.path))
    ) {
      return deny("venue.path", "grant-policy: capability path not in grant venue allowlist");
    }
  }

  // time bounds.
  if (policy.time) {
    const nowMs = input.now.getTime();
    if (policy.time.notBefore !== undefined && nowMs < Date.parse(policy.time.notBefore)) {
      return deny("time.notBefore", "grant-policy: grant not usable yet (before notBefore)");
    }
    if (policy.time.notAfter !== undefined && nowMs > Date.parse(policy.time.notAfter)) {
      return deny("time.notAfter", "grant-policy: grant usage window has ended (after notAfter)");
    }
    if (policy.time.allowedWindowUtc) {
      const { startMinuteUtc, endMinuteUtc } = policy.time.allowedWindowUtc;
      const minute = input.now.getUTCHours() * 60 + input.now.getUTCMinutes();
      const inside =
        startMinuteUtc < endMinuteUtc
          ? minute >= startMinuteUtc && minute < endMinuteUtc
          : minute >= startMinuteUtc || minute < endMinuteUtc;
      if (!inside) {
        return deny("time.window", "grant-policy: outside the allowed time-of-day window");
      }
    }
  }

  // rate limit. A missing counter is a missing REQUIRED signal: deny (the
  // invoke layer must wire the count; a cap that cannot be checked cannot pass).
  if (policy.rate) {
    if (typeof input.invokesInWindow !== "number" || !Number.isFinite(input.invokesInWindow)) {
      return deny("rate.signal-missing", "grant-policy: invoke count unavailable for rate window");
    }
    if (input.invokesInWindow >= policy.rate.maxInvokes) {
      return deny(
        "rate.limit",
        `grant-policy: rate limit exceeded (${policy.rate.maxInvokes} per ${policy.rate.windowSeconds}s)`,
      );
    }
  }

  // amount limits. The declared arg must be a non-negative safe integer
  // (micros); anything else denies — value that cannot be read cannot be bounded.
  let amountMicros: number | undefined;
  if (policy.amount) {
    const rawAmount = input.args[policy.amount.argField];
    if (typeof rawAmount !== "number" || !Number.isSafeInteger(rawAmount) || rawAmount < 0) {
      return deny(
        "amount.arg",
        `grant-policy: invoke arg "${policy.amount.argField}" must be a non-negative integer (micros)`,
      );
    }
    amountMicros = rawAmount;
    if (
      policy.amount.perInvokeMaxMicros !== undefined &&
      amountMicros > policy.amount.perInvokeMaxMicros
    ) {
      return deny(
        "amount.perInvokeMax",
        `grant-policy: amount ${amountMicros} exceeds per-invoke cap ${policy.amount.perInvokeMaxMicros}`,
        amountMicros,
      );
    }
    if (policy.amount.window) {
      const sum = input.allowedAmountMicrosInWindow;
      if (typeof sum !== "number" || !Number.isFinite(sum)) {
        return deny(
          "amount.signal-missing",
          "grant-policy: rolling amount sum unavailable for window cap",
          amountMicros,
        );
      }
      if (sum + amountMicros > policy.amount.window.maxMicros) {
        return deny(
          "amount.windowMax",
          `grant-policy: rolling window cap exceeded (${sum} + ${amountMicros} > ${policy.amount.window.maxMicros})`,
          amountMicros,
        );
      }
    }
  }

  // approval routing (only reachable after every hard constraint passed).
  if (policy.approval?.always === true) {
    return {
      effect: "approval_required",
      rule: "approval.always",
      reason: "grant-policy: this grant requires human approval for every invoke",
      amountMicros,
    };
  }
  if (
    policy.amount?.approvalOverMicros !== undefined &&
    amountMicros !== undefined &&
    amountMicros > policy.amount.approvalOverMicros
  ) {
    return {
      effect: "approval_required",
      rule: "amount.approvalOver",
      reason: `grant-policy: amount ${amountMicros} over approval threshold ${policy.amount.approvalOverMicros}`,
      amountMicros,
    };
  }

  return {
    effect: "allow",
    rule: "allow",
    reason: "grant-policy: all grant constraints passed",
    amountMicros,
  };
}

/**
 * The verdict for a grant that carries NO policy document (NULL column — only
 * possible for rows written outside the migrated path). Strict mode fails
 * closed (deny); compatibility mode preserves pre-policy behavior explicitly.
 */
export function noPolicyVerdict(strict: boolean): GrantPolicyVerdict {
  return strict
    ? {
        effect: "deny",
        rule: "no-policy.strict",
        reason: "grant-policy: grant has no policy and strict mode is enabled",
      }
    : {
        effect: "allow",
        rule: "no-policy.permissive",
        reason: "grant-policy: grant has no policy (permissive compatibility mode)",
      };
}
