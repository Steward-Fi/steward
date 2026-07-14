/**
 * capability-intent.ts — the `capability-intent` contributed policy rule.
 *
 * WHAT THIS GATES
 * ---------------
 * a `capability-intent` rule governs whether an agent may INVOKE a named
 * capability (e.g. `github.pr.comment`) through Steward's capability layer. it
 * is the per-call-intent policy the credential plane leans on before delegating
 * to the proxy: the invoke route (W-1c) populates `ctx.capability` with the
 * capability name/args/host/path/method, and this rule decides allow / deny /
 * require-approval, plus argument- and rate-constraints.
 *
 * WHY IT LIVES HERE (policy-engine) BUT LOOKS LIKE A PLUGIN CONTRIBUTION
 * ---------------------------------------------------------------------
 * it is authored AS a {@link PolicyRuleContribution} — the exact shape a plugin
 * registers via the Phase-2b registry — so W-1a's capability plugin can register
 * it through the plugin host with ZERO rework. but the evaluator + config schema
 * + tests are a library export of `@stwd/policy-engine` (not a route, not a
 * package): W-1b ships the decision logic; the plugin package (W-1a) owns
 * registration; the invoke path (W-1c) owns wiring the context + the effective
 * default-deny (see the INVOKE-LAYER CONTRACT below).
 *
 * FAIL-CLOSED EVERYWHERE
 * ----------------------
 * this rule sits in front of live credentials (money-rail-adjacent), so every
 * ambiguity denies: a missing/mistyped config, a constrained arg that is absent,
 * an invalid regex in config, a rate cap without a count — all deny. the rule
 * NEVER throws (a throw would be caught by the registry as a deny, but we prefer
 * an explicit reason) and NEVER silently passes a governed action.
 *
 * APPLICABILITY (mirrors the typed-data pattern)
 * ----------------------------------------------
 *  - `ctx.capability` ABSENT  -> not a capability invoke -> PASS (this rule is
 *    inert on ordinary transaction signs; it cannot interfere with tx signing).
 *  - `ctx.capability` PRESENT but the capability NAME does not match this rule's
 *    `capabilities` list -> NOT APPLICABLE -> PASS. this rule only evaluates the
 *    capabilities it governs; whether an UNGOVERNED capability is allowed is the
 *    invoke layer's default-deny decision, NOT this rule's.
 *
 * INVOKE-LAYER CONTRACT (what W-1c must implement)
 * ------------------------------------------------
 * the engine composes all rules with all-must-pass semantics, and this rule
 * passes for any capability it does not name. that means "no rule allows this
 * capability" evaluates to PASS at the engine level. therefore the EFFECTIVE
 * DEFAULT-DENY must live in the INVOKE LAYER (W-1c):
 *   1. resolve the grant fail-closed; if no grant, deny before policy runs.
 *   2. after the engine's decision, REQUIRE that at least one `capability-intent`
 *      rule MATCHED the invoked capability with `effect: "allow"` (and passed).
 *      if the capability matched no allow rule, DENY — an invoke is permitted
 *      only when explicitly allowed, never by the absence of a deny.
 *   3. populate `ctx.capability` (name/args/host/path/method) AND
 *      `ctx.capabilityInvokeCount1h` (trailing-hour invoke count for this agent)
 *      so `maxCallsPerHour` can be enforced. absent count => this rule denies.
 *   4. audit every invoke + decision.
 */

import type {
  ContributedPolicyResult,
  ContributedPolicyRule,
  PolicyRuleContribution,
} from "@stwd/shared";
import type { EvaluatorContext } from "./evaluators";

/** the contributed rule-type discriminator. */
export const CAPABILITY_INTENT_RULE_TYPE = "capability-intent" as const;

/** The effect a matching `capability-intent` rule applies. */
export type CapabilityIntentEffect = "allow" | "deny" | "require-approval";

/** Constraints evaluated ONLY on an `effect: "allow"` match. */
export interface CapabilityIntentConstraints {
  /**
   * Max capability INVOKES per trailing hour. Evaluated against
   * `ctx.capabilityInvokeCount1h` (NOT the tx counter). If this is set but the
   * count is absent, the rule DENIES (fail closed) — the invoke layer (W-1c)
   * must wire the count.
   */
  readonly maxCallsPerHour?: number;
  /**
   * Every key must exist in `ctx.capability.args` and STRICTLY (===) equal the
   * configured string. A missing arg or a mismatch denies.
   */
  readonly argEquals?: Record<string, string>;
  /**
   * Every key must exist in `ctx.capability.args` and match the configured
   * regex (full-string, anchored). A missing arg, a non-string arg, or a
   * no-match denies. An INVALID regex in config denies (compiled defensively;
   * never throws).
   */
  readonly argMatches?: Record<string, string>;
}

/** The jsonb config of a `capability-intent` rule. */
export interface CapabilityIntentConfig {
  /**
   * Capability names this rule governs. Exact names (`github.pr.comment`) or a
   * SINGLE trailing-`.*` prefix glob (`github.*` matches `github.pr.comment`).
   * No general globbing. Case-sensitive.
   */
  readonly capabilities: string[];
  readonly effect: CapabilityIntentEffect;
  readonly constraints?: CapabilityIntentConstraints;
}

/**
 * Match a capability name against a single pattern.
 *   - trailing `.*` => prefix match on everything before the `.` (so `github.*`
 *     matches `github.pr.comment` and `github.x`, but NOT `github` itself and
 *     NOT `githubx.y`).
 *   - otherwise exact, case-sensitive.
 */
function patternMatches(pattern: string, name: string): boolean {
  if (typeof pattern !== "string" || pattern.length === 0) return false;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -1); // keep the trailing "." e.g. "github."
    return name.startsWith(prefix);
  }
  return pattern === name;
}

/** True when any configured pattern matches the invoked capability name. */
function capabilityMatches(config: CapabilityIntentConfig, name: string): boolean {
  return config.capabilities.some((pattern) => patternMatches(pattern, name));
}

/**
 * Recover ONLY the capability SELECTOR (the `capabilities` patterns) from an
 * otherwise-malformed rule config, WITHOUT validating the rest of the config.
 *
 * WHY THIS EXISTS (scope isolation, master-plan §5.3 / §"malformed-input
 * precedence applies to GOVERNING rules"):
 *   malformed-input precedence must apply to the rules that GOVERN the requested
 *   capability. A rule whose selector is well-formed and demonstrably scoped to a
 *   DIFFERENT capability must not brick an unrelated invoke just because some
 *   OTHER part of its config (effect, constraints) is malformed — it is not a
 *   governing rule for this request, so it is inert.
 *
 * RECOVERABILITY CONTRACT (fail closed on ambiguous scope):
 *   - `{ recoverable: true, matches }` when the `capabilities` selector is
 *     unambiguously well-formed: a non-empty array of non-empty strings whose
 *     glob usage is legal (same rule as `parseConfig`'s `badPattern` check). We
 *     can then say for certain whether it governs THIS capability (`matches`).
 *   - `{ recoverable: false }` when the selector itself cannot be trusted to
 *     determine scope (missing / not an array / empty / a non-string or empty
 *     entry / an illegal glob). We CANNOT rule out that this rule was meant to
 *     govern the requested capability, so the caller must treat it as
 *     potentially governing and hard-deny (never assume it is inert).
 *
 * This deliberately mirrors the selector-shaped checks in `parseConfig` so a
 * selector that would be REJECTED there is also "unrecoverable" here.
 */
function recoverSelectorMatch(
  rawInput: unknown,
  name: string,
): { recoverable: true; matches: boolean } | { recoverable: false } {
  if (typeof rawInput !== "object" || rawInput === null || Array.isArray(rawInput)) {
    return { recoverable: false };
  }
  const capabilities = (rawInput as Record<string, unknown>).capabilities;
  if (
    !Array.isArray(capabilities) ||
    capabilities.length === 0 ||
    !capabilities.every((c) => typeof c === "string" && c.length > 0)
  ) {
    return { recoverable: false };
  }
  // An illegal glob makes the selector's intended scope ambiguous (a bad pattern
  // can never match, so treating it as "non-governing" would be exactly the
  // silent-drop failure `parseConfig`'s badPattern check guards against). Fail
  // closed: unrecoverable.
  const badPattern = (capabilities as string[]).find(
    (p) => p.includes("*") && !(p.endsWith(".*") && !p.slice(0, -2).includes("*")),
  );
  if (badPattern !== undefined) {
    return { recoverable: false };
  }
  const matches = (capabilities as string[]).some((pattern) => patternMatches(pattern, name));
  return { recoverable: true, matches };
}

/**
 * Validate the (opaque) rule config into a typed shape, or return an error
 * reason. FAIL CLOSED: anything malformed is rejected (the caller denies).
 */
const ALLOWED_CONFIG_KEYS: ReadonlySet<string> = new Set(["capabilities", "effect", "constraints"]);
const ALLOWED_CONSTRAINT_KEYS: ReadonlySet<string> = new Set([
  "maxCallsPerHour",
  "argEquals",
  "argMatches",
]);

function parseConfig(rawInput: unknown): CapabilityIntentConfig | { error: string } {
  // FAIL CLOSED on a non-object config. `rule.config` is opaque jsonb and can be
  // null / a string / a number / an array at runtime (untyped storage, bad
  // migration, hand-edited row). `Object.keys(null)` (and friends) THROW, which
  // — before this guard — surfaced as an unhandled TypeError => HTTP 500 instead
  // of a decision. A 500 is worse than a deny for a money-rail gate: it is
  // ambiguous and can be retried into a race. Treat any non-plain-object config
  // as malformed => the caller hard-denies (never throws). Arrays are rejected
  // too: a JSON array is not a valid rule config shape.
  if (typeof rawInput !== "object" || rawInput === null || Array.isArray(rawInput)) {
    return {
      error: `capability-intent: config must be a non-null object (got ${
        rawInput === null ? "null" : Array.isArray(rawInput) ? "array" : typeof rawInput
      })`,
    };
  }
  const raw = rawInput as Record<string, unknown>;

  // FAIL CLOSED on unknown top-level keys: a misspelled key (e.g. `capabilties`
  // or `effects`) must never be silently ignored, since that could drop the
  // intended gate and let an action through unconstrained.
  const unknownTop = Object.keys(raw).filter((k) => !ALLOWED_CONFIG_KEYS.has(k));
  if (unknownTop.length > 0) {
    return { error: `capability-intent: unknown config key(s): ${unknownTop.join(", ")}` };
  }

  const capabilities = raw.capabilities;
  if (
    !Array.isArray(capabilities) ||
    capabilities.length === 0 ||
    !capabilities.every((c) => typeof c === "string" && c.length > 0)
  ) {
    return { error: "capability-intent: `capabilities` must be a non-empty string[]" };
  }

  // FAIL CLOSED on malformed patterns: `*` is supported ONLY as a single
  // trailing `.*` prefix glob (e.g. `github.*`). Any other `*` usage (e.g.
  // `github.*.delete`, `*.delete`, `git*hub`) would be treated by
  // `patternMatches` as an exact literal that can never match, silently making
  // a deny/require-approval rule inert. Reject it at parse so the misconfig
  // denies instead of passing (codex P2).
  const badPattern = (capabilities as string[]).find(
    (p) => p.includes("*") && !(p.endsWith(".*") && !p.slice(0, -2).includes("*")),
  );
  if (badPattern !== undefined) {
    return {
      error: `capability-intent: unsupported glob "${badPattern}" (\`*\` allowed only as a single trailing ".*")`,
    };
  }

  const effect = raw.effect;
  if (effect !== "allow" && effect !== "deny" && effect !== "require-approval") {
    return {
      error: `capability-intent: \`effect\` must be "allow" | "deny" | "require-approval" (got ${String(
        effect,
      )})`,
    };
  }

  let constraints: CapabilityIntentConstraints | undefined;
  if (raw.constraints !== undefined) {
    if (typeof raw.constraints !== "object" || raw.constraints === null) {
      return { error: "capability-intent: `constraints` must be an object when present" };
    }
    const c = raw.constraints as Record<string, unknown>;

    // FAIL CLOSED on unknown constraint keys: a typo like `maxCallPerHour` must
    // deny, not silently drop the rate cap on an `allow` rule (codex P2).
    const unknownConstraint = Object.keys(c).filter((k) => !ALLOWED_CONSTRAINT_KEYS.has(k));
    if (unknownConstraint.length > 0) {
      return {
        error: `capability-intent: unknown constraint key(s): ${unknownConstraint.join(", ")}`,
      };
    }

    if (c.maxCallsPerHour !== undefined) {
      if (
        typeof c.maxCallsPerHour !== "number" ||
        !Number.isFinite(c.maxCallsPerHour) ||
        c.maxCallsPerHour < 0 ||
        !Number.isInteger(c.maxCallsPerHour)
      ) {
        return {
          error: "capability-intent: `constraints.maxCallsPerHour` must be a non-negative integer",
        };
      }
    }

    if (c.argEquals !== undefined && !isStringRecord(c.argEquals)) {
      return { error: "capability-intent: `constraints.argEquals` must be Record<string,string>" };
    }
    if (c.argMatches !== undefined && !isStringRecord(c.argMatches)) {
      return { error: "capability-intent: `constraints.argMatches` must be Record<string,string>" };
    }

    constraints = {
      ...(c.maxCallsPerHour !== undefined ? { maxCallsPerHour: c.maxCallsPerHour as number } : {}),
      ...(c.argEquals !== undefined ? { argEquals: c.argEquals as Record<string, string> } : {}),
      ...(c.argMatches !== undefined ? { argMatches: c.argMatches as Record<string, string> } : {}),
    };
  }

  return {
    capabilities: capabilities as string[],
    effect,
    ...(constraints !== undefined ? { constraints } : {}),
  };
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  return Object.values(value).every((v) => typeof v === "string");
}

/**
 * Evaluate the constraints on an `effect: "allow"` match. Returns a deny result
 * on the FIRST failed constraint, or `null` when every constraint holds.
 */
function evaluateConstraints(
  base: { policyId: string; type: string },
  constraints: CapabilityIntentConstraints,
  capability: NonNullable<EvaluatorContext["capability"]>,
  ctx: EvaluatorContext,
): ContributedPolicyResult | null {
  const { args } = capability;

  // argEquals: every key must exist and strictly equal the configured string.
  if (constraints.argEquals) {
    for (const [key, expected] of Object.entries(constraints.argEquals)) {
      if (!Object.hasOwn(args, key)) {
        return {
          ...base,
          passed: false,
          reason: `capability-intent: required arg "${key}" is absent`,
        };
      }
      if (args[key] !== expected) {
        return {
          ...base,
          passed: false,
          reason: `capability-intent: arg "${key}" must equal "${expected}"`,
        };
      }
    }
  }

  // argMatches: every key must exist, be a string, and match the (defensively
  // compiled) regex. Invalid regex in config => deny (never throw).
  if (constraints.argMatches) {
    for (const [key, pattern] of Object.entries(constraints.argMatches)) {
      let re: RegExp;
      try {
        // anchor full-string so a partial match can't slip a governed arg.
        re = new RegExp(`^(?:${pattern})$`);
      } catch {
        return {
          ...base,
          passed: false,
          reason: `capability-intent: invalid regex for arg "${key}" in config`,
        };
      }
      if (!Object.hasOwn(args, key)) {
        return {
          ...base,
          passed: false,
          reason: `capability-intent: required arg "${key}" is absent`,
        };
      }
      const value = args[key];
      if (typeof value !== "string" || !re.test(value)) {
        return {
          ...base,
          passed: false,
          reason: `capability-intent: arg "${key}" does not match required pattern`,
        };
      }
    }
  }

  // maxCallsPerHour: evaluate against the capability-invoke counter. Absent
  // count => DENY (fail closed): we never borrow the tx counter and never
  // silently pass a rate cap.
  if (constraints.maxCallsPerHour !== undefined) {
    const count = ctx.capabilityInvokeCount1h;
    if (typeof count !== "number" || !Number.isFinite(count)) {
      return {
        ...base,
        passed: false,
        reason:
          "capability-intent: maxCallsPerHour set but capabilityInvokeCount1h is absent (invoke count not wired)",
      };
    }
    if (count >= constraints.maxCallsPerHour) {
      return {
        ...base,
        passed: false,
        reason: `capability-intent: hourly invoke cap reached (${constraints.maxCallsPerHour})`,
      };
    }
  }

  return null;
}

/**
 * The `capability-intent` evaluator. See the file header for the full semantics.
 */
export function evaluateCapabilityIntent(
  rule: ContributedPolicyRule,
  ctx: EvaluatorContext,
): ContributedPolicyResult {
  const base = { policyId: rule.id, type: rule.type };

  // 1. Not a capability invoke -> inert (cannot interfere with tx signing).
  if (!ctx.capability) {
    return { ...base, passed: true, reason: "not a capability invoke" };
  }

  // 2. Config must be well-formed (fail closed).
  const parsed = parseConfig(rule.config);
  if ("error" in parsed) {
    return { ...base, passed: false, reason: parsed.error };
  }

  const { name } = ctx.capability;

  // 3. This rule only governs the capabilities it names. A non-match is NOT
  //    APPLICABLE -> pass (the invoke layer's default-deny handles ungoverned
  //    capabilities; a plain "no matching allow" is NOT this rule's job to deny).
  if (!capabilityMatches(parsed, name)) {
    return { ...base, passed: true, reason: `capability "${name}" not governed by this rule` };
  }

  // 4. Matched. Apply the effect.
  switch (parsed.effect) {
    case "deny":
      return {
        ...base,
        passed: false,
        reason: `capability-intent: capability "${name}" is denied by policy`,
      };
    case "require-approval":
      return {
        ...base,
        passed: false,
        // the engine honours this via ManualApprovalSignal (see manual-approval.ts):
        // a non-passing result carrying requiresManualApproval routes to the queue.
        requiresManualApproval: true,
        reason: `capability-intent: capability "${name}" requires manual approval`,
      } as ContributedPolicyResult;
    case "allow": {
      if (parsed.constraints) {
        const denial = evaluateConstraints(base, parsed.constraints, ctx.capability, ctx);
        if (denial) return denial;
      }
      return {
        ...base,
        passed: true,
        reason: `capability-intent: capability "${name}" allowed`,
      };
    }
  }
}

/**
 * The composed decision over a set of `capability-intent` rules that GOVERN a
 * single invoked capability, in the canonical precedence order.
 *
 * CANONICAL COMPOSITION (master-plan §5.3 / PR2 canonicalization spec §6.3):
 *   1. a malformed/unknown rule config that GOVERNS this capability, or whose
 *      SELECTOR is unrecoverable (ambiguous scope), or an unavailable policy
 *      input => HARD DENY
 *   2. any matching hard deny (an `effect: "deny"` match, OR an `effect: "allow"`
 *      match that FAILS a hard constraint, OR a thrown evaluator error) => HARD
 *      DENY
 *   3. else any matching `require-approval` => APPROVAL REQUIRED
 *   4. else any matching passing `allow` => ALLOW
 *   5. else (no governing rule matched/passed) => HARD DENY / no governing allow
 *
 * MALFORMED-INPUT PRECEDENCE IS SCOPED TO GOVERNING RULES (master-plan §5.3).
 * A malformed rule config does NOT automatically brick every invoke: if the
 * rule's `capabilities` SELECTOR is well-formed and provably scoped to a
 * DIFFERENT capability, the rule is not governing this request and stays inert
 * even though the rest of its config is broken. Only a malformed rule that (a)
 * governs THIS capability, or (b) has an UNRECOVERABLE selector (so its scope
 * cannot be determined) => HARD DENY. Ambiguous scope fails closed.
 *
 * This is the single source of truth for capability-intent precedence. It FIXES
 * the prior invoke-layer bug where a passing allow could short-circuit an
 * applicable require-approval (allow-over-approval). A malformed governing
 * config, a failed hard constraint, or a thrown evaluator error can NEVER be
 * softened into an approval, and can never surface as a 500.
 *
 * The caller supplies ONLY the rules that already govern the invoked capability
 * (i.e. their `capabilities` list matches the name). Passing non-governing rules
 * is harmless — they evaluate as "not applicable" (pass) and are ignored — but
 * the effective default-deny (outcome 5) is defined over the GOVERNING set, so
 * the caller must not filter out governing rules before composing.
 */
export type CapabilityIntentCompositionEffect = "hard_deny" | "approval_required" | "allow";

export interface CapabilityIntentCompositionResult {
  readonly effect: CapabilityIntentCompositionEffect;
  readonly reason: string;
}

export function composeCapabilityIntentDecision(
  rules: readonly ContributedPolicyRule[],
  ctx: EvaluatorContext,
): CapabilityIntentCompositionResult {
  // Not a capability invoke at all: nothing to compose. Fail closed — the invoke
  // layer must only call this on an actual capability invoke with ctx.capability.
  if (!ctx.capability) {
    return { effect: "hard_deny", reason: "capability-intent: not a capability invoke" };
  }
  const { name } = ctx.capability;

  let approvalReason: string | undefined;
  let allowReason: string | undefined;

  for (const rule of rules) {
    // A DISABLED rule is inert, matching `evaluatePolicy`/`PolicyEngine`
    // semantics (any FALSY `enabled` => skipped, mirroring the generic engine's
    // `!rule.enabled` check — `false`, `undefined`, `null`, `0`, `""` all mean
    // "off"). Disabling a policy must reliably turn it off for every caller of
    // this exported helper — a disabled deny/require-approval (or even a disabled
    // malformed) rule must NOT block, queue, or hard-deny. We skip it BEFORE
    // parsing so a disabled-but-malformed rule cannot fail the composition closed
    // either.
    if (!rule.enabled) continue;

    // Evaluate this rule defensively. The whole per-rule body — parse, selector
    // recovery, and evaluation — is wrapped so that NOTHING it does can throw out
    // of the helper. A thrown error (a hostile jsonb getter, an evaluator bug,
    // anything) is treated exactly like a malformed config: fail closed on the
    // GOVERNING scope, never a 500, never an approval. `result === null` means
    // the rule was inert (non-governing / provably scoped elsewhere) and
    // contributes nothing.
    let result: ContributedPolicyResult | null;
    try {
      // Parse the config. A malformed/unknown config CANNOT simply hard-deny
      // every invoke: malformed-input precedence applies to GOVERNING rules only
      // (master-plan §5.3). A rule scoped (by a well-formed selector) to a
      // DIFFERENT capability is not governing this request and must stay inert
      // even if the rest of its config is broken. But if the selector itself is
      // unrecoverable, we cannot prove the rule is non-governing, so fail closed.
      const parsed = parseConfig(rule.config);
      if ("error" in parsed) {
        // Separate SELECTOR recovery from full-config validation.
        const sel = recoverSelectorMatch(rule.config, name);
        if (sel.recoverable && !sel.matches) {
          // Well-formed selector, provably scoped elsewhere => inert. The
          // malformed remainder cannot affect a capability this rule doesn't
          // govern.
          continue;
        }
        // Either the selector matches THIS capability (malformed governing rule)
        // or the selector is unrecoverable (ambiguous scope). Both HARD DENY and
        // short-circuit — a broken governing gate must never be silently dropped
        // and must never be softened into an approval.
        return { effect: "hard_deny", reason: parsed.error };
      }

      // Only rules that govern THIS capability contribute. A non-match is inert.
      if (!capabilityMatches(parsed, name)) {
        result = null;
      } else {
        result = evaluateCapabilityIntent(
          { id: rule.id, type: rule.type, enabled: rule.enabled, config: rule.config },
          ctx,
        );
      }
    } catch (err) {
      // A throw anywhere in the per-rule body. Scope it: if the selector is
      // recoverable and demonstrably elsewhere, the throw touched a non-governing
      // rule and is inert. Otherwise fail closed on the governing/ambiguous rule.
      let scopedElsewhere = false;
      try {
        const sel = recoverSelectorMatch(rule.config, name);
        scopedElsewhere = sel.recoverable && !sel.matches;
      } catch {
        scopedElsewhere = false;
      }
      if (scopedElsewhere) continue;
      return {
        effect: "hard_deny",
        reason: `capability-intent: evaluator error for capability "${name}" (${
          err instanceof Error ? err.message : String(err)
        })`,
      };
    }

    // Inert rule (non-governing / scoped elsewhere): contributes nothing.
    if (result === null) continue;

    // A matching require-approval fails without passing and carries the flag.
    if (result.requiresManualApproval === true && result.passed === false) {
      // Remember it, but keep scanning: a later hard deny must still win.
      if (approvalReason === undefined) {
        approvalReason =
          result.reason ?? `capability-intent: capability "${name}" requires manual approval`;
      }
      continue;
    }

    // A matching rule that did NOT pass and is NOT an approval is a HARD DENY.
    // This covers both an `effect: "deny"` match and an `effect: "allow"` match
    // that failed a hard constraint (arg/regex/rate). Deny wins immediately.
    if (result.passed === false) {
      return {
        effect: "hard_deny",
        reason: result.reason ?? `capability-intent: capability "${name}" denied by policy`,
      };
    }

    // A matching passing allow. Record it, but do NOT return yet: an approval or
    // a hard deny from another governing rule must be able to override it.
    if (allowReason === undefined) {
      allowReason = result.reason ?? `capability-intent: capability "${name}" allowed`;
    }
  }

  // No hard deny was seen. Approval outranks allow.
  if (approvalReason !== undefined) {
    return { effect: "approval_required", reason: approvalReason };
  }
  if (allowReason !== undefined) {
    return { effect: "allow", reason: allowReason };
  }

  // No governing rule matched with a passing allow => effective default-deny.
  return {
    effect: "hard_deny",
    reason: `capability-intent: no policy authorizes capability "${name}"`,
  };
}

/**
 * The `capability-intent` rule as a {@link PolicyRuleContribution}, ready for the
 * W-1a plugin to register via the plugin host with zero rework. Bound to the
 * policy engine's {@link EvaluatorContext}.
 */
export const capabilityIntentContribution: PolicyRuleContribution<EvaluatorContext> = {
  type: CAPABILITY_INTENT_RULE_TYPE,
  description:
    "gate a named capability invoke: allow / deny / require-approval + arg and hourly-invoke constraints (fail-closed)",
  evaluate: evaluateCapabilityIntent,
};
