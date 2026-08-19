/**
 * Capability issuance, renewal, and revocation core.
 *
 * This is the token/broker issuance layer that sits ON TOP of the already-shipped
 * capability plumbing (capabilities + grants + the proxy-broker invoke path). It
 * does NOT re-implement credential injection, policy evaluation, or the grant
 * lifecycle — it maps a per-agent MANIFEST entry to an issuance decision:
 *
 *   • token mode  → is handled by upstream-leases.ts. This module must never
 *                   substitute a Steward JWT for a provider credential.
 *   • broker mode → return a DELEGATION descriptor telling the agent to invoke
 *                   through Steward's existing broker endpoint
 *                   (POST /capabilities/:name/invoke); the credential never
 *                   leaves the enclave.
 *
 * RENEWAL: tokens are deliberately short-lived (minutes). The agent re-requests
 * (renew == issue again); each renewal re-checks the live manifest, so a
 * revocation (policy/grant edit) takes effect at the NEXT renewal — bounded by
 * the configured short TTL.
 *
 * REVOCATION: there is no token-revocation call here by design — short TTL +
 * re-check-on-renew IS the revocation mechanism (an operator disables the
 * capability or revokes the grant via the existing CRUD routes; the next renewal
 * sees no usable grant and denies). For the rare "kill it NOW" case, the existing
 * JWT revocation store (@stwd/auth revocationStore, jti-based) remains available;
 * we surface the minted jti so a caller can revoke it if needed.
 *
 * AUDIT: every enroll/issue/renew/revoke/exercise emits a structured event
 * through the injected `emitAudit` sink. This file defines the event shape and emits it; it does not
 * own the sink.
 */

import { resolveProviderMode } from "./provider-modes";
import type { Capability, CapabilityGrant } from "./schema";

/** Default short TTL for an issued token, in seconds. Minute-scale so a
 * revocation lands within one renewal cycle (Pillar-A <5min green criterion). */
export const DEFAULT_ISSUE_TTL_SECONDS = 120;
/** Hard ceiling on a requested TTL (an agent cannot ask for a long-lived token). */
export const MAX_ISSUE_TTL_SECONDS = 300;

/** The audit events this layer emits. `exercise` is emitted by the broker invoke
 * path (invoke.ts already records invocations; this is the higher-level audit
 * mirror). */
export type CapabilityAuditAction =
  | "capability.enroll"
  | "capability.issue"
  | "capability.renew"
  | "capability.revoke"
  | "capability.exercise";

/** Structured audit event. Deliberately free of secret material — identifiers,
 * mode, decision, and timing only. Lane E1 consumes this shape. */
export interface CapabilityAuditEvent {
  action: CapabilityAuditAction;
  tenantId: string;
  agentId: string;
  /** the manifest identifier, e.g. "discord:bot-token:soliza". */
  manifest: string;
  /** resolved capability id, when one was resolved. */
  capabilityId?: string | null;
  /** issuance mode chosen. */
  mode?: "token" | "broker";
  /** allow / deny. */
  decision: "allow" | "deny";
  /** deny reason (never leaks internals). */
  reason?: string;
  /** minted token jti (token mode allow only), so it can be revoked out-of-band. */
  jti?: string;
  /** issued-token TTL seconds (token mode allow only). */
  ttlSeconds?: number;
  /** event time, epoch ms. */
  at: number;
}

/** The audit sink contract. Non-throwing by contract; a sink failure must never
 * block a fail-closed decision (callers wrap it). */
export type CapabilityAuditSink = (event: CapabilityAuditEvent) => Promise<void> | void;

/** Token-minting contract (injected — the plugin passes @stwd/auth's
 * signAgentToken). Returns the compact JWT. */
export type ShortLivedTokenMinter = (args: {
  agentId: string;
  tenantId: string;
  scopes: string[];
  ttlSeconds: number;
}) => Promise<{ token: string; jti: string }>;

/** A resolved manifest entry: the abstract identifier + the underlying capability
 * grant it maps to. Produced by the manifest resolver (manifest.ts). */
export interface ResolvedManifestEntry {
  manifest: string;
  provider: string;
  capability: Capability;
  grant: CapabilityGrant;
}

/** The result of an issuance request. */
export type IssuanceResult =
  | {
      ok: true;
      mode: "token";
      /** the short-lived scoped token. */
      token: string;
      jti: string;
      ttlSeconds: number;
      /** the scopes the token carries (audit + client). */
      scopes: string[];
      manifest: string;
      capabilityId: string;
    }
  | {
      ok: true;
      mode: "broker";
      /** how the agent exercises this capability (no token — Steward brokers). */
      delegation: {
        /** the capability name to invoke via POST /capabilities/:name/invoke. */
        capabilityName: string;
        method: string;
        note: string;
      };
      manifest: string;
      capabilityId: string;
    }
  | { ok: false; error: string; code: IssuanceDenyCode };

export type IssuanceDenyCode =
  | "invalid_manifest"
  | "not_granted"
  | "ttl_out_of_range"
  | "mint_failed"
  | "upstream_issuer_required";

/** Clamp a requested TTL into the honest short-lived range. */
export function clampTtlSeconds(requested: number | undefined): number | null {
  if (requested === undefined) return DEFAULT_ISSUE_TTL_SECONDS;
  if (!Number.isFinite(requested) || requested <= 0) return null;
  const floored = Math.floor(requested);
  if (floored > MAX_ISSUE_TTL_SECONDS) return null;
  return floored;
}

/** The scope string a token-mode capability token carries. Namespaced by the
 * manifest identifier so a minted token authorizes EXACTLY this capability and
 * nothing else (least privilege). */
export function capabilityTokenScope(manifest: string): string {
  return `cap:${manifest}`;
}

/**
 * Issue (or renew — same operation) a manifest capability for an already-
 * authenticated agent. The resolver has ALREADY proven the agent holds a live,
 * usable grant for this manifest entry (so revocation is enforced by the resolver
 * returning nothing → `not_granted`). This function chooses the mode and either
 * mints a short-lived scoped token or returns a broker delegation, emitting the
 * audit event for the outcome.
 *
 * `isRenewal` only changes the audit action (`renew` vs `issue`); the security
 * path is identical — every renewal is a fresh, fully-checked issuance.
 */
export async function issueCapability(args: {
  tenantId: string;
  agentId: string;
  manifest: string;
  resolved: ResolvedManifestEntry | null;
  ttlSeconds?: number;
  isRenewal?: boolean;
  mintToken: ShortLivedTokenMinter;
  emitAudit: CapabilityAuditSink;
  now?: number;
}): Promise<IssuanceResult> {
  const at = args.now ?? Date.now();
  const action: CapabilityAuditAction = args.isRenewal ? "capability.renew" : "capability.issue";

  const audit = async (ev: Omit<CapabilityAuditEvent, "action" | "at">): Promise<void> => {
    try {
      await args.emitAudit({ action, at, ...ev });
    } catch {
      // audit sink failure must never change the decision.
    }
  };

  if (!args.resolved) {
    await audit({
      tenantId: args.tenantId,
      agentId: args.agentId,
      manifest: args.manifest,
      decision: "deny",
      reason: "capability not granted to agent",
    });
    return { ok: false, error: "capability not granted to agent", code: "not_granted" };
  }

  const { capability, provider } = args.resolved;
  const mode = resolveProviderMode(provider);

  if (mode === "broker") {
    await audit({
      tenantId: args.tenantId,
      agentId: args.agentId,
      manifest: args.manifest,
      capabilityId: capability.id,
      mode: "broker",
      decision: "allow",
    });
    return {
      ok: true,
      mode: "broker",
      delegation: {
        capabilityName: capability.name,
        method: capability.method,
        note:
          "broker mode: the credential stays in Steward. Exercise via " +
          `POST /capabilities/${capability.name}/invoke with your agent token.`,
      },
      manifest: args.manifest,
      capabilityId: capability.id,
    };
  }

  // A Steward JWT is not a GitHub credential. The real token-mode route is the
  // durable upstream lease path; fail closed if this generic helper is called.
  await audit({
    tenantId: args.tenantId,
    agentId: args.agentId,
    manifest: args.manifest,
    capabilityId: capability.id,
    mode: "token",
    decision: "deny",
    reason: "upstream issuer required",
  });
  return {
    ok: false,
    error: "provider token mode requires a configured upstream issuer",
    code: "upstream_issuer_required",
  };
}
