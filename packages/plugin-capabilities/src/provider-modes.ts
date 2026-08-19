/**
 * provider-modes.ts — the PROVIDER-MODES registry + manifest-identifier grammar.
 *
 * A per-agent capability MANIFEST is a declarative list of abstract capability
 * identifiers of the form:
 *
 *     provider:kind[:agent]
 *
 * e.g. `discord:bot-token:soliza`, `github:app:0xSolace`, `llm:pool-seat`,
 *      `wallet:sign`.
 *
 * When an agent requests a manifest capability, Steward answers in one of two
 * MODES:
 *
 *   • token mode  — Steward returns a SHORT-LIVED, SCOPED token the agent uses
 *                   directly against the provider (or against Steward's own
 *                   scoped surface). Only honest when the provider's tokens can
 *                   actually be down-scoped/short-lived.
 *
 *   • broker mode — Steward performs the upstream call ON BEHALF of the agent
 *                   (the credential never leaves the enclave). This is the honest
 *                   default whenever a provider's long-lived secret CANNOT be
 *                   down-scoped. Discord bot tokens are the canonical example:
 *                   Discord has no mechanism to mint a narrower, short-lived bot
 *                   token, so handing the raw token to an agent would defeat the
 *                   whole point — broker mode keeps it in the enclave and the
 *                   agent only ever gets a brokered result.
 *
 * This file is the SINGLE SOURCE OF TRUTH for which mode a provider uses. It is
 * pure (no db, no io) so it is trivially unit-testable and can be shared by the
 * client SDK (A3) and docs generation.
 *
 * Broker mode reuses the ALREADY-SHIPPED capability invoke path (invoke.ts /
 * @stwd/proxy-client): the credential is injected by the defended proxy and the
 * agent receives only the scrubbed upstream response. We do NOT build a parallel
 * broker; the manifest layer maps a manifest entry to a broker-mode capability
 * invocation.
 */

/** The two honest issuance modes. */
export type CapabilityMode = "token" | "broker";

/** A parsed manifest identifier. `agent` is optional (a manifest entry may be
 * agent-scoped in its name, or agent-implicit from the caller's identity). */
export interface ManifestIdentifier {
  provider: string;
  kind: string;
  agent?: string;
  /** the raw identifier as written, lower-cased/normalized. */
  raw: string;
}

/** Registry entry describing a provider's default issuance mode + rationale. */
export interface ProviderModeEntry {
  provider: string;
  mode: CapabilityMode;
  /** human-readable justification (drives the PROVIDER-MODES doc table). */
  rationale: string;
}

/**
 * THE PROVIDER-MODES TABLE.
 *
 * Ordered, explicit, and the source of the doc table. Adding a provider here is
 * a deliberate, reviewable act. Anything NOT listed defaults to broker mode
 * (fail-safe: never assume a provider's secret can be down-scoped).
 */
export const PROVIDER_MODES: readonly ProviderModeEntry[] = [
  {
    provider: "discord",
    mode: "broker",
    rationale:
      "Discord bot tokens cannot be down-scoped or short-lived by Discord; handing the raw " +
      "token to an agent would leak a long-lived credential. Steward brokers the call so the " +
      "token never leaves the enclave.",
  },
  {
    provider: "github",
    mode: "token",
    rationale:
      "GitHub App installation tokens are natively short-lived (≈1h) and scopable per " +
      "installation/permission; Steward can mint a scoped installation token in token mode. " +
      "(A raw PAT-backed github provider would instead be broker mode.)",
  },
  {
    provider: "llm",
    mode: "broker",
    rationale:
      "A shared LLM pool seat is a long-lived provider API key that cannot be down-scoped per " +
      "agent; Steward brokers completions through the credential-injection proxy so the key " +
      "stays in the enclave (spend/rate policy enforced server-side).",
  },
  {
    provider: "wallet",
    mode: "broker",
    rationale:
      "Signing authority must never leave custody. The agent requests a signature; Steward " +
      "(vault or threshold signer) performs it and returns only the signature. " +
      "There is no 'scoped short-lived private key' to hand out.",
  },
  {
    provider: "openai",
    mode: "broker",
    rationale:
      "OpenAI API keys are long-lived and not per-call scopable; brokered through the existing " +
      "OpenAI-compatible capability adapter so the key stays server-side.",
  },
  {
    provider: "stripe",
    mode: "broker",
    rationale:
      "Stripe secret keys are long-lived and highly sensitive; restricted keys still cannot be " +
      "minted short-lived per-agent on demand, so Steward brokers the call.",
  },
] as const;

/** Fast lookup index over the registry (lower-cased provider → entry). */
const PROVIDER_INDEX: ReadonlyMap<string, ProviderModeEntry> = new Map(
  PROVIDER_MODES.map((e) => [e.provider.toLowerCase(), e]),
);

/**
 * Resolve the issuance mode for a provider. Unknown providers default to BROKER
 * (fail-safe: never hand out a token for a provider we have not deliberately
 * classified as token-safe).
 */
export function resolveProviderMode(provider: string): CapabilityMode {
  const entry = PROVIDER_INDEX.get(provider.trim().toLowerCase());
  return entry ? entry.mode : "broker";
}

/** Full registry entry for a provider (or a synthetic broker default). */
export function providerModeEntry(provider: string): ProviderModeEntry {
  const key = provider.trim().toLowerCase();
  return (
    PROVIDER_INDEX.get(key) ?? {
      provider: key,
      mode: "broker",
      rationale:
        "Unclassified provider: defaults to broker mode (fail-safe — a token is never issued " +
        "for a provider not explicitly registered as token-safe).",
    }
  );
}

/** Validation bounds for identifier segments (defensive, keeps names sane). */
const SEGMENT_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/**
 * Parse a manifest identifier `provider:kind[:agent]`. Returns null on any
 * malformed input (wrong arity, illegal chars) — fail closed. Normalizes to
 * lower-case so `Discord:Bot-Token` and `discord:bot-token` are the same entry.
 */
export function parseManifestIdentifier(raw: string): ManifestIdentifier | null {
  if (typeof raw !== "string") return null;
  const normalized = raw.trim().toLowerCase();
  if (!normalized) return null;
  const parts = normalized.split(":");
  if (parts.length < 2 || parts.length > 3) return null;
  const [provider, kind, agent] = parts;
  if (!SEGMENT_RE.test(provider) || !SEGMENT_RE.test(kind)) return null;
  if (agent !== undefined && !SEGMENT_RE.test(agent)) return null;
  return {
    provider,
    kind,
    ...(agent !== undefined ? { agent } : {}),
    raw: agent !== undefined ? `${provider}:${kind}:${agent}` : `${provider}:${kind}`,
  };
}

/** Reconstruct the canonical identifier string from parts. */
export function formatManifestIdentifier(id: {
  provider: string;
  kind: string;
  agent?: string;
}): string {
  const base = `${id.provider.toLowerCase()}:${id.kind.toLowerCase()}`;
  return id.agent ? `${base}:${id.agent.toLowerCase()}` : base;
}
