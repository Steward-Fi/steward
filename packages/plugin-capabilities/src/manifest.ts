/**
 * manifest.ts — the per-agent capability MANIFEST resolver (lane A1, scope 2).
 *
 * A manifest is the declarative view of what an agent may request, expressed in
 * the abstract `provider:kind[:agent]` grammar (provider-modes.ts). It is NOT a
 * new store: it is a PROJECTION over the agent's live, usable capability grants
 * (the already-shipped capabilities + capability_grants model). This keeps a
 * single source of truth — an operator grants a capability via the existing CRUD,
 * and it automatically appears in the agent's manifest with its provider mode.
 *
 * How a capability acquires its manifest identifier (in priority order):
 *   1. `capability.constraints.manifest` — an explicit identifier set by the
 *      operator at capability-create time (the recommended, unambiguous path).
 *   2. `capability.name` — if the name itself is a valid `provider:kind[:agent]`
 *      identifier, it IS the manifest entry (convenient default; e.g. a
 *      capability literally named `discord:bot-token:soliza`).
 *
 * Because the manifest is derived from live grants, REVOCATION is automatic: an
 * operator disabling the capability or revoking the grant removes it from the
 * manifest, so the next issuance/renewal resolves nothing and denies (bounded by
 * the token TTL — the Pillar-A green criterion).
 */

import type { ResolvedManifestEntry } from "./issuance";
import { parseManifestIdentifier } from "./provider-modes";
import type { Capability, CapabilityGrant } from "./schema";
import type { CapabilityStore } from "./store";

/** Extract a capability's manifest identifier, or null if it has none. */
export function capabilityManifestId(cap: Capability): string | null {
  const constraints = (cap.constraints ?? {}) as Record<string, unknown>;
  const explicit = constraints.manifest;
  if (typeof explicit === "string") {
    const parsed = parseManifestIdentifier(explicit);
    if (parsed) return parsed.raw;
  }
  // Fall back to the capability name if it is itself a valid manifest id.
  const fromName = parseManifestIdentifier(cap.name);
  return fromName ? fromName.raw : null;
}

/** A single manifest listing row (what the agent sees when it lists its manifest). */
export interface ManifestListing {
  manifest: string;
  provider: string;
  kind: string;
  /** the underlying capability name (what broker mode invokes). */
  capabilityName: string;
  capabilityId: string;
  grantExpiresAt: Date | null;
}

/**
 * List an agent's manifest: every usable (active, unexpired, enabled) capability
 * grant that carries a valid manifest identifier, projected into the abstract
 * grammar. Capabilities WITHOUT a manifest id are omitted (they remain usable via
 * the raw invoke path but are not part of the declarative manifest surface).
 */
export async function listAgentManifest(
  store: CapabilityStore,
  tenantId: string,
  agentId: string,
  now: Date = new Date(),
): Promise<ManifestListing[]> {
  const usable = await store.listUsableCapabilitiesForAgent(tenantId, agentId, now);
  const out: ManifestListing[] = [];
  for (const { capability, grant } of usable) {
    const manifest = capabilityManifestId(capability);
    if (!manifest) continue;
    const parsed = parseManifestIdentifier(manifest);
    if (!parsed) continue;
    out.push({
      manifest,
      provider: parsed.provider,
      kind: parsed.kind,
      capabilityName: capability.name,
      capabilityId: capability.id,
      grantExpiresAt: grant.expiresAt,
    });
  }
  return out;
}

/**
 * Resolve ONE manifest identifier for an agent to its underlying capability
 * grant, or null if the agent does not currently hold a usable grant for it. This
 * is the check the issuance path relies on for revocation semantics: no live
 * grant → null → issuance denies.
 *
 * Fail-closed: an unparseable identifier resolves to null.
 */
export async function resolveManifestEntry(
  store: CapabilityStore,
  tenantId: string,
  agentId: string,
  manifestId: string,
  now: Date = new Date(),
): Promise<ResolvedManifestEntry | null> {
  const parsed = parseManifestIdentifier(manifestId);
  if (!parsed) return null;

  const usable = await store.listUsableCapabilitiesForAgent(tenantId, agentId, now);
  for (const { capability, grant } of usable) {
    const id = capabilityManifestId(capability);
    if (id === parsed.raw) {
      return matchToEntry(parsed.raw, parsed.provider, capability, grant);
    }
  }
  return null;
}

function matchToEntry(
  manifest: string,
  provider: string,
  capability: Capability,
  grant: CapabilityGrant,
): ResolvedManifestEntry {
  return { manifest, provider, capability, grant };
}
