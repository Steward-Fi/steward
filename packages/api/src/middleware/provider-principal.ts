/**
 * provider-principal.ts — the runtime-neutral provider principal seam (spec §7.1).
 *
 * A provider-action route MUST derive its immutable request actor (tenant +
 * agent) ONLY from the verified agent principal that the agent-jwt authenticator
 * installed into request context (`verifiedAgentPrincipal`). It NEVER reads actor
 * identity from request data, NEVER checks `trade:order`, and NEVER infers
 * provider access from token scopes — provider authority is decided downstream by
 * bindings/grants, never by JWT scope.
 *
 * `resolveProviderPrincipal(c)` reads only the verified typed context value that
 * `requireProviderAgentJwt` set. If it is absent (route mis-wired without the
 * provider auth middleware) it throws — fail closed rather than proceed with an
 * unauthenticated actor.
 */

import type { AppVariables, VerifiedAgentPrincipal } from "@stwd/shared";
import type { Context } from "hono";

/**
 * The provider principal shape specified by §7.1. It is structurally the
 * `VerifiedAgentPrincipal` context value; kept as its own exported name so the
 * provider service/route type against the seam rather than the raw context.
 */
export type ProviderPrincipalV1 = VerifiedAgentPrincipal;

export class ProviderPrincipalMissingError extends Error {
  constructor() {
    super("verifiedAgentPrincipal missing: provider route not behind requireProviderAgentJwt");
    this.name = "ProviderPrincipalMissingError";
  }
}

/**
 * Read the verified provider principal from request context. Throws
 * {@link ProviderPrincipalMissingError} when the provider auth middleware did not
 * run (fail closed). The value can ONLY have been set by
 * `installAgentJwtContext` after RS256/JWKS verification — a request header can
 * never set it.
 */
export function resolveProviderPrincipal(
  c: Context<{ Variables: AppVariables }>,
): ProviderPrincipalV1 {
  const principal = c.get("verifiedAgentPrincipal");
  if (!principal || principal.type !== "agent" || !principal.agentId || !principal.tenantId) {
    throw new ProviderPrincipalMissingError();
  }
  return principal;
}
