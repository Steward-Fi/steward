/**
 * validate.ts — capability create/update validation.
 *
 * a capability compiles to a legal narrow secret_route. so EVERY create/update
 * that touches the routing/injection fields is validated through the SHARED
 * secret-route validator (`@stwd/vault`'s `validateSecretRouteConfig`), INCLUDING
 * the per-host STRICT_HOSTS narrowness rules. this is the single source of truth
 * the proxy + the /secrets route CRUD already use; a capability can therefore
 * never be broader than a legal route, and a strict host (e.g. api.github.com)
 * forces an explicit method + >=2 path segments + no path wildcards here too.
 *
 * fail-closed: any missing/ambiguous field is rejected; a widen-by-patch on
 * update is rejected because the MERGED config is re-validated with strict-host
 * enforcement ON (never trusting a partial patch).
 */

import { validateSecretRouteConfig } from "@stwd/vault";
import { z } from "zod";
import type { CapabilitySpec } from "./store";

/**
 * Capability name: a dotted, lowercase, hierarchical identifier such as
 * "github.pr.comment". kept strict so a capability name is a stable, greppable
 * key (no whitespace, no injection-y characters). segments are alphanumeric +
 * hyphen, joined by dots.
 */
const CAPABILITY_NAME = /^[a-z0-9]+([-][a-z0-9]+)*(\.[a-z0-9]+([-][a-z0-9]+)*)*$/;
const MAX_CAPABILITY_NAME_LENGTH = 200;

/** v1 constraints bag: intentionally small + opaque; the policy layer (W-1b) reads it. */
const constraintsSchema = z.record(z.string(), z.unknown());

/** create body: the full capability spec (all routing/inject fields required). */
export const createCapabilitySchema = z.object({
  name: z
    .string()
    .min(1)
    .max(MAX_CAPABILITY_NAME_LENGTH)
    .regex(CAPABILITY_NAME, "name must be a dotted lowercase identifier, e.g. github.pr.comment"),
  secretId: z.string().uuid("secretId must be a uuid"),
  host: z.string().min(1),
  pathPattern: z.string().min(1),
  method: z.string().min(1),
  injectAs: z.string().optional(),
  injectKey: z.string().min(1),
  injectFormat: z.string().optional(),
  constraints: constraintsSchema.optional(),
  enabled: z.boolean().optional(),
});

export type CreateCapabilityBody = z.infer<typeof createCapabilitySchema>;

/**
 * update body: enable/disable + constraint updates + optional routing/inject
 * edits. every routing/inject field is optional (partial patch), but the MERGED
 * result is re-validated with strict-host enforcement ON (no widen-by-patch).
 */
export const updateCapabilitySchema = z
  .object({
    secretId: z.string().uuid().optional(),
    host: z.string().min(1).optional(),
    pathPattern: z.string().min(1).optional(),
    method: z.string().min(1).optional(),
    injectAs: z.string().optional(),
    injectKey: z.string().min(1).optional(),
    injectFormat: z.string().optional(),
    constraints: constraintsSchema.optional(),
    enabled: z.boolean().optional(),
  })
  .refine((b) => Object.keys(b).length > 0, {
    message: "at least one capability field is required",
  });

export type UpdateCapabilityBody = z.infer<typeof updateCapabilitySchema>;

/** grant body: which agent, optional expiry. */
export const createGrantSchema = z.object({
  agentId: z.string().min(1).max(64),
  expiresAt: z.string().datetime().optional(),
});

export type CreateGrantBody = z.infer<typeof createGrantSchema>;

/**
 * Normalize + validate a full capability spec through the shared secret-route
 * validator (strict hosts enforced). Returns the normalized spec, or an error
 * string on the first failed rule. injectAs defaults to "header" (the proxy's
 * only injection surface); injectFormat defaults to "{value}".
 */
export function validateCapabilitySpec(input: {
  secretId: string;
  host: string;
  pathPattern: string;
  method: string;
  injectAs?: string;
  injectKey: string;
  injectFormat?: string;
}): { ok: true; spec: CapabilitySpec } | { ok: false; error: string } {
  const injectAs = input.injectAs ?? "header";
  const injectFormat = input.injectFormat ?? "{value}";
  // normalize the same way SecretVault.createRoute / the route validator expect:
  // host lower-cased, method upper-cased. the shared validator re-checks both.
  const spec: CapabilitySpec = {
    secretId: input.secretId,
    host: input.host.trim().toLowerCase(),
    pathPattern: input.pathPattern.trim(),
    method: input.method.trim().toUpperCase(),
    injectAs,
    injectKey: input.injectKey.trim(),
    injectFormat,
  };

  const error = validateSecretRouteConfig(
    {
      hostPattern: spec.host,
      pathPattern: spec.pathPattern,
      method: spec.method,
      injectAs: spec.injectAs,
      injectKey: spec.injectKey,
      injectFormat: spec.injectFormat,
    },
    // create/full-spec validation ALWAYS enforces strict hosts (the config is
    // complete here — this is not a partial patch).
    { enforceStrictHosts: true },
  );
  if (error) return { ok: false, error };
  return { ok: true, spec };
}
