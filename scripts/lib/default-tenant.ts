/**
 * Default-tenant API key provisioning (SEC-012).
 *
 * scripts/provision-agent.ts must not insert the `default` tenant with
 * apiKeyHash = sha256("provision-agent:default") — a key anyone can derive
 * from this public repo, and a valid `X-Steward-Key` credential on any
 * instance where this script created the tenant before the API bootstrap
 * (the bootstrap uses .onConflictDoNothing() and never overwrites it).
 *
 * This module is the remediation:
 *   - tenant missing          → generate a random key, store only its hash,
 *                               return the key once for the operator.
 *   - tenant has legacy hash  → rotate to a fresh random key (the derivable
 *                               key stops working) and return the new key once.
 *   - tenant has any other hash → operator-managed (API bootstrap / platform
 *                               API); left untouched.
 *
 * Kept free of workspace-package imports (node:crypto + @stwd/auth's pure
 * api-keys helper only) so the logic is unit-testable without a database.
 */
import { generateApiKey, hashApiKey } from "../../packages/auth/src/api-keys";

/** The publicly derivable pre-SEC-012 key for the `default` tenant. */
export const LEGACY_DEFAULT_TENANT_API_KEY = "provision-agent:default";
export const LEGACY_DEFAULT_TENANT_API_KEY_HASH = hashApiKey(LEGACY_DEFAULT_TENANT_API_KEY);

/** Narrow DB surface so the decision logic is testable without drizzle. */
export interface DefaultTenantStore {
  /** Hash of the tenant's current API key, or null when the tenant is absent. */
  getApiKeyHash(tenantId: string): Promise<string | null>;
  insertTenant(values: {
    id: string;
    name: string;
    apiKeyHash: string;
    ownerAddress: string;
  }): Promise<void>;
  rotateApiKeyHash(
    tenantId: string,
    expectedApiKeyHash: string,
    apiKeyHash: string,
  ): Promise<boolean>;
}

export type EnsureDefaultTenantResult =
  | { status: "created"; apiKey: string }
  | { status: "rotated"; apiKey: string }
  | { status: "existing" };

export async function ensureDefaultTenant(
  store: DefaultTenantStore,
  args: { tenantId: string; tenantName: string; ownerAddress: string },
): Promise<EnsureDefaultTenantResult> {
  const existingHash = await store.getApiKeyHash(args.tenantId);

  if (existingHash === null) {
    const { key, hash } = generateApiKey();
    await store.insertTenant({
      id: args.tenantId,
      name: args.tenantName,
      apiKeyHash: hash,
      ownerAddress: args.ownerAddress,
    });
    return { status: "created", apiKey: key };
  }

  // Remediation path: rotate the publicly derivable legacy key on re-run so
  // already-provisioned instances are fixed instead of staying vulnerable.
  if (existingHash === LEGACY_DEFAULT_TENANT_API_KEY_HASH) {
    const { key, hash } = generateApiKey();
    const rotated = await store.rotateApiKeyHash(args.tenantId, existingHash, hash);
    // Another provisioner or operator may have rotated the key after our
    // read. Never overwrite that newer operator-managed credential or print a
    // key that was not actually stored.
    if (!rotated) return { status: "existing" };
    return { status: "rotated", apiKey: key };
  }

  return { status: "existing" };
}
