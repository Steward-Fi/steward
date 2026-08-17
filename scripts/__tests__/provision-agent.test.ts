/**
 * SEC-012 regression tests — default-tenant API key provisioning.
 *
 * Pre-fix, scripts/provision-agent.ts inserted the `default` tenant with
 * apiKeyHash = sha256("provision-agent:default"). That literal string —
 * published in this repo — was a working X-Steward-Key credential (tenant
 * auth is timingSafeEqual(sha256(presentedKey), apiKeyHash)). These tests
 * assert the remediated behavior: random keys for new tenants, automatic
 * rotation of the legacy derivable hash, and no touching of operator-managed
 * hashes.
 *
 * The logic lives in scripts/lib/default-tenant.ts (dependency-light, no
 * workspace imports) so it is testable without a database.
 */
import { describe, expect, test } from "bun:test";
import { validateApiKey } from "../../packages/auth/src/api-keys";
import {
  type DefaultTenantStore,
  ensureDefaultTenant,
  LEGACY_DEFAULT_TENANT_API_KEY,
  LEGACY_DEFAULT_TENANT_API_KEY_HASH,
} from "../lib/default-tenant";

interface FakeStore extends DefaultTenantStore {
  inserted: Array<{ id: string; apiKeyHash: string }>;
  rotations: Array<{ tenantId: string; apiKeyHash: string }>;
}

function fakeStore(existingHash: string | null): FakeStore {
  const store: FakeStore = {
    inserted: [],
    rotations: [],
    async getApiKeyHash() {
      return existingHash;
    },
    async insertTenant(values) {
      store.inserted.push(values);
    },
    async rotateApiKeyHash(tenantId, apiKeyHash) {
      store.rotations.push({ tenantId, apiKeyHash });
    },
  };
  return store;
}

const ARGS = { tenantId: "default", tenantName: "Default Steward Tenant", ownerAddress: "0xabc" };

describe("SEC-012 ensureDefaultTenant", () => {
  test("creates a missing tenant with a random (non-derivable) key", async () => {
    const store = fakeStore(null);
    const result = await ensureDefaultTenant(store, ARGS);

    expect(result.status).toBe("created");
    expect(store.inserted).toHaveLength(1);
    const { apiKeyHash } = store.inserted[0];
    // Not the publicly derivable legacy hash...
    expect(apiKeyHash).not.toBe(LEGACY_DEFAULT_TENANT_API_KEY_HASH);
    // ...and the returned key validates against the stored hash.
    expect(validateApiKey((result as { apiKey: string }).apiKey, apiKeyHash)).toBe(true);
    expect(validateApiKey(LEGACY_DEFAULT_TENANT_API_KEY, apiKeyHash)).toBe(false);
  });

  test("rotates the legacy derivable hash so the published key stops working", async () => {
    const store = fakeStore(LEGACY_DEFAULT_TENANT_API_KEY_HASH);
    const result = await ensureDefaultTenant(store, ARGS);

    expect(result.status).toBe("rotated");
    expect(store.inserted).toHaveLength(0);
    expect(store.rotations).toHaveLength(1);
    const newHash = store.rotations[0].apiKeyHash;
    expect(newHash).not.toBe(LEGACY_DEFAULT_TENANT_API_KEY_HASH);
    // The pre-fix published credential must no longer validate.
    expect(validateApiKey(LEGACY_DEFAULT_TENANT_API_KEY, newHash)).toBe(false);
    // The freshly printed key does.
    expect(validateApiKey((result as { apiKey: string }).apiKey, newHash)).toBe(true);
  });

  test("leaves an operator-managed hash untouched", async () => {
    const store = fakeStore("a".repeat(64));
    const result = await ensureDefaultTenant(store, ARGS);

    expect(result.status).toBe("existing");
    expect(store.inserted).toHaveLength(0);
    expect(store.rotations).toHaveLength(0);
  });

  test("legacy hash constant matches the pre-fix derivation", () => {
    // Guards the remediation trigger itself: the constant must equal
    // sha256("provision-agent:default") — the exact value pre-fix script
    // versions wrote — or already-provisioned instances would not rotate.
    expect(LEGACY_DEFAULT_TENANT_API_KEY_HASH).toBe(
      "93a3e57073bf915e403c48b44518efca07086ec8ada1b4b73e4a5278677d57cc",
    );
  });
});
