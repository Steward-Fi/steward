/**
 * SEC-012 regression tests — default-tenant API key provisioning.
 *
 * scripts/provision-agent.ts must not insert the `default` tenant with
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
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { validateApiKey } from "../../packages/auth/src/api-keys";
import {
  type DefaultTenantStore,
  ensureDefaultTenant,
  LEGACY_DEFAULT_TENANT_API_KEY,
  LEGACY_DEFAULT_TENANT_API_KEY_HASH,
} from "../lib/default-tenant";
import { writeProvisionSecrets } from "../lib/provision-secrets";

interface FakeStore extends DefaultTenantStore {
  inserted: Array<{ id: string; apiKeyHash: string }>;
  rotations: Array<{ tenantId: string; apiKeyHash: string }>;
  rotationWins: boolean;
}

function fakeStore(existingHash: string | null, rotationWins = true): FakeStore {
  const store: FakeStore = {
    inserted: [],
    rotations: [],
    rotationWins,
    async getApiKeyHash() {
      return existingHash;
    },
    async insertTenant(values) {
      store.inserted.push(values);
    },
    async rotateApiKeyHash(tenantId, _expectedApiKeyHash, apiKeyHash) {
      store.rotations.push({ tenantId, apiKeyHash });
      return store.rotationWins;
    },
  };
  return store;
}

const ARGS = { tenantId: "default", tenantName: "Default Steward Tenant", ownerAddress: "0xabc" };

describe("SEC-012 ensureDefaultTenant", () => {
  test("root manifest declares provision-agent direct imports", () => {
    const rootPackage = JSON.parse(
      readFileSync(join(import.meta.dir, "..", "..", "package.json"), "utf8"),
    ) as { dependencies?: Record<string, string> };
    expect(rootPackage.dependencies?.["@stwd/db"]).toBe("workspace:*");
    expect(rootPackage.dependencies?.["drizzle-orm"]).toBeDefined();
  });

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
    // The superseded credential must no longer validate.
    expect(validateApiKey(LEGACY_DEFAULT_TENANT_API_KEY, newHash)).toBe(false);
    // The freshly returned key does.
    expect(validateApiKey((result as { apiKey: string }).apiKey, newHash)).toBe(true);
  });

  test("leaves an operator-managed hash untouched", async () => {
    const store = fakeStore("a".repeat(64));
    const result = await ensureDefaultTenant(store, ARGS);

    expect(result.status).toBe("existing");
    expect(store.inserted).toHaveLength(0);
    expect(store.rotations).toHaveLength(0);
  });

  test("does not overwrite or print a key when a concurrent rotation wins", async () => {
    const store = fakeStore(LEGACY_DEFAULT_TENANT_API_KEY_HASH, false);
    const result = await ensureDefaultTenant(store, ARGS);

    expect(result).toEqual({ status: "existing" });
    expect("apiKey" in result).toBe(false);
  });

  test("legacy hash constant matches the retired derivation", () => {
    // Guards the remediation trigger itself: the constant must equal
    // sha256("provision-agent:default") — the exact value the retired script
    // versions wrote — or already-provisioned instances would not rotate.
    expect(LEGACY_DEFAULT_TENANT_API_KEY_HASH).toBe(
      "93a3e57073bf915e403c48b44518efca07086ec8ada1b4b73e4a5278677d57cc",
    );
  });
});

describe("provisioning secret output", () => {
  test("writes credentials to a mode-0600 file and safely updates it", () => {
    const tempRoot = mkdtempSync(join(tmpdir(), "steward-provision-test-"));
    try {
      const first = writeProvisionSecrets({ tenantApiKey: "tenant-secret" }, undefined, tempRoot);
      writeProvisionSecrets(
        {
          tenantApiKey: "tenant-secret",
          agentId: "agent-1",
          tradeSessionId: "session-secret",
          jwt: "jwt-secret",
        },
        first,
      );
      expect(statSync(dirname(first)).mode & 0o777).toBe(0o700);
      expect(statSync(first).mode & 0o777).toBe(0o600);
      const contents = readFileSync(first, "utf8");
      expect(contents).toContain("STEWARD_TENANT_API_KEY=tenant-secret");
      expect(contents).toContain("STEWARD_TRADE_SESSION_ID=session-secret");
      expect(contents).toContain("STEWARD_JWT=jwt-secret");
    } finally {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  test("rejects newline injection into the env output", () => {
    expect(() => writeProvisionSecrets({ jwt: "safe\nINJECTED=value" })).toThrow(
      "unsupported control character",
    );
  });

  test("CLI source never prints credential values to stdout", () => {
    const source = readFileSync(join(import.meta.dir, "..", "provision-agent.ts"), "utf8");
    expect(source).not.toMatch(/console\.log\([^\n]*(apiKey|\$\{jwt\}|\$\{session\.id\})/);
    expect(source).toContain("writeProvisionSecrets(provisionSecrets, credentialsPath)");
  });
});
