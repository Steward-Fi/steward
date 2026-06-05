// Sprint 4 Phase 1 Day 1 tests: venue-scoped vault API.
//
// Uses PGLite (in-process Postgres via WASM) so the test runs against the
// real Drizzle schema and the real 0022_vault_venue_scope migration, with
// no third-party infra. Master password is fixed for determinism; the
// underlying KeyStore still adds per-record IV + salt randomness.

import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";

import { agentWallets, eq, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { Vault } from "../vault";

const MASTER_PASSWORD = "test-vault-venue-scope";
const TENANT_ID = "test-tenant";

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

async function freshVault(): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  // Seed the tenant the vault will write under.
  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Test Tenant",
    apiKeyHash: "test-hash",
  });

  return new Vault({ masterPassword: MASTER_PASSWORD });
}

describe("Vault venue scoping (Sprint 4 Day 1)", () => {
  let vault: Vault;

  beforeEach(async () => {
    vault = await freshVault();
  });

  afterAll(async () => {
    // Close every PGLite client we opened so Bun's process exits cleanly
    // under CI (exit code 99 surfaces dangling async handles otherwise).
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
  });

  test("provisionVenueWallet creates a venue wallet with all default policies enabled", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");

    const result = await vault.provisionVenueWallet({
      tenantId: TENANT_ID,
      agentId: "sol",
      venue: "hyperliquid",
      chainFamily: "evm",
      approvedAddresses: ["0x1111111111111111111111111111111111111111"],
    });

    expect(result.address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    const walletRows = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, "sol"));
    expect(
      walletRows.some(
        (row) =>
          row.address === result.address &&
          row.chainFamily === "evm" &&
          row.venue === "hyperliquid",
      ),
    ).toBe(true);

    const policyRows = await getDb().select().from(policies).where(eq(policies.agentId, "sol"));
    const venuePolicies = policyRows.filter((row) =>
      ["leverage-cap", "venue-allowlist", "spending-limit", "approved-addresses"].includes(
        row.type,
      ),
    );

    expect(venuePolicies).toHaveLength(4);
    expect(venuePolicies.every((row) => row.enabled)).toBe(true);
    expect(venuePolicies.map((row) => row.type).sort()).toEqual(
      ["approved-addresses", "leverage-cap", "spending-limit", "venue-allowlist"].sort(),
    );

    const venueAllowlist = venuePolicies.find((row) => row.type === "venue-allowlist");
    expect(venueAllowlist?.enabled).toBe(true);
    expect(venueAllowlist?.config).toEqual({ allowedVenues: ["hyperliquid"] });

    const approvedAddresses = venuePolicies.find((row) => row.type === "approved-addresses");
    expect(approvedAddresses?.config).toEqual({
      addresses: ["0x1111111111111111111111111111111111111111"],
      mode: "whitelist",
    });
  });

  test("createWallet provisions a venue-scoped EVM wallet and returns the address", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");

    const wallet = await vault.createWallet({
      agentId: "sol",
      venue: "hyperliquid",
      chainType: "evm",
      purpose: "perp",
    });

    expect(wallet.agentId).toBe("sol");
    expect(wallet.chainFamily).toBe("evm");
    expect(wallet.venue).toBe("hyperliquid");
    expect(wallet.purpose).toBe("perp");
    expect(wallet.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  test("createWallet provisions a venue-scoped Solana wallet", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");

    const wallet = await vault.createWallet({
      agentId: "sol",
      venue: "drift",
      chainType: "solana",
    });

    expect(wallet.chainFamily).toBe("solana");
    expect(wallet.venue).toBe("drift");
    expect(wallet.purpose).toBeNull();
    // Solana addresses are base58, not 0x-prefixed.
    expect(wallet.address.startsWith("0x")).toBe(false);
    expect(wallet.address.length).toBeGreaterThan(30);
  });

  test("getWallet({ agentId, venue }) returns the venue-scoped row", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    const created = await vault.createWallet({
      agentId: "sol",
      venue: "hyperliquid",
      chainType: "evm",
    });

    const fetched = await vault.getWallet({ agentId: "sol", venue: "hyperliquid" });

    expect(fetched.address).toBe(created.address);
    expect(fetched.venue).toBe("hyperliquid");
    expect(fetched.chainFamily).toBe("evm");
  });

  test("getWallet({ agentId, chainId }) returns the legacy NULL-venue row (backward compat)", async () => {
    // createAgent writes legacy NULL-venue rows for both chain families.
    const identity = await vault.createAgent(TENANT_ID, "legacy-agent", "Legacy");

    const fetched = await vault.getWallet({ agentId: "legacy-agent", chainId: 8453 });

    expect(fetched.venue).toBeNull();
    expect(fetched.chainFamily).toBe("evm");
    expect(fetched.address).toBe(identity.walletAddresses?.evm ?? identity.walletAddress);
  });

  test("getWallet({ chainId }) of a Solana chainId resolves to the Solana legacy row", async () => {
    const identity = await vault.createAgent(TENANT_ID, "legacy-agent", "Legacy");

    const fetched = await vault.getWallet({ agentId: "legacy-agent", chainId: 101 });

    expect(fetched.chainFamily).toBe("solana");
    expect(fetched.venue).toBeNull();
    expect(fetched.address).toBe(identity.walletAddresses?.solana ?? "");
  });

  test("getWallet({ venue }) does NOT silently fall back to the legacy row", async () => {
    await vault.createAgent(TENANT_ID, "legacy-agent", "Legacy");

    // No hyperliquid wallet has been provisioned, so this MUST throw,
    // not return the legacy EVM row. Trade-sessions relies on this.
    await expect(
      vault.getWallet({ agentId: "legacy-agent", venue: "hyperliquid" }),
    ).rejects.toThrow(/No wallet found for agent legacy-agent on venue hyperliquid/);
  });

  test("getWallet with no venue, scope, or chainId throws", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    await expect(vault.getWallet({ agentId: "sol" })).rejects.toThrow(
      /getWallet requires either `venue`, `scope`, or `chainId`/,
    );
  });

  test("createWallet enforces venue uniqueness per (agentId, chainFamily)", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    await vault.createWallet({ agentId: "sol", venue: "hyperliquid", chainType: "evm" });

    // Second insert for the same (agentId, chainFamily, venue) tuple must
    // be rejected by the unique index from migration 0022.
    await expect(
      vault.createWallet({ agentId: "sol", venue: "hyperliquid", chainType: "evm" }),
    ).rejects.toThrow();
  });

  test("two distinct venues for the same agent + chainFamily coexist (the whole point)", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    const hl = await vault.createWallet({
      agentId: "sol",
      venue: "hyperliquid",
      chainType: "evm",
      purpose: "perp",
    });
    const pm = await vault.createWallet({
      agentId: "sol",
      venue: "polymarket",
      chainType: "evm",
      purpose: "predictions",
    });

    expect(hl.address).not.toBe(pm.address);

    const hlFetch = await vault.getWallet({ agentId: "sol", venue: "hyperliquid" });
    const pmFetch = await vault.getWallet({ agentId: "sol", venue: "polymarket" });
    expect(hlFetch.address).toBe(hl.address);
    expect(pmFetch.address).toBe(pm.address);
  });

  test("legacy + venue-scoped wallets coexist for the same agent + chainFamily", async () => {
    const identity = await vault.createAgent(TENANT_ID, "sol", "Sol");
    await vault.createWallet({ agentId: "sol", venue: "hyperliquid", chainType: "evm" });

    const legacy = await vault.getWallet({ agentId: "sol", chainId: 8453 });
    const hl = await vault.getWallet({ agentId: "sol", venue: "hyperliquid" });

    expect(legacy.address).toBe(identity.walletAddresses?.evm ?? "");
    expect(hl.address).not.toBe(legacy.address);
  });

  test("listWallets returns every wallet across venues and chain families", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    await vault.createWallet({ agentId: "sol", venue: "hyperliquid", chainType: "evm" });
    await vault.createWallet({ agentId: "sol", venue: "polymarket", chainType: "evm" });
    await vault.createWallet({ agentId: "sol", venue: "drift", chainType: "solana" });

    const all = await vault.listWallets({ agentId: "sol" });

    // 2 legacy (EVM + Solana from createAgent) + 3 venue-scoped = 5
    expect(all.length).toBe(5);

    const venues = all.map((w) => w.venue);
    expect(venues).toContain(null);
    expect(venues).toContain("hyperliquid");
    expect(venues).toContain("polymarket");
    expect(venues).toContain("drift");

    // Legacy NULL rows come first (NULLS FIRST in the ORDER BY).
    expect(all[0]!.venue).toBeNull();
  });

  test("createWallet provisions Bitcoin mainnet P2WPKH metadata with a scoped row", async () => {
    await vault.createAgent(TENANT_ID, "satoshi", "Satoshi");

    const wallet = await vault.createWallet({
      agentId: "satoshi",
      chainType: "bitcoin",
      bitcoin: { network: "mainnet", addressType: "p2wpkh" },
    });

    expect(wallet.agentId).toBe("satoshi");
    expect(wallet.chainFamily).toBe("bitcoin");
    expect(wallet.venue).toBe("bitcoin:mainnet:p2wpkh:0:0:0");
    expect(wallet.address).toMatch(/^bc1q/);
    expect(wallet.metadata.bitcoin).toMatchObject({
      network: "mainnet",
      addressType: "p2wpkh",
      account: 0,
      change: 0,
      index: 0,
      caip2: "bip122:000000000019d6689c085ae165831e93",
    });
    expect((wallet.metadata.bitcoin as { path: string }).path).toBe("m/84'/0'/0'/0/0");
  });

  test("listWallets serializes Bitcoin testnet Taproot metadata alongside EVM/Solana", async () => {
    await vault.createAgent(TENANT_ID, "satoshi", "Satoshi");
    const created = await vault.createWallet({
      agentId: "satoshi",
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2tr", account: 1, index: 7 },
    });

    const all = await vault.listWallets({ agentId: "satoshi" });
    const bitcoin = all.find((wallet) => wallet.chainFamily === "bitcoin");

    expect(bitcoin).toBeDefined();
    expect(bitcoin?.address).toBe(created.address);
    expect(bitcoin?.address).toMatch(/^tb1p/);
    expect(bitcoin?.metadata.bitcoin).toMatchObject({
      network: "testnet",
      addressType: "p2tr",
      account: 1,
      change: 0,
      index: 7,
      caip2: "bip122:000000000933ea01ad0ee984209779ba",
    });
    expect(all.map((wallet) => wallet.chainFamily).sort()).toEqual(["bitcoin", "evm", "solana"]);
  });

  test("exportPrivateKey includes Bitcoin scoped key material only through break-glass", async () => {
    await vault.createAgent(TENANT_ID, "satoshi", "Satoshi");
    const created = await vault.createWallet({
      agentId: "satoshi",
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2tr", account: 2, index: 9 },
    });

    await expect(vault.exportPrivateKey(TENANT_ID, "satoshi")).rejects.toThrow(/break-glass/);

    const exported = await vault.exportPrivateKey(TENANT_ID, "satoshi", {
      breakGlass: true,
      actorId: "test-actor",
      reason: "venue-scoping unit test: verify Bitcoin export metadata",
    });

    expect(exported.bitcoin).toHaveLength(1);
    expect(exported.bitcoin?.[0]).toMatchObject({
      address: created.address,
      venue: "bitcoin:testnet:p2tr:2:0:9",
      purpose: null,
      metadata: {
        bitcoin: {
          network: "testnet",
          addressType: "p2tr",
          path: "m/86'/1'/2'/0/9",
          account: 2,
          change: 0,
          index: 9,
          caip2: "bip122:000000000933ea01ad0ee984209779ba",
        },
      },
    });
    expect(exported.bitcoin?.[0]?.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(JSON.stringify(created)).not.toContain(exported.bitcoin?.[0]?.privateKey ?? "");
    expect(JSON.stringify(await vault.listWallets({ agentId: "satoshi" }))).not.toContain(
      exported.bitcoin?.[0]?.privateKey ?? "",
    );
  });

  test("createWallet rejects unknown chainType", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    await expect(
      vault.createWallet({ agentId: "sol", venue: "x", chainType: "unknown" as any }),
    ).rejects.toThrow(/unsupported chainType/);
  });

  test("createWallet rejects unknown agentId with a clear error (no FK leak)", async () => {
    await expect(
      vault.createWallet({ agentId: "ghost", venue: "hyperliquid", chainType: "evm" }),
    ).rejects.toThrow(/Agent ghost not found/);
  });

  test("private key is never returned by createWallet", async () => {
    await vault.createAgent(TENANT_ID, "sol", "Sol");
    const wallet = await vault.createWallet({
      agentId: "sol",
      venue: "hyperliquid",
      chainType: "evm",
    });
    // Type-level: the return type has no `privateKey` / `secretKey`. Runtime:
    // verify the returned object has no key-shaped fields.
    expect(Object.keys(wallet).sort()).toEqual(
      ["address", "agentId", "chainFamily", "metadata", "purpose", "venue"].sort(),
    );
  });

  test("importKey stores normalized EVM keys when callers omit 0x", async () => {
    await vault.createAgent(TENANT_ID, "import-agent", "Import Agent");
    const privateKey = generatePrivateKey();
    const barePrivateKey = privateKey.slice(2);

    const imported = await vault.importKey(TENANT_ID, "import-agent", barePrivateKey, "evm");
    const exported = await vault.exportPrivateKey(TENANT_ID, "import-agent", {
      breakGlass: true,
      actorId: "test-actor",
      reason: "venue-scoping unit test: verify imported key round-trips",
    });

    expect(imported.walletAddress).toBe(privateKeyToAccount(privateKey).address);
    expect(exported.evm?.privateKey).toBe(privateKey);
  });
});
