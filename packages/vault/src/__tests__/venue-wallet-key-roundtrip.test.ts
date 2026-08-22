/**
 * Regression: provisionVenueWallet must encrypt the venue key WITH its keystore
 * context (AAD), so the key can actually be decrypted for signing.
 *
 * The pre-existing venue-scoping test provisions a wallet and asserts the row +
 * policies, but never DECRYPTS — so it could not catch that provisionVenueWallet
 * encrypted with no AAD context while every read path (signTransaction,
 * signTypedData, master-password rotation) decrypts WITH { tenantId, agentId,
 * chainFamily, venue }. With no AAD on the ciphertext, that decrypt fails the
 * GCM auth tag and throws (the no-AAD fallback is off by default and disabled
 * outright in production) — making every venue wallet's funds permanently
 * unspendable. This test exercises the real decrypt-with-context path.
 */
import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { agentWallets, and, encryptedChainKeys, eq, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { KeyStore } from "../keystore";
import { backendFromKeyStore } from "../keystore-backend";
import { Vault } from "../vault";

const MASTER_PASSWORD = "test-venue-key-roundtrip";
const TENANT_ID = "test-tenant";

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

// Build a vault with a KeyStore we hold a reference to, so the test can decrypt
// the stored ciphertext exactly the way the sign path does.
async function freshVault(): Promise<{ vault: Vault; keyStore: KeyStore }> {
  // Determinism: the no-AAD legacy fallback must stay OFF so a mismatched/absent
  // AAD genuinely throws (this is the production posture).
  delete process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK;

  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Test Tenant", apiKeyHash: "test-hash" });

  const keyStore = new KeyStore(MASTER_PASSWORD);
  const vault = new Vault({
    masterPassword: MASTER_PASSWORD,
    keystoreBackend: backendFromKeyStore(keyStore),
  });
  return { vault, keyStore };
}

describe("provisionVenueWallet key round-trip (AAD context regression)", () => {
  let vault: Vault;
  let keyStore: KeyStore;

  beforeEach(async () => {
    ({ vault, keyStore } = await freshVault());
  });

  afterAll(async () => {
    for (const client of openClients) await client.close().catch(() => {});
    openClients.length = 0;
  });

  for (const chainFamily of ["evm", "solana"] as const) {
    test(`${chainFamily}: venue key decrypts with its venue context, and ONLY with it`, async () => {
      await vault.createAgent(TENANT_ID, "agent1", "Agent");
      const venue = "hyperliquid";

      await vault.provisionVenueWallet({
        tenantId: TENANT_ID,
        agentId: "agent1",
        venue,
        chainFamily,
        approvedAddresses: [],
      });

      // The ciphertext the sign path will read.
      const [row] = await getDb()
        .select()
        .from(encryptedChainKeys)
        .where(and(eq(encryptedChainKeys.agentId, "agent1"), eq(encryptedChainKeys.venue, venue)));
      expect(row).toBeTruthy();
      const enc = { ciphertext: row.ciphertext, iv: row.iv, tag: row.tag, salt: row.salt };

      // The real decrypt path supplies the full venue context. This is the
      // assertion that fails WITHOUT the fix (key was written with no AAD).
      const ctx = { tenantId: TENANT_ID, agentId: "agent1", chainFamily, venue };
      const secret = keyStore.decrypt(enc, ctx);
      expect(typeof secret).toBe("string");
      expect(secret.length).toBeGreaterThan(0);

      // The agentWallets address row exists for the same (agent, chainFamily, venue).
      const [walletRow] = await getDb()
        .select()
        .from(agentWallets)
        .where(and(eq(agentWallets.agentId, "agent1"), eq(agentWallets.venue, venue)));
      expect(walletRow?.chainFamily).toBe(chainFamily);

      if (chainFamily === "evm") {
        const typedData = {
          agentId: "agent1",
          tenantId: TENANT_ID,
          venue,
          domain: { name: "Steward wallet binding", version: "1", chainId: 8453 },
          types: { Binding: [{ name: "session", type: "string" }] },
          primaryType: "Binding",
          value: { session: "session-before-wallet-rotation" },
        };
        const signature = await vault.signTypedData({
          ...typedData,
          expectedWalletAddress: walletRow!.address,
        });
        expect(signature).toMatch(/^0x[0-9a-f]{130}$/i);

        const transaction = {
          agentId: "agent1",
          tenantId: TENANT_ID,
          to: "0x1111111111111111111111111111111111111111",
          value: "1",
          chainId: 8453,
          nonce: 0,
          gasLimit: "21000",
          venue,
          broadcast: false,
        };
        let rpcCalls = 0;
        const originalFetch = globalThis.fetch;
        globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
          rpcCalls += 1;
          const body = JSON.parse(String(init?.body)) as { id: number; method: string };
          if (body.method === "eth_chainId") {
            return Response.json({ jsonrpc: "2.0", id: body.id, result: "0x2105" });
          }
          if (body.method === "eth_gasPrice") {
            return Response.json({ jsonrpc: "2.0", id: body.id, result: "0x3b9aca00" });
          }
          throw new Error(`Unexpected JSON-RPC method: ${body.method}`);
        }) as typeof fetch;
        try {
          await expect(vault.signTransaction(transaction)).rejects.toThrow(
            "Hyperliquid transaction signing requires an authorized wallet assertion",
          );
          await expect(
            vault.signTransaction({
              ...transaction,
              walletAddress: "0x2222222222222222222222222222222222222222",
            }),
          ).rejects.toThrow("Transaction signer no longer matches the authorized wallet");
          expect(rpcCalls).toBe(0);

          const signedTransaction = await vault.signTransaction({
            ...transaction,
            walletAddress: walletRow!.address,
          });
          expect(signedTransaction).toMatch(/^0x[0-9a-f]+$/i);
          expect(rpcCalls).toBeGreaterThan(0);
        } finally {
          globalThis.fetch = originalFetch;
        }

        await expect(vault.signTypedData(typedData)).rejects.toThrow(
          "Hyperliquid typed-data signing requires an authorized wallet assertion",
        );

        await expect(
          vault.signTypedData({
            ...typedData,
            expectedWalletAddress: "0x2222222222222222222222222222222222222222",
          }),
        ).rejects.toThrow("Typed-data signer no longer matches the authorized wallet");

        await getDb()
          .delete(agentWallets)
          .where(
            and(
              eq(agentWallets.agentId, "agent1"),
              eq(agentWallets.chainFamily, "evm"),
              eq(agentWallets.venue, venue),
            ),
          );
        await expect(
          vault.signTypedData({
            ...typedData,
            expectedWalletAddress: walletRow!.address,
          }),
        ).rejects.toThrow("Typed-data signer no longer matches the authorized wallet");
      }

      // AAD genuinely binds the venue: a different or absent venue must NOT decrypt.
      expect(() => keyStore.decrypt(enc, { ...ctx, venue: "polymarket" })).toThrow();
      expect(() =>
        keyStore.decrypt(enc, { tenantId: TENANT_ID, agentId: "agent1", chainFamily }),
      ).toThrow();
    });
  }
});
