import { randomUUID } from "node:crypto";
import {
  agents,
  agentWallets,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  policies,
  toAgentIdentity,
  transactions,
} from "@stwd/db";
import type {
  AgentIdentity,
  PolicyResult,
  RpcRequest,
  RpcResponse,
  SignRequest,
  SignSolanaTransactionRequest,
  SignTypedDataRequest,
  TxStatus,
} from "@stwd/shared";
import { toCaip2 } from "@stwd/shared";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import {
  type Chain,
  createPublicClient,
  createWalletClient,
  formatEther,
  http,
  type TransactionSerializable,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  arbitrum,
  base,
  baseSepolia,
  bsc,
  bscTestnet,
  gnosis,
  mainnet,
  polygon,
} from "viem/chains";
import { deriveEvmKey, deriveSolanaKey } from "./hd-wallet";
import { type EncryptedKey, KeyStore } from "./keystore";
import { backendFromKeyStore, type KeystoreBackend } from "./keystore-backend";
import {
  assertSolanaTransferTransactionMatches,
  generateSolanaKeypair,
  getSolanaBalance,
  restoreSolanaKeypair,
  signEd25519Digest,
  signSolanaMessage,
  signSolanaTransaction,
} from "./solana";
import {
  assertParsedSolanaTransferMatches,
  isVersionedTransactionBytes,
} from "./solana-instructions";
import { getTokenBalances as fetchTokenBalances, type TokenBalance } from "./tokens";
import {
  ENTRY_POINT_V07,
  getUserOperationHash,
  packUserOperation,
  type UnpackedUserOperationFields,
} from "./userop";

export interface VaultConfig {
  masterPassword: string;
  rpcUrl?: string;
  chainId?: number;
  keystoreBackend?: KeystoreBackend;
}

/**
 * Explicit, logged authorization required to call exportPrivateKey. Forces the
 * caller to opt into a break-glass plaintext-key export rather than invoking it
 * casually; actorId/reason are surfaced in the vault's audit log line.
 */
export interface ExportPrivateKeyAuthorization {
  breakGlass: true;
  actorId: string;
  reason?: string;
}

const CHAINS: Record<number, Chain> = {
  1: mainnet, // Ethereum
  56: bsc, // BSC
  97: bscTestnet, // BSC Testnet
  100: gnosis, // Gnosis
  137: polygon, // Polygon
  8453: base, // Base
  42161: arbitrum, // Arbitrum
  84532: baseSepolia, // Base Sepolia
};

// Default public RPC URLs per EVM chain (override with env / VaultConfig.rpcUrl for the active chain)
const CHAIN_RPCS: Record<number, string> = {
  1: "https://eth.llamarpc.com",
  56: "https://bsc-dataseed.binance.org",
  97: "https://data-seed-prebsc-1-s1.bnbchain.org:8545",
  100: "https://rpc.gnosischain.com",
  137: "https://polygon-rpc.com",
  8453: "https://mainnet.base.org",
  42161: "https://arb1.arbitrum.io/rpc",
  84532: "https://sepolia.base.org",
};

// Solana RPC URLs (chainId 101 = mainnet-beta, 102 = devnet)
const SOLANA_RPCS: Record<number, string> = {
  101: "https://api.mainnet-beta.solana.com",
  102: "https://api.devnet.solana.com",
};

export function resolveSignVenueSelector(request: Pick<SignRequest, "venue">): string | null {
  return request.venue ?? null;
}

export function missingSigningKeyError(
  agentId: string,
  chainFamily: string,
  venue?: string | null,
): Error {
  const venueSuffix = venue ? ` with venue ${venue}` : "";
  return new Error(
    `No signing key found for agent ${agentId} on chain family ${chainFamily}${venueSuffix}`,
  );
}

export function assertEvmWalletAddressMatches(secretKey: string, walletAddress?: string): void {
  if (!walletAddress) return;
  const derivedAddress = privateKeyToAccount(secretKey as `0x${string}`).address;
  if (derivedAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    throw new Error(
      `Wallet address mismatch: resolved ${derivedAddress} but request specified ${walletAddress}`,
    );
  }
}

/**
 * Detect chain type from wallet address format.
 * EVM addresses start with "0x"; Solana addresses are base58 (no "0x" prefix).
 */
function detectChainType(walletAddress: string): "evm" | "solana" {
  return walletAddress.startsWith("0x") ? "evm" : "solana";
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Resolve the Solana RPC URL for a given convention chainId (101/102).
 * Falls back to mainnet-beta if the chainId isn't recognised.
 */
function resolveSolanaRpc(chainId?: number): string {
  return SOLANA_RPCS[chainId ?? 101] ?? SOLANA_RPCS[101];
}

export interface SignTransactionOptions {
  txId?: string;
  policyResults?: PolicyResult[];
  status?: TxStatus;
}

interface MnemonicWalletMaterial {
  evmPrivateKey: `0x${string}`;
  evmAddress: string;
  solanaSecretHex: string;
  solanaAddress: string;
}

export interface RestoreAgentFromMnemonicResult extends AgentIdentity {
  restoredExisting: boolean;
}

/**
 * Vault - the core signing service.
 *
 * Manages agent wallets: generates keypairs, stores encrypted private keys,
 * and signs transactions. The private key is decrypted only for the duration
 * of a signing operation and never exposed to agent containers.
 */
export class Vault {
  private keyStore: KeystoreBackend;
  private config: VaultConfig;

  constructor(config: VaultConfig) {
    this.config = config;
    this.keyStore =
      config.keystoreBackend ?? backendFromKeyStore(new KeyStore(config.masterPassword));
  }

  /**
   * Create a new agent wallet. Generates BOTH an EVM keypair AND a Solana keypair.
   * The EVM address is stored in `agents.walletAddress` for backwards compatibility.
   * Both addresses are stored in `agent_wallets` and both encrypted keys in
   * `encrypted_chain_keys`. The EVM key is also stored in the legacy
   * `encrypted_keys` table for backwards compatibility.
   *
   * @param chainType - Deprecated; ignored. Both chain families are always generated.
   */
  async createAgent(
    tenantId: string,
    agentId: string,
    name: string,
    platformId?: string,
    _chainType?: "evm" | "solana",
  ): Promise<AgentIdentity> {
    const db = getDb();
    const [existingAgent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (existingAgent) {
      throw new Error(`Agent ${agentId} already exists for tenant ${tenantId}`);
    }

    // ── Generate EVM keypair ─────────────────────────────────────────────
    const evmPrivateKey = generatePrivateKey();
    const evmAccount = privateKeyToAccount(evmPrivateKey);
    const evmAddress = evmAccount.address;

    // ── Generate Solana keypair ──────────────────────────────────────────
    const solKp = generateSolanaKeypair();
    const solanaAddress = solKp.publicKey;

    // ── Encrypt both keys ────────────────────────────────────────────────
    const evmEncrypted = await this.keyStore.encrypt(evmPrivateKey, {
      tenantId,
      agentId,
      chainFamily: "evm",
      venue: null,
    });
    const solEncrypted = await this.keyStore.encrypt(solKp.secretKey, {
      tenantId,
      agentId,
      chainFamily: "solana",
      venue: null,
    });

    const createdAt = new Date();

    // ── Persist all rows atomically - roll back everything on any failure ─
    await db.transaction(async (tx) => {
      // ── Persist agent row (walletAddress = EVM for backward compat) ────
      await tx.insert(agents).values({
        id: agentId,
        tenantId,
        name,
        walletAddress: evmAddress,
        platformId,
        createdAt,
        updatedAt: createdAt,
      });

      // ── Legacy encrypted_keys table (EVM key only, backward compat) ────
      await tx.insert(encryptedKeys).values({
        agentId,
        ciphertext: evmEncrypted.ciphertext,
        iv: evmEncrypted.iv,
        tag: evmEncrypted.tag,
        salt: evmEncrypted.salt,
      });

      // ── Multi-chain key storage ──────────────────────────────────────
      await tx.insert(encryptedChainKeys).values([
        {
          agentId,
          chainFamily: "evm",
          ciphertext: evmEncrypted.ciphertext,
          iv: evmEncrypted.iv,
          tag: evmEncrypted.tag,
          salt: evmEncrypted.salt,
        },
        {
          agentId,
          chainFamily: "solana",
          ciphertext: solEncrypted.ciphertext,
          iv: solEncrypted.iv,
          tag: solEncrypted.tag,
          salt: solEncrypted.salt,
        },
      ]);

      // ── Multi-chain public address storage ───────────────────────────
      await tx.insert(agentWallets).values([
        { agentId, chainFamily: "evm", address: evmAddress, createdAt },
        { agentId, chainFamily: "solana", address: solanaAddress, createdAt },
      ]);
    });

    return {
      id: agentId,
      tenantId,
      name,
      walletAddress: evmAddress,
      walletAddresses: { evm: evmAddress, solana: solanaAddress },
      platformId,
      createdAt,
    };
  }

  /**
   * Create a new agent wallet from a BIP-39 mnemonic.
   *
   * This is intentionally only for NEW agents: assigning a mnemonic to an
   * already-random wallet would create a false recovery guarantee. The caller
   * is responsible for showing the mnemonic exactly once and never persisting it.
   */
  async createAgentFromMnemonic(
    tenantId: string,
    agentId: string,
    name: string,
    mnemonic: string,
    options: { platformId?: string; passphrase?: string; walletType?: string } = {},
  ): Promise<AgentIdentity> {
    const db = getDb();
    const [existingAgent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (existingAgent) {
      throw new Error(`Agent ${agentId} already exists for tenant ${tenantId}`);
    }

    const material = await this.deriveMnemonicWalletMaterial(mnemonic, options.passphrase);

    const evmEncrypted = await this.keyStore.encrypt(material.evmPrivateKey, {
      tenantId,
      agentId,
      chainFamily: "evm",
      venue: null,
    });
    const solEncrypted = await this.keyStore.encrypt(material.solanaSecretHex, {
      tenantId,
      agentId,
      chainFamily: "solana",
      venue: null,
    });
    const createdAt = new Date();

    await db.transaction(async (tx) => {
      await tx.insert(agents).values({
        id: agentId,
        tenantId,
        name,
        walletAddress: material.evmAddress,
        platformId: options.platformId,
        walletType: options.walletType ?? "recoverable",
        createdAt,
        updatedAt: createdAt,
      });

      await tx.insert(encryptedKeys).values({
        agentId,
        ciphertext: evmEncrypted.ciphertext,
        iv: evmEncrypted.iv,
        tag: evmEncrypted.tag,
        salt: evmEncrypted.salt,
      });

      await tx.insert(encryptedChainKeys).values([
        {
          agentId,
          chainFamily: "evm",
          ciphertext: evmEncrypted.ciphertext,
          iv: evmEncrypted.iv,
          tag: evmEncrypted.tag,
          salt: evmEncrypted.salt,
        },
        {
          agentId,
          chainFamily: "solana",
          ciphertext: solEncrypted.ciphertext,
          iv: solEncrypted.iv,
          tag: solEncrypted.tag,
          salt: solEncrypted.salt,
        },
      ]);

      await tx.insert(agentWallets).values([
        { agentId, chainFamily: "evm", address: material.evmAddress, createdAt },
        { agentId, chainFamily: "solana", address: material.solanaAddress, createdAt },
      ]);
    });

    return {
      id: agentId,
      tenantId,
      name,
      walletAddress: material.evmAddress,
      walletAddresses: { evm: material.evmAddress, solana: material.solanaAddress },
      platformId: options.platformId,
      createdAt,
    };
  }

  private async deriveMnemonicWalletMaterial(
    mnemonic: string,
    passphrase?: string,
  ): Promise<MnemonicWalletMaterial> {
    const evmKey = await deriveEvmKey(mnemonic, { passphrase });
    const evmAddress = privateKeyToAccount(evmKey.privateKey).address;
    const solKey = await deriveSolanaKey(mnemonic, { passphrase });
    const solanaSecretHex = bytesToHex(solKey.secretKey);
    const solanaAddress = restoreSolanaKeypair(solanaSecretHex).publicKey.toBase58();
    return {
      evmPrivateKey: evmKey.privateKey,
      evmAddress,
      solanaSecretHex,
      solanaAddress,
    };
  }

  /**
   * Restore/import a mnemonic-backed agent wallet.
   *
   * Safe cases:
   *   - no agent exists: create the deterministic recoverable wallet;
   *   - a recoverable agent exists and the mnemonic derives the exact stored
   *     EVM/Solana identities: re-encrypt the derived keys for this deployment.
   *
   * Unsafe cases fail closed: an existing random/non-recoverable wallet or a
   * mnemonic whose derived addresses differ from the stored identity is refused.
   */
  async restoreAgentFromMnemonic(
    tenantId: string,
    agentId: string,
    name: string,
    mnemonic: string,
    options: { platformId?: string; passphrase?: string; walletType?: string } = {},
  ): Promise<RestoreAgentFromMnemonicResult> {
    const db = getDb();
    const [existingAgent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!existingAgent) {
      const created = await this.createAgentFromMnemonic(
        tenantId,
        agentId,
        name,
        mnemonic,
        options,
      );
      return { ...created, restoredExisting: false };
    }

    const walletType = existingAgent.walletType ?? "agent";
    const expectedType = options.walletType ?? "recoverable";
    if (walletType !== expectedType) {
      throw new Error("Existing wallet is not mnemonic-recoverable; refusing unsafe restore");
    }

    const material = await this.deriveMnemonicWalletMaterial(mnemonic, options.passphrase);
    const wallets = await db.select().from(agentWallets).where(eq(agentWallets.agentId, agentId));
    const evmWallet = wallets.find(
      (wallet) => wallet.chainFamily === "evm" && wallet.venue === null,
    );
    const solanaWallet = wallets.find(
      (wallet) => wallet.chainFamily === "solana" && wallet.venue === null,
    );

    if (existingAgent.walletAddress.toLowerCase() !== material.evmAddress.toLowerCase()) {
      throw new Error("Mnemonic does not match the existing wallet identity");
    }
    if (evmWallet && evmWallet.address.toLowerCase() !== material.evmAddress.toLowerCase()) {
      throw new Error("Mnemonic does not match the existing wallet identity");
    }
    if (solanaWallet && solanaWallet.address !== material.solanaAddress) {
      throw new Error("Mnemonic does not match the existing wallet identity");
    }

    const evmEncrypted = await this.keyStore.encrypt(material.evmPrivateKey, {
      tenantId,
      agentId,
      chainFamily: "evm",
      venue: null,
    });
    const solEncrypted = await this.keyStore.encrypt(material.solanaSecretHex, {
      tenantId,
      agentId,
      chainFamily: "solana",
      venue: null,
    });
    const now = new Date();

    await db.transaction(async (tx) => {
      await tx
        .update(agents)
        .set({
          walletAddress: material.evmAddress,
          platformId: options.platformId ?? existingAgent.platformId,
          updatedAt: now,
        })
        .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

      await tx
        .insert(encryptedKeys)
        .values({
          agentId,
          ciphertext: evmEncrypted.ciphertext,
          iv: evmEncrypted.iv,
          tag: evmEncrypted.tag,
          salt: evmEncrypted.salt,
        })
        .onConflictDoUpdate({
          target: encryptedKeys.agentId,
          set: {
            ciphertext: evmEncrypted.ciphertext,
            iv: evmEncrypted.iv,
            tag: evmEncrypted.tag,
            salt: evmEncrypted.salt,
          },
        });

      await tx
        .delete(encryptedChainKeys)
        .where(
          and(
            eq(encryptedChainKeys.agentId, agentId),
            inArray(encryptedChainKeys.chainFamily, ["evm", "solana"]),
            isNull(encryptedChainKeys.venue),
          ),
        );
      await tx.insert(encryptedChainKeys).values([
        {
          agentId,
          chainFamily: "evm",
          venue: null,
          ciphertext: evmEncrypted.ciphertext,
          iv: evmEncrypted.iv,
          tag: evmEncrypted.tag,
          salt: evmEncrypted.salt,
        },
        {
          agentId,
          chainFamily: "solana",
          venue: null,
          ciphertext: solEncrypted.ciphertext,
          iv: solEncrypted.iv,
          tag: solEncrypted.tag,
          salt: solEncrypted.salt,
        },
      ]);

      await tx
        .insert(agentWallets)
        .values([
          {
            agentId,
            chainFamily: "evm",
            venue: null,
            address: material.evmAddress,
            createdAt: now,
          },
          {
            agentId,
            chainFamily: "solana",
            venue: null,
            address: material.solanaAddress,
            createdAt: now,
          },
        ])
        .onConflictDoNothing();
    });

    const restored = await this.getAgent(tenantId, agentId);
    if (!restored) {
      throw new Error(`Restored wallet ${agentId} could not be fetched`);
    }
    return { ...restored, restoredExisting: true };
  }

  /**
   * Get an agent's public identity, including `walletAddresses` for agents
   * created with multi-wallet support.
   */
  async getAgent(tenantId: string, agentId: string): Promise<AgentIdentity | undefined> {
    const db = getDb();
    const [agent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!agent) return undefined;

    const identity = toAgentIdentity(agent) as AgentIdentity;
    const wallets = await db.select().from(agentWallets).where(eq(agentWallets.agentId, agentId));

    if (wallets.length > 0) {
      const addresses: { evm?: string; solana?: string } = {};
      for (const w of wallets) {
        if (w.chainFamily === "evm") addresses.evm = w.address;
        if (w.chainFamily === "solana") addresses.solana = w.address;
      }
      identity.walletAddresses = addresses;
    }

    return identity;
  }

  /**
   * List all agent identities for a tenant, including `walletAddresses`
   * for agents created with multi-wallet support.
   */
  async listAgents(
    tenantId: string,
    options: { limit?: number; offset?: number } = {},
  ): Promise<AgentIdentity[]> {
    const db = getDb();
    const limit = Math.min(Math.max(Math.floor(options.limit ?? 100), 1), 200);
    const offset = Math.min(Math.max(Math.floor(options.offset ?? 0), 0), 100_000);
    const rows = await db
      .select()
      .from(agents)
      .where(eq(agents.tenantId, tenantId))
      .limit(limit)
      .offset(offset);
    if (rows.length === 0) return [];

    const agentIds = rows.map((r) => r.id);
    const walletRows = await db
      .select()
      .from(agentWallets)
      .where(inArray(agentWallets.agentId, agentIds));

    // Build a map: agentId → { evm?, solana? }
    const walletMap = new Map<string, { evm?: string; solana?: string }>();
    for (const w of walletRows) {
      if (!walletMap.has(w.agentId)) walletMap.set(w.agentId, {});
      const entry = walletMap.get(w.agentId)!;
      if (w.chainFamily === "evm") entry.evm = w.address;
      if (w.chainFamily === "solana") entry.solana = w.address;
    }

    return rows.map((agent) => {
      const identity = toAgentIdentity(agent) as AgentIdentity;
      const addresses = walletMap.get(agent.id);
      if (addresses && Object.keys(addresses).length > 0) {
        identity.walletAddresses = addresses;
      }
      return identity;
    });
  }

  /**
   * List all agent identities for a tenant (alias for listAgents).
   */
  async listAgentsByTenant(
    tenantId: string,
    options: { limit?: number; offset?: number } = {},
  ): Promise<AgentIdentity[]> {
    return this.listAgents(tenantId, options);
  }

  /**
   * Get all wallet addresses for an agent across all chain families.
   * Returns a map of chainFamily → address.
   */
  async getAddresses(
    tenantId: string,
    agentId: string,
  ): Promise<Array<{ chainFamily: "evm" | "solana"; address: string }>> {
    const db = getDb();
    // Verify agent belongs to this tenant
    const [agent] = await db
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    if (!agent) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const wallets = await db.select().from(agentWallets).where(eq(agentWallets.agentId, agentId));

    // For legacy agents with no rows in agent_wallets, fall back to agents.walletAddress
    if (wallets.length === 0) {
      const [agentRow] = await db
        .select({ walletAddress: agents.walletAddress })
        .from(agents)
        .where(eq(agents.id, agentId));
      if (agentRow) {
        const chainFamily = detectChainType(agentRow.walletAddress);
        return [{ chainFamily, address: agentRow.walletAddress }];
      }
      return [];
    }

    return wallets.map((w) => ({
      chainFamily: w.chainFamily as "evm" | "solana",
      address: w.address,
    }));
  }

  /**
   * Sign a transaction. Decrypts the key, signs, then discards the key.
   * Routes to Solana or EVM based on chainId (101/102 = Solana, otherwise EVM).
   *
   * When `broadcast` is false (or request.broadcast is false), returns the
   * serialized signed transaction instead of broadcasting it.
   * Returns the transaction hash (when broadcast) or signed serialized tx (when not).
   */
  async signTransaction(
    request: SignRequest,
    options: SignTransactionOptions = {},
  ): Promise<string> {
    const db = getDb();

    // Verify agent exists for this tenant
    const [agentRow] = await db
      .select({ id: agents.id, walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, request.agentId), eq(agents.tenantId, request.tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    const chainId = request.chainId || this.config.chainId || 8453;
    // Determine chain family from chainId (101/102 = Solana)
    const isSolana = chainId === 101 || chainId === 102;
    const chainFamilyToUse = isSolana ? "solana" : "evm";
    const shouldBroadcast = request.broadcast !== false;

    // ── Resolve the correct signing key ─────────────────────────────────
    // 1. Try the multi-chain key table (new agents)
    // 2. Fall back to legacy single-key table (old EVM-only agents)
    let secretKey: string;
    const venue = resolveSignVenueSelector(request);
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, request.agentId),
          eq(encryptedChainKeys.chainFamily, chainFamilyToUse),
          venue ? eq(encryptedChainKeys.venue, venue) : isNull(encryptedChainKeys.venue),
        ),
      );

    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        {
          tenantId: request.tenantId,
          agentId: request.agentId,
          chainFamily: chainFamilyToUse,
          // Bind to the resolved venue selector so venue-scoped keys (provisioned
          // with the venue in their AAD context) decrypt correctly; null for the
          // default unscoped key.
          venue: chainKey.venue ?? venue,
        },
      );
    } else {
      if (venue) {
        throw missingSigningKeyError(request.agentId, chainFamilyToUse, venue);
      }
      // Fallback: legacy encrypted_keys table (EVM only)
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, request.agentId));
      if (!legacyKey) {
        throw missingSigningKeyError(request.agentId, chainFamilyToUse);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId: request.tenantId,
        agentId: request.agentId,
        chainFamily: chainFamilyToUse,
        venue: null,
      });
    }

    // Also resolve the wallet address for this chain (for Solana tx signing)
    let _walletAddress: string = agentRow.walletAddress; // default EVM
    if (isSolana) {
      const [solWallet] = await db
        .select({ address: agentWallets.address })
        .from(agentWallets)
        .where(
          and(
            eq(agentWallets.agentId, request.agentId),
            eq(agentWallets.chainFamily, "solana"),
            venue ? eq(agentWallets.venue, venue) : isNull(agentWallets.venue),
          ),
        );
      if (solWallet) _walletAddress = solWallet.address;
      else
        _walletAddress =
          detectChainType(agentRow.walletAddress) === "solana" ? agentRow.walletAddress : ""; // no solana wallet
    }

    let hash: string;

    if (isSolana) {
      if (request.walletAddress && _walletAddress) {
        if (_walletAddress.toLowerCase() !== request.walletAddress.toLowerCase()) {
          throw new Error(
            `Wallet address mismatch: resolved ${_walletAddress} but request specified ${request.walletAddress}`,
          );
        }
      }
      const rpcUrl = this.config.rpcUrl ?? resolveSolanaRpc(chainId);
      hash = await signSolanaTransaction(secretKey, request.to, BigInt(request.value), rpcUrl, {
        broadcast: shouldBroadcast,
      });
    } else {
      assertEvmWalletAddressMatches(secretKey, request.walletAddress);
      const account = privateKeyToAccount(secretKey as `0x${string}`);
      const chain = CHAINS[chainId];
      if (!chain) {
        throw new Error(`Unsupported EVM chain: ${chainId}`);
      }

      if (shouldBroadcast) {
        // Use chain-specific RPC. Prior versions fell back to
        // `this.config.rpcUrl` which is tenant-wide and may not match
        // the target chain (e.g. Steward config pointed at Base but
        // the tx is for BSC), causing RPC-side balance checks to fail
        // with 'total cost exceeds balance' (wrong chain's balance).
        const rpcUrl = CHAIN_RPCS[chainId] ?? this.config.rpcUrl;
        const client = createWalletClient({
          account,
          chain,
          transport: http(rpcUrl),
        });

        hash = await client.sendTransaction({
          to: request.to as `0x${string}`,
          value: BigInt(request.value),
          data: request.data as `0x${string}` | undefined,
          gas: request.gasLimit ? BigInt(request.gasLimit) : undefined,
        });
      } else {
        // Sign without broadcasting - return the serialized signed transaction
        const rpcUrl = CHAIN_RPCS[chainId] ?? this.config.rpcUrl;
        const publicClient = createPublicClient({
          chain,
          transport: http(rpcUrl),
        });
        const nonce =
          request.nonce ??
          (await publicClient.getTransactionCount({
            address: account.address,
          }));
        const gasPrice = await publicClient.getGasPrice();

        const txRequest: TransactionSerializable = {
          to: request.to as `0x${string}`,
          value: BigInt(request.value),
          data: request.data as `0x${string}` | undefined,
          gas: request.gasLimit ? BigInt(request.gasLimit) : 21000n,
          nonce,
          gasPrice,
          chainId,
        };

        hash = await account.signTransaction(txRequest);
      }
    }

    const txId = options.txId ?? crypto.randomUUID();
    const signedAt = new Date();
    const [existingTransaction] = await db
      .select({ agentId: transactions.agentId })
      .from(transactions)
      .where(eq(transactions.id, txId));
    if (existingTransaction && existingTransaction.agentId !== request.agentId) {
      throw new Error("Transaction id already belongs to a different agent");
    }

    await db
      .insert(transactions)
      .values({
        id: txId,
        agentId: request.agentId,
        status: shouldBroadcast ? (options.status ?? "signed") : "signed",
        toAddress: request.to,
        value: request.value,
        data: request.data,
        chainId,
        txHash: shouldBroadcast ? hash : undefined,
        policyResults: options.policyResults ?? [],
        signedAt,
        createdAt: signedAt,
      })
      .onConflictDoUpdate({
        target: transactions.id,
        set: {
          agentId: request.agentId,
          status: shouldBroadcast ? (options.status ?? "signed") : "signed",
          toAddress: request.to,
          value: request.value,
          data: request.data,
          chainId,
          txHash: shouldBroadcast ? hash : undefined,
          policyResults: options.policyResults ?? [],
          signedAt,
        },
      });

    return hash;
  }

  /**
   * Get the on-chain native balance for an agent's wallet.
   * Auto-detects EVM vs Solana from the wallet address format.
   * For Solana, pass chainId 101 (mainnet-beta) or 102 (devnet).
   */
  async getBalance(
    tenantId: string,
    agentId: string,
    chainId?: number,
  ): Promise<{
    native: bigint;
    nativeFormatted: string;
    chainId: number;
    symbol: string;
    walletAddress: string;
  }> {
    const agent = await this.getAgent(tenantId, agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    // For multi-wallet agents, chainId 101/102 requests Solana balance
    // For legacy agents, fall back to detecting from walletAddress format
    const requestedSolana = chainId === 101 || chainId === 102;
    const solanaAddress =
      agent.walletAddresses?.solana ??
      (detectChainType(agent.walletAddress) === "solana" ? agent.walletAddress : undefined);
    const isSolana =
      requestedSolana ||
      (!chainId && Boolean(solanaAddress) && detectChainType(agent.walletAddress) === "solana");

    if (isSolana && solanaAddress) {
      const resolvedChainId = chainId ?? 101;
      const rpcUrl = this.config.rpcUrl ?? resolveSolanaRpc(resolvedChainId);
      const { lamports, formatted } = await getSolanaBalance(solanaAddress, rpcUrl);
      return {
        native: lamports,
        nativeFormatted: formatted,
        chainId: resolvedChainId,
        symbol: "SOL",
        walletAddress: solanaAddress,
      };
    }

    const resolvedChainId = chainId && !requestedSolana ? chainId : (this.config.chainId ?? 8453);
    const chain = CHAINS[resolvedChainId];
    if (!chain) {
      throw new Error(`Unsupported EVM chain: ${resolvedChainId}`);
    }

    const evmAddress = agent.walletAddresses?.evm ?? agent.walletAddress;
    const rpcUrl = CHAIN_RPCS[resolvedChainId] ?? this.config.rpcUrl;
    const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
    const native = await publicClient.getBalance({
      address: evmAddress as `0x${string}`,
    });

    return {
      native,
      nativeFormatted: formatEther(native),
      chainId: resolvedChainId,
      symbol: chain.nativeCurrency.symbol,
      walletAddress: evmAddress,
    };
  }

  /**
   * Get ERC-20 token balances for an agent's EVM wallet on a given chain.
   *
   * @param tenantId - The tenant that owns the agent
   * @param agentId  - The agent whose wallet to query
   * @param chainId  - EVM chain ID (defaults to config chainId or 8453)
   * @param tokens   - Optional custom token contract addresses. If omitted, uses common tokens.
   * @returns Array of token balances including symbol, decimals, and formatted amounts.
   */
  async getTokenBalances(
    tenantId: string,
    agentId: string,
    chainId?: number,
    tokens?: string[],
  ): Promise<TokenBalance[]> {
    const agent = await this.getAgent(tenantId, agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const resolvedChainId = chainId ?? this.config.chainId ?? 8453;
    const evmAddress = agent.walletAddresses?.evm ?? agent.walletAddress;
    const rpcUrl = CHAIN_RPCS[resolvedChainId] ?? this.config.rpcUrl;

    return fetchTokenBalances(evmAddress, resolvedChainId, tokens, rpcUrl);
  }

  /**
   * Import an existing private key into the vault for an agent.
   * Creates the agent record if it doesn't exist, or updates the key if it does.
   * Returns the derived public address.
   *
   * @param chainType - "evm" or "solana"
   */
  async importKey(
    tenantId: string,
    agentId: string,
    privateKey: string,
    chainType: "evm" | "solana",
  ): Promise<{ walletAddress: string }> {
    const db = getDb();

    let walletAddress: string;

    let keyToStore = privateKey;

    if (chainType === "solana") {
      // For Solana, the private key should be a 64-byte hex string (seed + pubkey)
      // or a 32-byte hex seed - we'll handle both
      const kp = restoreSolanaKeypair(privateKey);
      walletAddress = kp.publicKey.toBase58();
    } else {
      // EVM - expect 0x-prefixed hex private key
      const normalizedKey = privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`;
      const account = privateKeyToAccount(normalizedKey as `0x${string}`);
      walletAddress = account.address;
      keyToStore = normalizedKey;
    }

    const encryptedKey = await this.keyStore.encrypt(keyToStore, {
      tenantId,
      agentId,
      chainFamily: chainType,
      venue: null,
    });
    const now = new Date();

    // Check if agent already exists
    const [existingAgent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    // Wrap all writes atomically - roll back on any failure
    await db.transaction(async (tx) => {
      if (existingAgent) {
        // Update wallet address and replace encrypted key
        await tx
          .update(agents)
          .set({ walletAddress, updatedAt: now })
          .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

        await tx.delete(encryptedKeys).where(eq(encryptedKeys.agentId, agentId));

        await tx.insert(encryptedKeys).values({
          agentId,
          ciphertext: encryptedKey.ciphertext,
          iv: encryptedKey.iv,
          tag: encryptedKey.tag,
          salt: encryptedKey.salt,
        });
      } else {
        // Create new agent record
        await tx.insert(agents).values({
          id: agentId,
          tenantId,
          name: agentId,
          walletAddress,
          createdAt: now,
          updatedAt: now,
        });

        await tx.insert(encryptedKeys).values({
          agentId,
          ciphertext: encryptedKey.ciphertext,
          iv: encryptedKey.iv,
          tag: encryptedKey.tag,
          salt: encryptedKey.salt,
        });
      }

      // ── Also write to multi-wallet tables so new signing paths find the key ─
      // Upsert into encrypted_chain_keys (replace if key already imported).
      // Sprint 4: target the partial unique index on (agent_id, chain_family)
      // WHERE venue IS NULL so this only conflicts with the legacy row, not
      // with venue-scoped wallets that share the same chain family.
      await tx
        .insert(encryptedChainKeys)
        .values({
          agentId,
          chainFamily: chainType,
          venue: null,
          ciphertext: encryptedKey.ciphertext,
          iv: encryptedKey.iv,
          tag: encryptedKey.tag,
          salt: encryptedKey.salt,
        })
        .onConflictDoUpdate({
          target: [encryptedChainKeys.agentId, encryptedChainKeys.chainFamily],
          targetWhere: sql`${encryptedChainKeys.venue} IS NULL`,
          set: {
            ciphertext: encryptedKey.ciphertext,
            iv: encryptedKey.iv,
            tag: encryptedKey.tag,
            salt: encryptedKey.salt,
          },
        });

      // Upsert into agent_wallets, same partial-index target.
      await tx
        .insert(agentWallets)
        .values({
          agentId,
          chainFamily: chainType,
          venue: null,
          address: walletAddress,
          createdAt: now,
        })
        .onConflictDoUpdate({
          target: [agentWallets.agentId, agentWallets.chainFamily],
          targetWhere: sql`${agentWallets.venue} IS NULL`,
          set: { address: walletAddress },
        });
    });

    return { walletAddress };
  }

  /**
   * Sign an arbitrary message. Routes to Solana Ed25519 or EVM ECDSA
   * based on the agent's wallet address format.
   */
  async signMessage(tenantId: string, agentId: string, message: string): Promise<string> {
    const db = getDb();

    // Verify agent exists for this tenant
    const [agentRow] = await db
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const isSolana = detectChainType(agentRow.walletAddress) === "solana";
    const chainFamilyToUse = isSolana ? "solana" : "evm";

    // Resolve signing key: prefer encryptedChainKeys (multi-wallet), fall back to legacy encryptedKeys
    let secretKey: string;
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, chainFamilyToUse),
          // Sprint 4: legacy lookup, NULL-venue only.
          isNull(encryptedChainKeys.venue),
        ),
      );

    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        { tenantId, agentId, chainFamily: chainFamilyToUse, venue: null },
      );
    } else {
      // Fallback: legacy encrypted_keys table
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, agentId));
      if (!legacyKey) {
        throw new Error(`No signing key found for agent ${agentId}`);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId,
        agentId,
        chainFamily: chainFamilyToUse,
        venue: null,
      });
    }

    if (isSolana) {
      return signSolanaMessage(secretKey, message);
    }

    const account = privateKeyToAccount(secretKey as `0x${string}`);
    const signature = await account.signMessage({ message });
    return signature;
  }

  /**
   * Sign a pre-hashed 32-byte EVM digest with the agent's secp256k1 key.
   * This is intentionally lower-level than signMessage and must remain guarded
   * at API edges because raw signatures bypass transaction/message semantics.
   */
  async signRawHash(
    tenantId: string,
    agentId: string,
    hash: `0x${string}`,
  ): Promise<{ signature: string; hash: `0x${string}`; walletAddress: string }> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
      throw new Error("hash must be a 32-byte hex string");
    }

    const db = getDb();
    const [agentRow] = await db
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }
    if (detectChainType(agentRow.walletAddress) !== "evm") {
      throw new Error("Raw secp256k1 signing requires an EVM agent");
    }

    let secretKey: string;
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, "evm"),
          isNull(encryptedChainKeys.venue),
        ),
      );

    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        { tenantId, agentId, chainFamily: "evm", venue: null },
      );
    } else {
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, agentId));
      if (!legacyKey) {
        throw new Error(`No EVM signing key for agent ${agentId}`);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId,
        agentId,
        chainFamily: "evm",
        venue: null,
      });
    }

    const account = privateKeyToAccount(secretKey as `0x${string}`);
    return {
      signature: await account.sign({ hash }),
      hash,
      walletAddress: account.address,
    };
  }

  /**
   * Sign a raw 32-byte digest across signature curves. This is the cross-curve
   * generalization of {@link signRawHash} and is intentionally lower-level than
   * the transaction/message signers — it MUST stay guarded at API edges because
   * raw signatures bypass transaction and message policy semantics.
   *
   * Curve dispatch (all require an exactly-32-byte payload so the edge cannot be
   * abused to blind-sign a full transaction message):
   *  - `secp256k1` → agent's EVM key, recoverable ECDSA via viem `account.sign`.
   *  - `ed25519`   → agent's Solana key, detached Ed25519 over the 32 bytes.
   *  - `stark`     → fail closed. No vetted starknet curve library is installed,
   *                  and hand-rolling curve crypto in a money path is unacceptable.
   */
  async signRawDigest(
    tenantId: string,
    agentId: string,
    curve: "secp256k1" | "ed25519" | "stark",
    payloadHex: string,
  ): Promise<{
    signature: string;
    curve: "secp256k1" | "ed25519";
    payloadHex: `0x${string}`;
    publicKey: string;
  }> {
    if (curve === "stark") {
      throw new Error(
        "stark curve raw signing is disabled: no vetted starknet signing library is installed",
      );
    }
    if (curve !== "secp256k1" && curve !== "ed25519") {
      throw new Error(`Unsupported raw-sign curve: ${String(curve)}`);
    }

    // Normalize + validate: a raw digest is exactly 32 bytes (64 hex chars).
    const normalized = payloadHex.startsWith("0x") ? payloadHex.slice(2) : payloadHex;
    if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
      throw new Error("payloadHex must be a 32-byte hex string");
    }
    const payloadHex0x = `0x${normalized.toLowerCase()}` as `0x${string}`;

    const db = getDb();
    const [agentRow] = await db
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    if (!agentRow) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    // Curve selects which key family signs: secp256k1 → the agent's EVM key,
    // ed25519 → the agent's Solana key. An agent provisioned via createAgent
    // owns both, so we resolve the requested family directly rather than gating
    // on the agent's "primary" wallet address. The tenant scoping above is the
    // authorization boundary (the encrypted-key tables are keyed by agentId).
    const chainFamily = curve === "secp256k1" ? "evm" : "solana";

    let secretKey: string;
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, chainFamily),
          isNull(encryptedChainKeys.venue),
        ),
      );
    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        { tenantId, agentId, chainFamily, venue: null },
      );
    } else if (curve === "secp256k1") {
      // Legacy encrypted_keys holds the EVM key only — a safe fallback for
      // secp256k1. NEVER fall back here for ed25519: it would decrypt the EVM
      // key under a Solana chainFamily context and produce a bogus signer.
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, agentId));
      if (!legacyKey) {
        throw new Error(`No evm signing key for agent ${agentId}`);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId,
        agentId,
        chainFamily: "evm",
        venue: null,
      });
    } else {
      throw new Error(`No solana signing key for agent ${agentId}`);
    }

    if (curve === "ed25519") {
      // Decode the validated 64-char hex to 32 bytes without depending on the
      // Buffer global (vault.ts otherwise avoids Node globals).
      const payloadBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        payloadBytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
      }
      const { signature, publicKey } = signEd25519Digest(secretKey, payloadBytes);
      return { signature, curve, payloadHex: payloadHex0x, publicKey };
    }

    const account = privateKeyToAccount(secretKey as `0x${string}`);
    return {
      signature: await account.sign({ hash: payloadHex0x }),
      curve,
      payloadHex: payloadHex0x,
      publicKey: account.address,
    };
  }

  /**
   * Sign an EIP-7702 set-code authorization. Lets an EOA temporarily delegate
   * execution to smart-contract code per transaction (Pectra, May 2025).
   * Returns { contractAddress, chainId, nonce, r, s, yParity, v } which the
   * caller attaches to the `authorizationList` of a type-4 transaction.
   *
   * Per EIP-7702, signing chainId=0 designates "any chain" - useful when the
   * delegation target is chain-agnostic. The vault accepts 0 explicitly so
   * callers can opt in; default is the chainId on the request.
   */
  async signAuthorization(
    tenantId: string,
    agentId: string,
    params: { contractAddress: `0x${string}`; chainId: number; nonce: number },
  ): Promise<{
    contractAddress: `0x${string}`;
    chainId: number;
    nonce: number;
    r: `0x${string}`;
    s: `0x${string}`;
    yParity: 0 | 1;
  }> {
    if (!/^0x[0-9a-fA-F]{40}$/.test(params.contractAddress)) {
      throw new Error("contractAddress must be a 20-byte hex address");
    }
    if (!Number.isInteger(params.chainId) || params.chainId < 0) {
      throw new Error("chainId must be a non-negative integer (0 = any chain)");
    }
    if (!Number.isInteger(params.nonce) || params.nonce < 0) {
      throw new Error("nonce must be a non-negative integer");
    }

    const db = getDb();
    const [agentRow] = await db
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    if (!agentRow) throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    if (detectChainType(agentRow.walletAddress) !== "evm") {
      throw new Error("signAuthorization requires an EVM agent");
    }

    let secretKey: string;
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, "evm"),
          isNull(encryptedChainKeys.venue),
        ),
      );
    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        { tenantId, agentId, chainFamily: "evm", venue: null },
      );
    } else {
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, agentId));
      if (!legacyKey) throw new Error(`No EVM signing key for agent ${agentId}`);
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId,
        agentId,
        chainFamily: "evm",
        venue: null,
      });
    }

    const account = privateKeyToAccount(secretKey as `0x${string}`);
    const signed = await account.signAuthorization({
      contractAddress: params.contractAddress,
      chainId: params.chainId,
      nonce: params.nonce,
    });
    return {
      contractAddress: params.contractAddress,
      chainId: params.chainId,
      nonce: params.nonce,
      r: signed.r as `0x${string}`,
      s: signed.s as `0x${string}`,
      yParity: signed.yParity as 0 | 1,
    };
  }

  /**
   * Sign EIP-712 typed data (`eth_signTypedData_v4`).
   * Used for DEX approvals, ERC-20 permits, and structured data signatures.
   */
  async signTypedData(request: SignTypedDataRequest): Promise<string> {
    const db = getDb();

    // Verify agent exists for this tenant
    const [agentRow] = await db
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, request.agentId), eq(agents.tenantId, request.tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    if (detectChainType(agentRow.walletAddress) === "solana") {
      throw new Error("EIP-712 typed data signing is not supported for Solana wallets");
    }

    // Resolve signing key: prefer encryptedChainKeys (multi-wallet), scoped by
    // venue when requested, then fall back to legacy encryptedKeys only for
    // legacy NULL-venue requests.
    let secretKey: string;
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, request.agentId),
          eq(encryptedChainKeys.chainFamily, "evm"),
          request.venue
            ? eq(encryptedChainKeys.venue, request.venue)
            : isNull(encryptedChainKeys.venue),
        ),
      );

    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        {
          tenantId: request.tenantId,
          agentId: request.agentId,
          chainFamily: "evm",
          venue: request.venue ?? null,
        },
      );
    } else {
      if (request.venue) {
        throw new Error(
          `No signing key found for agent ${request.agentId} on venue ${request.venue}`,
        );
      }
      // Fallback: legacy encrypted_keys table
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, request.agentId));
      if (!legacyKey) {
        throw new Error(`No signing key found for agent ${request.agentId}`);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId: request.tenantId,
        agentId: request.agentId,
        chainFamily: "evm",
        venue: null,
      });
    }

    const account = privateKeyToAccount(secretKey as `0x${string}`);

    const signature = await account.signTypedData({
      domain: {
        name: request.domain.name,
        version: request.domain.version,
        chainId: request.domain.chainId,
        verifyingContract: request.domain.verifyingContract as `0x${string}` | undefined,
        salt: request.domain.salt as `0x${string}` | undefined,
      },
      types: request.types as Record<string, Array<{ name: string; type: string }>>,
      primaryType: request.primaryType,
      message: request.value,
    });

    return signature;
  }

  /**
   * Sign an ERC-4337 EntryPoint v0.7 user operation hash with the agent's EVM key.
   * The signature is EIP-191-prefixed, which matches common account implementations.
   */
  async signUserOperation(request: {
    agentId: string;
    tenantId: string;
    userOperation: UnpackedUserOperationFields;
    entryPoint?: `0x${string}`;
    chainId: number;
  }): Promise<{
    signature: string;
    userOperationHash: string;
    entryPoint: string;
    chainId: number;
  }> {
    const db = getDb();

    const [agentRow] = await db
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, request.agentId), eq(agents.tenantId, request.tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    if (detectChainType(agentRow.walletAddress) === "solana") {
      throw new Error("ERC-4337 user operation signing is not supported for Solana wallets");
    }

    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, request.agentId),
          eq(encryptedChainKeys.chainFamily, "evm"),
          isNull(encryptedChainKeys.venue),
        ),
      );

    let secretKey: string;
    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        { tenantId: request.tenantId, agentId: request.agentId, chainFamily: "evm", venue: null },
      );
    } else {
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, request.agentId));
      if (!legacyKey) {
        throw new Error(`No signing key found for agent ${request.agentId}`);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId: request.tenantId,
        agentId: request.agentId,
        chainFamily: "evm",
        venue: null,
      });
    }

    const entryPoint = request.entryPoint ?? ENTRY_POINT_V07;
    const packed = packUserOperation(request.userOperation);
    const userOperationHash = getUserOperationHash(packed, entryPoint, request.chainId);
    const account = privateKeyToAccount(secretKey as `0x${string}`);
    const signature = await account.signMessage({ message: { raw: userOperationHash } });

    return {
      signature,
      userOperationHash,
      entryPoint,
      chainId: request.chainId,
    };
  }

  /**
   * Sign a serialized Solana transaction.
   * Accepts a base64-encoded transaction, signs it with the agent's Ed25519 key,
   * and optionally broadcasts it.
   *
   * Works for both multi-wallet agents (new) and legacy Solana-only agents.
   */
  async signSolanaTransaction(request: SignSolanaTransactionRequest): Promise<{
    signature: string;
    broadcast: boolean;
    chainId: number;
    caip2?: string;
  }> {
    const db = getDb();

    // Verify agent exists
    const [agentRow] = await db
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, request.agentId), eq(agents.tenantId, request.tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    // Resolve Solana key: prefer encryptedChainKeys (multi-wallet), fall back to
    // legacy encryptedKeys when the agent has a Solana walletAddress.
    let secretKey: string;
    const [chainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, request.agentId),
          eq(encryptedChainKeys.chainFamily, "solana"),
          isNull(encryptedChainKeys.venue),
        ),
      );

    if (chainKey) {
      secretKey = await this.keyStore.decrypt(
        {
          ciphertext: chainKey.ciphertext,
          iv: chainKey.iv,
          tag: chainKey.tag,
          salt: chainKey.salt,
        },
        {
          tenantId: request.tenantId,
          agentId: request.agentId,
          chainFamily: "solana",
          venue: null,
        },
      );
    } else {
      // Legacy path: only works if the walletAddress is a Solana address
      if (detectChainType(agentRow.walletAddress) !== "solana") {
        throw new Error(
          "Solana transaction signing requires a Solana wallet. This agent only has an EVM wallet.",
        );
      }
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, request.agentId));
      if (!legacyKey) {
        throw new Error(`No Solana signing key found for agent ${request.agentId}`);
      }
      secretKey = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
        tenantId: request.tenantId,
        agentId: request.agentId,
        chainFamily: "solana",
        venue: null,
      });
    }

    const keypair = restoreSolanaKeypair(secretKey);
    const chainId = request.chainId ?? 101;
    const rpcUrl = this.config.rpcUrl ?? resolveSolanaRpc(chainId);
    const shouldBroadcast = request.broadcast !== false;

    // Deserialize the transaction (legacy OR v0/versioned). A versioned message
    // sets the high bit of its first byte; legacy Transaction.from() throws on it
    // ("Versioned messages must be deserialized with VersionedMessage..."), so
    // every v0 tx — the modern default, mandatory for address-lookup-table DeFi
    // like Jupiter — would 500 at signing after passing the (version-aware)
    // policy gate. Branch on the version byte so both shapes sign.
    const {
      Transaction: SolTransaction,
      VersionedTransaction,
      Connection,
    } = await import("@solana/web3.js");
    const txBytes = Uint8Array.from(atob(request.transaction), (c) => c.charCodeAt(0));

    const requireEnvelope = (): { to: string; lamports: bigint } | null => {
      if (request.expectedTo === undefined && request.expectedValue === undefined) return null;
      if (request.expectedTo === undefined || request.expectedValue === undefined) {
        throw new Error("Solana transaction policy envelope requires expectedTo and expectedValue");
      }
      return { to: request.expectedTo, lamports: BigInt(request.expectedValue) };
    };

    let signedBytes: Uint8Array;
    if (isVersionedTransactionBytes(txBytes)) {
      const vtx = VersionedTransaction.deserialize(txBytes);
      const envelope = requireEnvelope();
      if (envelope) {
        // The byte-level legacy assertion can't read a v0 message; verify the
        // envelope via the version-aware parser instead.
        assertParsedSolanaTransferMatches(request.transaction, envelope);
      }
      vtx.sign([keypair]);
      signedBytes = vtx.serialize();
    } else {
      const tx = SolTransaction.from(txBytes);
      const envelope = requireEnvelope();
      if (envelope) {
        assertSolanaTransferTransactionMatches(tx, {
          from: keypair.publicKey,
          to: envelope.to,
          lamports: envelope.lamports,
        });
      }
      tx.partialSign(keypair);
      signedBytes = tx.serialize();
    }

    if (shouldBroadcast) {
      const connection = new Connection(rpcUrl, "confirmed");
      const sig = await connection.sendRawTransaction(signedBytes, {
        skipPreflight: false,
        preflightCommitment: "confirmed",
      });

      const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
      await connection.confirmTransaction(
        { signature: sig, blockhash, lastValidBlockHeight },
        "confirmed",
      );

      return {
        signature: sig,
        broadcast: true,
        chainId,
        caip2: toCaip2(chainId),
      };
    }

    // Return serialized signed transaction as base64
    const serialized = btoa(Array.from(signedBytes, (b) => String.fromCharCode(b)).join(""));
    return {
      signature: serialized,
      broadcast: false,
      chainId,
      caip2: toCaip2(chainId),
    };
  }

  /**
   * Export the decrypted private keys for an agent.
   * Returns both EVM and Solana keys where available.
   * The caller is responsible for securing the returned material.
   */
  async exportPrivateKey(
    tenantId: string,
    agentId: string,
    authorization?: ExportPrivateKeyAuthorization,
  ): Promise<{
    evm?: { privateKey: string; address: string };
    solana?: { privateKey: string; address: string };
  }> {
    // Defense-in-depth: this returns plaintext key material, so it must never be
    // invoked casually. Require an explicit break-glass authorization context that
    // the (admin + MFA + audited) caller constructs, and emit a log entry every time.
    if (!authorization?.breakGlass || !authorization.actorId?.trim()) {
      throw new Error(
        "exportPrivateKey requires an explicit break-glass authorization { breakGlass: true, actorId }",
      );
    }
    console.warn(
      `[Vault] BREAK-GLASS private key export: tenant=${tenantId} agent=${agentId} actor=${authorization.actorId} reason=${authorization.reason ?? "unspecified"}`,
    );

    const db = getDb();

    // Verify agent belongs to this tenant
    const [agentRow] = await db
      .select({ id: agents.id, tenantId: agents.tenantId })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!agentRow) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const result: {
      evm?: { privateKey: string; address: string };
      solana?: { privateKey: string; address: string };
    } = {};

    // ── Get EVM key (prefer multi-chain table, fall back to legacy) ──────
    const [evmChainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, "evm"),
          isNull(encryptedChainKeys.venue),
        ),
      );

    if (evmChainKey) {
      const pk = await this.keyStore.decrypt(
        {
          ciphertext: evmChainKey.ciphertext,
          iv: evmChainKey.iv,
          tag: evmChainKey.tag,
          salt: evmChainKey.salt,
        },
        { tenantId, agentId, chainFamily: "evm", venue: null },
      );
      const [evmWallet] = await db
        .select({ address: agentWallets.address })
        .from(agentWallets)
        .where(
          and(
            eq(agentWallets.agentId, agentId),
            eq(agentWallets.chainFamily, "evm"),
            isNull(agentWallets.venue),
          ),
        );
      result.evm = {
        privateKey: pk,
        address: evmWallet?.address ?? privateKeyToAccount(pk as `0x${string}`).address,
      };
    } else {
      // Legacy: encrypted_keys table (EVM only)
      const [legacyKey] = await db
        .select()
        .from(encryptedKeys)
        .where(eq(encryptedKeys.agentId, agentId));
      if (legacyKey) {
        const pk = await this.keyStore.decrypt(legacyKey as EncryptedKey, {
          tenantId,
          agentId,
          chainFamily: "evm",
          venue: null,
        });
        result.evm = {
          privateKey: pk,
          address: privateKeyToAccount(pk as `0x${string}`).address,
        };
      }
    }

    // ── Get Solana key ───────────────────────────────────────────────────
    const [solChainKey] = await db
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, "solana"),
          isNull(encryptedChainKeys.venue),
        ),
      );

    if (solChainKey) {
      const pk = await this.keyStore.decrypt(
        {
          ciphertext: solChainKey.ciphertext,
          iv: solChainKey.iv,
          tag: solChainKey.tag,
          salt: solChainKey.salt,
        },
        { tenantId, agentId, chainFamily: "solana", venue: null },
      );
      const [solWallet] = await db
        .select({ address: agentWallets.address })
        .from(agentWallets)
        .where(
          and(
            eq(agentWallets.agentId, agentId),
            eq(agentWallets.chainFamily, "solana"),
            isNull(agentWallets.venue),
          ),
        );
      result.solana = { privateKey: pk, address: solWallet?.address ?? "" };
    }

    return result;
  }

  /**
   * Proxy a read-only RPC call to the appropriate chain provider.
   * Supports both EVM and Solana RPC methods.
   */
  async rpcPassthrough(request: RpcRequest): Promise<RpcResponse> {
    const chainId = request.chainId;
    const isSolana = chainId === 101 || chainId === 102;

    let rpcUrl: string;
    if (isSolana) {
      rpcUrl = SOLANA_RPCS[chainId] ?? SOLANA_RPCS[101];
    } else {
      rpcUrl = CHAIN_RPCS[chainId] ?? this.config.rpcUrl ?? "";
    }

    if (!rpcUrl) {
      throw new Error(`No RPC URL configured for chainId ${chainId}`);
    }

    // Block signing/state-modifying methods - this is read-only passthrough
    const blockedMethods = [
      "eth_sendTransaction",
      "eth_sendRawTransaction",
      "eth_sign",
      "personal_sign",
      "eth_signTypedData",
      "eth_signTypedData_v4",
      "sendTransaction",
    ];
    if (blockedMethods.includes(request.method)) {
      throw new Error(
        `Method ${request.method} is not allowed via RPC passthrough - use the signing endpoints`,
      );
    }

    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: request.method,
        params: request.params ?? [],
      }),
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    return (await response.json()) as RpcResponse;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Sprint 4 Phase 1 Day 1: venue-scoped wallet API
  // ──────────────────────────────────────────────────────────────────────
  //
  // Wallets used to be keyed by (agentId, chainFamily). Trade-sessions now
  // need to address them per (agentId, venue) because Sol's BSC wallet
  // and Sol's Hyperliquid wallet sit on the same chainFamily (EVM) but
  // must hold distinct keys. `venue` is optional: legacy callers still
  // pass `chainId` (mapped to chainFamily), which resolves to the
  // NULL-venue row written by `createAgent`.

  /**
   * Look up a wallet for an agent.
   *
   * Priority:
   *   1. If `venue` is provided, return the row with that exact venue. If
   *      no row matches, throw - we never silently downgrade to a legacy
   *      wallet when a venue was explicitly requested.
   *   2. If only `chainId` is provided, map to chainFamily and return the
   *      legacy (venue IS NULL) row for that family. This preserves
   *      backward compat for @stwd/agent-trader and direct SDK callers.
   *
   * Throws if neither is provided, or if no matching row exists.
   */
  async getWallet(args: { agentId: string; venue?: string; chainId?: number }): Promise<{
    agentId: string;
    chainFamily: "evm" | "solana";
    venue: string | null;
    purpose: string | null;
    address: string;
  }> {
    const { agentId, venue, chainId } = args;
    if (!venue && chainId === undefined) {
      throw new Error("getWallet requires either `venue` or `chainId`");
    }

    const db = getDb();

    if (venue) {
      const [row] = await db
        .select()
        .from(agentWallets)
        .where(and(eq(agentWallets.agentId, agentId), eq(agentWallets.venue, venue)));

      if (!row) {
        throw new Error(`No wallet found for agent ${agentId} on venue ${venue}`);
      }
      return {
        agentId: row.agentId,
        chainFamily: row.chainFamily as "evm" | "solana",
        venue: row.venue,
        purpose: row.purpose,
        address: row.address,
      };
    }

    // Legacy fallback: chainId → chainFamily, then look up the NULL-venue row.
    const chainFamily = chainIdToChainFamily(chainId as number);
    const [row] = await db
      .select()
      .from(agentWallets)
      .where(
        and(
          eq(agentWallets.agentId, agentId),
          eq(agentWallets.chainFamily, chainFamily),
          isNull(agentWallets.venue),
        ),
      );

    if (!row) {
      throw new Error(`No legacy wallet found for agent ${agentId} on chain family ${chainFamily}`);
    }
    return {
      agentId: row.agentId,
      chainFamily: row.chainFamily as "evm" | "solana",
      venue: row.venue,
      purpose: row.purpose,
      address: row.address,
    };
  }

  /**
   * Provision a fresh, venue-scoped wallet for an agent with default safety
   * policies attached in the same DB transaction.
   *
   * This is the preferred onboarding path for venue wallets: the wallet is
   * never born without its venue allowlist, leverage cap, spend limits, and
   * withdrawal destination allowlist enabled.
   */
  async provisionVenueWallet(args: {
    tenantId: string;
    agentId: string;
    venue: string;
    chainFamily: "evm" | "solana";
    approvedAddresses: string[];
  }): Promise<{ address: string }> {
    const { tenantId, agentId, venue, chainFamily, approvedAddresses } = args;
    if (!tenantId) throw new Error("provisionVenueWallet requires a tenantId");
    if (!agentId) throw new Error("provisionVenueWallet requires an agentId");
    if (!venue) throw new Error("provisionVenueWallet requires a venue");
    if (chainFamily !== "evm" && chainFamily !== "solana") {
      throw new Error(`provisionVenueWallet: unsupported chainFamily ${chainFamily}`);
    }
    if (!Array.isArray(approvedAddresses)) {
      throw new Error("provisionVenueWallet requires approvedAddresses");
    }

    const db = getDb();

    const [agentRow] = await db
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    if (!agentRow) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    let address: string;
    let secret: string;
    if (chainFamily === "evm") {
      const pk = generatePrivateKey();
      const account = privateKeyToAccount(pk);
      address = account.address;
      secret = pk;
    } else {
      const kp = generateSolanaKeypair();
      address = kp.publicKey;
      secret = kp.secretKey;
    }

    const encrypted = await this.keyStore.encrypt(secret);
    const createdAt = new Date();
    const policyRows = [
      {
        id: randomUUID(),
        agentId,
        type: "leverage-cap" as const,
        enabled: true,
        config: { maxLeverage: 5 },
      },
      {
        id: randomUUID(),
        agentId,
        type: "venue-allowlist" as const,
        enabled: true,
        config: { allowedVenues: [venue] },
      },
      {
        id: randomUUID(),
        agentId,
        type: "spending-limit" as const,
        enabled: true,
        config: { maxPerTxUsd: 2000, maxPerDayUsd: 2000, maxPerWeekUsd: 5000 },
      },
      {
        id: randomUUID(),
        agentId,
        type: "approved-addresses" as const,
        enabled: true,
        config: { addresses: approvedAddresses, mode: "whitelist" },
      },
    ];

    await db.transaction(async (tx) => {
      await tx.insert(encryptedChainKeys).values({
        agentId,
        chainFamily,
        venue,
        purpose: "venue",
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        tag: encrypted.tag,
        salt: encrypted.salt,
      });

      await tx.insert(agentWallets).values({
        agentId,
        chainFamily,
        venue,
        purpose: "venue",
        address,
        createdAt,
      });

      await tx.insert(policies).values(policyRows);
    });

    return { address };
  }

  /**
   * Provision a fresh, venue-scoped wallet for an agent.
   *
   * Generates a new keypair (EVM via viem's `generatePrivateKey`, Solana
   * via Ed25519 in @solana/web3.js), encrypts the secret under the
   * vault's master KDF (AES-256-GCM + scrypt), and writes one row to
   * `agent_wallets` plus one to `encrypted_chain_keys`.
   *
   * Venue uniqueness is enforced by the DB index on
   * (agent_id, chain_family, COALESCE(venue, '')). A duplicate venue
   * request rejects at the DB layer.
   *
   * Returns the new public address. The private key is NEVER returned
   * and NEVER logged.
   */
  async createWallet(args: {
    agentId: string;
    venue: string;
    chainType: "evm" | "solana";
    purpose?: string;
  }): Promise<{
    agentId: string;
    chainFamily: "evm" | "solana";
    venue: string;
    purpose: string | null;
    address: string;
  }> {
    const { agentId, venue, chainType, purpose } = args;
    if (!venue) throw new Error("createWallet requires a venue");
    if (chainType !== "evm" && chainType !== "solana") {
      throw new Error(`createWallet: unsupported chainType ${chainType}`);
    }

    const db = getDb();

    // Verify the agent exists. Surfacing a clear error here beats a
    // foreign-key violation from Postgres.
    const [agentRow] = await db
      .select({ id: agents.id, tenantId: agents.tenantId })
      .from(agents)
      .where(eq(agents.id, agentId));
    if (!agentRow) {
      throw new Error(`Agent ${agentId} not found`);
    }

    let address: string;
    let secret: string;
    if (chainType === "evm") {
      const pk = generatePrivateKey();
      const account = privateKeyToAccount(pk);
      address = account.address;
      secret = pk;
    } else {
      const kp = generateSolanaKeypair();
      address = kp.publicKey;
      secret = kp.secretKey;
    }

    const encrypted = await this.keyStore.encrypt(secret, {
      tenantId: agentRow.tenantId,
      agentId,
      chainFamily: chainType,
      venue,
    });
    const createdAt = new Date();

    await db.transaction(async (tx) => {
      await tx.insert(encryptedChainKeys).values({
        agentId,
        chainFamily: chainType,
        venue,
        purpose: purpose ?? null,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        tag: encrypted.tag,
        salt: encrypted.salt,
      });

      await tx.insert(agentWallets).values({
        agentId,
        chainFamily: chainType,
        venue,
        purpose: purpose ?? null,
        address,
        createdAt,
      });
    });

    return {
      agentId,
      chainFamily: chainType,
      venue,
      purpose: purpose ?? null,
      address,
    };
  }

  /**
   * List every wallet an agent owns, across venues and chain families.
   * Used by the agent dashboard and by Worker A's trade-sessions package
   * to enumerate available trading surfaces.
   *
   * Legacy NULL-venue rows are included. Order: legacy first, then
   * venue-scoped, by creation time ascending.
   */
  async listWallets(args: { agentId: string }): Promise<
    Array<{
      agentId: string;
      chainFamily: "evm" | "solana";
      venue: string | null;
      purpose: string | null;
      address: string;
      createdAt: Date;
    }>
  > {
    const { agentId } = args;
    const db = getDb();

    const rows = await db
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, agentId))
      .orderBy(sql`${agentWallets.venue} NULLS FIRST`, agentWallets.createdAt);

    return rows.map((row) => ({
      agentId: row.agentId,
      chainFamily: row.chainFamily as "evm" | "solana",
      venue: row.venue,
      purpose: row.purpose,
      address: row.address,
      createdAt: row.createdAt,
    }));
  }
}

/**
 * Map an EVM chainId (or 101/102 for Solana) to its chain family.
 * Exposed at module scope so non-method callers (tests) can use it.
 */
function chainIdToChainFamily(chainId: number): "evm" | "solana" {
  if (chainId === 101 || chainId === 102) return "solana";
  return "evm";
}
