import { and, eq } from "drizzle-orm";
import { createPublicClient, createWalletClient, formatEther, http, type Chain } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { arbitrum, base, baseSepolia, bsc, bscTestnet, mainnet, polygon } from "viem/chains";

import {
  agents,
  encryptedKeys,
  getDb,
  toAgentIdentity,
  transactions,
} from "@stwd/db";
import type { PolicyResult, SignRequest, TxStatus, AgentIdentity } from "@stwd/shared";

import { KeyStore, type EncryptedKey } from "./keystore";
import {
  generateSolanaKeypair,
  getSolanaBalance,
  restoreSolanaKeypair,
  signSolanaMessage,
  signSolanaTransaction,
} from "./solana";

export interface VaultConfig {
  masterPassword: string;
  rpcUrl?: string;
  chainId?: number;
}

const CHAINS: Record<number, Chain> = {
  1: mainnet,        // Ethereum
  56: bsc,           // BSC
  97: bscTestnet,    // BSC Testnet
  137: polygon,      // Polygon
  8453: base,        // Base
  42161: arbitrum,    // Arbitrum
  84532: baseSepolia, // Base Sepolia
};

// Default public RPC URLs per EVM chain (override with env / VaultConfig.rpcUrl for the active chain)
const CHAIN_RPCS: Record<number, string> = {
  1: "https://eth.llamarpc.com",
  56: "https://bsc-dataseed.binance.org",
  97: "https://data-seed-prebsc-1-s1.bnbchain.org:8545",
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

/**
 * Detect chain type from wallet address format.
 * EVM addresses start with "0x"; Solana addresses are base58 (no "0x" prefix).
 */
function detectChainType(walletAddress: string): "evm" | "solana" {
  return walletAddress.startsWith("0x") ? "evm" : "solana";
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

/**
 * Vault — the core signing service.
 *
 * Manages agent wallets: generates keypairs, stores encrypted private keys,
 * and signs transactions. The private key is decrypted only for the duration
 * of a signing operation and never exposed to agent containers.
 */
export class Vault {
  private keyStore: KeyStore;
  private config: VaultConfig;

  constructor(config: VaultConfig) {
    this.config = config;
    this.keyStore = new KeyStore(config.masterPassword);
  }

  /**
   * Create a new agent wallet. Returns the public identity (never the private key).
   *
   * @param chainType - "evm" (default) for EVM chains, "solana" for Solana Ed25519 keypair.
   */
  async createAgent(
    tenantId: string,
    agentId: string,
    name: string,
    platformId?: string,
    chainType?: "evm" | "solana"
  ): Promise<AgentIdentity> {
    const db = getDb();
    const [existingAgent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (existingAgent) {
      throw new Error(`Agent ${agentId} already exists for tenant ${tenantId}`);
    }

    let walletAddress: string;
    let secretKeyToStore: string;

    if (chainType === "solana") {
      const kp = generateSolanaKeypair();
      walletAddress = kp.publicKey;
      secretKeyToStore = kp.secretKey;
    } else {
      const privateKey = generatePrivateKey();
      const account = privateKeyToAccount(privateKey);
      walletAddress = account.address;
      secretKeyToStore = privateKey;
    }

    const encryptedKey = this.keyStore.encrypt(secretKeyToStore);

    const createdAt = new Date();
    await db.insert(agents).values({
      id: agentId,
      tenantId,
      name,
      walletAddress,
      platformId,
      createdAt,
      updatedAt: createdAt,
    });

    await db.insert(encryptedKeys).values({
      agentId,
      ciphertext: encryptedKey.ciphertext,
      iv: encryptedKey.iv,
      tag: encryptedKey.tag,
      salt: encryptedKey.salt,
    });

    return {
      id: agentId,
      tenantId,
      name,
      walletAddress,
      platformId,
      createdAt,
    };
  }

  /**
   * Get an agent's public identity
   */
  async getAgent(tenantId: string, agentId: string): Promise<AgentIdentity | undefined> {
    const db = getDb();
    const [agent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    return agent ? toAgentIdentity(agent) : undefined;
  }

  /**
   * List all agent identities
   */
  async listAgents(tenantId: string): Promise<AgentIdentity[]> {
    const db = getDb();
    const rows = await db.select().from(agents).where(eq(agents.tenantId, tenantId));
    return rows.map(toAgentIdentity);
  }

  /**
   * List all agent identities for a tenant
   */
  async listAgentsByTenant(tenantId: string): Promise<AgentIdentity[]> {
    return this.listAgents(tenantId);
  }

  /**
   * Sign a transaction. Decrypts the key, signs, then discards the key.
   * Routes to Solana or EVM based on chainId (101/102 = Solana, otherwise EVM).
   * Returns the transaction hash / signature.
   */
  async signTransaction(
    request: SignRequest,
    options: SignTransactionOptions = {}
  ): Promise<string> {
    const db = getDb();
    const [stored] = await db
      .select({
        agentId: agents.id,
        tenantId: agents.tenantId,
        walletAddress: agents.walletAddress,
        encryptedKey: encryptedKeys,
      })
      .from(agents)
      .innerJoin(encryptedKeys, eq(encryptedKeys.agentId, agents.id))
      .where(and(eq(agents.id, request.agentId), eq(agents.tenantId, request.tenantId)));

    if (!stored) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    const secretKey = this.keyStore.decrypt(stored.encryptedKey as EncryptedKey);
    const chainId = request.chainId || this.config.chainId || 8453;
    const isSolana = detectChainType(stored.walletAddress) === "solana";

    let hash: string;

    if (isSolana) {
      const rpcUrl = this.config.rpcUrl ?? resolveSolanaRpc(chainId);
      hash = await signSolanaTransaction(
        secretKey,
        request.to,
        BigInt(request.value),
        rpcUrl
      );
    } else {
      const account = privateKeyToAccount(secretKey as `0x${string}`);
      const chain = CHAINS[chainId];
      if (!chain) {
        throw new Error(`Unsupported EVM chain: ${chainId}`);
      }

      const client = createWalletClient({
        account,
        chain,
        transport: http(this.config.rpcUrl),
      });

      hash = await client.sendTransaction({
        to: request.to as `0x${string}`,
        value: BigInt(request.value),
        data: request.data as `0x${string}` | undefined,
        gas: request.gasLimit ? BigInt(request.gasLimit) : undefined,
      });
    }

    const txId = options.txId ?? crypto.randomUUID();
    const signedAt = new Date();

    await db
      .insert(transactions)
      .values({
        id: txId,
        agentId: request.agentId,
        status: options.status ?? "signed",
        toAddress: request.to,
        value: request.value,
        data: request.data,
        chainId,
        txHash: hash,
        policyResults: options.policyResults ?? [],
        signedAt,
        createdAt: signedAt,
      })
      .onConflictDoUpdate({
        target: transactions.id,
        set: {
          agentId: request.agentId,
          status: options.status ?? "signed",
          toAddress: request.to,
          value: request.value,
          data: request.data,
          chainId,
          txHash: hash,
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
    chainId?: number
  ): Promise<{ native: bigint; nativeFormatted: string; chainId: number; symbol: string; walletAddress: string }> {
    const agent = await this.getAgent(tenantId, agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const isSolana = detectChainType(agent.walletAddress) === "solana";

    if (isSolana) {
      const resolvedChainId = chainId ?? 101;
      const rpcUrl = this.config.rpcUrl ?? resolveSolanaRpc(resolvedChainId);
      const { lamports, formatted } = await getSolanaBalance(agent.walletAddress, rpcUrl);
      return {
        native: lamports,
        nativeFormatted: formatted,
        chainId: resolvedChainId,
        symbol: "SOL",
        walletAddress: agent.walletAddress,
      };
    }

    const resolvedChainId = chainId ?? this.config.chainId ?? 8453;
    const chain = CHAINS[resolvedChainId];
    if (!chain) {
      throw new Error(`Unsupported EVM chain: ${resolvedChainId}`);
    }

    const rpcUrl = CHAIN_RPCS[resolvedChainId] ?? this.config.rpcUrl;
    const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
    const native = await publicClient.getBalance({ address: agent.walletAddress as `0x${string}` });

    return {
      native,
      nativeFormatted: formatEther(native),
      chainId: resolvedChainId,
      symbol: chain.nativeCurrency.symbol,
      walletAddress: agent.walletAddress,
    };
  }

  /**
   * Sign an arbitrary message. Routes to Solana Ed25519 or EVM ECDSA
   * based on the agent's wallet address format.
   */
  async signMessage(tenantId: string, agentId: string, message: string): Promise<string> {
    const db = getDb();
    const [stored] = await db
      .select({
        walletAddress: agents.walletAddress,
        encryptedKey: encryptedKeys,
      })
      .from(agents)
      .innerJoin(encryptedKeys, eq(encryptedKeys.agentId, agents.id))
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!stored) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const secretKey = this.keyStore.decrypt(stored.encryptedKey as EncryptedKey);
    const isSolana = detectChainType(stored.walletAddress) === "solana";

    if (isSolana) {
      return signSolanaMessage(secretKey, message);
    }

    const account = privateKeyToAccount(secretKey as `0x${string}`);
    const signature = await account.signMessage({ message });
    return signature;
  }
}
