import { and, eq } from "drizzle-orm";
import { createWalletClient, http, type Chain } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";

import {
  agents,
  encryptedKeys,
  getDb,
  toAgentIdentity,
  transactions,
} from "@steward/db";
import type { PolicyResult, SignRequest, TxStatus, AgentIdentity } from "@steward/shared";

import { KeyStore, type EncryptedKey } from "./keystore";

export interface VaultConfig {
  masterPassword: string;
  rpcUrl?: string;
  chainId?: number;
}

const CHAINS: Record<number, Chain> = {
  8453: base,
  84532: baseSepolia,
};

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
   */
  async createAgent(
    tenantId: string,
    agentId: string,
    name: string,
    platformId?: string
  ): Promise<AgentIdentity> {
    const db = getDb();
    const [existingAgent] = await db
      .select()
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (existingAgent) {
      throw new Error(`Agent ${agentId} already exists for tenant ${tenantId}`);
    }

    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);
    const encryptedKey = this.keyStore.encrypt(privateKey);

    const createdAt = new Date();
    await db.insert(agents).values({
      id: agentId,
      tenantId,
      name,
      walletAddress: account.address,
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
      walletAddress: account.address,
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
   * Returns the signed transaction hash.
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
        encryptedKey: encryptedKeys,
      })
      .from(agents)
      .innerJoin(encryptedKeys, eq(encryptedKeys.agentId, agents.id))
      .where(and(eq(agents.id, request.agentId), eq(agents.tenantId, request.tenantId)));

    if (!stored) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    const privateKey = this.keyStore.decrypt(
      stored.encryptedKey as EncryptedKey
    ) as `0x${string}`;
    const account = privateKeyToAccount(privateKey);

    const chainId = request.chainId || this.config.chainId || 8453;
    const chain = CHAINS[chainId];
    if (!chain) {
      throw new Error(`Unsupported chain: ${chainId}`);
    }

    const client = createWalletClient({
      account,
      chain,
      transport: http(this.config.rpcUrl),
    });

    const hash = await client.sendTransaction({
      to: request.to as `0x${string}`,
      value: BigInt(request.value),
      data: request.data as `0x${string}` | undefined,
      gas: request.gasLimit ? BigInt(request.gasLimit) : undefined,
    });

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
   * Sign arbitrary data (for ERC-8004 registration, etc.)
   */
  async signMessage(tenantId: string, agentId: string, message: string): Promise<string> {
    const db = getDb();
    const [stored] = await db
      .select({
        encryptedKey: encryptedKeys,
      })
      .from(agents)
      .innerJoin(encryptedKeys, eq(encryptedKeys.agentId, agents.id))
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));

    if (!stored) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const privateKey = this.keyStore.decrypt(
      stored.encryptedKey as EncryptedKey
    ) as `0x${string}`;
    const account = privateKeyToAccount(privateKey);

    const signature = await account.signMessage({ message });
    return signature;
  }
}
