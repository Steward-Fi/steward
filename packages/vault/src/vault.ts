import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createWalletClient, http, type Chain } from "viem";
import { base, baseSepolia } from "viem/chains";
import { KeyStore, type EncryptedKey } from "./keystore";
import type { AgentIdentity, SignRequest } from "@steward/shared";

export interface VaultConfig {
  masterPassword: string;
  rpcUrl?: string;
  chainId?: number;
}

interface StoredAgent {
  identity: AgentIdentity;
  encryptedKey: EncryptedKey;
}

const CHAINS: Record<number, Chain> = {
  8453: base,
  84532: baseSepolia,
};

/**
 * Vault — the core signing service.
 *
 * Manages agent wallets: generates keypairs, stores encrypted private keys,
 * and signs transactions. The private key is decrypted only for the duration
 * of a signing operation and never exposed to agent containers.
 */
export class Vault {
  private keyStore: KeyStore;
  private agents: Map<string, StoredAgent> = new Map();
  private config: VaultConfig;

  constructor(config: VaultConfig) {
    this.config = config;
    this.keyStore = new KeyStore(config.masterPassword);
  }

  /**
   * Create a new agent wallet. Returns the public identity (never the private key).
   */
  createAgent(tenantId: string, agentId: string, name: string, platformId?: string): AgentIdentity {
    const scopedAgentId = this.getScopedAgentKey(tenantId, agentId);
    if (this.agents.has(scopedAgentId)) {
      throw new Error(`Agent ${agentId} already exists for tenant ${tenantId}`);
    }

    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);

    const identity: AgentIdentity = {
      id: agentId,
      tenantId,
      name,
      walletAddress: account.address,
      platformId,
      createdAt: new Date(),
    };

    const encryptedKey = this.keyStore.encrypt(privateKey);

    this.agents.set(scopedAgentId, { identity, encryptedKey });

    return identity;
  }

  /**
   * Get an agent's public identity
   */
  getAgent(tenantId: string, agentId: string): AgentIdentity | undefined {
    return this.agents.get(this.getScopedAgentKey(tenantId, agentId))?.identity;
  }

  /**
   * List all agent identities
   */
  listAgents(): AgentIdentity[] {
    return Array.from(this.agents.values()).map((a) => a.identity);
  }

  /**
   * List all agent identities for a tenant
   */
  listAgentsByTenant(tenantId: string): AgentIdentity[] {
    return this.listAgents().filter((agent) => agent.tenantId === tenantId);
  }

  /**
   * Sign a transaction. Decrypts the key, signs, then discards the key.
   * Returns the signed transaction hash.
   */
  async signTransaction(request: SignRequest): Promise<string> {
    const stored = this.agents.get(this.getScopedAgentKey(request.tenantId, request.agentId));
    if (!stored) {
      throw new Error(`Agent ${request.agentId} not found for tenant ${request.tenantId}`);
    }

    // Decrypt key (ephemeral)
    const privateKey = this.keyStore.decrypt(stored.encryptedKey) as `0x${string}`;
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

    return hash;
  }

  /**
   * Sign arbitrary data (for ERC-8004 registration, etc.)
   */
  async signMessage(tenantId: string, agentId: string, message: string): Promise<string> {
    const stored = this.agents.get(this.getScopedAgentKey(tenantId, agentId));
    if (!stored) {
      throw new Error(`Agent ${agentId} not found for tenant ${tenantId}`);
    }

    const privateKey = this.keyStore.decrypt(stored.encryptedKey) as `0x${string}`;
    const account = privateKeyToAccount(privateKey);

    const signature = await account.signMessage({ message });
    return signature;
  }

  private getScopedAgentKey(tenantId: string, agentId: string): string {
    return `${tenantId}:${agentId}`;
  }
}
