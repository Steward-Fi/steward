/**
 * ERC-8004 Identity Registry client.
 *
 * Handles agent card creation and on-chain registration.
 * Current implementation is stubbed — contract calls will replace the mocks
 * once the registry contract is deployed.
 */

import type { AgentCard, RegistrationResult, RegistryConfig } from "./types";

export class IdentityRegistryClient {
  readonly config: RegistryConfig;

  constructor(config: RegistryConfig) {
    this.config = config;
  }

  /** Build a well-formed AgentCard from partial inputs. */
  buildAgentCard(params: {
    name: string;
    description: string;
    walletAddress: string;
    apiUrl: string;
    capabilities?: string[];
    services?: string[];
  }): AgentCard {
    return {
      name: params.name,
      description: params.description,
      walletAddress: params.walletAddress,
      apiUrl: params.apiUrl,
      capabilities: params.capabilities ?? [],
      services: params.services ?? [],
    };
  }

  /**
   * Register an agent on-chain.
   *
   * TODO: Replace stub with actual contract interaction (ethers/viem).
   * The flow will be: upload AgentCard JSON to IPFS, call registry.register(tokenURI),
   * then return the minted token ID and tx hash.
   */
  async register(
    _agentCard: AgentCard,
    _privateKey?: string,
  ): Promise<RegistrationResult> {
    // TODO: Implement actual on-chain registration
    const mockTokenId = `0x${Date.now().toString(16)}`;
    return {
      tokenId: mockTokenId,
      txHash: `0x${"0".repeat(64)}`,
      chainId: this.config.chainId,
      registryAddress: this.config.registryAddress,
      agentCardUri: `ipfs://placeholder/${mockTokenId}`,
    };
  }

  /**
   * Look up an existing registration by token ID.
   *
   * TODO: Replace stub with registry.tokenURI(tokenId) call + JSON fetch.
   */
  async getRegistration(_tokenId: string): Promise<AgentCard | null> {
    // TODO: Implement actual on-chain lookup
    return null;
  }
}
