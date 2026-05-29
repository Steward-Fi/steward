/**
 * ERC-8004 identity registry client.
 *
 * Real on-chain contract calls are not yet implemented (the registry contracts
 * are not deployed and no real registry addresses exist). Rather than silently
 * returning fabricated data that callers could mistake for verified on-chain
 * state, the mutating/lookup methods refuse to operate when no real registry is
 * configured.
 */

import { isRegistryConfigured } from "./chains";
import type { AgentCard, RegistrationResult, RegistryConfig } from "./types";

export class IdentityRegistryClient {
  readonly config: RegistryConfig;

  constructor(config: RegistryConfig) {
    this.config = config;
  }

  /**
   * True only when this client points at a real, deployed registry. While this
   * is false, no method will produce data that may be treated as on-chain
   * verified.
   */
  isConfigured(): boolean {
    return isRegistryConfigured(this.config);
  }

  /** Build an AgentCard from partial inputs. Pure — safe regardless of config. */
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
   * Register an agent on-chain. Refuses to fabricate a registration when no
   * real registry is configured — returning a fake tokenId / zero txHash would
   * let callers believe an on-chain registration occurred when none did.
   */
  async register(_agentCard: AgentCard, _privateKey?: string): Promise<RegistrationResult> {
    if (!this.isConfigured()) {
      throw new Error(
        "ERC8004 registry not configured — refusing to fabricate registration. " +
          `chainId=${this.config.chainId} registryAddress=${this.config.registryAddress}`,
      );
    }
    // Real on-chain registration is not yet implemented.
    throw new Error("ERC8004 on-chain registration is not yet implemented");
  }

  /**
   * Look up a registration. Returns null = "unknown / not verified on-chain".
   * Callers must treat null as unverified, never as "confirmed registered".
   */
  async getRegistration(_tokenId: string): Promise<AgentCard | null> {
    if (!this.isConfigured()) return null;
    // Real on-chain lookup is not yet implemented; nothing verified to return.
    return null;
  }
}
