/**
 * ERC-8004: Agent Commerce Protocol — core type definitions.
 *
 * These types model the on-chain identity registry, reputation layer,
 * and discovery protocol defined in ERC-8004.
 */

/** Describes an agent's public identity card stored on-chain or off-chain (IPFS / HTTP). */
export interface AgentCard {
  name: string;
  description: string;
  walletAddress: string;
  apiUrl: string;
  capabilities: string[];
  services: string[];
}

/** Result returned after successfully registering an agent on-chain. */
export interface RegistrationResult {
  tokenId: string;
  txHash: string;
  chainId: number;
  registryAddress: string;
  agentCardUri: string;
  /**
   * True only when the registration was confirmed against a real, configured
   * on-chain registry. Callers MUST NOT treat the result as authoritative when
   * this is false.
   */
  verified: boolean;
}

/**
 * Aggregated reputation for a registered agent.
 *
 * `verified` is true only when the score was read from a real, configured
 * on-chain reputation registry. When false, the numeric `score*` fields are
 * absent (undefined) — they must never be presented as authoritative on-chain
 * data and must not be displayed as a real "score of 0".
 */
export interface ReputationScore {
  agentId: string;
  verified: boolean;
  scoreOnchain?: number;
  scoreInternal?: number;
  scoreCombined?: number;
  feedbackCount?: number;
  lastUpdated: string;
}

/** A single feedback signal submitted by one address about an agent. */
export interface FeedbackSignal {
  fromAddress: string;
  toAgentTokenId: string;
  /** 1 (worst) to 5 (best). */
  score: 1 | 2 | 3 | 4 | 5;
  comment: string;
  taskId: string;
  timestamp: string;
}

/** Configuration for a specific chain's ERC-8004 registry deployment. */
export interface RegistryConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  registryAddress: string;
}
