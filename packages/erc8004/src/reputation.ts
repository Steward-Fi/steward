/**
 * ERC-8004 Reputation Registry client.
 *
 * Handles feedback submission and reputation score lookups.
 * Current implementation is stubbed — contract calls will replace the mocks
 * once the reputation contract is deployed.
 */

import type { FeedbackSignal, RegistryConfig, ReputationScore } from "./types";

export class ReputationRegistryClient {
  readonly config: RegistryConfig;

  constructor(config: RegistryConfig) {
    this.config = config;
  }

  /**
   * Submit a feedback signal for an agent.
   *
   * TODO: Replace stub with on-chain feedback submission.
   * Returns the transaction hash.
   */
  async postFeedback(_params: FeedbackSignal): Promise<string> {
    // TODO: Implement actual on-chain feedback submission
    return `0x${"0".repeat(64)}`;
  }

  /**
   * Get the aggregated reputation score for an agent.
   *
   * TODO: Replace stub with on-chain reputation lookup + internal score merge.
   */
  async getReputation(agentTokenId: string): Promise<ReputationScore> {
    // TODO: Implement actual reputation lookup
    return {
      agentId: agentTokenId,
      scoreOnchain: 0,
      scoreInternal: 0,
      scoreCombined: 0,
      feedbackCount: 0,
      lastUpdated: new Date().toISOString(),
    };
  }

  /**
   * Retrieve feedback history for an agent.
   *
   * TODO: Replace stub with event log query from the reputation contract.
   */
  async getFeedbackHistory(_agentTokenId: string, _limit?: number): Promise<FeedbackSignal[]> {
    // TODO: Implement actual feedback history lookup
    return [];
  }
}
