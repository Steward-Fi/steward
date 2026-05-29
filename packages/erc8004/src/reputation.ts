/**
 * ERC-8004 reputation registry client.
 *
 * Real on-chain reputation reads/writes are not yet implemented. To avoid
 * presenting fabricated numbers as verified on-chain reputation, this client
 * refuses to write and returns an explicitly-unverified score (with no numeric
 * fields) when no real registry is configured.
 */

import { isRegistryConfigured } from "./chains";
import type { FeedbackSignal, RegistryConfig, ReputationScore } from "./types";

export class ReputationRegistryClient {
  readonly config: RegistryConfig;

  constructor(config: RegistryConfig) {
    this.config = config;
  }

  /** True only when this client points at a real, deployed registry. */
  isConfigured(): boolean {
    return isRegistryConfigured(this.config);
  }

  /**
   * Submit feedback on-chain. Refuses to return a fake success hash when no
   * real registry is configured — a zero hash would falsely signal that
   * feedback was committed on-chain.
   */
  async postFeedback(_params: FeedbackSignal): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error(
        "ERC8004 reputation registry not configured — refusing to fabricate feedback submission. " +
          `chainId=${this.config.chainId} registryAddress=${this.config.registryAddress}`,
      );
    }
    throw new Error("ERC8004 on-chain feedback submission is not yet implemented");
  }

  /**
   * Read aggregated reputation. When no real registry is configured (or until
   * on-chain reads are implemented), returns a result flagged `verified: false`
   * with NO numeric score fields. Callers must not present this as an
   * authoritative on-chain score — in particular it must never be shown as a
   * real "score of 0".
   */
  async getReputation(agentTokenId: string): Promise<ReputationScore> {
    return {
      agentId: agentTokenId,
      verified: false,
      lastUpdated: new Date().toISOString(),
    };
  }

  /** Return no history until on-chain feedback events are indexed. */
  async getFeedbackHistory(_agentTokenId: string, _limit?: number): Promise<FeedbackSignal[]> {
    return [];
  }
}
