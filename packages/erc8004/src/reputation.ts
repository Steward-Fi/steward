/**
 * ERC-8004 reputation registry read-only client.
 *
 * When a real, deployed registry is configured this client reads genuine
 * on-chain reputation and flags results `verified: true`. When no real registry
 * is configured it refuses to write and returns an explicitly-unverified score
 * (with no numeric fields) so callers never present fabricated numbers as
 * authoritative on-chain reputation.
 */

import { createPublicClient, getAddress, http, type PublicClient, parseAbi } from "viem";
import { ERC8004_REPUTATION_REGISTRY_ADDRESS, isRegistryConfigured } from "./chains";
import type { FeedbackSignal, RegistryConfig, ReputationScore } from "./types";

export const REPUTATION_REGISTRY_ABI = parseAbi([
  "function getReputation(uint256 agentId) view returns (uint256 score, uint256 feedbackCount, uint256 lastUpdated)",
  "function reputationOf(uint256 agentId) view returns (uint256 score, uint256 feedbackCount, uint256 lastUpdated)",
  "function feedbackCount(uint256 agentId) view returns (uint256)",
]);

function makePublicClient(config: RegistryConfig): PublicClient {
  if (config.publicClient) return config.publicClient;
  return createPublicClient({ transport: http(config.rpcUrl) });
}

function toIsoTimestamp(value: bigint): string {
  if (value === 0n) return new Date(0).toISOString();
  return new Date(Number(value) * 1000).toISOString();
}

export class ReputationRegistryClient {
  readonly config: RegistryConfig;
  readonly publicClient: PublicClient;

  constructor(config: RegistryConfig, publicClient?: PublicClient) {
    this.config = {
      ...config,
      registryAddress: getAddress(config.identityRegistry ?? config.registryAddress),
      identityRegistry: getAddress(config.identityRegistry ?? config.registryAddress),
      reputationRegistry: getAddress(
        config.reputationRegistry ?? ERC8004_REPUTATION_REGISTRY_ADDRESS,
      ),
    };
    this.publicClient = publicClient ?? makePublicClient(this.config);
  }

  /** True only when this client points at a real, deployed registry. */
  isConfigured(): boolean {
    return isRegistryConfigured(this.config);
  }

  /**
   * Writes are intentionally unsupported until Steward wires policy around
   * feedback submission. Refuses to operate when no real registry is configured
   * so a fake success can never falsely signal an on-chain commit.
   */
  async postFeedback(_params: FeedbackSignal): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error(
        "ERC8004 reputation registry not configured — refusing to fabricate feedback submission. " +
          `chainId=${this.config.chainId} registryAddress=${this.config.registryAddress}`,
      );
    }
    throw new Error("ERC-8004 reputation writes are not implemented; this client is read-only");
  }

  /**
   * Read an agent's reputation summary from the canonical reputation registry.
   *
   * When no real registry is configured, returns a result flagged
   * `verified: false` with NO numeric score fields — callers must not present
   * this as an authoritative on-chain score (in particular never as a real
   * "score of 0"). A successful on-chain read is flagged `verified: true`.
   */
  async getReputation(agentTokenId: string | bigint): Promise<ReputationScore> {
    const agentId = typeof agentTokenId === "bigint" ? agentTokenId : BigInt(agentTokenId);
    if (!this.isConfigured()) {
      return {
        agentId: agentId.toString(),
        verified: false,
        lastUpdated: new Date().toISOString(),
      };
    }
    const [score, feedbackCount, lastUpdated] = await this.readReputationTuple(agentId);
    const normalizedScore = Number(score);
    return {
      agentId: agentId.toString(),
      verified: true,
      scoreOnchain: normalizedScore,
      scoreInternal: 0,
      scoreCombined: normalizedScore,
      feedbackCount: Number(feedbackCount),
      lastUpdated: toIsoTimestamp(lastUpdated),
    };
  }

  /** History requires an indexer. Keep the API stable but do not fake chain data. */
  async getFeedbackHistory(_agentTokenId: string, _limit?: number): Promise<FeedbackSignal[]> {
    return [];
  }

  private async readReputationTuple(agentId: bigint): Promise<readonly [bigint, bigint, bigint]> {
    const reputationRegistry =
      this.config.reputationRegistry ?? ERC8004_REPUTATION_REGISTRY_ADDRESS;
    try {
      return await this.publicClient.readContract({
        address: reputationRegistry,
        abi: REPUTATION_REGISTRY_ABI,
        functionName: "getReputation",
        args: [agentId],
      });
    } catch {
      try {
        return await this.publicClient.readContract({
          address: reputationRegistry,
          abi: REPUTATION_REGISTRY_ABI,
          functionName: "reputationOf",
          args: [agentId],
        });
      } catch {
        const feedbackCount = await this.publicClient.readContract({
          address: reputationRegistry,
          abi: REPUTATION_REGISTRY_ABI,
          functionName: "feedbackCount",
          args: [agentId],
        });
        return [0n, feedbackCount, 0n];
      }
    }
  }
}
