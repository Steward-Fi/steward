/**
 * ERC-8004 reputation registry read-only client.
 */

import { createPublicClient, getAddress, http, type PublicClient, parseAbi } from "viem";
import { ERC8004_REPUTATION_REGISTRY_ADDRESS } from "./chains";
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

  /** Writes are intentionally unsupported until Steward wires policy around feedback submission. */
  async postFeedback(_params: FeedbackSignal): Promise<string> {
    throw new Error("ERC-8004 reputation writes are not implemented; this client is read-only");
  }

  /** Read an agent's reputation summary from the canonical reputation registry. */
  async getReputation(agentTokenId: string | bigint): Promise<ReputationScore> {
    const agentId = typeof agentTokenId === "bigint" ? agentTokenId : BigInt(agentTokenId);
    const [score, feedbackCount, lastUpdated] = await this.readReputationTuple(agentId);
    const normalizedScore = Number(score);
    return {
      agentId: agentId.toString(),
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
