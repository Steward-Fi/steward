/**
 * ERC-8004 identity registry client.
 *
 * When a real, deployed registry is configured this client performs genuine
 * on-chain calls. When no real registry is configured, mutating/lookup methods
 * refuse to operate rather than fabricating data that callers could mistake for
 * verified on-chain state.
 */

import {
  type Address,
  createPublicClient,
  decodeEventLog,
  encodeFunctionData,
  getAddress,
  type Hex,
  http,
  isAddress,
  type PublicClient,
  parseAbi,
} from "viem";
import { isRegistryConfigured } from "./chains";
import type {
  AgentCard,
  AgentRegistrationPayload,
  Eip8004Signer,
  RegistrationResult,
  RegistryConfig,
} from "./types";

export const EIP8004_REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";

export const IDENTITY_REGISTRY_ABI = parseAbi([
  "function register(string agentURI) returns (uint256 agentId)",
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function tokenURI(uint256 tokenId) view returns (string)",
  "function balanceOf(address owner) view returns (uint256)",
  "function tokenOfOwnerByIndex(address owner, uint256 index) view returns (uint256)",
  "event Registered(uint256 indexed agentId, string agentURI, address indexed owner)",
]);

type RegistrationLog = {
  eventName: "Registered";
  args: { agentId: bigint; agentURI: string; owner: Address };
};

function makePublicClient(config: RegistryConfig): PublicClient {
  if (config.publicClient) return config.publicClient;
  return createPublicClient({
    transport: http(config.rpcUrl),
  });
}

function toBase64(value: string): string {
  if (typeof Buffer !== "undefined") return Buffer.from(value, "utf8").toString("base64");
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): string {
  if (typeof Buffer !== "undefined") return Buffer.from(value, "base64").toString("utf8");
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function parseAgentURI(agentURI: string): AgentRegistrationPayload | null {
  const prefix = "data:application/json;base64,";
  if (!agentURI.startsWith(prefix)) return null;

  try {
    const decoded = JSON.parse(
      fromBase64(agentURI.slice(prefix.length)),
    ) as Partial<AgentRegistrationPayload>;
    if (typeof decoded.name !== "string") return null;
    return {
      type: typeof decoded.type === "string" ? decoded.type : EIP8004_REGISTRATION_TYPE,
      name: decoded.name,
      description: typeof decoded.description === "string" ? decoded.description : "",
      image: typeof decoded.image === "string" ? decoded.image : "",
      active: typeof decoded.active === "boolean" ? decoded.active : true,
      supportedTrust: Array.isArray(decoded.supportedTrust) ? decoded.supportedTrust : [],
    };
  } catch {
    return null;
  }
}

export function buildAgentURI(card: AgentCard): {
  agentURI: string;
  payload: AgentRegistrationPayload;
} {
  const payload: AgentRegistrationPayload = {
    type: EIP8004_REGISTRATION_TYPE,
    name: card.name ?? "",
    description: card.description?.trim() ? card.description : "I'm four.meme trading agent",
    image: card.image ?? "",
    active: card.active ?? true,
    supportedTrust: card.supportedTrust ?? [""],
  };
  const json = JSON.stringify(payload);
  return {
    agentURI: `data:application/json;base64,${toBase64(json)}`,
    payload,
  };
}

export function encodeRegisterCalldata(agentURI: string): Hex {
  return encodeFunctionData({
    abi: IDENTITY_REGISTRY_ABI,
    functionName: "register",
    args: [agentURI],
  });
}

export function decodeRegisteredLog(log: {
  address?: Address;
  data: Hex;
  topics: readonly Hex[];
}): RegistrationLog | null {
  try {
    const decoded = decodeEventLog({
      abi: IDENTITY_REGISTRY_ABI,
      data: log.data,
      topics: log.topics as [Hex, ...Hex[]],
    });
    if (decoded.eventName !== "Registered") return null;
    return decoded as unknown as RegistrationLog;
  } catch {
    return null;
  }
}

export class IdentityRegistryClient {
  readonly config: RegistryConfig;
  readonly publicClient: PublicClient;

  constructor(config: RegistryConfig, publicClient?: PublicClient) {
    const identityRegistry = getAddress(config.identityRegistry ?? config.registryAddress);
    this.config = {
      ...config,
      registryAddress: identityRegistry,
      identityRegistry,
      reputationRegistry: config.reputationRegistry
        ? getAddress(config.reputationRegistry)
        : undefined,
    };
    this.publicClient = publicClient ?? makePublicClient(this.config);
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
    image?: string;
    active?: boolean;
    supportedTrust?: string[];
  }): AgentCard {
    return {
      name: params.name,
      description: params.description,
      walletAddress: params.walletAddress,
      apiUrl: params.apiUrl,
      capabilities: params.capabilities ?? [],
      services: params.services ?? [],
      image: params.image,
      active: params.active,
      supportedTrust: params.supportedTrust,
    };
  }

  buildAgentURI(agentCard: AgentCard): { agentURI: string; payload: AgentRegistrationPayload } {
    return buildAgentURI(agentCard);
  }

  /**
   * Register an agent on-chain. Refuses to operate when no real registry is
   * configured — returning a fabricated registration would let callers believe
   * an on-chain registration occurred when none did.
   */
  async register(agentCard: AgentCard, signer: Eip8004Signer): Promise<RegistrationResult> {
    if (!this.isConfigured()) {
      throw new Error(
        "ERC8004 registry not configured — refusing to fabricate registration. " +
          `chainId=${this.config.chainId} registryAddress=${this.config.registryAddress}`,
      );
    }
    const { agentURI, payload } = this.buildAgentURI(agentCard);
    const data = encodeRegisterCalldata(agentURI);
    const txHash = await signer.sendTransaction({
      to: this.config.identityRegistry,
      data,
      value: 0n,
    });

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== "success") {
      throw new Error(`ERC-8004 register reverted (status=${receipt.status}, tx=${txHash})`);
    }

    const registryAddress = this.config.identityRegistry.toLowerCase();
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== registryAddress) continue;
      const decoded = decodeRegisteredLog(log);
      if (!decoded) continue;
      return {
        tokenId: decoded.args.agentId.toString(),
        txHash,
        chainId: this.config.chainId,
        registryAddress: this.config.identityRegistry,
        agentCardUri: decoded.args.agentURI,
        agentURI: decoded.args.agentURI,
        payload,
        verified: true,
      };
    }

    throw new Error(`ERC-8004 register: Registered event not found in receipt (tx=${txHash})`);
  }

  /**
   * Look up a registration. Returns null when the registry is not configured
   * (unknown / not verified on-chain) or when the token does not exist.
   * Callers must treat null as unverified, never as "confirmed registered".
   */
  async getRegistration(tokenId: string | bigint): Promise<AgentCard | null> {
    if (!this.isConfigured()) return null;
    const agentId = typeof tokenId === "bigint" ? tokenId : BigInt(tokenId);
    try {
      const [owner, tokenURI] = await Promise.all([
        this.publicClient.readContract({
          address: this.config.identityRegistry,
          abi: IDENTITY_REGISTRY_ABI,
          functionName: "ownerOf",
          args: [agentId],
        }),
        this.publicClient.readContract({
          address: this.config.identityRegistry,
          abi: IDENTITY_REGISTRY_ABI,
          functionName: "tokenURI",
          args: [agentId],
        }),
      ]);
      const payload = parseAgentURI(tokenURI);
      return {
        name: payload?.name ?? "",
        description: payload?.description ?? "",
        walletAddress: owner,
        apiUrl: "",
        capabilities: [],
        services: [],
        image: payload?.image,
        active: payload?.active,
        supportedTrust: payload?.supportedTrust,
        agentURI: tokenURI,
        tokenId: agentId.toString(),
      };
    } catch (error) {
      const message =
        error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
      if (
        message.includes("nonexistent") ||
        message.includes("not found") ||
        message.includes("invalid token")
      ) {
        return null;
      }
      throw error;
    }
  }

  async getRegistrationByOwner(owner: string): Promise<AgentCard | null> {
    if (!isAddress(owner)) throw new Error(`Invalid owner address: ${owner}`);
    const ownerAddress = getAddress(owner);
    try {
      const tokenId = await this.publicClient.readContract({
        address: this.config.identityRegistry,
        abi: IDENTITY_REGISTRY_ABI,
        functionName: "tokenOfOwnerByIndex",
        args: [ownerAddress, 0n],
      });
      return this.getRegistration(tokenId);
    } catch {
      try {
        const balance = await this.publicClient.readContract({
          address: this.config.identityRegistry,
          abi: IDENTITY_REGISTRY_ABI,
          functionName: "balanceOf",
          args: [ownerAddress],
        });
        if (balance === 0n) return null;
      } catch {
        return null;
      }
      throw new Error(
        "ERC-8004 identity registry does not expose tokenOfOwnerByIndex; cannot resolve owner to token id",
      );
    }
  }
}
