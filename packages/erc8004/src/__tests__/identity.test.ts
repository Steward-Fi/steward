import { describe, expect, test } from "bun:test";
import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  getAddress,
  parseAbiParameters,
  zeroHash,
} from "viem";
import { REGISTRY_CONFIGS } from "../chains";
import {
  buildAgentURI,
  decodeRegisteredLog,
  encodeRegisterCalldata,
  IDENTITY_REGISTRY_ABI,
  IdentityRegistryClient,
} from "../identity";
import type { Eip8004Signer } from "../types";

const txHash = "0x1111111111111111111111111111111111111111111111111111111111111111";
const owner = getAddress("0x1234567890123456789012345678901234567890");

describe("ERC-8004 identity client", () => {
  test("encodes register(agentURI) calldata", () => {
    const card = {
      name: "Sol",
      description: "Steward agent",
      walletAddress: owner,
      apiUrl: "https://agent.example",
      capabilities: [],
      services: [],
    };
    const { agentURI } = buildAgentURI(card);

    expect(encodeRegisterCalldata(agentURI)).toBe(
      encodeFunctionData({
        abi: IDENTITY_REGISTRY_ABI,
        functionName: "register",
        args: [agentURI],
      }),
    );
  });

  test("decodes Registered event receipt into real agent id", async () => {
    const config = REGISTRY_CONFIGS[56];
    const card = {
      name: "Sol",
      description: "Steward agent",
      walletAddress: owner,
      apiUrl: "https://agent.example",
      capabilities: [],
      services: [],
    };
    const { agentURI } = buildAgentURI(card);
    const topics = encodeEventTopics({
      abi: IDENTITY_REGISTRY_ABI,
      eventName: "Registered",
      args: { agentId: 42n, owner },
    });
    const data = encodeAbiParameters(parseAbiParameters("string"), [agentURI]);
    const publicClient = {
      waitForTransactionReceipt: async () => ({
        status: "success",
        logs: [{ address: config.identityRegistry, topics, data }],
      }),
    };
    let sentData = zeroHash;
    const signer: Eip8004Signer = {
      sendTransaction: async ({ to, data }) => {
        expect(to).toBe(config.identityRegistry);
        sentData = data;
        return txHash;
      },
    };

    const result = await new IdentityRegistryClient(config, publicClient as never).register(
      card,
      signer,
    );

    expect(sentData).toBe(encodeRegisterCalldata(agentURI));
    expect(result.tokenId).toBe("42");
    expect(result.txHash).toBe(txHash);
    expect(result.agentURI).toBe(agentURI);
    expect(decodeRegisteredLog({ data, topics })?.args.agentId).toBe(42n);
  });

  test("getRegistration returns null when token is genuinely absent", async () => {
    const config = REGISTRY_CONFIGS[56];
    const publicClient = {
      readContract: async () => {
        throw new Error("ERC721: invalid token ID");
      },
    };

    const result = await new IdentityRegistryClient(config, publicClient as never).getRegistration(
      "999",
    );

    expect(result).toBeNull();
  });
});
