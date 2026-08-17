import type { Address, Hex, PublicClient } from "viem";

export enum JobStatus {
  OPEN = "OPEN",
  FUNDED = "FUNDED",
  SUBMITTED = "SUBMITTED",
  SETTLED = "SETTLED",
  REJECTED = "REJECTED",
  REFUNDED = "REFUNDED",
}

export interface ERC8183Addresses {
  agenticCommerce?: Address;
  evaluatorRouter?: Address;
  optimisticPolicy?: Address;
  paymentToken?: Address;
}

export interface ERC8183ChainConfig {
  chainId: number;
  name: string;
  /**
   * Single RPC endpoint all chain reads for this deployment trust (same
   * single-source caveat as ERC-8004's RegistryConfig.rpcUrl, SEC-112): use
   * operator-controlled, ideally redundant infrastructure for production.
   */
  rpcUrl: string;
  addresses: ERC8183Addresses;
}

export interface RequiredERC8183Addresses {
  agenticCommerce: Address;
  evaluatorRouter: Address;
  optimisticPolicy: Address;
  paymentToken: Address;
}

export interface SignerAdapter {
  sendTransaction(params: { to: Address; data: Hex; value?: bigint }): Promise<Hex>;
}

export interface JobConfig {
  chainId?: number;
  publicClient: PublicClient;
  signer: SignerAdapter;
  addresses: RequiredERC8183Addresses;
}

export interface CreateJobParams {
  provider: Address;
  router?: Address;
  expiredAt: bigint | number;
  description: string;
}

export interface Job {
  id: bigint;
  status: JobStatus;
  client?: Address;
  provider: Address;
  router?: Address;
  policy?: Address;
  budget: bigint;
  expiredAt?: bigint;
  deliverableHash?: Hex;
}

export interface CreateJobResult {
  jobId: bigint;
  txHash: Hex;
}
