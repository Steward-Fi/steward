import {
  type Address,
  decodeEventLog,
  encodeFunctionData,
  type Hex,
  type PublicClient,
} from "viem";
import type {
  CreateJobParams,
  CreateJobResult,
  Job,
  JobConfig,
  RequiredERC8183Addresses,
  SignerAdapter,
} from "./types.ts";
import { JobStatus } from "./types.ts";

// ABI derived from ERC-8183 spec; verify against deployed contract before mainnet.
export const AGENTIC_COMMERCE_ABI = [
  {
    type: "function",
    name: "createJob",
    stateMutability: "nonpayable",
    inputs: [
      { name: "provider", type: "address" },
      { name: "router", type: "address" },
      { name: "expiredAt", type: "uint64" },
      { name: "description", type: "string" },
    ],
    outputs: [{ name: "jobId", type: "uint256" }],
  },
  {
    type: "function",
    name: "setBudget",
    stateMutability: "nonpayable",
    inputs: [
      { name: "jobId", type: "uint256" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "fund",
    stateMutability: "nonpayable",
    inputs: [
      { name: "jobId", type: "uint256" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "submit",
    stateMutability: "nonpayable",
    inputs: [
      { name: "jobId", type: "uint256" },
      { name: "deliverableHash", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "dispute",
    stateMutability: "nonpayable",
    inputs: [{ name: "jobId", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "claimRefund",
    stateMutability: "nonpayable",
    inputs: [{ name: "jobId", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "getJob",
    stateMutability: "view",
    inputs: [{ name: "jobId", type: "uint256" }],
    outputs: [
      {
        name: "job",
        type: "tuple",
        components: [
          { name: "id", type: "uint256" },
          { name: "status", type: "uint8" },
          { name: "client", type: "address" },
          { name: "provider", type: "address" },
          { name: "router", type: "address" },
          { name: "policy", type: "address" },
          { name: "budget", type: "uint256" },
          { name: "expiredAt", type: "uint64" },
          { name: "deliverableHash", type: "bytes32" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "getJobStatus",
    stateMutability: "view",
    inputs: [{ name: "jobId", type: "uint256" }],
    outputs: [{ name: "status", type: "uint8" }],
  },
  {
    type: "event",
    name: "JobCreated",
    inputs: [
      { name: "jobId", type: "uint256", indexed: true },
      { name: "client", type: "address", indexed: true },
      { name: "provider", type: "address", indexed: true },
      { name: "router", type: "address", indexed: false },
      { name: "expiredAt", type: "uint64", indexed: false },
      { name: "description", type: "string", indexed: false },
    ],
  },
] as const;

// ABI derived from ERC-8183 spec; verify against deployed contract before mainnet.
export const EVALUATOR_ROUTER_ABI = [
  {
    type: "function",
    name: "registerJob",
    stateMutability: "nonpayable",
    inputs: [
      { name: "jobId", type: "uint256" },
      { name: "policy", type: "address" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "settle",
    stateMutability: "nonpayable",
    inputs: [{ name: "jobId", type: "uint256" }],
    outputs: [],
  },
] as const;

export const ERC20_ABI = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "ok", type: "bool" }],
  },
] as const;

const STATUS_BY_CODE: Record<number, JobStatus> = {
  0: JobStatus.OPEN,
  1: JobStatus.FUNDED,
  2: JobStatus.SUBMITTED,
  3: JobStatus.SETTLED,
  4: JobStatus.REJECTED,
  5: JobStatus.REFUNDED,
};

type CommerceFunctionName = "setBudget" | "fund" | "submit" | "dispute" | "claimRefund";
type RouterFunctionName = "registerJob" | "settle";

export class ERC8183Client {
  readonly publicClient: PublicClient;
  readonly signer: SignerAdapter;
  readonly addresses: RequiredERC8183Addresses;

  constructor(config: JobConfig) {
    this.publicClient = config.publicClient;
    this.signer = config.signer;
    this.addresses = validateAddresses(config.addresses);
  }

  async createJob(params: CreateJobParams): Promise<CreateJobResult> {
    const router = params.router ?? this.addresses.evaluatorRouter;
    const data = encodeFunctionData({
      abi: AGENTIC_COMMERCE_ABI,
      functionName: "createJob",
      args: [params.provider, router, BigInt(params.expiredAt), params.description],
    });
    const txHash = await this.signer.sendTransaction({ to: this.addresses.agenticCommerce, data });
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
    return { jobId: decodeJobCreatedId(receipt.logs), txHash };
  }

  registerJob(jobId: bigint, policy = this.addresses.optimisticPolicy): Promise<Hex> {
    return this.writeRouter("registerJob", [jobId, policy]);
  }

  setBudget(jobId: bigint, amount: bigint): Promise<Hex> {
    return this.writeCommerce("setBudget", [jobId, amount]);
  }

  async fund(jobId: bigint, amount: bigint): Promise<{ approveTxHash: Hex; fundTxHash: Hex }> {
    const approveData = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: "approve",
      args: [this.addresses.agenticCommerce, amount],
    });
    const approveTxHash = await this.signer.sendTransaction({
      to: this.addresses.paymentToken,
      data: approveData,
    });
    await this.publicClient.waitForTransactionReceipt({ hash: approveTxHash });
    const fundTxHash = await this.writeCommerce("fund", [jobId, amount]);
    return { approveTxHash, fundTxHash };
  }

  submit(jobId: bigint, deliverableHash: Hex): Promise<Hex> {
    return this.writeCommerce("submit", [jobId, deliverableHash]);
  }

  dispute(jobId: bigint): Promise<Hex> {
    return this.writeCommerce("dispute", [jobId]);
  }

  settle(jobId: bigint): Promise<Hex> {
    return this.writeRouter("settle", [jobId]);
  }

  claimRefund(jobId: bigint): Promise<Hex> {
    return this.writeCommerce("claimRefund", [jobId]);
  }

  async getJob(jobId: bigint): Promise<Job> {
    const raw = await this.publicClient.readContract({
      address: this.addresses.agenticCommerce,
      abi: AGENTIC_COMMERCE_ABI,
      functionName: "getJob",
      args: [jobId],
    });
    return normalizeJob(raw as RawJobTuple);
  }

  async getJobStatus(jobId: bigint): Promise<JobStatus> {
    const raw = await this.publicClient.readContract({
      address: this.addresses.agenticCommerce,
      abi: AGENTIC_COMMERCE_ABI,
      functionName: "getJobStatus",
      args: [jobId],
    });
    return toJobStatus(Number(raw));
  }

  private writeCommerce(
    functionName: CommerceFunctionName,
    args: readonly unknown[],
  ): Promise<Hex> {
    const data = encodeFunctionData({
      abi: AGENTIC_COMMERCE_ABI,
      functionName,
      args,
    } as any);
    return this.signer.sendTransaction({ to: this.addresses.agenticCommerce, data });
  }

  private writeRouter(functionName: RouterFunctionName, args: readonly unknown[]): Promise<Hex> {
    const data = encodeFunctionData({
      abi: EVALUATOR_ROUTER_ABI,
      functionName,
      args,
    } as any);
    return this.signer.sendTransaction({ to: this.addresses.evaluatorRouter, data });
  }
}

function validateAddresses(addresses: Partial<RequiredERC8183Addresses>): RequiredERC8183Addresses {
  const missing = ["agenticCommerce", "evaluatorRouter", "optimisticPolicy", "paymentToken"].filter(
    (key) => !addresses[key as keyof RequiredERC8183Addresses],
  );
  if (missing.length > 0) {
    throw new Error(
      `ERC-8183 client requires explicit deployment addresses: missing ${missing.join(", ")}`,
    );
  }
  return addresses as RequiredERC8183Addresses;
}

function decodeJobCreatedId(logs: readonly { data: Hex; topics: readonly Hex[] }[]): bigint {
  for (const log of logs) {
    try {
      const decoded = decodeEventLog({
        abi: AGENTIC_COMMERCE_ABI,
        data: log.data,
        topics: [...log.topics] as any,
      });
      if (decoded.eventName === "JobCreated") {
        return decoded.args.jobId;
      }
    } catch {
      // Skip unrelated logs in the same receipt.
    }
  }
  throw new Error("JobCreated event not found in createJob receipt");
}

type RawJobTuple = readonly [
  bigint,
  number,
  Address,
  Address,
  Address,
  Address,
  bigint,
  bigint,
  Hex,
] & {
  id?: bigint;
  status?: number;
  client?: Address;
  provider?: Address;
  router?: Address;
  policy?: Address;
  budget?: bigint;
  expiredAt?: bigint;
  deliverableHash?: Hex;
};

function normalizeJob(raw: RawJobTuple): Job {
  return {
    id: raw.id ?? raw[0],
    status: toJobStatus(Number(raw.status ?? raw[1])),
    client: raw.client ?? raw[2],
    provider: raw.provider ?? raw[3],
    router: raw.router ?? raw[4],
    policy: raw.policy ?? raw[5],
    budget: raw.budget ?? raw[6],
    expiredAt: raw.expiredAt ?? raw[7],
    deliverableHash: raw.deliverableHash ?? raw[8],
  };
}

function toJobStatus(code: number): JobStatus {
  const status = STATUS_BY_CODE[code];
  if (!status) {
    throw new Error(`Unknown ERC-8183 job status code: ${code}`);
  }
  return status;
}
