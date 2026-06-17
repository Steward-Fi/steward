#!/usr/bin/env bun
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";
import {
  createWithdrawTypedData,
  type HyperliquidTransport,
  submitWithdraw,
  toWithdrawAction,
} from "@stwd/venue-hyperliquid";
import {
  type Address,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  type Hex,
  http,
  type PublicClient,
  parseAbi,
  parseSignature,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { arbitrum } from "viem/chains";

export const BUILDER_EOA = "0x0af1133030Afe754FB7438dD2e86F93e11030CCa" as const;
export const PLATFORM_SAFE = "0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c" as const;
export const ARBITRUM_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831" as const;
export const ARBITRUM_CHAIN_ID = 42161;
export const DEFAULT_SWEEP_MIN_USDC = "50";
export const DEFAULT_HL_BASE_URL = "https://api.hyperliquid.xyz";
export const DEFAULT_ARBITRUM_RPC_URL = "https://arb1.arbitrum.io/rpc";
export const DEFAULT_KEY_PATH = "~/.moltbot/secrets/hl-builder-eoa.json";

const USDC_DECIMALS = 6n;
const USDC_SCALE = 10n ** USDC_DECIMALS;
const USDC_DECIMAL_RE = /^\d+(?:\.(\d{0,6})?)?$/;
const erc20Abi = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
]);

export interface SweepConfig {
  dryRun: boolean;
  minUsdc: string;
  keyPath: string;
  hlBaseUrl: string;
  arbitrumRpcUrl: string;
  settlementPollMs: number;
  settlementTimeoutMs: number;
  now: () => number;
}

export interface ChainClient {
  getUsdcBalance(owner: Address): Promise<bigint>;
  sendUsdcTransfer(args: {
    account: ReturnType<typeof privateKeyToAccount>;
    to: Address;
    amount: bigint;
  }): Promise<Hex>;
}

export interface SweepDeps {
  fetchClearinghouseState(user: Address): Promise<unknown>;
  chainClient: ChainClient;
  signAndSubmitWithdraw(args: {
    privateKey: Hex;
    amountUsdc: string;
    destination: Address;
    time: number;
  }): Promise<unknown>;
  loadPrivateKey(path: string): Promise<Hex>;
  sleep(ms: number): Promise<void>;
  log(message: string): void;
}

export interface SweepPlan {
  builder: Address;
  safe: Address;
  usdc: Address;
  dryRun: boolean;
  minUsdc: string;
  withdrawableUsdc: string;
  withdrawableBaseUnits: bigint;
  thresholdBaseUnits: bigint;
  shouldWithdraw: boolean;
  withdrawalAmountUsdc: string | null;
  startingArbitrumUsdcBaseUnits: bigint;
  projectedTransferBaseUnits: bigint;
  transfer: {
    chainId: typeof ARBITRUM_CHAIN_ID;
    token: Address;
    from: Address;
    to: Address;
    amount: bigint;
    data: Hex;
  } | null;
}

export interface SweepResult extends SweepPlan {
  withdrawalSubmitted: boolean;
  withdrawalResponse?: unknown;
  transferSubmitted: boolean;
  transferHash?: Hex;
  summary: string;
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return resolve(homedir(), path.slice(2));
  return path;
}

export function parseUsdcToBaseUnits(raw: string): bigint {
  const value = raw.trim();
  if (!USDC_DECIMAL_RE.test(value)) throw new Error(`invalid USDC decimal: ${raw}`);
  const [whole, frac = ""] = value.split(".");
  return BigInt(whole) * USDC_SCALE + BigInt(frac.padEnd(Number(USDC_DECIMALS), "0"));
}

export function formatUsdcBaseUnits(amount: bigint): string {
  const whole = amount / USDC_SCALE;
  const frac = amount % USDC_SCALE;
  if (frac === 0n) return whole.toString();
  return `${whole}.${frac.toString().padStart(Number(USDC_DECIMALS), "0").replace(/0+$/, "")}`;
}

export function extractWithdrawableUsdc(state: unknown): string {
  const withdrawable = (state as { withdrawable?: unknown } | null)?.withdrawable;
  if (typeof withdrawable !== "string" && typeof withdrawable !== "number") {
    throw new Error("Hyperliquid clearinghouseState did not include withdrawable balance");
  }
  return String(withdrawable);
}

export function buildUsdcTransferData(to: Address, amount: bigint): Hex {
  return encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [to, amount] });
}

export async function readBuilderPrivateKey(path: string): Promise<Hex> {
  const raw = await readFile(expandHome(path), "utf8");
  const parsed = JSON.parse(raw) as unknown;
  const candidate =
    typeof parsed === "string"
      ? parsed
      : parsed && typeof parsed === "object"
        ? ((parsed as Record<string, unknown>).privateKey ??
          (parsed as Record<string, unknown>).key ??
          (parsed as Record<string, unknown>).secretKey)
        : null;
  if (typeof candidate !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(candidate)) {
    throw new Error(`invalid builder EOA key file shape at ${path}`);
  }
  return candidate as Hex;
}

export function createDefaultChainClient(rpcUrl: string): ChainClient {
  const publicClient = createPublicClient({
    chain: arbitrum,
    transport: http(rpcUrl),
  }) as PublicClient;
  return {
    async getUsdcBalance(owner) {
      return publicClient.readContract({
        address: ARBITRUM_USDC,
        abi: erc20Abi,
        functionName: "balanceOf",
        args: [owner],
      });
    },
    async sendUsdcTransfer({ account, to, amount }) {
      const walletClient = createWalletClient({
        account,
        chain: arbitrum,
        transport: http(rpcUrl),
      }) as WalletClient;
      return walletClient.writeContract({
        address: ARBITRUM_USDC,
        abi: erc20Abi,
        functionName: "transfer",
        args: [to, amount],
        chain: arbitrum,
        account,
      });
    },
  };
}

export function createDefaultDeps(config: SweepConfig): SweepDeps {
  const transport: HyperliquidTransport = { fetch };
  return {
    async fetchClearinghouseState(user) {
      const response = await fetch(`${config.hlBaseUrl}/info`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "clearinghouseState", user }),
      });
      const json = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(`Hyperliquid info returned ${response.status}: ${JSON.stringify(json)}`);
      return json;
    },
    chainClient: createDefaultChainClient(config.arbitrumRpcUrl),
    async signAndSubmitWithdraw({ privateKey, amountUsdc, destination, time }) {
      const action = toWithdrawAction({ amount: amountUsdc, destination, time });
      const typedData = createWithdrawTypedData({ amount: amountUsdc, destination, time });
      const signature = await privateKeyToAccount(privateKey).signTypedData({
        domain: typedData.domain,
        types: typedData.types,
        primaryType: typedData.primaryType,
        message: typedData.value,
      } as never);
      const parsed = parseSignature(signature);
      const resp = await submitWithdraw(
        {
          action,
          nonce: time,
          signature: { r: parsed.r, s: parsed.s, v: Number(parsed.v) },
        },
        { transport, baseUrl: config.hlBaseUrl },
      );
      // HL can reject with HTTP 200 + { status: "err" }. Throw so the sweep does
      // not falsely treat a rejected withdrawal as submitted and proceed to transfer.
      const status =
        resp && typeof resp === "object" && "status" in resp
          ? (resp as { status?: unknown }).status
          : undefined;
      if (status === "err") {
        throw new Error(
          `Hyperliquid withdraw rejected: ${JSON.stringify(resp)}`,
        );
      }
      return resp;
    },
    loadPrivateKey: readBuilderPrivateKey,
    sleep: (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms)),
    log: console.log,
  };
}

async function waitForSettlement(args: {
  deps: SweepDeps;
  config: SweepConfig;
  previousBalance: bigint;
  expectedIncrease: bigint;
}): Promise<bigint> {
  if (args.expectedIncrease <= 0n) return args.previousBalance;
  const deadline = args.config.now() + args.config.settlementTimeoutMs;
  let current = await args.deps.chainClient.getUsdcBalance(BUILDER_EOA);
  while (current < args.previousBalance + args.expectedIncrease && args.config.now() < deadline) {
    await args.deps.sleep(args.config.settlementPollMs);
    current = await args.deps.chainClient.getUsdcBalance(BUILDER_EOA);
  }
  return current;
}

export async function runSweep(
  config: SweepConfig,
  deps = createDefaultDeps(config),
): Promise<SweepResult> {
  const state = await deps.fetchClearinghouseState(BUILDER_EOA);
  const withdrawableUsdc = extractWithdrawableUsdc(state);
  const withdrawableBaseUnits = parseUsdcToBaseUnits(withdrawableUsdc);
  const thresholdBaseUnits = parseUsdcToBaseUnits(config.minUsdc);
  const shouldWithdraw = withdrawableBaseUnits > thresholdBaseUnits;
  const withdrawalAmountUsdc = shouldWithdraw ? formatUsdcBaseUnits(withdrawableBaseUnits) : null;
  const startingArbitrumUsdcBaseUnits = await deps.chainClient.getUsdcBalance(BUILDER_EOA);
  const projectedTransferBaseUnits =
    startingArbitrumUsdcBaseUnits + (shouldWithdraw ? withdrawableBaseUnits : 0n);
  const transfer =
    projectedTransferBaseUnits > 0n
      ? {
          chainId: ARBITRUM_CHAIN_ID as typeof ARBITRUM_CHAIN_ID,
          token: ARBITRUM_USDC,
          from: BUILDER_EOA,
          to: PLATFORM_SAFE,
          amount: projectedTransferBaseUnits,
          data: buildUsdcTransferData(PLATFORM_SAFE, projectedTransferBaseUnits),
        }
      : null;

  const plan: SweepPlan = {
    builder: BUILDER_EOA,
    safe: PLATFORM_SAFE,
    usdc: ARBITRUM_USDC,
    dryRun: config.dryRun,
    minUsdc: config.minUsdc,
    withdrawableUsdc,
    withdrawableBaseUnits,
    thresholdBaseUnits,
    shouldWithdraw,
    withdrawalAmountUsdc,
    startingArbitrumUsdcBaseUnits,
    projectedTransferBaseUnits,
    transfer,
  };

  deps.log(
    JSON.stringify({
      event: "hl_builder_sweep.plan",
      dryRun: config.dryRun,
      builder: BUILDER_EOA,
      safe: PLATFORM_SAFE,
      usdc: ARBITRUM_USDC,
      withdrawableUsdc,
      minUsdc: config.minUsdc,
      shouldWithdraw,
      projectedTransferUsdc: formatUsdcBaseUnits(projectedTransferBaseUnits),
    }),
  );

  if (config.dryRun) {
    const summary = `DRY_RUN builder=${BUILDER_EOA} withdrawable=${withdrawableUsdc} min=${config.minUsdc} shouldWithdraw=${shouldWithdraw} projectedTransfer=${formatUsdcBaseUnits(projectedTransferBaseUnits)} safe=${PLATFORM_SAFE}`;
    deps.log(summary);
    return { ...plan, withdrawalSubmitted: false, transferSubmitted: false, summary };
  }

  const privateKey = await deps.loadPrivateKey(config.keyPath);
  const account = privateKeyToAccount(privateKey);
  if (account.address.toLowerCase() !== BUILDER_EOA.toLowerCase()) {
    throw new Error(
      `builder EOA key address mismatch: expected ${BUILDER_EOA}, got ${account.address}`,
    );
  }

  let withdrawalResponse: unknown;
  if (shouldWithdraw && withdrawalAmountUsdc) {
    withdrawalResponse = await deps.signAndSubmitWithdraw({
      privateKey,
      amountUsdc: withdrawalAmountUsdc,
      destination: BUILDER_EOA,
      time: config.now(),
    });
    deps.log(
      JSON.stringify({
        event: "hl_builder_sweep.withdraw_submitted",
        amountUsdc: withdrawalAmountUsdc,
      }),
    );
  }

  const executableTransferBalance = shouldWithdraw
    ? await waitForSettlement({
        deps,
        config,
        previousBalance: startingArbitrumUsdcBaseUnits,
        expectedIncrease: withdrawableBaseUnits,
      })
    : await deps.chainClient.getUsdcBalance(BUILDER_EOA);

  let transferHash: Hex | undefined;
  if (executableTransferBalance > 0n) {
    transferHash = await deps.chainClient.sendUsdcTransfer({
      account,
      to: PLATFORM_SAFE,
      amount: executableTransferBalance,
    });
    deps.log(
      JSON.stringify({
        event: "hl_builder_sweep.transfer_submitted",
        amountUsdc: formatUsdcBaseUnits(executableTransferBalance),
        hash: transferHash,
      }),
    );
  }

  const summary = `EXECUTED builder=${BUILDER_EOA} withdrawable=${withdrawableUsdc} min=${config.minUsdc} withdrawalSubmitted=${Boolean(withdrawalResponse)} transferSubmitted=${Boolean(transferHash)} safe=${PLATFORM_SAFE}`;
  deps.log(summary);
  return {
    ...plan,
    withdrawalSubmitted: Boolean(withdrawalResponse),
    withdrawalResponse,
    transferSubmitted: Boolean(transferHash),
    transferHash,
    summary,
  };
}

export function configFromEnvAndArgs(env: NodeJS.ProcessEnv, argv: string[]): SweepConfig {
  const hasDryRun = argv.includes("--dry-run");
  const hasExecute = argv.includes("--execute");
  if (hasDryRun && hasExecute) throw new Error("use only one of --dry-run or --execute");
  return {
    dryRun: !hasExecute,
    minUsdc: env.SWEEP_MIN_USDC ?? DEFAULT_SWEEP_MIN_USDC,
    keyPath: env.HL_BUILDER_KEY_PATH ?? DEFAULT_KEY_PATH,
    hlBaseUrl: env.HL_BASE_URL ?? DEFAULT_HL_BASE_URL,
    arbitrumRpcUrl: env.ARBITRUM_RPC_URL ?? DEFAULT_ARBITRUM_RPC_URL,
    settlementPollMs: Number(env.SWEEP_SETTLEMENT_POLL_MS ?? "30000"),
    settlementTimeoutMs: Number(env.SWEEP_SETTLEMENT_TIMEOUT_MS ?? "900000"),
    now: Date.now,
  };
}

function isMain(): boolean {
  const entry = process.argv[1] ? resolve(process.argv[1]) : "";
  return import.meta.url === new URL(`file://${entry}`).href;
}

if (isMain()) {
  runSweep(configFromEnvAndArgs(process.env, process.argv.slice(2))).catch((error) => {
    console.error(
      JSON.stringify({
        event: "hl_builder_sweep.failed",
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exitCode = 1;
  });
}
