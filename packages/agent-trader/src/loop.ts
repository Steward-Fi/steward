/**
 * Per-agent trading loop.
 *
 * Each active agent runs its own independent timer.  On every tick:
 *   1. Resolve the agent's wallet address from Steward
 *   2. Fetch on-chain + historical state
 *   3. Run the strategy → get a TradeDecision
 *   4. If the decision is buy/sell → build & submit the transaction
 *   5. Handle the Steward response (signed / pending / rejected)
 *
 * The loop is deliberately crash-resilient: errors are logged and the loop
 * continues on the next tick.
 */

import type { StewardApiError, StewardClient } from "@stwd/sdk";
import type { AgentTraderConfig, TraderConfig } from "./config.js";
import { logDecision, logError, logInfo, logSubmission, logWarn } from "./logger.js";
import { fetchAgentState } from "./state.js";
import { resolveStrategy } from "./strategies/index.js";
import type { AgentState, Strategy, TradeDecision } from "./strategies/types.js";
import { buildSwapTx, computeExpectedOut, toSignInput, UnsafeSwapError } from "./trade-builder.js";

// ─── Loop handle ─────────────────────────────────────────────────────────────

export interface AgentLoop {
  agentId: string;
  stop(): void;
}

// ─── Agent wallet cache ────────────────────────────────────────────────────────

const walletCache = new Map<string, string>(); // agentId → walletAddress

async function resolveWallet(steward: StewardClient, agentId: string): Promise<string | null> {
  const cachedWallet = walletCache.get(agentId);
  if (cachedWallet) return cachedWallet;

  try {
    const agent = await steward.getAgent(agentId);
    walletCache.set(agentId, agent.walletAddress);
    return agent.walletAddress;
  } catch (err) {
    logError("Could not resolve agent wallet address", err, { agentId });
    return null;
  }
}

// ─── Single tick ──────────────────────────────────────────────────────────────

/**
 * Injectable dependencies for {@link runTick}. Production passes nothing and the
 * real implementations are used; tests substitute a deterministic state fetcher
 * to exercise the build/sign chokepoint without live RPC/oracle calls.
 */
export interface RunTickDeps {
  fetchState?: (
    agentConfig: AgentTraderConfig,
    walletAddress: string,
    steward: StewardClient,
  ) => Promise<AgentState>;
}

export async function runTick(
  agentConfig: AgentTraderConfig,
  strategy: Strategy,
  steward: StewardClient,
  globalConfig: TraderConfig,
  deps: RunTickDeps = {},
): Promise<void> {
  const { agentId, tokenAddress, chainId = 8453, portalAddress, slippageBps } = agentConfig;
  const dryRun = globalConfig.dryRun ?? false;
  const fetchState = deps.fetchState ?? fetchAgentState;

  // 1. Wallet address
  const walletAddress = await resolveWallet(steward, agentId);
  if (!walletAddress) return;

  // 2. Fetch state
  let state: AgentState;
  try {
    state = await fetchState(agentConfig, walletAddress, steward);
  } catch (err) {
    logError("Failed to fetch agent state — skipping tick", err, { agentId });
    return;
  }

  // 3. Strategy evaluation
  let decision: TradeDecision;
  try {
    decision = await strategy.evaluate(state);
  } catch (err) {
    logError("Strategy threw during evaluation — skipping tick", err, {
      agentId,
      strategy: strategy.name,
    });
    return;
  }

  logDecision({
    agentId,
    strategy: strategy.name,
    action: decision.action,
    amount: decision.amount,
    reason: decision.reason,
    confidence: decision.confidence,
    dryRun,
  });

  if (decision.action === "hold") return;

  // 3b. Low-confidence price gate. For price-driven strategies, a single-pair/
  //     spot price (priceConfidence !== "high") is trivially manipulable, so it
  //     must not, on its own, trigger a trade. Suppress to hold. (The strategies
  //     also self-guard; this is the authoritative chokepoint.)
  if (strategy.requiresPriceConfidence && state.priceConfidence !== "high") {
    logWarn("Suppressing trade — price confidence too low to act on", {
      agentId,
      strategy: strategy.name,
      action: decision.action,
      priceConfidence: state.priceConfidence,
    });
    return;
  }

  // 4. Build transaction
  if (!portalAddress) {
    logWarn("Agent has no portalAddress configured — cannot build swap tx", {
      agentId,
    });
    return;
  }

  // Derive a real expected-output quote from the current token price (native-wei
  // per token-unit). buildSwapTx turns this into a slippage-protected
  // amountOutMin and FAILS CLOSED (UnsafeSwapError) if no safe floor can be
  // computed — we never submit an unprotected swap.
  let amountInBig: bigint;
  try {
    amountInBig = BigInt(decision.amount);
  } catch {
    logWarn("Strategy produced a non-integer trade amount — skipping tick", {
      agentId,
      strategy: strategy.name,
      amount: decision.amount,
    });
    return;
  }

  const expectedOut = computeExpectedOut(decision.action, amountInBig, state.tokenPrice);

  let builtTx: ReturnType<typeof buildSwapTx>;
  try {
    builtTx = buildSwapTx(
      decision.action,
      tokenAddress,
      decision.amount,
      portalAddress,
      walletAddress,
      chainId,
      expectedOut,
      slippageBps,
    );
  } catch (err) {
    if (err instanceof UnsafeSwapError) {
      // Fail-closed: refuse to submit a swap without slippage protection.
      logWarn("Refusing to build swap — no safe slippage bound; skipping trade", {
        agentId,
        strategy: strategy.name,
        action: decision.action,
        amount: decision.amount,
        slippageBps: slippageBps ?? 100,
        priceConfidence: state.priceConfidence,
        reason: err.message,
      });
      return;
    }
    throw err;
  }

  if (dryRun) {
    logInfo("DRY RUN — transaction not submitted", {
      agentId,
      tx: builtTx,
    });
    return;
  }

  // 5. Submit through Steward
  const signInput = toSignInput(builtTx);

  try {
    const result = await steward.signTransaction(agentId, signInput);

    if ("txHash" in result) {
      logSubmission({
        agentId,
        txId: result.txHash,
        status: "signed",
        to: builtTx.to,
        value: builtTx.value,
        dataLen: builtTx.data.length,
        chainId,
      });
    } else if ("status" in result && result.status === "pending_approval") {
      logSubmission({
        agentId,
        status: "pending_approval",
        to: builtTx.to,
        value: builtTx.value,
        dataLen: builtTx.data.length,
        chainId,
      });
      logInfo("Transaction queued for human approval — will execute on approval webhook", {
        agentId,
        policyResults: result.results,
      });
    } else if ("signedTx" in result) {
      logSubmission({
        agentId,
        status: "signed",
        to: builtTx.to,
        value: builtTx.value,
        dataLen: builtTx.data.length,
        chainId,
      });
      logInfo("Transaction signed but not broadcast", {
        agentId,
        signedTxLength: result.signedTx.length,
        caip2: result.caip2,
      });
    }
  } catch (err) {
    const apiErr = err as StewardApiError;

    if (apiErr.status === 403) {
      logSubmission({
        agentId,
        status: "rejected",
        to: builtTx.to,
        value: builtTx.value,
        dataLen: builtTx.data.length,
        chainId,
        error: apiErr.message,
      });
    } else {
      logSubmission({
        agentId,
        status: "error",
        to: builtTx.to,
        value: builtTx.value,
        dataLen: builtTx.data.length,
        chainId,
        error: apiErr.message,
      });
    }
  }
}

// ─── Loop factory ─────────────────────────────────────────────────────────────

export function startAgentLoop(
  agentConfig: AgentTraderConfig,
  steward: StewardClient,
  globalConfig: TraderConfig,
): AgentLoop {
  const { agentId, strategy: strategyName, params, intervalSeconds } = agentConfig;

  const strategy = resolveStrategy(strategyName, params);

  if (!strategy) {
    // "manual" strategy — no automatic trading
    logInfo(`Agent "${agentId}" using manual strategy — loop is passive`);
    return {
      agentId,
      stop: () => {
        /* nothing to stop */
      },
    };
  }

  logInfo(`Starting trading loop for agent "${agentId}"`, {
    strategy: strategyName,
    intervalSeconds,
    dryRun: globalConfig.dryRun,
  });

  let stopped = false;

  // Run immediately, then on a repeating interval
  const run = () => {
    if (stopped) return;
    runTick(agentConfig, strategy, steward, globalConfig).catch((err) => {
      logError("Unhandled error in trading tick", err, { agentId });
    });
  };

  // Stagger first tick slightly to avoid thundering herd on startup
  const jitterMs = Math.floor(Math.random() * 5000);
  const initialTimer = setTimeout(() => {
    run();
    if (!stopped) {
      const interval = setInterval(() => {
        if (stopped) {
          clearInterval(interval);
          return;
        }
        run();
      }, intervalSeconds * 1000);

      // Attach stop to clear interval
      loop.stop = () => {
        stopped = true;
        clearInterval(interval);
        logInfo(`Stopped trading loop for agent "${agentId}"`);
      };
    }
  }, jitterMs);

  const loop: AgentLoop = {
    agentId,
    stop: () => {
      stopped = true;
      clearTimeout(initialTimer);
      logInfo(`Stopped trading loop for agent "${agentId}" (before first tick)`);
    },
  };

  return loop;
}
