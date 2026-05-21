"use client";

/**
 * DetectedWallets surfaces wallets the user has connected on auto-detected
 * EVM chains (e.g. Gnosis, Polygon). It reads wagmi's account state and
 * renders one row per chain the user has either explicitly switched to,
 * or that we have a recorded address for.
 *
 * The list of chains shown is driven by `@stwd/shared`'s `CHAIN_PROVIDERS`
 * registry, filtered to the wagmi-configured EVM chains — adding a new
 * chain provider auto-extends what this component can detect.
 */
import { CHAIN_PROVIDERS, type ChainProvider } from "@stwd/shared";
import { useAccount, useChainId, useConfig } from "wagmi";
import { ChainBadge } from "./chain-badge";

interface DetectedWallet {
  provider: ChainProvider;
  address: `0x${string}`;
  active: boolean;
}

export function DetectedWallets() {
  const { address, isConnected } = useAccount();
  const activeChainId = useChainId();
  const config = useConfig();

  if (!isConnected || !address) {
    return (
      <p className="text-xs text-zinc-500">Connect a wallet to auto-detect available chains.</p>
    );
  }

  const wagmiChainIds = new Set(config.chains.map((c) => c.id));
  const detected: DetectedWallet[] = CHAIN_PROVIDERS.filter(
    (p) => p.family === "evm" && wagmiChainIds.has(p.numericId),
  ).map((provider) => ({
    provider,
    address,
    active: provider.numericId === activeChainId,
  }));

  if (detected.length === 0) {
    return <p className="text-xs text-zinc-500">No supported chains detected.</p>;
  }

  return (
    <ul className="space-y-2" data-testid="detected-wallets">
      {detected.map(({ provider, address: addr, active }) => (
        <li
          key={provider.caip2}
          data-testid={`detected-wallet-${provider.numericId}`}
          data-active={active}
          className={`flex items-center justify-between rounded border px-3 py-2 text-sm ${
            active ? "border-zinc-700 bg-zinc-900/50" : "border-zinc-800"
          }`}
        >
          <div className="flex items-center gap-2">
            <ChainBadge chainId={provider.numericId} />
            {active && (
              <span className="text-[10px] uppercase tracking-wide text-emerald-400">Active</span>
            )}
          </div>
          <a
            href={provider.explorerAddressUrl(addr)}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-zinc-400 hover:text-zinc-200"
          >
            {addr.slice(0, 6)}…{addr.slice(-4)}
          </a>
        </li>
      ))}
    </ul>
  );
}
