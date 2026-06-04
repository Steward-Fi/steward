import type { CreateWalletFn } from "@rainbow-me/rainbowkit";
import { type CreateConnectorFn, createConnector } from "wagmi";

type HexAddress = `0x${string}`;

export interface StewardEip1193Provider {
  request(args: { method: string; params?: unknown }): Promise<unknown>;
  on?(event: string, listener: (...args: unknown[]) => void): void;
  removeListener?(event: string, listener: (...args: unknown[]) => void): void;
}

export type StewardGlobalWalletProviderFactory =
  | StewardEip1193Provider
  | (() => StewardEip1193Provider | Promise<StewardEip1193Provider>);

export interface StewardGlobalWalletOptions {
  /** Stable RainbowKit wallet id. Defaults to "steward-global". */
  id?: string;
  /** Wallet name shown in wallet pickers. Defaults to "Steward". */
  name?: string;
  /** Icon URL or data URL shown by RainbowKit. */
  iconUrl: string;
  /** CSS color behind transparent icons. Defaults to Steward dark. */
  iconBackground?: string;
  /** wagmi connector factory for the global wallet provider. */
  connector: CreateConnectorFn;
  /** Optional reverse-DNS identifier for EIP-6963-style discovery. */
  rdns?: string;
  /** Optional RainbowKit download metadata. */
  downloadUrls?: Record<string, string>;
}

export interface StewardGlobalWalletConnectorOptions {
  /** Stable wagmi connector id. Defaults to "steward-global". */
  id?: string;
  /** Wallet name shown in connector libraries. Defaults to "Steward". */
  name?: string;
  /** EIP-1193 provider or lazy provider factory. */
  provider: StewardGlobalWalletProviderFactory;
  /** Optional connector icon URL. */
  icon?: string;
  /** Optional reverse-DNS identifier for EIP-6963-style discovery. */
  rdns?: string;
}

/**
 * Wraps a Steward-compatible global wallet connector as a RainbowKit wallet.
 *
 * The connector itself is supplied by the wallet provider/app so Steward does
 * not hard-code a hosted wallet relationship. This keeps the open-source SDK
 * usable with self-hosted global-wallet providers while matching RainbowKit's
 * custom-wallet surface.
 */
export function createStewardGlobalWallet({
  id = "steward-global",
  name = "Steward",
  iconUrl,
  iconBackground = "#070b12",
  connector,
  rdns,
  downloadUrls,
}: StewardGlobalWalletOptions): CreateWalletFn {
  return () => ({
    id,
    name,
    iconUrl,
    iconBackground,
    rdns,
    downloadUrls,
    createConnector: () => connector,
  });
}

function parseChainId(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "string") {
    return value.startsWith("0x") ? Number.parseInt(value, 16) : Number.parseInt(value, 10);
  }
  return 1;
}

function normalizeAccounts(value: unknown): readonly HexAddress[] {
  return Array.isArray(value)
    ? value.filter((account): account is HexAddress => {
        return typeof account === "string" && /^0x[a-fA-F0-9]{40}$/.test(account);
      })
    : [];
}

function chainHex(chainId: number): `0x${string}` {
  return `0x${chainId.toString(16)}`;
}

/**
 * Creates a ConnectKit/wagmi-compatible connector for a Steward global wallet.
 *
 * The provider can be a self-hosted popup/iframe/global-wallet implementation
 * as long as it exposes the standard EIP-1193 request/event surface.
 */
export function createStewardGlobalWalletConnector({
  id = "steward-global",
  name = "Steward",
  provider,
  icon,
  rdns,
}: StewardGlobalWalletConnectorOptions): CreateConnectorFn<StewardEip1193Provider> {
  let cachedProvider: StewardEip1193Provider | null = null;
  const getProvider = async (): Promise<StewardEip1193Provider> => {
    if (cachedProvider) return cachedProvider;
    cachedProvider = typeof provider === "function" ? await provider() : provider;
    return cachedProvider;
  };

  return createConnector<StewardEip1193Provider>((config) => ({
    id,
    name,
    icon,
    rdns,
    type: "injected",
    async connect({ chainId } = {}) {
      const walletProvider = await getProvider();
      const accounts = normalizeAccounts(
        await walletProvider.request({ method: "eth_requestAccounts" }),
      );
      const currentChainId = parseChainId(await walletProvider.request({ method: "eth_chainId" }));
      if (chainId && currentChainId !== chainId && this.switchChain) {
        await this.switchChain({ chainId });
      }
      const connectedChainId = chainId ?? currentChainId;
      config.emitter.emit("connect", { accounts, chainId: connectedChainId });
      return { accounts, chainId: connectedChainId };
    },
    async disconnect() {
      const walletProvider = await getProvider();
      try {
        await walletProvider.request({
          method: "wallet_revokePermissions",
          params: [{ eth_accounts: {} }],
        });
      } catch {
        // Many EIP-1193 providers do not support programmatic disconnect.
      }
      config.emitter.emit("disconnect");
    },
    async getAccounts() {
      return normalizeAccounts(await (await getProvider()).request({ method: "eth_accounts" }));
    },
    async getChainId() {
      return parseChainId(await (await getProvider()).request({ method: "eth_chainId" }));
    },
    async getProvider() {
      return getProvider();
    },
    async isAuthorized() {
      return (await this.getAccounts()).length > 0;
    },
    async switchChain({ chainId }) {
      const walletProvider = await getProvider();
      await walletProvider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: chainHex(chainId) }],
      });
      const chain = config.chains.find((candidate) => candidate.id === chainId);
      if (!chain) throw new Error(`Chain ${chainId} is not configured`);
      config.emitter.emit("change", { chainId });
      return chain;
    },
    onAccountsChanged(accounts) {
      const normalized = normalizeAccounts(accounts);
      if (normalized.length === 0) config.emitter.emit("disconnect");
      else config.emitter.emit("change", { accounts: normalized });
    },
    onChainChanged(chainId) {
      config.emitter.emit("change", { chainId: parseChainId(chainId) });
    },
    onConnect(connectInfo) {
      config.emitter.emit("connect", { accounts: [], chainId: parseChainId(connectInfo.chainId) });
    },
    onDisconnect() {
      config.emitter.emit("disconnect");
    },
    onMessage(message) {
      config.emitter.emit("message", message);
    },
    async setup() {
      const walletProvider = await getProvider();
      walletProvider.on?.("accountsChanged", (accounts) => {
        this.onAccountsChanged(accounts as string[]);
      });
      walletProvider.on?.("chainChanged", (nextChainId) => {
        this.onChainChanged(String(nextChainId));
      });
      walletProvider.on?.("connect", (connectInfo) => {
        this.onConnect?.(connectInfo as { chainId?: string | number });
      });
      walletProvider.on?.("disconnect", (error) => {
        this.onDisconnect(error instanceof Error ? error : undefined);
      });
      walletProvider.on?.("message", (message) => {
        this.onMessage?.(message as { type: string; data?: unknown });
      });
    },
  }));
}
