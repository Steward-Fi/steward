import { metaMask } from "wagmi/connectors";
import type { CreateConnectorFn } from "wagmi";

/**
 * dApp metadata MetaMask Connect surfaces during the connection handshake.
 * This is the modern `dapp` field (the old `dappMetadata` alias is deprecated).
 */
export interface StewardMetaMaskDappMetadata {
  /** App name shown in the MetaMask Connect prompt. */
  name?: string;
  /** App URL. Defaults to the host page origin in the browser. */
  url?: string;
  /** Optional icon URL shown alongside the name. */
  iconUrl?: string;
}

export interface StewardMetaMaskConnectorOptions {
  /**
   * dApp metadata. Steward fills in a sensible default name/url, callers can
   * override either field. In the browser, `url` defaults to `location.origin`.
   */
  dapp?: StewardMetaMaskDappMetadata;
  /**
   * Pass-through for any other MetaMask Connect parameters (connectAndSign,
   * connectWith, etc.). Kept loose so we don't pin a connector minor version.
   */
  [key: string]: unknown;
}

const DEFAULT_DAPP_NAME = "Steward";

function defaultDappUrl(): string | undefined {
  if (typeof window !== "undefined" && window.location?.origin) {
    return window.location.origin;
  }
  return undefined;
}

/**
 * MetaMask Connect (EVM) connector for Steward, RainbowKit-free.
 *
 * Wraps wagmi v3's built-in `metaMask()` connector with Steward-friendly
 * defaults so it drops straight into a wagmi v3 `createConfig`. Because it does
 * not touch RainbowKit, it works on wagmi v3 today without waiting for a
 * RainbowKit v3 release.
 *
 * Requires the optional peers `wagmi@^3` and `@metamask/connect-evm@^2.1.0`.
 *
 * Usage:
 *   import { createConfig, http } from "wagmi";
 *   import { mainnet, base } from "wagmi/chains";
 *   import { createStewardMetaMaskConnector } from "@stwd/react/wallet/evm";
 *
 *   const config = createConfig({
 *     chains: [mainnet, base],
 *     connectors: [
 *       createStewardMetaMaskConnector({ dapp: { name: "My Steward App" } }),
 *     ],
 *     transports: { [mainnet.id]: http(), [base.id]: http() },
 *   });
 */
export function createStewardMetaMaskConnector(
  options: StewardMetaMaskConnectorOptions = {},
): CreateConnectorFn {
  const { dapp, ...rest } = options;
  const mergedDapp: StewardMetaMaskDappMetadata = {
    name: DEFAULT_DAPP_NAME,
    url: defaultDappUrl(),
    ...dapp,
  };
  return metaMask({ dapp: mergedDapp, ...rest }) as CreateConnectorFn;
}
