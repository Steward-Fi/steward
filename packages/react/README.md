# @stwd/react

Embeddable React components for Steward agent wallet management. Drop-in UI for wallet overview, transaction history, policy controls, approval queues, spend analytics, and wallet login.

## Install

```bash
npm install @stwd/react @stwd/sdk
```

## Quick Start

```tsx
import { StewardProvider, WalletOverview, PolicyControls, TransactionHistory } from "@stwd/react";
import "@stwd/react/styles.css";
import { StewardClient } from "@stwd/sdk";

const client = new StewardClient({
  baseUrl: "https://api.steward.fi",
  bearerToken: agentJwt,
});

function AgentWalletPage({ agentId }: { agentId: string }) {
  return (
    <StewardProvider client={client} agentId={agentId}>
      <WalletOverview showQR />
      <PolicyControls />
      <TransactionHistory pageSize={10} />
    </StewardProvider>
  );
}
```

## Wallet Login

First-class EVM and Solana sign-in. Uses [wagmi](https://wagmi.sh) and [RainbowKit](https://rainbowkit.com) on EVM, and [`@solana/wallet-adapter-react`](https://github.com/anza-xyz/wallet-adapter) on Solana.

Adding wallet login does not require backend changes. The component signs SIWE or SIWS messages and exchanges them through the Steward auth SDK.

Wallet login is imported from subpaths to keep optional wallet peer deps off the root entrypoint. Pick the chain(s) you actually need:

```ts
// EVM only (no Solana peers required)
import {
  createDefaultWagmiConfig,
  EVMWalletProvider,
} from "@stwd/react/wallet/evm";

// Solana only (no EVM peers required)
import {
  createDefaultSolanaWallets,
  SolanaWalletProvider,
} from "@stwd/react/wallet/solana";

// Both chains (combined entry; requires both peer families)
import {
  createDefaultWagmiConfig,
  EVMWalletProvider,
  SolanaWalletProvider,
  WalletLogin,
} from "@stwd/react/wallet";
```

Consumers that do not use wallet login can continue importing everything else from `@stwd/react` without installing wagmi, RainbowKit, or Solana wallet packages.

The per-chain entries (`/wallet/evm` and `/wallet/solana`) are the recommended way to consume wallet login: they let you skip the peer install for the chain you don't use. The combined `/wallet` entry remains for apps that support both chains.

### Wallet packages

```bash
bun add @stwd/react @stwd/sdk
# EVM
bun add wagmi viem @rainbow-me/rainbowkit @tanstack/react-query
# Solana (core)
bun add @solana/wallet-adapter-react @solana/wallet-adapter-react-ui \
        @solana/wallet-adapter-wallets @solana/web3.js bs58
# Solana wallet adapters (the curated default set)
bun add @solana/wallet-adapter-phantom @solana/wallet-adapter-solflare \
        @solana/wallet-adapter-coinbase @solana/wallet-adapter-trust \
        @solana/wallet-adapter-coin98
```

All wallet packages are declared as optional peer dependencies. Install only the families you need. `@tanstack/react-query` is required whenever you use `EVMWalletProvider` or anything wagmi downstream.

The Solana adapters are imported from their own subpackages rather than from the `@solana/wallet-adapter-wallets` barrel because the barrel re-exports every adapter (including hardware ones) and forces strict ESM (Node SSR, pnpm, Yarn PnP) to resolve dependencies that are not actually used. Strict package managers will not let `@stwd/react` reach those subpackages transitively, so they must be installed directly when you want default Solana coverage.

### WalletConnect project ID

RainbowKit WalletConnect connectors require a WalletConnect Cloud project ID. Get one free at <https://cloud.walletconnect.com>, or use Steward's shared development project ID for first-time testing:

```txt
2c7ddf841a48e522748c5e2782d73443
```

Recommended env var pattern:

```ts
const walletConnectProjectId =
  process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || "2c7ddf841a48e522748c5e2782d73443";
```

Use your own project ID for production apps when possible. The shared ID is intentionally not baked into the library.

### EVM example with curated RainbowKit wallets

`createDefaultWagmiConfig` returns a wagmi config with Steward's curated wallet order:
MetaMask, Coinbase Wallet, WalletConnect, Rainbow, Rabby, Trust Wallet, Phantom EVM, Ledger, Safe, and generic injected. Brave is discovered by the browser injected provider and EIP-6963 support.

```tsx
import { StewardProvider } from "@stwd/react";
import {
  createDefaultWagmiConfig,
  EVMWalletProvider,
  WalletLogin,
} from "@stwd/react/wallet";
import "@stwd/react/styles.css";
import "@rainbow-me/rainbowkit/styles.css";
import { mainnet, base } from "wagmi/chains";

const walletConnectProjectId =
  process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || "2c7ddf841a48e522748c5e2782d73443";

const wagmiConfig = createDefaultWagmiConfig({
  appName: "Steward",
  projectId: walletConnectProjectId,
  chains: [mainnet, base],
});

export function EvmLogin() {
  return (
    <StewardProvider
      client={client}
      agentId="agent_abc"
      auth={{ baseUrl: "https://api.steward.fi" }}
    >
      <EVMWalletProvider config={wagmiConfig}>
        <WalletLogin chains="evm" />
      </EVMWalletProvider>
    </StewardProvider>
  );
}
```

If you render `WalletLogin` directly, it is already the wallet UI. To enable wallet sign-in inside the broader `<StewardLogin>` modal (alongside passkey, email, OAuth), pass the `showWallets` prop on `<StewardLogin>` instead.

### Drop-in: `<StewardLoginWithWallets>`

The simplest possible wallet-login surface, one component, no provider wiring. Bundles `<EVMWalletProvider>` + `<SolanaWalletProvider>` and renders `<StewardLogin showWallets>` inside. All `<StewardLogin>` props (passkey, email, OAuth, title, callbacks, etc) are forwarded.

```tsx
import { StewardProvider } from "@stwd/react";
import { StewardLoginWithWallets } from "@stwd/react/wallet";
import "@stwd/react/styles.css";
import "@rainbow-me/rainbowkit/styles.css";
import "@solana/wallet-adapter-react-ui/styles.css";

export default function Login() {
  return (
    <StewardProvider auth={{ baseUrl: "https://api.steward.fi" }}>
      <StewardLoginWithWallets
        title="Sign in"
        showPasskey
        showEmail
        showGoogle
        showDiscord
        evm={{ appName: "My App" }}
        solana={{ endpoint: "https://api.mainnet-beta.solana.com" }}
        onSuccess={({ token }) => console.log("signed in:", token)}
      />
    </StewardProvider>
  );
}
```

**Sensible defaults:**
- WalletConnect projectId falls back to `process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID`, then to a Steward shared default for first-time testing. Production apps should set their own.
- EVM chains default to `[mainnet, base, polygon, optimism, arbitrum, bsc]`. Pass `evm.chains` to override.
- Solana endpoint defaults to public mainnet-beta (rate-limited; not for production). Pass `solana.endpoint` with a private RPC.
- Solana wallet list defaults to the curated software-only set (`createDefaultSolanaWallets()`). Pass `solana.wallets` to override.

**Per-chain gates:**
```tsx
<StewardLoginWithWallets enable={{ solana: false }} ... />
```
Disables the Solana wrap entirely. Same for `enable.evm`.

**Bring your own wagmi config:**
```tsx
<StewardLoginWithWallets evm={{ config: myWagmiConfig }} ... />
```

This component pulls BOTH EVM and Solana peer dep trees. Apps that want only one chain should use `<StewardLogin showWallets={{ evm: true }}>` directly with `<EVMWalletProvider>` and import from the chain-specific subpath `@stwd/react/wallet/evm` to skip the Solana peer install entirely.

### Solana example with expanded defaults

`SolanaWalletProvider` now defaults to `DEFAULT_SOLANA_WALLETS`, which includes Phantom, Solflare, Coinbase Wallet, Trust Wallet, MathWallet, and Coin98. Wallets that implement the Solana Wallet Standard, including Backpack and Brave when installed in the browser, are discovered at runtime by wallet-adapter. Hardware Solana wallets (Ledger, Trezor) are excluded from defaults because their adapters do not implement `signMessage` and cannot complete the SIWS sign-in flow; apps that want hardware support in non-login contexts can extend the wallet list explicitly.

```tsx
import { StewardProvider } from "@stwd/react";
import {
  DEFAULT_SOLANA_WALLETS,
  SolanaWalletProvider,
  WalletLogin,
} from "@stwd/react/wallet";
import "@stwd/react/styles.css";
import "@solana/wallet-adapter-react-ui/styles.css";

const customWallet = createMySolanaWalletAdapter();

export function SolanaLogin() {
  return (
    <StewardProvider
      client={client}
      agentId="agent_abc"
      auth={{ baseUrl: "https://api.steward.fi" }}
    >
      <SolanaWalletProvider
        endpoint="https://api.mainnet-beta.solana.com"
        wallets={[...DEFAULT_SOLANA_WALLETS, customWallet]}
      >
        <WalletLogin chains="solana" />
      </SolanaWalletProvider>
    </StewardProvider>
  );
}
```

### Combined EVM and Solana example

```tsx
<StewardProvider client={client} agentId="agent_abc" auth={{ baseUrl: "https://api.steward.fi" }}>
  <EVMWalletProvider config={wagmiConfig}>
    <SolanaWalletProvider endpoint="https://api.mainnet-beta.solana.com">
      <WalletLogin chains="both" onSuccess={(res, kind) => console.log(kind, res.token)} />
    </SolanaWalletProvider>
  </EVMWalletProvider>
</StewardProvider>
```

### Bring your own providers

`<EVMWalletProvider>` and `<SolanaWalletProvider>` are optional convenience wrappers. `<EVMWalletProvider>` also mounts a `QueryClientProvider` for wagmi v2 hooks. Pass your own `queryClient` prop if your app already has one. If your app already mounts wagmi, RainbowKit, TanStack Query, and Solana wallet-adapter providers elsewhere, `<WalletLogin />` will pick them up automatically.

`<EVMWalletProvider>` still accepts any consumer-supplied wagmi `config`. `createDefaultWagmiConfig` is additive and recommended for apps that want Steward's curated wallet order.

### WalletLogin props

| Prop | Type | Default | Notes |
| ---- | ---- | ------- | ----- |
| `chains` | `"evm" \| "solana" \| "both"` | `"both"` | Two-column layout on desktop when `"both"`. |
| `onSuccess` | `(result, kind) => void` | - | Fires after SIWE or SIWS exchange. |
| `onError` | `(error, kind) => void` | - | Fires on wallet reject, network errors, etc. |
| `className` | `string` | - | Appended to the root element. |
| `classes` | `WalletLoginClassOverrides` | - | Per-slot className overrides. |
| `evmLabel` | `string` | `"Ethereum"` | Column heading for EVM. |
| `solanaLabel` | `string` | `"Solana"` | Column heading for Solana. |
| `evmSignLabel` | `(walletName) => string` | - | Override the sign button label. |
| `solanaSignLabel` | `(walletName) => string` | - | Override the sign button label. |

### Wallet login FAQ

**Does it work without `<EVMWalletProvider>` or `<SolanaWalletProvider>`?**
Yes. They are optional convenience wrappers. `<WalletLogin />` only needs ambient wagmi and RainbowKit context for EVM, plus Solana wallet-adapter context for Solana.

**Can I ship EVM only?**
Yes. Install only the EVM peer deps, pass `chains="evm"`, and skip the Solana providers entirely. The Solana panel is tree-shaken out when unused.

**Can I ship Solana only?**
Yes. Install only the Solana peer deps, pass `chains="solana"`, and skip wagmi and RainbowKit providers.

**How do errors surface?**
Inline under the relevant column and via `onError(error, kind)`.

**Does `<WalletLogin />` disconnect the wallet after sign-in?**
No. The wallet stays connected so the user can re-sign or sign transactions. Call `useDisconnect()` or `useWallet().disconnect()` yourself if you want to drop the connection.

**Solana sign-in is disabled.**
This means either the connected wallet does not implement `signMessage`, or `@stwd/sdk` has not been upgraded to a version that exposes `signInWithSolana`. Upgrade to `@stwd/sdk >= 0.8.0`.

## Components

| Component | Description |
|-----------|-------------|
| `<StewardProvider>` | Context provider, wraps all other components |
| `<WalletOverview>` | Wallet address, balance, chain info, funding QR |
| `<TransactionHistory>` | Paginated tx list with status badges and explorer links |
| `<PolicyControls>` | Human-friendly policy toggles, spending limits, address lists, etc. |
| `<ApprovalQueue>` | Pending transaction review with approve/deny |
| `<SpendDashboard>` | Spend tracking with budget bars and charts |
| `<WalletLogin>` | EVM and Solana wallet sign-in UI from `@stwd/react/wallet` |

## Hooks

All components use public hooks. Use them directly for custom UIs:

```tsx
import { useSteward, useWallet, useTransactions, usePolicies, useApprovals, useSpend } from "@stwd/react";
```

| Hook | Returns |
|------|---------|
| `useSteward()` | Client, agentId, features, theme, tenant config |
| `useWallet()` | Agent data, balance, addresses with auto-refresh |
| `useTransactions(opts?)` | Paginated transaction history |
| `usePolicies()` | Policy CRUD and template support |
| `useApprovals(interval?)` | Pending approvals plus approve/reject actions |
| `useSpend(range?)` | Spend analytics for time range |

## Theming

Components use CSS custom properties. Override any `--stwd-*` variable:

```css
.stwd-root {
  --stwd-primary: #8B5CF6;
  --stwd-accent: #A78BFA;
  --stwd-bg: #0F0F0F;
  --stwd-surface: #1A1A2E;
  --stwd-text: #FAFAFA;
  --stwd-muted: #6B7280;
  --stwd-success: #10B981;
  --stwd-error: #EF4444;
  --stwd-warning: #F59E0B;
  --stwd-radius: 12px;
  --stwd-font: Inter, system-ui, sans-serif;
}
```

Or pass theme overrides to the provider:

```tsx
<StewardProvider
  client={client}
  agentId={agentId}
  theme={{ primaryColor: "#FF6B35", colorScheme: "light" }}
>
```

## Peer Dependencies

Required:

- `react >= 18`
- `react-dom >= 18`
- `@stwd/sdk >= 0.7.3`

Optional, install only what you use:

- EVM: `wagmi ^2.0.0`, `viem ^2.0.0`, `@rainbow-me/rainbowkit ^2.0.0`, `@tanstack/react-query ^5.0.0`
- Solana: `@solana/wallet-adapter-react ^0.15.0`, `@solana/wallet-adapter-react-ui ^0.9.0`, `@solana/wallet-adapter-wallets ^0.19.38`, `@solana/web3.js ^1.98.0`, `bs58 ^5.0.0`

## License

MIT
