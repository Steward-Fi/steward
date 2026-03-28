# @stwd/react

Embeddable React components for Steward agent wallet management. Drop-in UI for wallet overview, transaction history, policy controls, approval queues, and spend analytics.

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

## Components

| Component | Description |
|-----------|-------------|
| `<StewardProvider>` | Context provider — wraps all other components |
| `<WalletOverview>` | Wallet address, balance, chain info, funding QR |
| `<TransactionHistory>` | Paginated tx list with status badges and explorer links |
| `<PolicyControls>` | Human-friendly policy toggles (spending limits, address lists, etc.) |
| `<ApprovalQueue>` | Pending transaction review with approve/deny |
| `<SpendDashboard>` | Spend tracking with budget bars and charts |

## Hooks

All components use public hooks. Use them directly for custom UIs:

```tsx
import { useSteward, useWallet, useTransactions, usePolicies, useApprovals, useSpend } from "@stwd/react";
```

| Hook | Returns |
|------|---------|
| `useSteward()` | Client, agentId, features, theme, tenant config |
| `useWallet()` | Agent data, balance, addresses with auto-refresh |
| `useTransactions(opts?)` | Paginated tx history |
| `usePolicies()` | Policy CRUD + template support |
| `useApprovals(interval?)` | Pending approvals + approve/reject actions |
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

- `react >= 18`
- `@stwd/sdk >= 0.1.0`

## License

MIT
