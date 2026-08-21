# Steward

Steward is an open-source, self-hostable governed credential proxy and policy and approval layer for agent provider actions and wallets. It ships scoped grants, exact-request approval, policy-bound execution authorization on the primary EVM sign path, and signed audit evidence verifiable offline. Bring your own agent runtime, cloud, identity provider, and custodian.

[![npm](https://img.shields.io/npm/v/@stwd/sdk)](https://www.npmjs.com/package/@stwd/sdk)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-steward.fi-blue)](https://docs.steward.fi)

## What exists today

Steward provides encrypted wallet and credential storage, authenticated tenant-scoped APIs, policy evaluation and approval workflows, a credential-injecting proxy, operator freeze controls, and signed audit evidence. Wallet and configured provider capabilities are the core. Trading venue packages are optional extensions.

| Area | Current implementation |
|---|---|
| **Custody** | Wallet keys and credentials are encrypted at rest under an operator-held root. Optional AWS KMS envelope wrapping is available, along with an operator-supplied PKCS#11 wrapping adapter and an external custody interface. Local and KMS envelope modes expose plaintext key material to the application at sign time. |
| **Scoped grants** | Named provider capabilities can bind an agent grant to a configured host, path, method, credential route, expiry, and revocation state. Grants are tenant-scoped today, not first-class client-workspace grants. |
| **Policy and approval** | Governed routes evaluate policy before calling signing or proxy operations. Wallet workflows support human approval, and provider capabilities support an exact-request approval and resume flow. |
| **Execution authorization** | The primary EVM transaction sign path and compatible approval replay require a signed, payload-bound, backend-bound, single-use authorization immediately before raw signing. This boundary does not cover every signing or proxy surface. |
| **Audit evidence** | Steward writes a tenant-scoped HMAC audit chain and exports Ed25519-signed evidence bundles through `/audit/bundle`. Bundles can be checked offline with `scripts/verify-evidence-bundle.mjs`. The verifier checks the signature against the public key carried in the bundle, so operators must separately compare that key with an out-of-band trusted signing key or fingerprint. An operator controlling all relevant keys can fabricate a self-consistent history. |
| **Deployment** | Self-hosted Docker and embedded PGLite modes are available. Operators bring their own runtime, cloud, identity, and custody configuration. |

## Architecture

```text
agent runtime           Steward governed paths               target systems
┌─────────────┐      ┌────────────────────────────┐      ┌──────────────────┐
│ scoped token│─────>│ auth + route policy checks │─────>│ configured APIs  │
│ no raw keys │      │ exact-request approvals    │      │ chains/custodian │
│ no API keys │      │ wallet + secret storage    │      └──────────────────┘
└─────────────┘      │ credential proxy           │
                     │ signed audit evidence      │
                     └────────────────────────────┘
```

Steward's long-term direction is an open authority plane across supported agent execution surfaces. Today, enforcement is surface-specific. Consult the security surface inventory and documentation before treating any path as governed.

## Quick start

```bash
npm install @stwd/sdk
```

```typescript
import { StewardClient } from "@stwd/sdk";

const steward = new StewardClient({
  // Point this at your self-hosted Steward instance.
  baseUrl: "http://localhost:3200",
  apiKey: "stw_your_tenant_key",
  tenantId: "my-app",
});

const agent = await steward.createWallet("operations-bot", "Operations Bot");
console.log(agent.walletAddresses);

const result = await steward.signTransaction("operations-bot", {
  to: "0xRecipient",
  value: "10000000000000000",
  chainId: 8453,
});
```

See the full [quickstart guide](docs/quickstart.mdx) for authentication setup and policies. See the [deployment guide](docs/deployment.md) for self-hosting.

## Auth widget

Install React components for login and wallet management:

```bash
npm install @stwd/react @stwd/sdk
```

```tsx
import { StewardProvider, StewardLogin, StewardAuthGuard } from "@stwd/react";
import "@stwd/react/styles.css";

function App() {
  return (
    <StewardProvider
      client={stewardClient}
      auth={{ baseUrl: "http://localhost:3200" }}
    >
      <StewardAuthGuard fallback={<StewardLogin methods={["passkey", "email", "google"]} />}>
        <Dashboard />
      </StewardAuthGuard>
    </StewardProvider>
  );
}
```

Components include `StewardLogin`, `StewardAuthGuard`, `StewardUserButton`, `StewardTenantPicker`, `WalletOverview`, `PolicyControls`, `ApprovalQueue`, `SpendDashboard`, and `TransactionHistory`.

## Packages

| Package | Description |
|---|---|
| [`@stwd/sdk`](https://www.npmjs.com/package/@stwd/sdk) | TypeScript client for Steward's governed wallet and provider capability APIs. |
| [`@stwd/react`](https://www.npmjs.com/package/@stwd/react) | React components for Steward authentication, wallets, policies, and approvals. |
| [`@stwd/eliza-plugin`](https://www.npmjs.com/package/@stwd/eliza-plugin) | ElizaOS integration for Steward-scoped wallet and provider capabilities. |
| [`@stwd/mcp`](https://www.npmjs.com/package/@stwd/mcp) | MCP tools for invoking Steward-authorized wallet and provider capabilities. |
| `@stwd/api` | Steward authorization, approval, execution, and evidence API. |
| `@stwd/vault` | Local and pluggable wallet-key storage and signing primitives. Policy enforcement is provided by governed execution paths. |
| `@stwd/policy-engine` | Composable policy decisions for scoped provider capabilities and wallet actions. |
| `@stwd/proxy` | Credential-injecting proxy for configured routes. |
| `@stwd/plugin-wxmr` | Opt-in wxmr.io integration for Monero on Solana bridge handoffs. |

## Self-hosting

### Docker

```bash
git clone https://github.com/Steward-Fi/steward.git && cd steward
cp .env.example .env
# Set every value required by docker-compose.yml in .env: POSTGRES_PASSWORD,
# STEWARD_MASTER_PASSWORD, STEWARD_JWT_SECRET, STEWARD_EMAIL_CODE_SECRET,
# STEWARD_EXECUTION_AUTH_SECRET, STEWARD_KDF_SALT, STEWARD_AUDIT_HMAC_KEY,
# and STEWARD_PROXY_REQUEST_SIGNING_SECRET. Use a distinct random root for each.
# The bundled private-network services also require deliberate choices for
# STEWARD_ACK_LOCAL_CUSTODY, STEWARD_ALLOW_INSECURE_DB, and
# STEWARD_ALLOW_INSECURE_REDIS; read the deployment and custody guides first.
docker compose config  # fail fast on missing required configuration
docker compose up -d
curl http://127.0.0.1:3200/ready
```

This starts the API on port 3200, the proxy on port 8080, PostgreSQL, and Redis. API migrations run automatically on startup unless `SKIP_MIGRATIONS` is set.

### Embedded mode

```bash
bun run start:local
```

Embedded mode uses PGLite, an in-process PostgreSQL-compatible database through WASM. Data persists to `~/.steward/data/`. It is intended for local development, CLI agents, and desktop apps.

To use platform routes, configure both `STEWARD_PLATFORM_KEYS` and explicit
`STEWARD_PLATFORM_KEY_SCOPES`; an unmapped key authenticates but has no platform
authorization.

### Selected environment variables

This table is not a complete production or Compose checklist. The required
interpolation guards in `docker-compose.yml` are authoritative for the shipped
stack, and runtime security guards may require additional explicit posture
choices.

| Variable | Description |
|---|---|
| `STEWARD_MASTER_PASSWORD` | Derives vault encryption keys. There is no recovery if it is lost. |
| `DATABASE_URL` | PostgreSQL connection string, not needed in embedded mode. |
| `STEWARD_JWT_SECRET` | Canonical JWT signing and verification secret. Required in production and at least 32 characters. Keep it server-side and separate from the master password. |
| `STEWARD_SESSION_SECRET` | Deprecated compatibility fallback for existing deployments. Rename it to `STEWARD_JWT_SECRET`. |
| `REDIS_URL` | Redis for rate limiting and token/spend state. Adapter swap/earn/bridge daily-cap admission requires available Redis except in explicitly acknowledged development/test memory mode; the production proxy also fails closed unless its explicit soft-fail override is enabled. |
| `RESEND_API_KEY` | Email magic-link authentication, optional. |
| `PASSKEY_RP_ID` | WebAuthn relying-party domain, optional. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth, optional. |
| `X_CLIENT_ID` / `X_CLIENT_SECRET` | Provider-account X OAuth connect and lifecycle recovery, optional. Distinct from human sign-in credentials. |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Discord OAuth, optional. |

See [`.env.example`](.env.example) and the [deployment guide](docs/deployment.md)
for configuration details.

## Shipped capabilities

- **Credential proxy:** configured routes inject provider credentials server-side without returning them to the supported agent caller.
- **Scoped grants:** named capabilities support per-agent grants, expiry, revocation, argument constraints, and rate constraints.
- **Wallet policy and approval:** supported wallet routes evaluate policy and can hold an exact request for human review.
- **Primary EVM execution authorization:** the primary EVM transaction sign path uses a signed, short-lived, single-use execution authorization immediately before raw signing.
- **Signed audit evidence:** tenant-scoped HMAC chaining, Ed25519 checkpoints, bundle export, and an offline verifier.
- **Encrypted custody:** local AES encryption, optional AWS KMS envelope wrapping, a PKCS#11 wrapping adapter, and an external-custody interface.
- **Authentication:** passkeys, email magic links, SIWE, Google OAuth, and Discord OAuth.
- **SDKs and integrations:** TypeScript SDK, React components, ElizaOS plugin, and MCP server.
- **Self-hosting:** Docker with PostgreSQL and Redis, plus embedded PGLite mode.

## Scope and trust limits

- Steward governs configured routes and supported signing paths. It does not govern arbitrary agent network egress or every action in the product.
- The primary EVM sign path has the shipped execution authorization boundary. Other wallet and proxy paths have their own documented boundaries.
- Steward does not claim MPC custody, native HSM signing, non-custodial operation, or that keys never enter application memory.
- Evidence bundles are tamper-evident after the bundled public key is separately matched to a trusted signing key or fingerprint. They are not operator-proof when the operator controls the audit and signing keys.
- Steward does not prove that a policy-allowed action is semantically legitimate or safe from prompt injection.

## Supported wallet networks

Wallet primitives support Ethereum, Base, Polygon, Arbitrum, BSC, Gnosis, Base Sepolia, BSC Testnet, Solana, Bitcoin, and Monero. Support differs by route, operation, custody backend, and deployment. This list is not a claim that every network shares the primary EVM execution authorization boundary.

The opt-in `@stwd/plugin-wxmr` integration prepares handoffs in both directions
between native Monero and Monero on Solana. Steward policy-checks the handoff
request, but the plugin does not sign, submit, settle, or verify completion of
the bridge operation; users complete it interactively at [wxmr.io](https://wxmr.io).

## Integrations

- [ElizaOS](https://elizaos.ai) through [`@stwd/eliza-plugin`](https://www.npmjs.com/package/@stwd/eliza-plugin)
- [Monero on Solana](https://wxmr.io) bridge handoffs through the opt-in `@stwd/plugin-wxmr` integration ([guide](docs/guides/monero-on-solana.mdx))
- wagmi v2 and v3, with a MetaMask Connect EVM connector
- Model Context Protocol server for AI agents and IDEs

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and pull-request guidelines.

## Links

- Website: [steward.fi](https://steward.fi)
- Docs: [docs.steward.fi](https://docs.steward.fi)
- npm: [@stwd/sdk](https://www.npmjs.com/package/@stwd/sdk), [@stwd/react](https://www.npmjs.com/package/@stwd/react), [@stwd/eliza-plugin](https://www.npmjs.com/package/@stwd/eliza-plugin)

## License

[MIT](LICENSE)
