---
title: "ERC-8004 integration"
description: "Current Steward identity, discovery, and reputation behavior for EVM registries."
---

# ERC-8004 integration

Steward currently exposes a tenant-scoped database view of ERC-8004 registration
records and public discovery data. It does not relay registrations between
chains, bridge attestations to Solana, aggregate cross-chain reputation, or
operate a production on-chain indexer.

## API behavior

The API mounts these routes:

- `POST /agents/:id/register-onchain` validates an owner/admin session with
  recent MFA, records an audited **pending** registration request, and stores the
  proposed agent card. It does not submit an EVM transaction.
- `GET /agents/:id/onchain` returns the tenant's stored registration and
  reputation-cache rows. Reputation values are explicitly marked unverified.
- `POST /agents/:id/feedback` is disabled because signed on-chain feedback is
  not implemented.
- `GET /discovery/agents` and `GET /discovery/registries` expose stored discovery
  records. They do not prove that a registry or score was verified on-chain.

The placeholder registry address
`0x0000000000000000000000000000000000008004` identifies pending/unconfigured
records. Consumers must not interpret it as a deployed contract.

## Library behavior

`@stwd/erc8004` contains an EVM client used independently of the API routes. A
caller must provide a real RPC endpoint, deployed identity and reputation
registry addresses, and an `Eip8004Signer` for identity registration.

The identity client can:

- encode an ERC-8004 registration payload;
- submit `register(string agentURI)` through the caller-provided signer;
- wait for a successful receipt and require a matching `Registered` event; and
- read `ownerOf` and `tokenURI` for an existing token.

The reputation client is read-only. It reads `getReputation`,
`reputationOf`, or `feedbackCount` from the configured EVM registry. It rejects
all feedback writes. Feedback history also requires an external indexer and
currently returns no records.

Both clients fail closed when configured with a zero or placeholder registry.
Unconfigured identity lookups return `null`; unconfigured reputation lookups
return `verified: false` without numeric score fields.

## Supported configuration

`REGISTRY_CONFIGS` supplies RPC defaults and registry addresses for Ethereum,
Base, BSC, BSC Testnet, Gnosis, and Arbitrum. These entries are client
configuration, not deployment verification. Operators must independently verify
contract deployment and bytecode on the selected chain before treating results
as authoritative.

Solana wallets elsewhere in Steward are unrelated to ERC-8004. No Solana-native
registry, Wormhole/LayerZero bridge, universal cross-chain agent mapping, batch
relay, or per-tenant mirror-chain configuration is implemented.
