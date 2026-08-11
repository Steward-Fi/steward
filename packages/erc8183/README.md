# @stwd/erc8183

Vendor-neutral TypeScript client for **ERC-8183** agentic-commerce job
settlement. General-purpose Steward infrastructure: it presumes **no specific
deployment** and is **not affiliated with any product**. You deploy your own
ERC-8183-compatible contracts and inject their addresses.

## What it is

ERC-8183 defines an on-chain agentic-commerce flow: a client creates a **job**
with a provider, funds a budget, the provider submits a deliverable, and an
evaluator/policy settles or refunds. This package is the client wrapper around
that standard's `AgenticCommerce`, `EvaluatorRouter`, and `OptimisticPolicy`
contracts.

## Design principles

- **No baked-in addresses.** The library ships zero contract addresses. The
  client `throw`s if you don't provide them. There is no blessed deployment.
- **No vendor affiliation.** Nothing about waifu, eliza, or any product. Just
  the ERC-8183 standard.
- **Bring your own signer + RPC.** You inject a `SignerAdapter` and a viem
  `PublicClient`, so key management and chain selection stay in your control.

## Usage

```ts
import {
	ERC8183Client,
	registerERC8183ChainConfig,
} from "@stwd/erc8183";
import { createPublicClient, http } from "viem";
import { bsc } from "viem/chains";

// Register YOUR deployment (one-time), or pass addresses directly below.
registerERC8183ChainConfig({
	chainId: 56,
	name: "BSC",
	rpcUrl: "https://bsc-dataseed.binance.org",
	addresses: {
		agenticCommerce: "0x...", // your deployed contracts
		evaluatorRouter: "0x...",
		optimisticPolicy: "0x...",
		paymentToken: "0x...",
	},
});

const client = new ERC8183Client({
	publicClient: createPublicClient({ chain: bsc, transport: http() }),
	signer: yourSignerAdapter, // { sendTransaction({ to, data, value? }) }
	addresses: {
		agenticCommerce: "0x...",
		evaluatorRouter: "0x...",
		optimisticPolicy: "0x...",
		paymentToken: "0x...",
	},
});

const { jobId, txHash } = await client.createJob({
	provider: "0x...",
	expiredAt: Math.floor(Date.now() / 1000) + 3600,
	description: "image-gen invocation #123",
});
```

## Separation of concerns

- **This package (Steward):** the general ERC-8183 client. Sovereign,
  reusable, address-injected.
- **Your product (e.g. waifu / eliza cloud):** deploys its own ERC-8183
  contracts on its chain and injects those addresses into this client.
