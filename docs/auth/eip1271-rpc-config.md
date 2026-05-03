---
title: EIP-1271 RPC Configuration
description: Configure JSON-RPC endpoints for smart contract wallet (Safe) sign-in support.
---

# EIP-1271 RPC configuration

Steward supports sign-in with smart contract wallets (Safe, Argent, Ambire, etc.) via [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271). When a SIWE signature can't be verified via ECDSA recover (the EOA path), the API calls the wallet contract's `isValidSignature(bytes32, bytes)` method on-chain to verify.

This requires a JSON-RPC endpoint for whichever chain the smart contract wallet is deployed on.

## Default behavior

Out of the box, Steward uses public RPC endpoints from `publicnode.com` for major chains:

| Chain | Chain ID | Default RPC |
| --- | --- | --- |
| Ethereum mainnet | 1 | `https://ethereum-rpc.publicnode.com` |
| Base | 8453 | `https://base-rpc.publicnode.com` |
| BSC | 56 | `https://bsc-rpc.publicnode.com` |
| Polygon | 137 | `https://polygon-bor-rpc.publicnode.com` |
| Optimism | 10 | `https://optimism-rpc.publicnode.com` |
| Arbitrum One | 42161 | `https://arbitrum-one-rpc.publicnode.com` |
| Sepolia (testnet) | 11155111 | `https://ethereum-sepolia-rpc.publicnode.com` |
| Base Sepolia (testnet) | 84532 | `https://base-sepolia-rpc.publicnode.com` |

Public RPCs are rate-limited and prone to outages. **For production, override with private RPC endpoints.**

## Override per chain

Set environment variables of the form `SIWE_RPC_<CHAIN_ID>`:

```bash
SIWE_RPC_1=https://your-private-mainnet-rpc.example
SIWE_RPC_8453=https://your-private-base-rpc.example
SIWE_RPC_56=https://your-private-bsc-rpc.example
```

Recommended providers: Alchemy, Infura, QuickNode, Helius (Solana), or your own node.

## Adding a new chain

Drop a corresponding env var. No code changes required:

```bash
SIWE_RPC_534352=https://scroll-rpc.example   # Scroll
SIWE_RPC_324=https://zksync-rpc.example      # zkSync Era
```

If a smart contract wallet attempts SIWE from a chain with no RPC configured (and no default fallback), the verify endpoint returns `401 Invalid signature`. The user should be informed to either switch to a supported chain or contact the operator to add the chain.

## EOA flow is unaffected

The verification path tries ECDSA recover first via the `siwe` library. EIP-1271 is a fallback only when ECDSA recover fails. EOA wallets (MetaMask, Rabby, hardware wallets driving an EOA) never enter the EIP-1271 codepath and don't depend on RPC availability.

## Verification flow

```
POST /v1/auth/verify
  → siwe.verify({ signature })           // ECDSA recover (EOA)
    ✓ success → mint JWT
    ✗ failure → fall through to EIP-1271

  → readContract(isValidSignature)
    ✓ returns 0x1626ba7e → mint JWT
    ✗ returns other     → 401 Invalid signature
    ✗ no RPC available  → 401 Invalid signature
    ✗ contract call err → 401 Invalid signature
```

## Limitations

- Only one signature path per request. We don't currently allow a multi-sig threshold check beyond what the contract itself enforces (Safe handles its own threshold internally; Steward only checks the final aggregated signature).
- Counter-factual / not-yet-deployed Safes are NOT supported. The contract must exist on-chain with a working `isValidSignature` method at sign-in time.
- ERC-6492 (counter-factual signatures) support is a future enhancement. Track in `docs/auth/AUTH_ROADMAP.md` if interested.
