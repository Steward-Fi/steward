# 05 — Supported Chains

## Overview

Steward supports two chain families: EVM-compatible chains and Solana. Each family uses different key types, signing algorithms, and address formats.

## EVM Chains

### Key Generation

- **Algorithm:** secp256k1
- **Method:** Random 32-byte private key via `generatePrivateKey()` (viem)
- **Address derivation:** Keccak-256 hash of public key, last 20 bytes, EIP-55 checksum

### Supported Networks

| Chain | Chain ID | RPC Default | Status |
|-------|----------|------------|--------|
| Ethereum Mainnet | 1 | eth.llamarpc.com | Supported |
| BSC | 56 | bsc-dataseed.binance.org | Supported |
| BSC Testnet | 97 | data-seed-prebsc-1-s1.bnbchain.org:8545 | Supported |
| Polygon | 137 | polygon-rpc.com | Supported |
| Base | 8453 | mainnet.base.org | Primary |
| Arbitrum | 42161 | arb1.arbitrum.io/rpc | Supported |
| Base Sepolia | 84532 | sepolia.base.org | Testnet |

### Signing Methods

| Operation | Method | Notes |
|-----------|--------|-------|
| Sign Transaction | EIP-1559 (Type 2) | Default for all EVM chains |
| Sign Message | personal_sign (EIP-191) | Prefix: `\x19Ethereum Signed Message:\n` |
| Sign Typed Data | EIP-712 | Domain separator + typed struct hashing |

### Transaction Fields

EVM transactions support the following fields:

| Field | Type | Required | Default |
|-------|------|----------|---------|
| to | address | Yes | — |
| value | uint256 (wei string) | Yes | — |
| data | hex string | No | "0x" |
| chainId | uint | Yes | Config default |
| gasLimit | uint | No | Estimated |
| maxFeePerGas | uint | No | From chain |
| maxPriorityFeePerGas | uint | No | From chain |
| nonce | uint | No | From chain |

If gas fields are omitted, the vault estimates gas using the chain's RPC. If nonce is omitted, the next nonce is fetched from the chain.

### Broadcast

After signing, the vault broadcasts the transaction via `eth_sendRawTransaction` to the configured RPC URL. The returned `txHash` is stored in the transaction record.

If `broadcast: false` is set in the request, the signed transaction is returned without broadcasting. The `txHash` field will be null.

## Solana

### Key Generation

- **Algorithm:** Ed25519
- **Method:** `Keypair.generate()` from `@solana/web3.js`
- **Address:** Base58-encoded public key
- **Storage:** Full 64-byte secret key (includes both private and public components)

### Supported Networks

| Network | Chain ID (Convention) | RPC Default |
|---------|----------------------|------------|
| Mainnet Beta | 101 | api.mainnet-beta.solana.com |
| Devnet | 102 | api.devnet.solana.com |

Note: Solana does not use numeric chain IDs natively. The values 101 and 102 are Steward conventions for routing.

### Signing Methods

| Operation | Method | Notes |
|-----------|--------|-------|
| Sign Transaction | Ed25519 | Deserialize → sign → serialize |
| Sign Message | Ed25519 | Direct message signing via `nacl.sign.detached` |

### Transaction Format

Solana transactions are passed as base64-encoded serialized transaction objects. The vault:

1. Deserializes the transaction from base64
2. Signs with the agent's Ed25519 keypair
3. Returns the signed transaction as base64

Solana transactions are NOT broadcast by default (the agent or platform handles submission). This may change in future versions.

### Balance Query

```
GET /vault/:agentId/balance?chainId=101
```

Returns native SOL balance:

```json
{
  "ok": true,
  "data": {
    "native": "1500000000",
    "nativeFormatted": "1.5",
    "symbol": "SOL",
    "chainId": 101,
    "walletAddress": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
  }
}
```

## Chain Detection

The vault detects chain family from the agent's wallet address format:

- Address starts with `0x` → EVM
- Otherwise → Solana (base58)

For signing requests, `chainId` determines routing:
- 101 or 102 → Solana signing path
- Any other value → EVM signing path

If the `chainId` does not match the agent's wallet type (e.g., chainId=8453 for a Solana wallet), the vault MUST return an error.

## Adding New Chains

### EVM Chains

Adding a new EVM chain requires:

1. Add entry to `CHAINS` map with viem chain configuration
2. Add default RPC URL to `CHAIN_RPCS` map
3. No code changes — all EVM chains use the same signing logic

### Non-EVM Chains

Adding a non-EVM chain family requires:

1. New key generation module (matching the chain's curve)
2. New signing implementation
3. New chain ID convention (if the chain doesn't use numeric IDs)
4. Updated chain detection logic
5. Updated types in `@stwd/shared`

## Future Chains (Planned)

| Chain | Curve | Priority | Notes |
|-------|-------|----------|-------|
| Bitcoin | secp256k1 | P2 | BIP-84 (native SegWit) |
| Cosmos | secp256k1 | P3 | Bech32 addresses |
| Sui | Ed25519 | P3 | Similar to Solana |
