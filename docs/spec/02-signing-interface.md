# 02 — Signing Interface

## Overview

The signing interface defines how agents request transaction signing, how the vault processes those requests, and what responses look like. All signing operations go through the policy engine before any key material is decrypted.

## Request Flow

```
1. Agent sends sign request (HTTP POST)
2. Auth middleware validates credentials (API key or JWT)
3. Policy engine evaluates all enabled policies
4. If all policies pass → vault decrypts key, signs, returns signature
5. If soft policy fails → transaction queued for manual approval
6. If hard policy fails → request rejected, error returned
7. Key material zeroized from memory
```

## Sign Transaction

### Request

```
POST /vault/:agentId/sign
Content-Type: application/json
Authorization: Bearer <agent-jwt>
```

```json
{
  "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C",
  "value": "50000000000000000",
  "data": "0x",
  "chainId": 8453,
  "gasLimit": "21000",
  "maxFeePerGas": "1000000000",
  "maxPriorityFeePerGas": "1000000"
}
```

#### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| to | string | Destination address (EVM hex or Solana base58) |
| value | string | Transaction value in smallest unit (wei for EVM) |
| chainId | integer | Numeric chain identifier |

#### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| data | string | Hex-encoded calldata (EVM) |
| gasLimit | string | Gas limit (EVM) |
| maxFeePerGas | string | EIP-1559 max fee (EVM) |
| maxPriorityFeePerGas | string | EIP-1559 priority fee (EVM) |
| nonce | integer | Transaction nonce (auto-resolved if omitted) |
| broadcast | boolean | Whether to broadcast after signing (default: true) |

### Response (Approved)

```json
{
  "ok": true,
  "data": {
    "txHash": "0x8d7592b93cad0983b481451c6d0c05900a1c6d74...",
    "signedTx": "0xf86c...",
    "chainId": 8453,
    "status": "signed",
    "txId": "550e8400-e29b-41d4-a716-446655440000",
    "policyResults": [
      { "id": "limit", "type": "spending-limit", "passed": true },
      { "id": "addrs", "type": "approved-addresses", "passed": true }
    ]
  }
}
```

### Response (Queued for Approval)

When a soft policy (auto-approve-threshold) fails but all hard policies pass:

```json
{
  "ok": true,
  "data": {
    "status": "pending_approval",
    "txId": "550e8400-e29b-41d4-a716-446655440000",
    "message": "Transaction exceeds auto-approve threshold. Queued for manual review.",
    "policyResults": [
      { "id": "limit", "type": "spending-limit", "passed": true },
      { "id": "auto", "type": "auto-approve-threshold", "passed": false, "reason": "Value 1.5 ETH exceeds threshold 1.0 ETH" }
    ]
  }
}
```

### Response (Rejected)

When a hard policy fails:

```json
{
  "ok": false,
  "error": "Policy violation: spending-limit",
  "data": {
    "status": "rejected",
    "txId": "550e8400-e29b-41d4-a716-446655440000",
    "policyResults": [
      { "id": "limit", "type": "spending-limit", "passed": false, "reason": "Daily spend 4.5 ETH exceeds limit 5.0 ETH by this transaction" }
    ]
  }
}
```

## Sign Message

### Request

```
POST /vault/:agentId/sign-message
```

```json
{
  "message": "Hello, world!",
  "chainId": 8453
}
```

### Response

```json
{
  "ok": true,
  "data": {
    "signature": "0x1b2e...",
    "address": "0x9E12...",
    "message": "Hello, world!"
  }
}
```

Message signing is NOT subject to policy evaluation. Policies gate value transfers, not message signatures.

## Sign Typed Data (EIP-712)

### Request

```
POST /vault/:agentId/sign-typed-data
```

```json
{
  "domain": { "name": "MyDApp", "version": "1", "chainId": 8453 },
  "types": { ... },
  "primaryType": "...",
  "message": { ... }
}
```

### Response

```json
{
  "ok": true,
  "data": {
    "signature": "0xab12...",
    "address": "0x9E12..."
  }
}
```

EIP-712 signing is NOT subject to policy evaluation (same rationale as message signing).

## Chain Routing

The vault routes signing operations based on `chainId`:

| Chain ID | Family | Signing Method |
|----------|--------|---------------|
| 1, 56, 97, 137, 8453, 42161, 84532 | EVM | secp256k1 via viem |
| 101, 102 | Solana | Ed25519 via @solana/web3.js |

If a `chainId` is not recognized, the vault MUST return an error rather than attempting to sign with a default chain.

## RPC Passthrough

```
POST /vault/:agentId/rpc
```

The RPC endpoint accepts standard JSON-RPC requests and routes them to the appropriate chain RPC, signing any methods that require a signature (eth_sendTransaction) through the vault.

Supported methods:
- `eth_sendTransaction` — signs and broadcasts
- `eth_signTransaction` — signs without broadcasting
- `eth_getBalance` — passthrough (no signing)
- `eth_call` — passthrough (no signing)

Unsupported methods MUST return a JSON-RPC error with code `-32601` (Method not found).

## Error Codes

| HTTP Status | Error | Meaning |
|-------------|-------|---------|
| 400 | `invalid_request` | Missing or malformed fields |
| 401 | `unauthorized` | Invalid or expired credentials |
| 403 | `policy_violation` | Hard policy rejected the transaction |
| 404 | `agent_not_found` | Agent ID does not exist for this tenant |
| 429 | `rate_limited` | Too many API requests (not tx rate limit) |
| 500 | `signing_error` | Vault failed to sign (chain error, RPC error) |

All error responses follow the shape:

```json
{
  "ok": false,
  "error": "<error_code>",
  "message": "<human-readable description>"
}
```
