# ERC-8004 Integration Architecture

**Date:** 2026-04-11
**Status:** Design (no code yet)
**Author:** Worker Q (Sol)
**Branch:** `docs/erc8004-architecture`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [ERC-8004 Primer](#2-erc-8004-primer)
3. [Architecture Overview](#3-architecture-overview)
4. [Multi-Registry Model (White-Label)](#4-multi-registry-model-white-label)
5. [Identity Integration](#5-identity-integration)
6. [Reputation Integration](#6-reputation-integration)
7. [Validation Integration](#7-validation-integration)
8. [Contract Interaction](#8-contract-interaction)
9. [New API Endpoints](#9-new-api-endpoints)
10. [New SDK Methods](#10-new-sdk-methods)
11. [Database Schema Changes](#11-database-schema-changes)
12. [Gas Strategy](#12-gas-strategy)
13. [Migration Plan](#13-migration-plan)
14. [Competitive Position](#14-competitive-position)
15. [Implementation Phases](#15-implementation-phases)
16. [Open Questions](#16-open-questions)

---

## 1. Executive Summary

Steward integrates ERC-8004 "Trustless Agents" to give every agent wallet a portable, verifiable on-chain identity. The integration serves two roles:

- **Registrar:** Steward mints and manages ERC-8004 identity NFTs for agents created through its API.
- **Consumer:** Steward reads reputation and validation data from the ERC-8004 registries to inform policy decisions.

The critical design requirement: **a white-label, multi-registry model where each tenant can have their own registry, but all registries are interoperable.** Steward maintains a default registry, tenants can optionally deploy their own, and cross-registry discovery and reputation aggregation happen at the platform level.

This positions Steward as the first wallet infrastructure that natively ties agent identity, reputation, and policy enforcement into a single stack.

---

## 2. ERC-8004 Primer

ERC-8004 defines three on-chain registries deployed as per-chain singletons via CREATE2 (same address on every chain):

### 2.1 Identity Registry

- ERC-721 NFT with URIStorage extension
- Each agent gets a `tokenId` (called `agentId` in ERC-8004) and an `agentURI` pointing to a JSON registration file
- Registration file contains: name, description, image, service endpoints (A2A, MCP, web, etc.), wallet address, supported trust mechanisms
- The NFT owner controls the agent's identity (can transfer, delegate, update URI)
- On-chain metadata via `getMetadata()`/`setMetadata()` for extensibility
- `agentWallet` is a reserved metadata key, requires EIP-712 signature to change

### 2.2 Reputation Registry

- Any address can give feedback to any registered agent
- Feedback: signed fixed-point value (int128) + valueDecimals (uint8), optional tags (tag1, tag2), endpoint URI, off-chain feedbackURI
- Feedback is stored on-chain (value, tags, revoked status) and emitted as events (URI, hash)
- Read functions: `getSummary()`, `readFeedback()`, `readAllFeedback()`, `getClients()`
- Agent owners cannot self-rate (enforced at contract level)
- Revocation: clients can revoke their own feedback
- Response appending: anyone can add context to existing feedback (spam flagging, refund proofs)

### 2.3 Validation Registry

- Agents request validation from validator contracts
- Validators respond with a 0-100 score (binary or granular)
- Supports: stake-secured re-execution, zkML proofs, TEE attestations, trusted judges
- Request/response pattern with on-chain event trail

### 2.4 Contract Addresses

All chains use the same deterministic CREATE2 address:

| Contract | Address |
|----------|---------|
| Identity Registry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
| Reputation Registry | Deployed alongside, linked via `initialize(identityRegistry)` |
| Validation Registry | Deployed alongside, linked via `initialize(identityRegistry)` |

**Primary chain for Steward: Base (chainId 8453, CAIP-2 `eip155:8453`)**

Reputation and Validation registry addresses are discoverable from the Identity Registry deployment. They need to be looked up on-chain or via Chitin's API.

### 2.5 Chitin Protocol

Chitin is the highest-level abstraction over ERC-8004. It provides:

- **SDK:** `@chitin-id/sdk` with a `register()` function that handles Arweave upload + ERC-8004 minting in one call
- **REST API:** `https://api.chitin.id/v1` with endpoints for registration, profile, verification
- **Soul layer:** Extends ERC-8004 with soul hashing (system prompt verification), merkle proofs for selective disclosure
- **Free tier:** First 10,000 agents globally get permanent free access

For Steward's purposes, Chitin is the preferred registration pathway (handles Arweave storage, gas relay, and the full ERC-8004 minting flow). Direct contract interaction is the fallback for tenants who want full control.

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Steward Platform                      │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐   │
│  │  Tenant A │  │  Tenant B │  │  Steward Default   │   │
│  │ (own reg) │  │ (default) │  │  Registry (Base)   │   │
│  └─────┬─────┘  └─────┬─────┘  └─────────┬──────────┘   │
│        │              │                   │              │
│  ┌─────▼──────────────▼───────────────────▼──────────┐  │
│  │              Registry Manager Service              │  │
│  │  - Manages registration across multiple registries │  │
│  │  - Aggregates reputation cross-registry            │  │
│  │  - Indexes all known registries for discovery      │  │
│  └─────────────────────┬─────────────────────────────┘  │
│                        │                                 │
│  ┌─────────────────────▼─────────────────────────────┐  │
│  │              ERC-8004 Service Layer                 │  │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────────┐     │  │
│  │  │Identity │  │Reputation│  │  Validation   │     │  │
│  │  │ Client  │  │  Client  │  │   Client      │     │  │
│  │  └────┬────┘  └────┬─────┘  └──────┬───────┘     │  │
│  └───────┼─────────────┼───────────────┼─────────────┘  │
│          │             │               │                 │
└──────────┼─────────────┼───────────────┼─────────────────┘
           │             │               │
     ┌─────▼─────────────▼───────────────▼──────┐
     │       Base L2 (ERC-8004 Contracts)        │
     │  Identity │ Reputation │ Validation       │
     │  Registry │  Registry  │  Registry        │
     └───────────────────────────────────────────┘
```

### Integration Points

| Steward Event | ERC-8004 Action |
|---------------|-----------------|
| Agent created (`POST /agents`) | Mint ERC-8004 identity NFT (optional, configurable) |
| Agent URI updated | Call `setAgentURI()` on-chain |
| Transaction signed successfully | Post positive feedback to Reputation Registry |
| Policy violation (tx rejected) | Post negative feedback to Reputation Registry |
| Policy evaluation completed | Submit validation request (optional) |
| Agent deleted | Transfer or burn NFT (configurable) |

---

## 4. Multi-Registry Model (White-Label)

This is the core architectural differentiator. Steward doesn't just integrate with ONE ERC-8004 registry. It supports a federated model.

### 4.1 Registry Types

| Type | Description | Who Deploys | Example |
|------|-------------|-------------|---------|
| **Steward Default** | The canonical Steward registry on Base | Steward platform | All agents without a tenant-specific registry |
| **Tenant Custom** | A tenant deploys their own Identity Registry | Tenant (with Steward tooling) | Milady Cloud agents get their own registry |
| **External** | A third-party registry that Steward indexes | Third party | Agents registered via Chitin directly |

### 4.2 Tenant Configuration

New field in `tenantConfigs`:

```typescript
// In tenant_configs table / TenantControlPlaneConfig
{
  erc8004: {
    // Which registry this tenant's agents register on
    registryAddress: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", // default = Steward's
    registryChainId: 8453,                                          // default = Base
    
    // Auto-register agents on creation?
    autoRegister: false,  // default false (opt-in)
    
    // Registration method
    registrationMethod: "chitin" | "direct",  // chitin = via Chitin API, direct = raw contract call
    
    // Chitin API key (if using chitin method)
    chitinApiKey: "chtn_live_xxx",  // stored encrypted in secrets vault
    
    // Agent URI template (Handlebars-style)
    agentUriTemplate: "https://{{tenantDomain}}/agents/{{agentId}}/card.json",
    
    // Custom metadata to include in all agent registrations
    defaultMetadata: {
      platform: "steward",
      tenant: "{{tenantId}}"
    },
    
    // Gas sponsorship
    gasStrategy: "platform" | "tenant" | "agent",  // who pays
  }
}
```

### 4.3 Registry Federation

Steward maintains a **registry index** that tracks all known registries:

```
registries table:
  id          - UUID
  address     - contract address
  chainId     - chain the registry is deployed on
  caip2       - CAIP-2 identifier (e.g. eip155:8453)
  name        - human-readable name
  tenantId    - FK to tenants (null = third-party/steward default)
  type        - "steward_default" | "tenant" | "third-party"
  lastIndexed - timestamp of last agent sync
  agentCount  - cached count
  createdAt
```

### 4.4 Cross-Registry Discovery

When a discovery query comes in (`GET /discovery/agents`), Steward:

1. Queries its local database for agents across ALL indexed registries
2. Filters by requested criteria (capability, chain, reputation threshold)
3. Returns results with registry source metadata

This means an agent registered in Tenant A's registry is discoverable by Tenant B, as long as both registries are indexed by Steward. ERC-8004's design makes this natural: the Identity Registry is a public ERC-721 contract, so anyone can read any agent's registration.

### 4.5 Cross-Registry Reputation

Reputation is agent-specific, not registry-specific. The Reputation Registry tracks feedback by `agentId` within its linked Identity Registry. For cross-registry reputation:

1. **Same chain:** If both registries are on Base, Steward queries both Reputation Registries and aggregates scores.
2. **Cross-chain:** If registries are on different chains, Steward runs an indexer per chain and aggregates off-chain.
3. **Aggregation formula:** Weighted average by feedback count and client trust scores (off-chain computation, on-chain data).

In practice for v1: all Steward registries will be on Base, so cross-registry reputation aggregation is straightforward (multiple contract reads on the same chain).

---

## 5. Identity Integration

### 5.1 Registration Flow

When an agent is created in Steward and ERC-8004 registration is triggered (either automatically via `autoRegister: true` or manually via `POST /agents/:id/register-onchain`):

```
1. Agent created in Steward DB (existing flow)
2. If autoRegister OR manual trigger:
   a. Build agent registration JSON (agentURI content)
   b. Upload to Arweave (via Chitin) or host at tenant URL
   c. Call register(agentURI) on Identity Registry
      - Via Chitin API: POST /register
      - Via direct: contract.register(agentURI)
   d. Receive tokenId (agentId in ERC-8004 terms)
   e. Store tokenId in agents.erc8004TokenId
   f. Set agentWallet metadata on-chain (requires EIP-712 sig from agent's key)
   g. Emit webhook: agent.registered_onchain
```

### 5.2 Agent Registration File Schema

The agentURI points to a JSON file following the ERC-8004 registration spec. For Steward agents:

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "trading-bot-alpha",
  "description": "Autonomous DeFi trading agent managed by Steward. Operates within policy-enforced spending limits on Base.",
  "image": "https://steward.fi/agents/trading-bot-alpha/avatar.png",
  "services": [
    {
      "name": "steward",
      "endpoint": "https://api.steward.fi/v1/agents/trading-bot-alpha",
      "version": "1.0"
    },
    {
      "name": "A2A",
      "endpoint": "https://api.steward.fi/v1/agents/trading-bot-alpha/.well-known/agent-card.json",
      "version": "0.3.0"
    }
  ],
  "agentWallet": "0x...",
  "active": true,
  "registrations": [
    {
      "agentId": 42,
      "agentRegistry": "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
    }
  ],
  "supportedTrust": [
    "reputation",
    "erc-8004"
  ],
  "x402Support": false,
  "steward": {
    "tenantId": "milady",
    "policyTypes": ["spending-limit", "approved-addresses", "rate-limit"],
    "chainFamilies": ["evm", "solana"],
    "capabilities": ["sign-transaction", "sign-message", "sign-typed-data"],
    "policyEnforced": true
  }
}
```

The `steward` extension field communicates Steward-specific metadata that other agents/platforms can use to understand the agent's capabilities and constraints. This is allowed by the ERC-8004 spec (registration files are extensible).

### 5.3 Agent Card A2A Endpoint

For agents that support A2A (Agent-to-Agent) discovery, Steward can auto-generate an A2A agent card at a well-known URL. This is a future consideration, not part of v1. The `services` array in the registration file is the hook point.

### 5.4 Registry Selection Logic

When registering an agent on-chain:

```
1. Check tenant config: does this tenant have a custom registryAddress?
   YES → use tenant's registry
   NO  → use Steward default registry

2. Check registration method:
   "chitin" → use Chitin API (handles Arweave + minting)
   "direct" → use direct contract call (requires gas funding)

3. Determine gas payer:
   "platform" → Steward platform wallet pays
   "tenant"   → tenant's configured gas wallet pays
   "agent"    → agent's own wallet pays (agent must have Base ETH)
```

---

## 6. Reputation Integration

### 6.1 Automatic Feedback Posting

After each transaction that passes through Steward's policy engine, post feedback to the Reputation Registry:

| Steward Event | Feedback Value | Tag1 | Tag2 | Notes |
|---------------|---------------|------|------|-------|
| Transaction signed + broadcast | `100` (valueDecimals: 0) | `tx.success` | `steward` | Positive signal |
| Transaction signed, not broadcast | `50` (valueDecimals: 0) | `tx.signed` | `steward` | Neutral (offline sign) |
| Policy violation (rejected) | `-50` (valueDecimals: 0) | `policy.violation` | policy type | Negative signal |
| Approval queue: approved | `75` (valueDecimals: 0) | `tx.approved` | `steward` | Human-approved |
| Approval queue: denied | `-25` (valueDecimals: 0) | `tx.denied` | `steward` | Human-denied |

**Who posts feedback?** The Steward platform wallet posts feedback as the `clientAddress`. This means Steward itself is a reputation client. Its feedback carries weight proportional to how trusted Steward is as a reviewer, which the community can evaluate independently.

**Off-chain feedback file:** Each feedback event includes a `feedbackURI` pointing to an Arweave or IPFS document with:

```json
{
  "agentRegistry": "eip155:8453:0x8004...",
  "agentId": 42,
  "clientAddress": "eip155:8453:0xStewardPlatformWallet",
  "createdAt": "2026-04-11T12:00:00Z",
  "value": 100,
  "valueDecimals": 0,
  "tag1": "tx.success",
  "tag2": "steward",
  "endpoint": "https://api.steward.fi/v1/vault/trading-bot-alpha/sign",
  "steward": {
    "txHash": "0x...",
    "chainId": 8453,
    "policyResults": [
      { "type": "spending-limit", "passed": true },
      { "type": "approved-addresses", "passed": true }
    ],
    "valueWei": "50000000000000000",
    "valueUsd": 95.50
  }
}
```

### 6.2 Reputation-Based Policy Adjustment

This is the powerful loop: an agent's on-chain reputation influences its Steward policy limits.

New policy type: `reputation-threshold` (future, not in v1 schema yet):

```json
{
  "id": "rep-boost",
  "type": "reputation-threshold",
  "enabled": true,
  "config": {
    "reputationSource": "erc8004",
    "minScore": 80,
    "boostMultiplier": 1.5,
    "targetPolicies": ["spending-limit"],
    "minFeedbackCount": 10
  }
}
```

This would mean: if the agent has an ERC-8004 reputation score >= 80 with at least 10 feedback entries, multiply its spending limits by 1.5x.

For v1, reputation is read-only (displayed, not enforced). Reputation-based policy adjustment is a v2 feature.

### 6.3 Cross-Tenant Reputation Query

`GET /agents/:id/reputation` aggregates reputation from:

1. The agent's home registry (where it was registered)
2. Any other indexed registries where the same wallet address has feedback
3. Off-chain: Steward's internal transaction history for that agent

The response normalizes scores to a 0-100 scale with source attribution.

---

## 7. Validation Integration

### 7.1 Policy Evaluations as Validation Evidence

Steward's policy engine produces a deterministic pass/fail result for every signing request. This is valuable validation data:

```
Agent requests: signTransaction(to, value, chainId)
  └── Policy engine evaluates 5 rules
      ├── spending-limit:       PASS
      ├── approved-addresses:   PASS
      ├── rate-limit:           PASS
      ├── time-window:          PASS
      └── auto-approve:         PASS (below threshold)
  
  → POST validationRequest to Validation Registry
    requestURI → IPFS document with full evaluation context
    
  → Steward responds as validator:
    response: 100 (all passed)
    tag: "policy-evaluation"
```

### 7.2 Third-Party Validation

External validators can verify Steward's policy decisions by:

1. Reading the `requestURI` document (contains the transaction, policies, and evaluation context)
2. Re-running the policy evaluation independently
3. Posting a `validationResponse` with their own score

This creates an audit trail where Steward's policy enforcement is independently verifiable.

### 7.3 V1 Scope

Validation integration is the lowest priority of the three registries. For v1:

- **Emit events** for policy evaluations (stored in Steward's DB, as today)
- **Do not** post to the Validation Registry on-chain (gas cost per tx is too high)
- **Prepare** the data model so validation can be enabled per-tenant later

V2: Optional per-tenant configuration to post validation evidence for high-value transactions (above a configurable threshold).

---

## 8. Contract Interaction

### 8.1 Deployed Contracts on Base

| Contract | Address | Chain |
|----------|---------|-------|
| ERC-8004 Identity Registry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | Base (8453) |
| Reputation Registry | TBD (query from Chitin or on-chain event logs) | Base (8453) |
| Validation Registry | TBD (query from Chitin or on-chain event logs) | Base (8453) |

**Note:** The exact Reputation and Validation Registry addresses on Base need to be confirmed. The Identity Registry is deterministic via CREATE2, but the other registries are deployed via `initialize()` calls that link them to a specific Identity Registry. Chitin's deployment on Base should have all three.

### 8.2 Contract ABIs

The Identity Registry extends ERC-721 with these additional functions:

```solidity
// Registration
function register(string agentURI) third-party returns (uint256 agentId)
function register(string agentURI, MetadataEntry[] calldata metadata) third-party returns (uint256 agentId)
function register() third-party returns (uint256 agentId)

// URI management
function setAgentURI(uint256 agentId, string calldata newURI) third-party

// Metadata
function getMetadata(uint256 agentId, string memory metadataKey) third-party view returns (bytes memory)
function setMetadata(uint256 agentId, string memory metadataKey, bytes memory metadataValue) third-party

// Wallet
function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature) third-party
function getAgentWallet(uint256 agentId) external view returns (address)
```

The Reputation Registry:

```solidity
function giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash) third-party
function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external
function getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2) third-party view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)
function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) third-party view returns (int128 value, uint8 valueDecimals, string tag1, string tag2, bool isRevoked)
function readAllFeedback(uint256 agentId, address[] clientAddresses, string tag1, string tag2, bool includeRevoked) third-party view returns (...)
function getClients(uint256 agentId) third-party view returns (address[])
```

### 8.3 Gas Cost Estimates (Base L2)

Base L2 gas is very cheap. Estimates at ~0.001 gwei base fee:

| Operation | Estimated Gas | Estimated Cost (Base) |
|-----------|--------------|----------------------|
| `register(agentURI)` | ~150,000 - 250,000 | < $0.01 |
| `setAgentURI()` | ~50,000 - 80,000 | < $0.005 |
| `setMetadata()` | ~30,000 - 60,000 | < $0.005 |
| `setAgentWallet()` | ~60,000 - 100,000 | < $0.005 |
| `giveFeedback()` | ~80,000 - 150,000 | < $0.01 |
| `revokeFeedback()` | ~30,000 - 50,000 | < $0.005 |
| `validationRequest()` | ~80,000 - 120,000 | < $0.01 |

At Base's current L2 fee levels, the cost per operation is negligible (sub-cent). This makes per-transaction reputation posting economically feasible, unlike mainnet.

### 8.4 Batch Registration

For tenants with many existing agents, individual registration is inefficient. Options:

1. **Chitin batch API:** If available (check Chitin docs for batch endpoints)
2. **Multicall contract:** Bundle multiple `register()` calls into a single transaction via a multicall contract
3. **Sequential with nonce management:** Fire registrations in rapid succession with pre-incremented nonces

Recommendation: Use Chitin's API for individual registrations (they handle gas relay). For batch migration of existing agents (50+ agents), use a dedicated migration script with multicall.

---

## 9. New API Endpoints

### 9.1 On-Chain Registration

```
POST /agents/:agentId/register-onchain
```

Mints an ERC-8004 identity NFT for an existing Steward agent.

**Request:**
```json
{
  "registryAddress": "0x8004...",     // optional, defaults to tenant/steward default
  "chainId": 8453,                    // optional, defaults to Base
  "method": "chitin",                 // "chitin" or "direct"
  "agentUri": "https://...",          // optional, auto-generated if omitted
  "metadata": {                       // optional additional on-chain metadata
    "platform": "steward"
  }
}
```

**Response (202 Accepted):**
```json
{
  "ok": true,
  "data": {
    "status": "pending",
    "registrationId": "reg_abc123",
    "estimatedCompletionMs": 15000
  }
}
```

Registration is async because it involves an on-chain transaction. The result is delivered via:
- Polling: `GET /agents/:agentId/registration-status`
- Webhook: `agent.registered_onchain` event

**Response after completion:**
```json
{
  "ok": true,
  "data": {
    "erc8004TokenId": "42",
    "registryAddress": "0x8004...",
    "chainId": 8453,
    "agentUri": "ar://Qm3x...",
    "txHash": "0x...",
    "registeredAt": "2026-04-11T12:00:00Z"
  }
}
```

### 9.2 Reputation

```
GET /agents/:agentId/reputation
```

Fetches aggregated reputation for an agent across all indexed registries.

**Query params:**
- `registryAddress` - filter to specific registry (optional)
- `tag1` - filter by tag1 (optional)
- `minFeedbackCount` - minimum feedback entries to include (optional)

**Response:**
```json
{
  "ok": true,
  "data": {
    "agentId": "trading-bot-alpha",
    "erc8004TokenId": "42",
    "aggregated": {
      "score": 87,
      "totalFeedback": 156,
      "positiveCount": 142,
      "negativeCount": 14,
      "sources": [
        {
          "registry": "eip155:8453:0x8004...",
          "registryName": "Steward Default",
          "feedbackCount": 120,
          "averageScore": 89
        },
        {
          "registry": "eip155:8453:0xTenantReg...",
          "registryName": "Milady Cloud",
          "feedbackCount": 36,
          "averageScore": 82
        }
      ]
    },
    "recentFeedback": [
      {
        "clientAddress": "0x...",
        "value": 100,
        "tag1": "tx.success",
        "tag2": "steward",
        "timestamp": "2026-04-11T11:30:00Z"
      }
    ]
  }
}
```

### 9.3 Feedback

```
POST /agents/:agentId/feedback
```

Posts a feedback signal to the Reputation Registry. Typically called by the platform after transactions, but also exposed for manual feedback.

**Request:**
```json
{
  "value": 100,
  "valueDecimals": 0,
  "tag1": "tx.success",
  "tag2": "steward",
  "endpoint": "https://api.steward.fi/v1/vault/agent-id/sign",
  "feedbackUri": "ipfs://Qm...",
  "feedbackHash": "0x..."
}
```

**Response (202 Accepted):**
```json
{
  "ok": true,
  "data": {
    "status": "pending",
    "txHash": null,
    "estimatedCompletionMs": 5000
  }
}
```

### 9.4 Discovery

```
GET /discovery/agents
```

Cross-registry agent search.

**Query params:**
- `capability` - filter by capability (e.g. "sign-transaction", "a2a")
- `chain` - filter by supported chain (CAIP-2)
- `minReputation` - minimum reputation score
- `registry` - filter to specific registry
- `tenant` - filter to specific tenant
- `active` - boolean, only active agents (default true)
- `page`, `limit` - pagination

**Response:**
```json
{
  "ok": true,
  "data": {
    "agents": [
      {
        "agentId": "trading-bot-alpha",
        "erc8004TokenId": "42",
        "name": "Trading Bot Alpha",
        "registry": "eip155:8453:0x8004...",
        "registryName": "Steward Default",
        "walletAddress": "0x...",
        "reputation": { "score": 87, "feedbackCount": 156 },
        "capabilities": ["sign-transaction", "sign-message"],
        "chains": ["eip155:8453"],
        "active": true,
        "agentUri": "ar://Qm3x..."
      }
    ],
    "total": 342,
    "page": 1,
    "limit": 20
  }
}
```

```
GET /discovery/registries
```

Lists all known registries indexed by Steward.

**Response:**
```json
{
  "ok": true,
  "data": [
    {
      "address": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
      "chainId": 8453,
      "caip2": "eip155:8453",
      "name": "Steward Default Registry",
      "type": "steward_default",
      "agentCount": 1250,
      "lastIndexed": "2026-04-11T12:00:00Z"
    },
    {
      "address": "0xTenantRegistry...",
      "chainId": 8453,
      "caip2": "eip155:8453",
      "name": "Milady Cloud Registry",
      "type": "tenant",
      "tenantId": "milady",
      "agentCount": 43,
      "lastIndexed": "2026-04-11T11:55:00Z"
    }
  ]
}
```

---

## 10. New SDK Methods

### 10.1 Registration

```typescript
// Register agent on-chain (mint ERC-8004 identity)
const result = await steward.registerOnchain("agent-id", {
  method: "chitin",           // optional, defaults to tenant config
  registryAddress: "0x...",   // optional, defaults to tenant/steward default
  agentUri: "https://...",    // optional, auto-generated if omitted
});
// result: { status: "pending", registrationId: "reg_abc123" }

// Poll for completion
const status = await steward.getRegistrationStatus("agent-id");
// status: { erc8004TokenId: "42", txHash: "0x...", ... }
```

### 10.2 Reputation

```typescript
// Get reputation (aggregated cross-registry)
const rep = await steward.getReputation("agent-id");
// rep: { score: 87, totalFeedback: 156, sources: [...] }

// Get reputation with filters
const rep = await steward.getReputation("agent-id", {
  tag1: "tx.success",
  registryAddress: "0x...",
});

// Post feedback
await steward.postFeedback("agent-id", {
  value: 100,
  valueDecimals: 0,
  tag1: "tx.success",
  tag2: "integration-test",
});
```

### 10.3 Discovery

```typescript
// Discover agents across registries
const results = await steward.discoverAgents({
  capability: "sign-transaction",
  chain: "eip155:8453",
  minReputation: 70,
  limit: 20,
});
// results: { agents: [...], total: 342 }

// List known registries
const registries = await steward.listRegistries();
```

### 10.4 Full Agent Identity

```typescript
// Get agent with full ERC-8004 data
const agent = await steward.getAgent("agent-id");
// agent.erc8004TokenId: "42"
// agent.erc8004Registry: "eip155:8453:0x8004..."

// Get the on-chain agent card (resolved agentURI)
const card = await steward.getAgentCard("agent-id");
// card: { name, description, services, agentWallet, ... }
```

---

## 11. Database Schema Changes

### 11.1 New Tables

```sql
-- Registry index: tracks all known ERC-8004 registries
CREATE TABLE erc8004_registries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  address VARCHAR(42) NOT NULL,
  chain_id INTEGER NOT NULL,
  caip2 VARCHAR(128) NOT NULL,
  name VARCHAR(255),
  type VARCHAR(32) NOT NULL DEFAULT 'third-party',  -- steward_default, tenant, third-party
  tenant_id VARCHAR(64) REFERENCES tenants(id) ON DELETE SET NULL,
  reputation_registry_address VARCHAR(42),
  validation_registry_address VARCHAR(42),
  last_indexed_at TIMESTAMPTZ,
  agent_count INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(address, chain_id)
);

-- Agent on-chain registrations (an agent can be registered in multiple registries)
CREATE TABLE erc8004_registrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id VARCHAR(64) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  registry_id UUID NOT NULL REFERENCES erc8004_registries(id) ON DELETE CASCADE,
  token_id VARCHAR(255) NOT NULL,          -- ERC-8004 agentId (tokenId)
  agent_uri TEXT,                           -- current agentURI
  agent_uri_hash VARCHAR(66),              -- keccak256 of agentURI content for change detection
  registration_tx_hash VARCHAR(66),
  status VARCHAR(32) NOT NULL DEFAULT 'pending',  -- pending, registered, failed
  registered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(registry_id, token_id),
  UNIQUE(agent_id, registry_id)
);

-- Cached reputation data (refreshed periodically)
CREATE TABLE erc8004_reputation_cache (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id VARCHAR(64) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  registry_id UUID NOT NULL REFERENCES erc8004_registries(id) ON DELETE CASCADE,
  score INTEGER,                            -- normalized 0-100
  feedback_count INTEGER DEFAULT 0,
  positive_count INTEGER DEFAULT 0,
  negative_count INTEGER DEFAULT 0,
  last_refreshed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(agent_id, registry_id)
);

-- Feedback queue (outbound feedback to post on-chain)
CREATE TABLE erc8004_feedback_queue (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id VARCHAR(64) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  registry_id UUID NOT NULL REFERENCES erc8004_registries(id),
  value SMALLINT NOT NULL,
  value_decimals SMALLINT NOT NULL DEFAULT 0,
  tag1 VARCHAR(255),
  tag2 VARCHAR(255),
  endpoint TEXT,
  feedback_uri TEXT,
  feedback_hash VARCHAR(66),
  status VARCHAR(32) NOT NULL DEFAULT 'pending',  -- pending, submitted, confirmed, failed
  tx_hash VARCHAR(66),
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  submitted_at TIMESTAMPTZ
);

CREATE INDEX idx_feedback_queue_status ON erc8004_feedback_queue(status);
```

### 11.2 Modified Tables

The existing `agents` table already has `erc8004TokenId`. No schema change needed, but this field becomes the foreign key to the primary registration in `erc8004_registrations`.

The `tenant_configs` table gets a new `erc8004` JSONB field in the existing `featureFlags` or as a new column:

```sql
ALTER TABLE tenant_configs ADD COLUMN erc8004_config JSONB NOT NULL DEFAULT '{}';
```

---

## 12. Gas Strategy

### 12.1 Who Pays?

Three options, configurable per tenant:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **Platform** | Steward platform wallet pays gas for all registrations and feedback | Default for hosted mode. Steward absorbs the cost (sub-cent on Base) |
| **Tenant** | Tenant configures a gas wallet. Steward uses it for that tenant's operations | White-label tenants who want cost isolation |
| **Agent** | The agent's own wallet pays gas | Self-sovereign agents with their own ETH |

### 12.2 Platform Gas Wallet

Steward needs a dedicated gas wallet on Base for on-chain operations:

- **Address:** Configured via `STEWARD_GAS_WALLET_KEY` env var
- **Funding:** Pre-fund with ~0.1 ETH on Base (covers ~10,000+ operations)
- **Monitoring:** Alert when balance drops below 0.01 ETH
- **Security:** Key stored in vault, not in env directly (or use a separate KMS)

### 12.3 Chitin Gas Relay

When using Chitin's API for registration, Chitin handles gas (free for first 10,000 agents globally). This is the recommended path for most tenants. Direct contract interaction only needed for:

- Tenants with custom registries
- High-volume batch operations
- Tenants who need full control

---

## 13. Migration Plan

### 13.1 Existing Agents

Steward already has agents in production (Milady Cloud, Babylon, etc.). Migration strategy:

**Phase 1: Opt-in (default)**
- Add `POST /agents/:id/register-onchain` endpoint
- Tenants call it explicitly for agents they want registered
- No automatic registration
- Backfill `erc8004TokenId` as agents are registered

**Phase 2: Auto-register new agents**
- Tenants can enable `autoRegister: true` in their config
- New agents created after enablement are automatically registered
- Existing agents still require manual registration

**Phase 3: Bulk migration tool**
- Admin endpoint: `POST /platform/erc8004/migrate` with tenant filter
- Registers all un-registered agents in a tenant
- Rate-limited to avoid gas spikes
- Progress tracking via webhook events

### 13.2 Reputation Backfill

Steward has historical transaction data that can be converted to ERC-8004 reputation:

1. Query all completed transactions for registered agents
2. Generate feedback entries (positive for successful, negative for violations)
3. Batch-submit to Reputation Registry
4. This gives agents "day 1" reputation based on their Steward track record

**Caveat:** Backfilled reputation is posted by Steward's platform wallet, so it's clearly identifiable as platform-generated (not organic client feedback). This is transparent and appropriate.

### 13.3 Schema Migration

New Drizzle migration file: `packages/db/drizzle/0013_erc8004_registries.sql`

- Creates all new tables (registries, registrations, reputation_cache, feedback_queue)
- Adds `erc8004_config` column to `tenant_configs`
- Seeds the Steward default registry row
- Non-destructive: no changes to existing data

---

## 14. Competitive Position

### 14.1 Current Landscape

As of April 2026, ERC-8004 adoption is growing (20K+ agents, 70+ projects) but no major wallet infrastructure provider has deeply integrated it:

| Platform | ERC-8004 Integration | Notes |
|----------|---------------------|-------|
| Privy (Stripe) | None | Consumer wallet focus, no agent identity layer |
| Turnkey | None | Key management only, no identity |
| Dynamic | None | Auth widget, no on-chain identity |
| Crossmint | Partial | NFT minting but not ERC-8004 specific |
| Chitin Protocol | Full (they built it) | Registration platform, not wallet infra |
| Steward (proposed) | Full + white-label | Wallet + policy + identity + reputation |

### 14.2 Steward's Unique Angle

**"The only wallet infrastructure where your agent's on-chain identity and reputation are backed by cryptographically-enforced policy."**

Key differentiators:

1. **Policy-backed reputation:** Steward's reputation signals aren't just self-reported. They come from a policy engine that cryptographically enforces transaction rules. When Steward says an agent has a good track record, that track record was verified at the signing layer.

2. **White-label registries:** No other platform offers multi-registry support. Tenants get their own namespace while remaining interoperable.

3. **Closed-loop trust:** Identity (who is this agent?) + Reputation (is it trustworthy?) + Policy (what can it do?) in one API. Other platforms require stitching 3+ services together.

4. **Wallet-native registration:** The agent's wallet IS its identity. No separate wallet + identity management. Steward creates the wallet, registers the identity, and enforces the policies, all in one `createAgent()` call (when auto-register is enabled).

5. **Cross-registry discovery:** Steward becomes a meta-index of all agent registries its tenants use, creating a discovery layer that spans organizational boundaries.

### 14.3 Go-to-Market Implications

- **For Milady Cloud / Eliza Cloud:** Every container agent gets an ERC-8004 passport automatically. Agents can be discovered and trusted by other agents across the ecosystem.
- **For Strata Reserve:** RWA agents with verifiable on-chain identity and policy-enforced transaction limits. Institutional trust layer.
- **For Babylon:** Game NPCs with reputation that carries across game sessions and platforms.

---

## 15. Implementation Phases

### Phase 1: Foundation (Week 1-2)

- [ ] New DB tables (migration 0013)
- [ ] ERC-8004 service layer (`packages/erc8004/` or within `packages/api/src/services/erc8004/`)
  - Identity client (viem contract interaction)
  - Chitin API client
- [ ] `POST /agents/:id/register-onchain` endpoint
- [ ] `GET /agents/:id/reputation` endpoint (read-only from chain)
- [ ] Tenant config: `erc8004_config` JSONB
- [ ] Seed Steward default registry

### Phase 2: Reputation (Week 2-3)

- [ ] Feedback queue processor (background job)
- [ ] Auto-feedback after transactions (hook into vault signing flow)
- [ ] `POST /agents/:id/feedback` endpoint
- [ ] Reputation cache refresh job
- [ ] `GET /agents/:id/reputation` with aggregation

### Phase 3: Discovery + White-Label (Week 3-4)

- [ ] Registry index and sync job
- [ ] `GET /discovery/agents` endpoint
- [ ] `GET /discovery/registries` endpoint
- [ ] Tenant custom registry deployment tooling
- [ ] Cross-registry reputation aggregation

### Phase 4: SDK + Migration (Week 4-5)

- [ ] `@stwd/sdk` new methods (registerOnchain, getReputation, postFeedback, discoverAgents)
- [ ] Migration script for existing agents
- [ ] Reputation backfill from transaction history
- [ ] Dashboard UI: agent identity card, reputation display

### Phase 5: Advanced (Future)

- [ ] Reputation-based policy adjustment (new policy type)
- [ ] Validation Registry integration (on-chain policy proofs)
- [ ] A2A agent card generation
- [ ] x402 payment integration
- [ ] Cross-chain registry support (beyond Base)

---

## 16. Open Questions

1. **Chitin vs. Direct:** Should Steward default to Chitin for all registrations, or offer direct contract interaction as the default with Chitin as optional? Chitin adds the soul layer (hash verification, Arweave archival) which is valuable but adds a dependency.

2. **Reputation posting frequency:** Post feedback after EVERY transaction, or batch on a schedule (e.g. daily summaries)? Per-tx is more granular but creates more on-chain activity. Base is cheap enough that per-tx is feasible.

3. **Tenant registry deployment:** Should Steward provide a UI/API to deploy a new Identity Registry contract for a tenant, or require tenants to deploy their own and just register the address? Deploying for them is better UX but adds complexity.

4. **Sybil resistance:** The Reputation Registry's `getSummary()` requires filtering by `clientAddresses` to avoid Sybil attacks. How does Steward curate trusted client addresses for reputation queries? Build a trust list of known platforms?

5. **Agent ownership:** When Steward registers an ERC-8004 identity, who owns the NFT? The Steward platform wallet? The tenant's wallet? The agent's own wallet? This has implications for transferability and control.

6. **Privacy:** The registration file is public (on-chain URI). Should Steward agents expose their full policy configuration in the registration file, or only advertise capabilities? Leaking policy limits could be a security concern.

7. **Gas budget alerts:** Should the platform wallet gas balance be exposed as a metric in the dashboard? Tenants using their own gas wallets would need balance monitoring too.

---

*This document is a design proposal. Implementation details will evolve as we build.*
