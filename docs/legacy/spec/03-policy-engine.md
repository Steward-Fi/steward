# 03 — Policy Engine

## Overview

The policy engine evaluates a set of rules against every transaction signing request before any key material is decrypted. Policies are composable, independently evaluated, and divided into two categories: hard gates (reject on failure) and soft gates (queue for human review on failure).

## Policy Categories

### Hard Policies

Hard policies reject the transaction immediately if they fail. The vault never decrypts the key.

| Type | Description |
|------|-------------|
| `spending-limit` | Caps per-transaction, per-day, and per-week spend |
| `approved-addresses` | Whitelist or blocklist destination addresses |
| `rate-limit` | Maximum transactions per hour and per day |
| `time-window` | Restrict signing to specific UTC hours |

### Soft Policies

Soft policies queue the transaction for human approval if they fail, rather than rejecting outright. All hard policies must still pass.

| Type | Description |
|------|-------------|
| `auto-approve-threshold` | Auto-sign below a value threshold; queue above |

## Evaluation Logic

```
evaluate(policies[], request) → EvaluationResult

1. If no policies exist → auto-approve (approved=true)
2. Evaluate ALL policies against the request
3. Separate results into hard policies and soft policies
4. If ANY hard policy fails → reject (approved=false, requiresManualApproval=false)
5. If all hard policies pass AND soft policy fails → queue (approved=false, requiresManualApproval=true)
6. If all policies pass → approve (approved=true, requiresManualApproval=false)
```

Key behaviors:
- All policies are evaluated even if an early one fails (complete results for auditability)
- Hard policy failure always takes precedence over soft policy evaluation
- A single hard policy failure is sufficient to reject

## Policy Rule Schema

```json
{
  "id": "unique-policy-id",
  "type": "spending-limit | approved-addresses | rate-limit | time-window | auto-approve-threshold",
  "enabled": true,
  "config": { ... }
}
```

- `id`: Unique identifier within the agent's policy set
- `type`: One of the five defined policy types
- `enabled`: Boolean. Disabled policies are skipped during evaluation
- `config`: Type-specific configuration object (see below)

## Policy Type Specifications

### spending-limit

Controls how much value an agent can transfer.

```json
{
  "type": "spending-limit",
  "config": {
    "maxPerTx": "100000000000000000",
    "maxPerDay": "1000000000000000000",
    "maxPerWeek": "5000000000000000000"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| maxPerTx | string (wei) | No | Maximum value per single transaction |
| maxPerDay | string (wei) | No | Maximum cumulative value in 24 hours |
| maxPerWeek | string (wei) | No | Maximum cumulative value in 7 days |

Evaluation context required: `spentToday` (bigint), `spentThisWeek` (bigint), `request.value`.

At least one of the three limits MUST be set. Omitted limits are not enforced.

Value comparison uses BigInt arithmetic. The `value` field in the sign request is interpreted as the smallest unit of the chain's native currency (wei for EVM, lamports for Solana).

### approved-addresses

Controls which destination addresses are allowed or blocked.

```json
{
  "type": "approved-addresses",
  "config": {
    "mode": "whitelist",
    "addresses": ["0xDEX...", "0xBRIDGE..."]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| mode | string | Yes | `whitelist` (only these allowed) or `blocklist` (these blocked) |
| addresses | string[] | Yes | List of addresses |

Address comparison MUST be case-insensitive for EVM addresses (mixed-case checksummed addresses must match). For Solana addresses, comparison is case-sensitive (base58 is case-sensitive).

### rate-limit

Controls transaction frequency.

```json
{
  "type": "rate-limit",
  "config": {
    "maxPerHour": 10,
    "maxPerDay": 50
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| maxPerHour | integer | No | Maximum transactions in the last 60 minutes |
| maxPerDay | integer | No | Maximum transactions in the last 24 hours |

Evaluation context required: `recentTxCount1h`, `recentTxCount24h`.

At least one limit MUST be set.

### time-window

Restricts signing to specific hours of the day (UTC).

```json
{
  "type": "time-window",
  "config": {
    "startHour": 9,
    "endHour": 17,
    "startMinute": 0,
    "endMinute": 0
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| startHour | integer (0-23) | Yes | Window start hour (UTC) |
| endHour | integer (0-23) | Yes | Window end hour (UTC) |
| startMinute | integer (0-59) | No | Window start minute (default 0) |
| endMinute | integer (0-59) | No | Window end minute (default 0) |

If `endHour < startHour`, the window wraps around midnight (e.g., startHour=22, endHour=6 means 10 PM to 6 AM UTC).

### auto-approve-threshold

Defines a value boundary: below the threshold, transactions auto-approve (if all hard policies pass). Above the threshold, transactions are queued for human review.

```json
{
  "type": "auto-approve-threshold",
  "config": {
    "threshold": "500000000000000000"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| threshold | string (wei) | Yes | Value threshold for auto-approval |

This is the ONLY soft policy. Failure does not reject. It queues.

## Evaluation Result

```typescript
interface EvaluationResult {
  approved: boolean;
  results: PolicyResult[];
  requiresManualApproval: boolean;
}

interface PolicyResult {
  id: string;
  type: string;
  passed: boolean;
  reason?: string;
}
```

- `approved=true` → vault signs immediately
- `approved=false, requiresManualApproval=true` → queued for human review
- `approved=false, requiresManualApproval=false` → rejected, no signing occurs

## Approval Queue

When `requiresManualApproval` is true:

1. Transaction is stored with status `pending_approval`
2. A webhook event `approval_required` is dispatched (if webhook URL is configured)
3. The API returns the pending status to the agent
4. A human reviews and approves/rejects via the dashboard or API
5. If approved, the vault signs and broadcasts
6. If rejected, the transaction is marked `rejected`

Approval endpoints:

- `POST /approvals/:txId/approve` — signs and broadcasts the queued transaction
- `POST /approvals/:txId/reject` — rejects with optional reason

## Policy Management API

- `GET /agents/:agentId/policies` — list all policies for an agent
- `PUT /agents/:agentId/policies` — replace all policies for an agent
- `PATCH /agents/:agentId/policies/:policyId` — update a single policy

Policies are stored per-agent. Tenant-level default policies are a planned extension.
