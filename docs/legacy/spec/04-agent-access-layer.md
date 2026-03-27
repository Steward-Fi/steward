# 04 — Agent Access Layer

## Overview

The agent access layer defines how agents authenticate to Steward, how tenants are isolated, and how permissions are scoped. Steward supports three credential types with different access levels.

## Credential Hierarchy

```
Platform Key (god mode)
  └─ Tenant API Key (tenant-scoped)
       └─ Agent JWT Token (agent-scoped)
```

| Credential | Scope | Can Create Agents | Can Sign | Can Manage Policies |
|------------|-------|-------------------|----------|-------------------|
| Platform Key | All tenants | Yes | Yes | Yes |
| Tenant API Key | One tenant | Yes | Yes | Yes |
| Agent JWT | One agent | No | Own wallet only | No |

## Platform Key Authentication

The platform key (`X-Steward-Platform-Key` header) provides full administrative access across all tenants. It is intended for trusted platform operators (e.g., Eliza Cloud provisioning system).

```
X-Steward-Platform-Key: stw_platform_...
```

The platform key is set via `STEWARD_PLATFORM_KEY` environment variable. It MUST NOT be distributed to agents or end users. Platform key requests bypass tenant scoping and can operate on any tenant's resources.

### Platform Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | /platform/tenants | Create a new tenant |
| GET | /platform/tenants | List all tenants |
| GET | /platform/tenants/:id | Get tenant details |
| POST | /platform/tenants/:id/agents | Create agent for tenant |
| GET | /platform/stats | System-wide statistics |
| POST | /platform/agents/:agentId/token | Generate agent JWT |

## Tenant API Key Authentication

Tenant API keys authenticate platform clients (dashboards, backend services) to operate within a single tenant's scope.

```
X-Steward-Tenant-Id: my-platform
X-Steward-Api-Key: stw_...
```

### Key Format

Tenant API keys follow the format: `stw_<random 32 hex chars>`

Keys are stored as SHA-256 hashes. The raw key is shown once at creation and cannot be retrieved. Key validation uses timing-safe comparison to prevent timing attacks.

### Key Generation

```
rawKey = "stw_" + hex(randomBytes(16))
hash = SHA-256(rawKey)
store hash in tenants.apiKeyHash
return rawKey to caller (once)
```

### Tenant Isolation

All queries within a tenant-authenticated request are filtered by `tenantId`. An agent created under tenant A cannot be accessed by tenant B's API key. This filtering is applied at the database query level, not application middleware.

## Agent JWT Authentication

Agent JWTs are the most restricted credential type. They authenticate a single agent and limit access to that agent's own wallet operations.

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Token Structure

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "my-platform",
  "scope": "agent",
  "iat": 1711200000,
  "exp": 1742736000,
  "iss": "steward"
}
```

- `scope: "agent"` distinguishes agent tokens from session JWTs
- `agentId` restricts all operations to this agent's resources
- `tenantId` provides tenant isolation
- Default expiry: 30 days (configurable via `AGENT_TOKEN_EXPIRY`)

### Agent Token Permissions

An agent token can:
- Sign transactions for its own wallet (`POST /vault/:agentId/sign`)
- Sign messages for its own wallet (`POST /vault/:agentId/sign-message`)
- Query its own balance (`GET /vault/:agentId/balance`)
- Access its own transaction history (`GET /agents/:agentId/history`)

An agent token cannot:
- Create or delete agents
- Modify policies
- Access other agents' resources
- Access tenant-level endpoints

### Token Validation

1. Decode JWT header, verify `alg: "HS256"`
2. Verify signature against `STEWARD_JWT_SECRET` (or `STEWARD_MASTER_PASSWORD` fallback)
3. Check `exp` has not passed
4. Check `iss` is `"steward"`
5. Check `scope` is `"agent"`
6. Verify `agentId` in token matches `:agentId` in request path
7. Verify agent exists and belongs to `tenantId` in token

If any check fails, return 401 Unauthorized.

## Session JWT (Dashboard)

Dashboard users authenticate via SIWE (Sign-In with Ethereum) and receive session JWTs.

```json
{
  "address": "0x1234...",
  "tenantId": "my-platform",
  "iat": 1711200000,
  "exp": 1711286400,
  "iss": "steward"
}
```

Session JWTs do NOT have `scope: "agent"` and grant full tenant-scoped access (same as tenant API key).

### SIWE Flow

1. Client requests nonce: `GET /auth/nonce`
2. Client signs EIP-4361 message with wallet
3. Client submits signature: `POST /auth/verify` with `{ message, signature }`
4. Server verifies SIWE message, creates session JWT
5. Client uses JWT for subsequent requests

## Rate Limiting

API-level rate limiting (distinct from policy-engine rate limits):

- **Global:** 100 requests per minute per IP
- **Auth endpoints:** 5 requests per minute per IP (nonce, verify)

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1711200060
```

Exceeded rate limits return 429 with:
```json
{
  "ok": false,
  "error": "rate_limited",
  "message": "Too many requests. Try again in 45 seconds."
}
```

## Request Correlation

Every API request receives a correlation ID via the `X-Request-Id` response header. If the client sends `X-Request-Id` in the request, the server echoes it. Otherwise, a UUID is generated.

Correlation IDs are included in:
- Response headers
- Transaction records
- Webhook payloads
- Error logs

This enables end-to-end tracing of a transaction from agent request through policy evaluation, signing, and webhook delivery.

## Security Requirements

1. The JWT secret MUST be separate from the master password in production (`STEWARD_JWT_SECRET`).
2. Agent tokens SHOULD use the shortest practical expiry for the use case.
3. Platform keys MUST NOT be transmitted to agent containers.
4. All authentication endpoints MUST use timing-safe comparison.
5. Failed authentication attempts SHOULD be logged with source IP and credential type (but not the credential value).
