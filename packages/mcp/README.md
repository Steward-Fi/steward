# @stwd/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
exposes [Steward](https://steward.fi) agent-wallet and auth operations as tools
that AI agents and MCP-aware IDEs (Claude Code, Cursor, etc.) can call.

The server is a **thin, authenticated client**. Wallet tools call the Steward API
through the official [`@stwd/sdk`](../sdk) `StewardClient`. Provider-action tools
use a narrow internal HTTP transport for the existing v2 routes. Both transports
use only server configuration. Tool arguments cannot choose a tenant, credential,
host, or URL. The package holds no provider credentials, private keys, or policy
authority. Steward evaluates every action server-side, and this server cannot
override the result.

## Install

```bash
bun add @stwd/mcp        # or: npm i @stwd/mcp
```

The package ships a `stwd-mcp` binary that speaks MCP over stdio.

## Configuration

Configuration is read from the environment. The server fails fast with a clear
message if required values are missing.

| Variable | Required | Description |
| --- | --- | --- |
| `STEWARD_URL` (or `STEWARD_BASE_URL`) | yes | Steward API base URL, e.g. `http://localhost:3200`. `http://` is rejected for non-localhost hosts. |
| `STEWARD_API_KEY` | one of | Tenant API key. |
| `STEWARD_JWT` (or `STEWARD_BEARER_TOKEN`) | one of | Agent-scoped bearer token. Preferred over `STEWARD_API_KEY` when both are set. |
| `STEWARD_TENANT_ID` | no | Tenant id scoping requests. |
| `STEWARD_AGENT_ID` | no | Default agent id used by agent-scoped tools when a call omits `agentId`. |

At least one credential (`STEWARD_API_KEY` or a bearer token) must be provided.

### Secrets handling

- Credentials are passed only to the SDK and sent on the wire by it; this
  package never logs raw secret values.
- The stderr startup banner prints a **redacted** config (secrets shown as
  `****<last4>`). The MCP JSON-RPC protocol uses stdout exclusively; all
  diagnostics go to stderr.
- Plaintext `http://` to a remote host is refused so credentials are never sent
  unencrypted.

## Add to Claude Code

```bash
claude mcp add steward \
  --env STEWARD_URL=http://localhost:3200 \
  --env STEWARD_API_KEY=sk_live_... \
  --env STEWARD_TENANT_ID=your_tenant \
  --env STEWARD_AGENT_ID=your_default_agent \
  -- stwd-mcp
```

## Add to Cursor / Claude Desktop (JSON config)

Add an entry to your MCP config (`~/.cursor/mcp.json`, or
`claude_desktop_config.json` for Claude Desktop):

```json
{
  "mcpServers": {
    "steward": {
      "command": "stwd-mcp",
      "env": {
        "STEWARD_URL": "http://localhost:3200",
        "STEWARD_API_KEY": "sk_live_...",
        "STEWARD_TENANT_ID": "your_tenant",
        "STEWARD_AGENT_ID": "your_default_agent"
      }
    }
  }
}
```

If the package is not installed globally, use `bunx`/`npx`:

```json
{
  "mcpServers": {
    "steward": {
      "command": "npx",
      "args": ["-y", "@stwd/mcp"],
      "env": { "STEWARD_URL": "http://localhost:3200", "STEWARD_API_KEY": "sk_live_..." }
    }
  }
}
```

## Tools

Every agent-scoped tool accepts an optional `agentId`; when omitted it falls
back to `STEWARD_AGENT_ID`. Inputs are validated against a JSON Schema and
re-checked with Zod inside each handler. Results are returned as JSON text plus
structured content; Steward API errors surface their HTTP status and any policy
`results` so an agent can understand *why* an action was blocked.

| Tool | Kind | SDK method | Description |
| --- | --- | --- | --- |
| `provider_action_invoke` | write (destructive) | `POST /v2/provider-actions` | Submit an action for provider authorization and policy evaluation. |
| `provider_action_status` | read | `GET /v2/provider-actions/:id` | Fetch the authenticated agent's own action intent status. Foreign and absent actions return the same not-found response. |
| `provider_action_approval` | read | `GET /v2/provider-actions/:id/approval` | Fetch approval state. The API requires an eligible human session and recent MFA. |
| `provider_action_case` | read | `GET /v2/provider-actions/:id/case` | Fetch the correlated case manifest. |
| `provider_action_evidence` | read | `GET /v2/provider-actions/:id/evidence` | Fetch the correlated signed evidence bundle. |
| `list_wallets` | read | `listAgents` | List all agent wallets visible to the credentials. |
| `get_wallet` | read | `getAgent` | Fetch a single agent wallet's identity. |
| `create_wallet` | write | `createWallet` | Provision a new agent wallet (keys stay in Steward). |
| `get_balance` | read | `getBalance` | Native + token balances, optionally per chain. |
| `get_addresses` | read | `getAddresses` | All on-chain addresses across chain families. |
| `sign_transaction` | write (destructive) | `signTransaction` | Policy-enforced transaction signing. |
| `create_transfer` | write (destructive) | `createTransferAction` | Policy-enforced native/ERC-20 transfer. |
| `list_policies` | read | `getPolicies` | Policy rules attached to an agent wallet. |
| `get_policy` | read | `getPolicyRule` | A single policy rule by id. |
| `list_pending_approvals` | read | `listApprovals` | Transactions awaiting human approval. |
| `get_audit_log` | read | `getAuditLog` | Paginated tenant audit log with filters. |

### Authorization boundary

Provider tools send the same configured Steward credential and optional tenant
header as the existing MCP client. They do not accept tenant, actor, bearer,
provider credential, URL, or host arguments. Approval, case, and evidence reads
retain the API's human-session, MFA, role, workspace, and tenant gates. In
particular, an agent JWT cannot use MCP to impersonate a human approver.

Invocation and the agent-scoped status route both accept an agent JWT. Status is
bound server-side to the verified tenant and agent, so a process can poll only
actions that same agent submitted. Approval, case, and evidence reads continue
to require eligible human sessions and recent MFA, with case and evidence
further limited to owner/admin. The agent-readable route does not weaken or
stand in for any of those human gates.

These tools **do not implement MCP OAuth 2.1 resource-server semantics**. That
separate authorization-layer work is tracked by issue #219.

## Development

```bash
bun install
bun run build      # tsc -> dist/
bun test           # bun:test unit + in-memory integration tests
bun run lint       # biome
```

## License

MIT
