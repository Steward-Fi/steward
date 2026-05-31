# @stwd/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
exposes [Steward](https://steward.fi) agent-wallet and auth operations as tools
that AI agents and MCP-aware IDEs (Claude Code, Cursor, etc.) can call.

The server is a **thin, authenticated client**. It calls the Steward API through
the official [`@stwd/sdk`](../sdk) `StewardClient` and never reimplements HTTP,
holds private keys, or bypasses policy. Every signing or transfer tool is
evaluated by Steward's policy engine server-side — a request may be signed,
broadcast, rejected, or queued for human approval, and this server cannot
override that decision.

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
| `STEWARD_URL` (or `STEWARD_BASE_URL`) | yes | Steward API base URL, e.g. `https://api.steward.fi`. `http://` is rejected for non-localhost hosts. |
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
  --env STEWARD_URL=https://api.steward.fi \
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
        "STEWARD_URL": "https://api.steward.fi",
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
      "env": { "STEWARD_URL": "https://api.steward.fi", "STEWARD_API_KEY": "sk_live_..." }
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

## Development

```bash
bun install
bun run build      # tsc -> dist/
bun test           # bun:test unit + in-memory integration tests
bun run lint       # biome
```

## License

MIT
