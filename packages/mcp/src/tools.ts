import { StewardApiError, type StewardClient } from "@stwd/sdk";
import { z } from "zod";
import type { StewardMcpConfig } from "./config.js";

/**
 * Minimal shape of an MCP tool result. Matches the `content` + `isError`
 * subset of the MCP SDK's `CallToolResult` that this server produces, so the
 * tool handlers can be exercised in unit tests without an MCP transport.
 */
export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  /** Machine-readable mirror of the text payload for structured consumers. */
  structuredContent?: Record<string, unknown>;
}

/**
 * A registered Steward tool. `inputSchema` is a Zod raw shape (a record of Zod
 * schemas) so it can be handed directly to the MCP SDK's `registerTool`, which
 * derives the public JSON Schema and validates incoming arguments.
 */
export interface StewardTool {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodRawShape;
  /**
   * Tool annotations surfaced to clients. `readOnlyHint` lets clients
   * distinguish safe read tools from state-changing ones; `destructiveHint`
   * flags wallet-moving operations.
   */
  annotations: {
    title: string;
    readOnlyHint: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
  handler: (args: unknown) => Promise<ToolResult>;
}

/** Context shared by all tool factories. */
export interface ToolContext {
  client: StewardClient;
  config: Pick<StewardMcpConfig, "defaultAgentId">;
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function okResult(value: unknown): ToolResult {
  const structured =
    value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : { result: value };
  return {
    content: [{ type: "text", text: jsonText(value) }],
    structuredContent: structured,
  };
}

function errorResult(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

/**
 * Convert any thrown value into a structured, log-safe error result. Steward
 * API errors surface their HTTP status and any policy `results` payload so the
 * agent can understand *why* an action was blocked (e.g. policy violation,
 * pending approval) without leaking transport internals.
 */
export function toErrorResult(err: unknown): ToolResult {
  if (err instanceof StewardApiError) {
    const detail: Record<string, unknown> = { error: err.message, status: err.status };
    if (err.data && typeof err.data === "object") {
      const data = err.data as { results?: unknown };
      if (data.results !== undefined) detail.policyResults = data.results;
    }
    return errorResult(`Steward API error (HTTP ${err.status}): ${jsonText(detail)}`);
  }
  if (err instanceof z.ZodError) {
    const issues = err.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
    return errorResult(`Invalid tool input: ${issues.join("; ")}`);
  }
  if (err instanceof Error) return errorResult(err.message);
  return errorResult(String(err));
}

/**
 * Resolve the effective agent id for an agent-scoped tool: the explicit
 * `agentId` argument wins, otherwise the server's configured default. Throws a
 * clear error when neither is available.
 */
function resolveAgentId(ctx: ToolContext, explicit?: string): string {
  const id = explicit?.trim() || ctx.config.defaultAgentId;
  if (!id) {
    throw new Error(
      "No agent id provided and no default configured. Pass `agentId`, or set STEWARD_AGENT_ID on the server.",
    );
  }
  return id;
}

interface ToolDefinition<S extends z.ZodObject<z.ZodRawShape>> {
  name: string;
  description: string;
  schema: S;
  readOnly: boolean;
  destructive?: boolean;
  run: (input: z.infer<S>, ctx: ToolContext) => Promise<unknown>;
}

/**
 * Turn a single schema-backed definition into a {@link StewardTool}. The schema
 * is the single source of truth: its `.shape` is published to MCP clients and
 * the same schema parses incoming arguments inside the handler (defense in
 * depth on top of the SDK's own validation).
 */
function defineTool<S extends z.ZodObject<z.ZodRawShape>>(
  ctx: ToolContext,
  def: ToolDefinition<S>,
): StewardTool {
  const title = titleCase(def.name);
  return {
    name: def.name,
    title,
    description: def.description,
    inputSchema: def.schema.shape,
    annotations: {
      title,
      readOnlyHint: def.readOnly,
      ...(def.destructive ? { destructiveHint: true } : {}),
      openWorldHint: true,
    },
    handler: async (args: unknown) => {
      let input: z.infer<S>;
      try {
        input = def.schema.parse(args ?? {});
      } catch (err) {
        return toErrorResult(err);
      }
      try {
        return okResult(await def.run(input, ctx));
      } catch (err) {
        return toErrorResult(err);
      }
    },
  };
}

function titleCase(name: string): string {
  return name
    .split("_")
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(" ");
}

// ─── Shared input fragments ──────────────────────────────────────────────

const agentIdField = z
  .string()
  .min(1)
  .optional()
  .describe("Steward agent id. Falls back to the server's STEWARD_AGENT_ID when omitted.");

const evmAddress = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, "must be a 0x-prefixed 20-byte hex address");

const hexData = z.string().regex(/^0x[0-9a-fA-F]*$/, "must be 0x-prefixed hex");

const decimalString = z.string().regex(/^\d+$/, "must be a base-10 integer string");

const positiveInt = z.number().int().positive();

/**
 * Build the full set of Steward MCP tools bound to a client + config.
 *
 * The set is intentionally scoped to safe, policy-respecting operations. Every
 * signing / transfer tool routes through the SDK, which hits Steward's
 * policy-enforced API - this server holds no keys and cannot bypass policy.
 */
export function buildTools(ctx: ToolContext): StewardTool[] {
  return [
    defineTool(ctx, {
      name: "list_wallets",
      description:
        "List all agent wallets visible to the configured credentials. Returns each agent's id, name, and wallet address(es).",
      schema: z.object({}).strict(),
      readOnly: true,
      run: () => ctx.client.listAgents(),
    }),
    defineTool(ctx, {
      name: "get_wallet",
      description: "Fetch a single agent wallet's identity (id, name, addresses, metadata).",
      schema: z.object({ agentId: agentIdField }).strict(),
      readOnly: true,
      run: ({ agentId }) => ctx.client.getAgent(resolveAgentId(ctx, agentId)),
    }),
    defineTool(ctx, {
      name: "create_wallet",
      description:
        "Provision a new agent wallet. Returns the created agent identity including EVM and Solana addresses. Private keys never leave Steward.",
      schema: z
        .object({
          agentId: z.string().min(1).describe("Unique id for the new agent."),
          name: z.string().min(1).describe("Human-readable name for the wallet."),
          platformId: z.string().min(1).optional().describe("Optional external platform id."),
        })
        .strict(),
      readOnly: false,
      run: ({ agentId, name, platformId }) => ctx.client.createWallet(agentId, name, platformId),
    }),
    defineTool(ctx, {
      name: "get_balance",
      description:
        "Get the native and token balances for an agent wallet, optionally scoped to a specific chain.",
      schema: z
        .object({
          agentId: agentIdField,
          chainId: positiveInt.optional().describe("EVM chain id to scope the balance query."),
        })
        .strict(),
      readOnly: true,
      run: ({ agentId, chainId }) => ctx.client.getBalance(resolveAgentId(ctx, agentId), chainId),
    }),
    defineTool(ctx, {
      name: "get_addresses",
      description:
        "List every on-chain address for an agent wallet across all chain families (EVM, Solana).",
      schema: z.object({ agentId: agentIdField }).strict(),
      readOnly: true,
      run: ({ agentId }) => ctx.client.getAddresses(resolveAgentId(ctx, agentId)),
    }),
    defineTool(ctx, {
      name: "sign_transaction",
      description:
        "Request a transaction signature for an agent wallet. The request is evaluated against the agent's policies server-side: it may be signed, broadcast, rejected, or queued for approval. This server cannot bypass policy.",
      schema: z
        .object({
          agentId: agentIdField,
          to: evmAddress.describe("Recipient / contract address."),
          value: decimalString.describe("Amount in wei as a base-10 integer string."),
          data: hexData.optional().describe("Calldata as 0x-prefixed hex."),
          chainId: positiveInt.optional(),
          broadcast: z
            .boolean()
            .optional()
            .describe("Broadcast after signing (default true). Set false to only sign."),
        })
        .strict(),
      readOnly: false,
      destructive: true,
      run: ({ agentId, to, value, data, chainId, broadcast }) =>
        ctx.client.signTransaction(resolveAgentId(ctx, agentId), {
          to,
          value,
          data,
          chainId,
          broadcast,
        }),
    }),
    defineTool(ctx, {
      name: "create_transfer",
      description:
        "Create a native or ERC-20 token transfer from an agent wallet. Routed through Steward's policy engine, so the result may be signed, broadcast, rejected, or pending approval.",
      schema: z
        .object({
          agentId: agentIdField,
          to: evmAddress.describe("Recipient address."),
          token: z
            .string()
            .min(1)
            .optional()
            .describe('ERC-20 contract address, or "native" for the chain asset (default).'),
          value: decimalString.optional().describe("Amount in wei (native) or token base units."),
          amountWei: decimalString.optional().describe("Alias for value in wei."),
          chainId: positiveInt.optional(),
          broadcast: z.boolean().optional(),
          referenceId: z
            .string()
            .min(1)
            .optional()
            .describe("Caller-supplied id mirrored in webhooks/audit."),
          sponsor: z.boolean().optional().describe("Request tenant-configured gas sponsorship."),
        })
        .strict(),
      readOnly: false,
      destructive: true,
      run: ({ agentId, ...input }) =>
        ctx.client.createTransferAction(resolveAgentId(ctx, agentId), input),
    }),
    defineTool(ctx, {
      name: "list_policies",
      description:
        "List the policy rules attached to an agent wallet (spending limits, allowlists, approval thresholds, etc.).",
      schema: z.object({ agentId: agentIdField }).strict(),
      readOnly: true,
      run: ({ agentId }) => ctx.client.getPolicies(resolveAgentId(ctx, agentId)),
    }),
    defineTool(ctx, {
      name: "get_policy",
      description: "Fetch a single policy rule for an agent wallet by rule id.",
      schema: z
        .object({ agentId: agentIdField, ruleId: z.string().min(1).describe("Policy rule id.") })
        .strict(),
      readOnly: true,
      run: ({ agentId, ruleId }) => ctx.client.getPolicyRule(resolveAgentId(ctx, agentId), ruleId),
    }),
    defineTool(ctx, {
      name: "list_pending_approvals",
      description:
        "List transactions awaiting human approval for the tenant. Defaults to pending entries; pass `status` to filter (pending, approved, denied).",
      schema: z
        .object({
          status: z.string().min(1).optional().describe('Filter by status (default "pending").'),
          limit: positiveInt.max(200).optional(),
          offset: z.number().int().nonnegative().optional(),
        })
        .strict(),
      readOnly: true,
      run: ({ status, limit, offset }) =>
        ctx.client.listApprovals({ status: status ?? "pending", limit, offset }),
    }),
    defineTool(ctx, {
      name: "get_audit_log",
      description:
        "Fetch a page of tenant audit-log entries. Supports filtering by agent, action (sign/approve/reject/proxy), status, and date range.",
      schema: z
        .object({
          agentId: z.string().min(1).optional().describe("Filter to a single agent."),
          action: z
            .string()
            .min(1)
            .optional()
            .describe("Filter by action: sign | approve | reject | proxy."),
          status: z.string().min(1).optional(),
          dateFrom: z.string().min(1).optional().describe("ISO-8601 lower bound."),
          dateTo: z.string().min(1).optional().describe("ISO-8601 upper bound."),
          page: positiveInt.optional(),
          limit: positiveInt.max(500).optional(),
        })
        .strict(),
      readOnly: true,
      run: (params) => ctx.client.getAuditLog(params),
    }),
  ];
}
