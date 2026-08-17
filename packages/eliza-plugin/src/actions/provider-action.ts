import { createHash } from "node:crypto";
import type {
  Action,
  ActionResult,
  HandlerOptions,
  IAgentRuntime,
  Memory,
  State,
} from "@elizaos/core";
import type { ProviderActionInvokeInput } from "@stwd/sdk";
import type { StewardService } from "../services/StewardService.js";

const CREDENTIAL_KEY =
  /(?:authorization|cookie|token|secret|credential|api[-_]?key|private[-_]?key)$/i;

function containsCredentialKey(value: unknown, depth = 0): boolean {
  if (depth > 20) return true;
  if (Array.isArray(value)) return value.some((item) => containsCredentialKey(item, depth + 1));
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(
    ([key, nested]) => CREDENTIAL_KEY.test(key) || containsCredentialKey(nested, depth + 1),
  );
}

function canonicalize(value: unknown, ancestors = new Set<object>()): unknown {
  if (!value || typeof value !== "object") return value;
  if (ancestors.has(value)) throw new TypeError("cyclic provider action arguments");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => canonicalize(item, ancestors));
    }
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, nested]) => [key, canonicalize(nested, ancestors)]),
    );
  } finally {
    ancestors.delete(value);
  }
}

function stableRetryKey(message: Memory, params: Record<string, unknown>): string | null {
  if (typeof params.idempotencyKey === "string") {
    return /^[\x21-\x7e]{8,255}$/.test(params.idempotencyKey) ? params.idempotencyKey : null;
  }
  const messageId = (message as { id?: unknown }).id;
  if (typeof messageId !== "string" || messageId.length === 0) return null;
  const publicAction = {
    messageId,
    workspaceId: params.workspaceId,
    providerAccountId: params.providerAccountId,
    operationKey: params.operationKey,
    arguments: params.arguments,
  };
  try {
    const canonical = JSON.stringify(canonicalize(publicAction));
    if (typeof canonical !== "string") return null;
    return `eliza-${createHash("sha256").update(canonical).digest("hex")}`;
  } catch {
    return null;
  }
}

export const providerAction: Action = {
  name: "STEWARD_PROVIDER_ACTION",
  description:
    "Invoke a workspace-scoped provider operation through Steward policy and exact-request approval",
  similes: ["invoke provider action", "run governed provider operation", "use provider authority"],
  parameters: [
    {
      name: "workspaceId",
      description: "Steward workspace id",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "providerAccountId",
      description: "Steward provider account id",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "operationKey",
      description: "Registered operation key such as github.issue.list",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "arguments",
      description: "Public operation arguments only; never credentials",
      required: true,
      schema: { type: "object" },
    },
    {
      name: "idempotencyKey",
      description: "Optional stable retry key",
      required: false,
      schema: { type: "string" },
    },
  ],
  examples: [],
  async validate(runtime: IAgentRuntime): Promise<boolean> {
    return (runtime.getService("steward" as any) as StewardService | null)?.isConnected() ?? false;
  },
  async handler(
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    options?: HandlerOptions,
  ): Promise<ActionResult> {
    const params = options?.parameters ?? {};
    if (
      typeof params.workspaceId !== "string" ||
      typeof params.providerAccountId !== "string" ||
      typeof params.operationKey !== "string" ||
      !params.arguments ||
      typeof params.arguments !== "object" ||
      Array.isArray(params.arguments)
    ) {
      return {
        success: false,
        error: "workspaceId, providerAccountId, operationKey, and arguments are required",
        text: "A governed provider action needs a workspace, provider account, operation, and public arguments.",
      };
    }
    if (containsCredentialKey(params.arguments)) {
      return {
        success: false,
        error: "provider credentials must not be supplied in action arguments",
        text: "Provider credentials stay in Steward and cannot be passed by the agent.",
      };
    }

    const idempotencyKey = stableRetryKey(message, params);
    if (!idempotencyKey) {
      return {
        success: false,
        error: "a valid idempotencyKey or stable message id is required",
        text: "Provider action was not submitted because no stable retry identity was available.",
      };
    }

    const input: ProviderActionInvokeInput = {
      workspaceId: params.workspaceId,
      providerAccountId: params.providerAccountId,
      operationKey: params.operationKey,
      arguments: params.arguments as Record<string, unknown>,
      idempotencyKey,
    };

    try {
      const result = await (
        runtime.getService("steward" as any) as StewardService
      ).invokeProviderAction(input);
      const pending = result.status === "pending_approval";
      const failed = result.status === "stub_failed";
      const denied = result.status === "denied_access" || result.status === "denied_policy";
      return {
        success: !failed && !denied,
        text: denied
          ? `Provider action ${result.id} was denied and persisted with status ${result.status}. It did not execute.`
          : pending
            ? `Provider action ${result.id} is blocked pending human approval. It has not executed.`
            : `Provider action ${result.id} completed with status ${result.status}.`,
        data: {
          ...result,
          caseId: result.id,
          blocked: pending,
          approvalRequired: pending,
        },
      };
    } catch {
      return {
        success: false,
        error: "provider action submission failed",
        text: "Provider action was not submitted because Steward could not complete the request.",
      };
    }
  },
};
