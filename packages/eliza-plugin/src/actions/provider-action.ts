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
import { containsSensitiveCredentialKey } from "@stwd/shared";
import type { StewardService } from "../services/StewardService.js";

function canonicalize(value: unknown, ancestors = new Set<object>()): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite provider action number");
    return value;
  }
  if (typeof value !== "object") throw new TypeError("non-JSON provider action value");
  if (ancestors.has(value)) throw new TypeError("cyclic provider action arguments");
  ancestors.add(value);
  try {
    if (Object.hasOwn(value, "toJSON")) {
      throw new TypeError("provider action arguments must not define toJSON");
    }
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
      if (descriptor.enumerable && !("value" in descriptor)) {
        throw new TypeError("provider action arguments must not contain accessors");
      }
    }
    if (Array.isArray(value)) {
      return value.map((item) => canonicalize(item, ancestors));
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("provider action arguments must contain only plain records");
    }
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
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
    try {
      canonicalize(params.arguments);
    } catch {
      return {
        success: false,
        error: "provider action arguments must be finite, plain JSON values",
        text: "Provider action was not submitted because its public arguments were not plain JSON values.",
      };
    }
    if (containsSensitiveCredentialKey(params.arguments)) {
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
