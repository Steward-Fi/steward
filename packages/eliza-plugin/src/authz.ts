/**
 * Sender authorization for Steward actions.
 *
 * Every action exported by this plugin is wrapped with {@link guardAction}. The
 * guard answers "WHO is asking, and WHERE" before the action is surfaced to the
 * planner (validate) and again before it executes (handler), because validate
 * is advisory on some runtime paths.
 *
 * Identity rules:
 * - The sender is `message.entityId`, which the connector derives from the
 *   platform-verified account id. Message text, display names, `content.name`,
 *   and metadata are never consulted. Impersonating the owner's display name
 *   does nothing.
 * - Owner identity comes from `STEWARD_OWNER_ENTITY_IDS` (plugin setting) when
 *   configured, otherwise from elizaOS core's role system (`checkSenderRole`).
 * - An unknown sender is a stranger. A stranger can chat, nothing else.
 * - If Steward, role resolution, or room lookup is unavailable, the guard fails
 *   closed.
 *
 * Spend and admin actions require the owner in a direct message. Steward does
 * not expose a route for routing a chat request to a human approver yet, so a
 * spend request from anyone else, or from any group or public room, is denied
 * with a message instead of being forwarded. Steward's own policies (limits,
 * allowlists, manual approval) still apply to everything that passes.
 */
import type {
  Action,
  ActionResult,
  HandlerCallback,
  HandlerOptions,
  IAgentRuntime,
  Memory,
  State,
} from "@elizaos/core";
import * as elizaCore from "@elizaos/core";

/** How much damage an action can do. Ordered from least to most dangerous. */
export type RiskClass = "chat" | "read" | "reversible-write" | "spend" | "admin";

/** Sender roles, from least to most trusted. `agent` is the agent itself. */
export type SenderRole = "stranger" | "member" | "admin" | "owner";

/** Conversation audience, derived from the stored room type, never the message. */
export type Audience = "dm" | "group" | "self" | "unknown";

export interface ActionAuthzPolicy {
  risk: RiskClass;
  /** Minimum sender role. Spend and admin additionally require owner + DM. */
  minRole: SenderRole;
  /**
   * Whether the action needs the connected StewardService. SUBMIT_TRADE talks
   * to Steward with its own JWT config, so it sets this to false.
   */
  requiresStewardService?: boolean;
}

export type AuthzDenyCode =
  | "steward_unavailable"
  | "identity_unavailable"
  | "room_unavailable"
  | "unknown_audience"
  | "role_too_low"
  | "spend_requires_owner"
  | "spend_requires_dm"
  | "admin_requires_owner"
  | "agent_spend_disabled";

export interface SenderContext {
  /** Platform-verified entity id from the message, or null when absent. */
  entityId: string | null;
  role: SenderRole;
  isAgentSelf: boolean;
  audience: Audience;
  /** Set when identity or room resolution failed. Forces fail-closed. */
  resolutionError?: "identity_unavailable" | "room_unavailable";
}

export type AuthzDecision =
  | { allowed: true; sender: SenderContext; policy: ActionAuthzPolicy }
  | {
      allowed: false;
      code: AuthzDenyCode;
      message: string;
      sender: SenderContext;
      policy: ActionAuthzPolicy;
    };

const ROLE_RANK: Record<SenderRole, number> = {
  stranger: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

const RISK_RANK: Record<RiskClass, number> = {
  chat: 0,
  read: 1,
  "reversible-write": 2,
  spend: 3,
  admin: 4,
};

/**
 * Risk class and minimum role for every action shipped by this plugin.
 * New actions must be added here; {@link guardAction} throws on unknown names.
 */
export const STEWARD_ACTION_POLICIES = {
  STEWARD_CHECK_SPEND: { risk: "read", minRole: "member" },
  STEWARD_LIST_APPROVALS: { risk: "read", minRole: "member" },
  STEWARD_REQUEST_APPROVAL: { risk: "read", minRole: "member" },
  // Credentialed outbound HTTP can move money or post as the operator, and the
  // effect is not reversible from here. Gate it like spend.
  STEWARD_CALL_GOVERNED_API: { risk: "spend", minRole: "owner" },
  // Provider operations act with Steward-held provider authority. Same reason.
  STEWARD_PROVIDER_ACTION: { risk: "spend", minRole: "owner" },
  STEWARD_SIGN_TRANSACTION: { risk: "spend", minRole: "owner" },
  STEWARD_TRANSFER: { risk: "spend", minRole: "owner" },
  SUBMIT_TRADE: { risk: "spend", minRole: "owner", requiresStewardService: false },
} as const satisfies Record<string, ActionAuthzPolicy>;

export type StewardActionName = keyof typeof STEWARD_ACTION_POLICIES;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function settingValue(runtime: IAgentRuntime, key: string): unknown {
  const getSetting = (runtime as { getSetting?: (k: string) => unknown }).getSetting;
  if (typeof getSetting === "function") {
    try {
      const value = getSetting.call(runtime, key);
      if (value !== null && value !== undefined && value !== "") return value;
    } catch {
      // fall through to env
    }
  }
  const env = process.env[key];
  return typeof env === "string" && env.trim() ? env : undefined;
}

/**
 * Configured owner entity ids. Accepts `character.settings.steward.ownerEntityIds`
 * (array), or `STEWARD_OWNER_ENTITY_IDS` as a JSON array or comma list. Only
 * well-formed UUIDs are kept, so a wildcard or name can never match.
 */
export function getConfiguredOwnerEntityIds(runtime: IAgentRuntime): string[] {
  const character = (runtime as { character?: { settings?: Record<string, unknown> } }).character;
  const stewardSettings = character?.settings?.steward as Record<string, unknown> | undefined;
  let raw: unknown = stewardSettings?.ownerEntityIds;
  if (raw === undefined) raw = settingValue(runtime, "STEWARD_OWNER_ENTITY_IDS");
  if (raw === undefined) return [];

  let list: unknown[] = [];
  if (Array.isArray(raw)) {
    list = raw;
  } else if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        list = Array.isArray(parsed) ? parsed : [];
      } catch {
        list = [];
      }
    } else {
      list = trimmed.split(",");
    }
  }
  const ids = new Set<string>();
  for (const entry of list) {
    if (typeof entry !== "string") continue;
    const id = entry.trim().toLowerCase();
    if (UUID_PATTERN.test(id)) ids.add(id);
  }
  return [...ids];
}

function booleanSetting(runtime: IAgentRuntime, key: string): boolean {
  const value = settingValue(runtime, key);
  return value === true || (typeof value === "string" && value.trim().toLowerCase() === "true");
}

function autonomousSpendEnabled(runtime: IAgentRuntime): boolean {
  return booleanSetting(runtime, "STEWARD_ALLOW_AUTONOMOUS_SPEND");
}

/** Map a stored room type to an audience. Unrecognized types are unknown. */
export function audienceForRoomType(
  type: unknown,
  opts: { apiRoomsAreDm?: boolean } = {},
): Audience {
  switch (type) {
    case "DM":
    case "VOICE_DM":
      return "dm";
    // The agent's own HTTP chat API. Whether the API caller's entity id is
    // trustworthy depends on how the API is exposed, so it is not a DM unless
    // the operator opts in with STEWARD_API_ROOMS_ARE_DM=true.
    case "API":
      return opts.apiRoomsAreDm ? "dm" : "unknown";
    case "GROUP":
    case "VOICE_GROUP":
    case "THREAD":
    case "WORLD":
    case "FORUM":
    case "FEED":
      return "group";
    case "SELF":
    case "AUTONOMOUS":
      return "self";
    default:
      return "unknown";
  }
}

type CoreRoleCheck = (
  runtime: IAgentRuntime,
  message: Memory,
) => Promise<{ role?: string } | null | undefined>;

function coreCheckSenderRole(): CoreRoleCheck | null {
  const candidate = (elizaCore as Record<string, unknown>).checkSenderRole;
  return typeof candidate === "function" ? (candidate as CoreRoleCheck) : null;
}

function roleFromCore(role: unknown): SenderRole {
  switch (role) {
    case "OWNER":
      return "owner";
    case "ADMIN":
      return "admin";
    case "USER":
      return "member";
    default:
      return "stranger";
  }
}

/**
 * Resolve who sent the message and where. Reads only `message.entityId`,
 * `message.roomId`, the stored room, configured owner ids, and core roles.
 */
export async function resolveSender(
  runtime: IAgentRuntime,
  message: Memory | undefined,
): Promise<SenderContext> {
  const rawEntityId = typeof message?.entityId === "string" ? message.entityId.trim() : "";
  const entityId = rawEntityId.length > 0 ? rawEntityId : null;
  const agentId = typeof runtime?.agentId === "string" ? runtime.agentId : null;
  const isAgentSelf = entityId !== null && agentId !== null && entityId === agentId;

  let audience: Audience = "unknown";
  let resolutionError: SenderContext["resolutionError"];
  const roomId = typeof message?.roomId === "string" ? message.roomId : null;
  if (roomId && typeof runtime?.getRoom === "function") {
    try {
      const room = await runtime.getRoom(roomId);
      audience = audienceForRoomType(room?.type, {
        apiRoomsAreDm: booleanSetting(runtime, "STEWARD_API_ROOMS_ARE_DM"),
      });
    } catch {
      resolutionError = "room_unavailable";
    }
  }

  if (entityId === null) {
    return { entityId, role: "stranger", isAgentSelf: false, audience, resolutionError };
  }
  if (isAgentSelf) {
    // The agent is not a human principal. It gets operator-level read access,
    // and spend only through the explicit autonomous opt-in.
    return { entityId, role: "admin", isAgentSelf: true, audience, resolutionError };
  }

  const configuredOwners = getConfiguredOwnerEntityIds(runtime);
  if (configuredOwners.includes(entityId.toLowerCase())) {
    return { entityId, role: "owner", isAgentSelf: false, audience, resolutionError };
  }

  let role: SenderRole = "stranger";
  const check = coreCheckSenderRole();
  if (check && message) {
    try {
      const result = await check(runtime, message);
      role = roleFromCore(result?.role);
    } catch {
      return {
        entityId,
        role: "stranger",
        isAgentSelf: false,
        audience,
        resolutionError: resolutionError ?? "identity_unavailable",
      };
    }
  }
  // When owners are configured explicitly, that list is the only source of
  // owner authority. A core OWNER that is not on the list is capped at admin.
  if (role === "owner" && configuredOwners.length > 0) role = "admin";
  return { entityId, role, isAgentSelf: false, audience, resolutionError };
}

function stewardConnected(runtime: IAgentRuntime): boolean {
  try {
    const service = runtime?.getService?.("steward" as any) as {
      isConnected?: () => boolean;
    } | null;
    return typeof service?.isConnected === "function" && service.isConnected() === true;
  } catch {
    return false;
  }
}

const DENY_MESSAGES: Record<AuthzDenyCode, string> = {
  steward_unavailable:
    "Steward is not connected, so this wallet action is unavailable. Nothing was sent.",
  identity_unavailable:
    "I could not verify who sent this request, so I did not run this wallet action.",
  room_unavailable:
    "I could not verify what kind of conversation this is, so I did not run this wallet action.",
  unknown_audience:
    "I could not verify what kind of conversation this is, so I did not run this wallet action.",
  role_too_low: "You do not have permission to use this wallet action.",
  spend_requires_owner:
    "Only the wallet owner can request this. Nothing was sent to Steward, and there is no approval queued.",
  spend_requires_dm:
    "Wallet spending only runs from a direct message with the owner. Ask me again in a DM. Nothing was sent to Steward.",
  admin_requires_owner: "Only the wallet owner can do this, from a direct message.",
  agent_spend_disabled:
    "Autonomous spending is disabled for this agent (STEWARD_ALLOW_AUTONOMOUS_SPEND is not set). Nothing was sent.",
};

function deny(
  code: AuthzDenyCode,
  sender: SenderContext,
  policy: ActionAuthzPolicy,
): AuthzDecision {
  return { allowed: false, code, message: DENY_MESSAGES[code], sender, policy };
}

/**
 * Pure decision over an already-resolved sender. Exposed for tests.
 * Fail-closed order: service, resolution errors, audience, role, risk rules.
 */
export function decide(
  sender: SenderContext,
  policy: ActionAuthzPolicy,
  opts: { stewardConnected: boolean; autonomousSpend: boolean },
): AuthzDecision {
  if (policy.risk === "chat") return { allowed: true, sender, policy };
  if (policy.requiresStewardService !== false && !opts.stewardConnected) {
    return deny("steward_unavailable", sender, policy);
  }
  if (sender.resolutionError) return deny(sender.resolutionError, sender, policy);
  if (sender.audience === "unknown") return deny("unknown_audience", sender, policy);

  const highRisk = RISK_RANK[policy.risk] >= RISK_RANK.spend;
  if (sender.isAgentSelf) {
    if (!highRisk) return { allowed: true, sender, policy };
    if (policy.risk === "spend" && sender.audience === "self" && opts.autonomousSpend) {
      return { allowed: true, sender, policy };
    }
    return deny(
      policy.risk === "admin" ? "admin_requires_owner" : "agent_spend_disabled",
      sender,
      policy,
    );
  }

  if (highRisk) {
    if (sender.role !== "owner") {
      return deny(
        policy.risk === "admin" ? "admin_requires_owner" : "spend_requires_owner",
        sender,
        policy,
      );
    }
    if (sender.audience !== "dm") {
      return deny(
        policy.risk === "admin" ? "admin_requires_owner" : "spend_requires_dm",
        sender,
        policy,
      );
    }
  }
  if (ROLE_RANK[sender.role] < ROLE_RANK[policy.minRole]) {
    return deny("role_too_low", sender, policy);
  }
  return { allowed: true, sender, policy };
}

/** Resolve the sender for `message` and decide whether it may run `policy`. */
export async function authorizeSender(
  runtime: IAgentRuntime,
  message: Memory | undefined,
  policy: ActionAuthzPolicy,
): Promise<AuthzDecision> {
  if (policy.risk === "chat") {
    return {
      allowed: true,
      sender: { entityId: null, role: "stranger", isAgentSelf: false, audience: "unknown" },
      policy,
    };
  }
  let sender: SenderContext;
  try {
    sender = await resolveSender(runtime, message);
  } catch {
    sender = {
      entityId: null,
      role: "stranger",
      isAgentSelf: false,
      audience: "unknown",
      resolutionError: "identity_unavailable",
    };
  }
  return decide(sender, policy, {
    stewardConnected: stewardConnected(runtime),
    autonomousSpend: autonomousSpendEnabled(runtime),
  });
}

/**
 * Wrap an action so validate() hides it from senders who may not run it and
 * handler() refuses to execute for them even if validate was skipped.
 */
export function guardAction(action: Action): Action {
  const policy = (STEWARD_ACTION_POLICIES as Record<string, ActionAuthzPolicy>)[action.name];
  if (!policy) {
    throw new Error(`[Steward] No authorization policy declared for action ${action.name}`);
  }
  const innerValidate = action.validate;
  const innerHandler = action.handler;
  return {
    ...action,
    async validate(runtime: IAgentRuntime, message: Memory, state?: State, options?: any) {
      const decision = await authorizeSender(runtime, message, policy);
      if (!decision.allowed) return false;
      return innerValidate(runtime, message, state, options);
    },
    async handler(
      runtime: IAgentRuntime,
      message: Memory,
      state?: State,
      options?: HandlerOptions | Record<string, any>,
      callback?: HandlerCallback,
      responses?: Memory[],
    ): Promise<ActionResult | undefined> {
      const decision = await authorizeSender(runtime, message, policy);
      if (!decision.allowed) {
        console.warn(
          `[Steward] Denied ${action.name}: ${decision.code} (risk=${policy.risk}, role=${decision.sender.role}, audience=${decision.sender.audience})`,
        );
        await callback?.({ text: decision.message, action: action.name } as any, action.name);
        return {
          success: false,
          error: `unauthorized: ${decision.code}`,
          text: decision.message,
          data: {
            authz: {
              allowed: false,
              code: decision.code,
              risk: policy.risk,
              role: decision.sender.role,
              audience: decision.sender.audience,
            },
          },
        };
      }
      return innerHandler(runtime, message, state, options as any, callback, responses);
    },
  };
}
