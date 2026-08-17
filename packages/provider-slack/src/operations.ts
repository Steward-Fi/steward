import { createHash } from "node:crypto";
import {
  CanonError,
  type CanonicalMethod,
  canonicalizeRawInternalSlackAction,
  type JsonValue,
  SLACK_CANONICAL_ORIGIN,
  type SlackCanonicalActionV1,
} from "@stwd/shared";

export const SLACK_OPERATION_KEYS = [
  "slack.chat.postMessage",
  "slack.conversations.list",
  "slack.users.info",
] as const;
export type SlackOperationKey = (typeof SLACK_OPERATION_KEYS)[number];
export const SLACK_OPERATION_RISK: Readonly<Record<SlackOperationKey, "read" | "write">> = {
  "slack.chat.postMessage": "write",
  "slack.conversations.list": "read",
  "slack.users.info": "read",
};
export function isSlackOperationKey(value: unknown): value is SlackOperationKey {
  return typeof value === "string" && (SLACK_OPERATION_KEYS as readonly string[]).includes(value);
}
export interface SlackActionBuild {
  operationKey: SlackOperationKey;
  method: CanonicalMethod;
  risk: "read" | "write";
  action: SlackCanonicalActionV1;
  safeSummary: Record<string, unknown>;
  policyArgs: Record<string, unknown>;
}

const CHANNEL_RE = /^[CGD][A-Z0-9]{8,19}$/;
const USER_RE = /^[UW][A-Z0-9]{8,19}$/;
const THREAD_TS_RE = /^[0-9]{10,16}\.[0-9]{6}$/;
const TYPES = new Set(["public_channel", "private_channel", "mpim", "im"]);
const CREDENTIAL_KEY =
  /(?:authorization|cookie|token|secret|credential|api[-_]?key|private[-_]?key)$/i;

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "arguments must be an object");
  }
  return value as Record<string, unknown>;
}
function keys(args: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(args)) {
    if (!allowed.includes(key)) throw new CanonError("CANON_UNKNOWN_FIELD", `unknown '${key}'`);
  }
}
function required(args: Record<string, unknown>, key: string): unknown {
  if (!(key in args)) throw new CanonError("CANON_REQUIRED_FIELD_MISSING", `missing '${key}'`);
  return args[key];
}
function identifier(value: unknown, name: string, re: RegExp): string {
  if (typeof value !== "string") throw new CanonError("CANON_FIELD_TYPE_INVALID", `${name} string`);
  if (!re.test(value)) throw new CanonError("CANON_PATH_SEGMENT_INVALID", `invalid ${name}`);
  return value;
}
function text(value: unknown): string {
  if (typeof value !== "string") throw new CanonError("CANON_FIELD_TYPE_INVALID", "text string");
  if ([...value].length < 1 || [...value].length > 40000) {
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "text length out of range");
  }
  return value;
}
function assertPublicJson(value: unknown, depth = 0): asserts value is JsonValue {
  if (depth > 12) throw new CanonError("CANON_FIELD_TYPE_INVALID", "blocks too deeply nested");
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new CanonError("CANON_NUMBER_UNSAFE", "unsafe blocks number");
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 100)
      throw new CanonError("CANON_FIELD_TYPE_INVALID", "blocks array too long");
    for (const item of value) assertPublicJson(item, depth + 1);
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      if (CREDENTIAL_KEY.test(key)) {
        throw new CanonError("CANON_UNKNOWN_FIELD", "credential-shaped blocks field");
      }
      assertPublicJson(nested, depth + 1);
    }
    return;
  }
  throw new CanonError("CANON_FIELD_TYPE_INVALID", "unsupported blocks value");
}

function postMessage(raw: unknown): SlackActionBuild {
  const args = object(raw);
  keys(args, ["channel", "text", "blocks", "thread_ts"]);
  const channel = identifier(required(args, "channel"), "channel", CHANNEL_RE);
  if (!("text" in args) && !("blocks" in args)) {
    throw new CanonError("CANON_REQUIRED_FIELD_MISSING", "text or blocks required");
  }
  const body: Record<string, JsonValue> = { channel };
  if ("text" in args) body.text = text(args.text);
  if ("blocks" in args) {
    if (!Array.isArray(args.blocks) || args.blocks.length < 1 || args.blocks.length > 50) {
      throw new CanonError("CANON_FIELD_TYPE_INVALID", "blocks must contain 1..50 items");
    }
    assertPublicJson(args.blocks);
    body.blocks = args.blocks;
  }
  if ("thread_ts" in args) {
    body.thread_ts = identifier(args.thread_ts, "thread_ts", THREAD_TS_RE);
  }
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  if (bytes.length > 200_000) throw new CanonError("CANON_FIELD_TYPE_INVALID", "body too large");
  const hasBlocks = "blocks" in body;
  const textLength = typeof body.text === "string" ? [...body.text].length : 0;
  return {
    operationKey: "slack.chat.postMessage",
    method: "POST",
    risk: "write",
    action: canonicalizeRawInternalSlackAction({
      method: "POST",
      origin: SLACK_CANONICAL_ORIGIN,
      path: "/api/chat.postMessage",
      contentType: "application/json",
      body,
    }),
    safeSummary: {
      operation: "slack.chat.postMessage",
      channel,
      hasBlocks,
      textLength,
      bodySha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    },
    policyArgs: { channel, hasBlocks, textLength },
  };
}

function conversationsList(raw: unknown): SlackActionBuild {
  const args = object(raw);
  keys(args, ["types", "limit", "cursor"]);
  const query: Array<[string, string]> = [];
  let types: string[] = ["public_channel"];
  if ("types" in args) {
    if (
      !Array.isArray(args.types) ||
      args.types.length < 1 ||
      args.types.some((v) => !TYPES.has(String(v)))
    ) {
      throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", "invalid conversation types");
    }
    types = [...new Set(args.types as string[])].sort();
  }
  query.push(["types", types.join(",")]);
  const limit = args.limit ?? 100;
  if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > 200) {
    throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", "limit out of range");
  }
  query.push(["limit", String(limit)]);
  if ("cursor" in args) {
    if (typeof args.cursor !== "string" || !/^[A-Za-z0-9=_-]{1,512}$/.test(args.cursor)) {
      throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", "invalid cursor");
    }
    query.push(["cursor", args.cursor]);
  }
  return {
    operationKey: "slack.conversations.list",
    method: "GET",
    risk: "read",
    action: canonicalizeRawInternalSlackAction({
      method: "GET",
      origin: SLACK_CANONICAL_ORIGIN,
      path: "/api/conversations.list",
      query,
    }),
    safeSummary: {
      operation: "slack.conversations.list",
      types,
      limit,
      hasCursor: "cursor" in args,
    },
    policyArgs: { types, limit },
  };
}

function usersInfo(raw: unknown): SlackActionBuild {
  const args = object(raw);
  keys(args, ["user"]);
  const user = identifier(required(args, "user"), "user", USER_RE);
  return {
    operationKey: "slack.users.info",
    method: "GET",
    risk: "read",
    action: canonicalizeRawInternalSlackAction({
      method: "GET",
      origin: SLACK_CANONICAL_ORIGIN,
      path: "/api/users.info",
      query: [["user", user]],
    }),
    safeSummary: { operation: "slack.users.info", user },
    policyArgs: { user },
  };
}

export function buildSlackAction(key: SlackOperationKey, args: unknown): SlackActionBuild {
  if (key === "slack.chat.postMessage") return postMessage(args);
  if (key === "slack.conversations.list") return conversationsList(args);
  if (key === "slack.users.info") return usersInfo(args);
  throw new CanonError("CANON_PROFILE_UNSUPPORTED", "unknown Slack operation");
}
