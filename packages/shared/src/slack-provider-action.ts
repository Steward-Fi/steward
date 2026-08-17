/** Canonical profile for Slack Web API provider actions. */
import {
  CanonError,
  type CanonicalMethod,
  canonicalizeContentType,
  canonicalizeMethod,
  canonicalizeQueryPairs,
  type JsonValue,
  jcsStringify,
  normalizePath,
  type QueryPair,
} from "./provider-action.js";

export const SLACK_PROVIDER_ACTION_PROFILE = "slack.provider-action.v1" as const;
export const SLACK_CANONICAL_ORIGIN = "https://slack.com" as const;

export interface SlackCanonicalActionV1 {
  profile: typeof SLACK_PROVIDER_ACTION_PROFILE;
  method: CanonicalMethod;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: null | JsonValue;
}

export interface RawInternalSlackAction {
  method: string;
  origin: string;
  path: string;
  query?: QueryPair[];
  contentType?: string;
  body?: JsonValue;
}

export function canonicalizeSlackOrigin(raw: string): string {
  if (typeof raw !== "string" || raw.length === 0 || /[\u0000-\u0020\u007f]/.test(raw)) {
    throw new CanonError("CANON_ORIGIN_INVALID", "invalid Slack origin");
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CanonError("CANON_ORIGIN_INVALID", "invalid Slack origin");
  }
  if (url.protocol !== "https:") {
    throw new CanonError("CANON_ORIGIN_SCHEME_UNSUPPORTED", "Slack origin must use https");
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw new CanonError("CANON_ORIGIN_INVALID", "Slack origin must not contain URL components");
  }
  if (url.port && url.port !== "443") {
    throw new CanonError("CANON_ORIGIN_PORT_UNSUPPORTED", "non-default Slack port");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host !== "slack.com") {
    throw new CanonError("CANON_ORIGIN_NOT_ALLOWED", `host '${host}' not allowed`);
  }
  return SLACK_CANONICAL_ORIGIN;
}

export function canonicalizeRawInternalSlackAction(
  raw: RawInternalSlackAction,
): SlackCanonicalActionV1 {
  const method = canonicalizeMethod(raw.method);
  const origin = canonicalizeSlackOrigin(raw.origin);
  const normalizedPath = normalizePath(raw.path);
  if (!normalizedPath.startsWith("/api/")) {
    throw new CanonError("CANON_PATH_SEGMENT_INVALID", "Slack path must be under /api/");
  }
  const orderedQueryPairs = canonicalizeQueryPairs(raw.query ?? []);
  let canonicalBody: null | JsonValue = null;
  const selectedHeaders: Array<[string, string]> = [];
  if (raw.body !== undefined) {
    if (method === "GET" || method === "HEAD") {
      throw new CanonError("CANON_BODY_FORBIDDEN", `${method} cannot carry a body`);
    }
    if (raw.contentType === undefined) {
      throw new CanonError("CANON_BODY_CONTENT_TYPE_REQUIRED", "body present without content type");
    }
    selectedHeaders.push(["content-type", canonicalizeContentType(raw.contentType)]);
    // JCS validation is part of the canonicalization boundary.
    jcsStringify(raw.body);
    canonicalBody = raw.body;
  } else if (raw.contentType !== undefined) {
    throw new CanonError("CANON_BODY_FORBIDDEN", "content type without body");
  }
  return {
    profile: SLACK_PROVIDER_ACTION_PROFILE,
    method,
    origin,
    normalizedPath,
    orderedQueryPairs,
    selectedHeaders,
    canonicalBody,
  };
}

export interface SlackGoldenVector {
  id: string;
  action: SlackCanonicalActionV1;
  canonicalActionBytes: string;
  actionDigest: string;
}

const postMessage = canonicalizeRawInternalSlackAction({
  method: "POST",
  origin: SLACK_CANONICAL_ORIGIN,
  path: "/api/chat.postMessage",
  contentType: "application/json",
  body: { channel: "C12345678", text: "hello" },
});
const conversationsList = canonicalizeRawInternalSlackAction({
  method: "GET",
  origin: SLACK_CANONICAL_ORIGIN,
  path: "/api/conversations.list",
  query: [
    ["limit", "100"],
    ["types", "private_channel,public_channel"],
  ],
});

export const SLACK_GOLDEN_VECTORS: SlackGoldenVector[] = [
  {
    id: "SGV-01",
    action: postMessage,
    canonicalActionBytes:
      '{"canonicalBody":{"channel":"C12345678","text":"hello"},"method":"POST","normalizedPath":"/api/chat.postMessage","orderedQueryPairs":[],"origin":"https://slack.com","profile":"slack.provider-action.v1","selectedHeaders":[["content-type","application/json"]]}',
    actionDigest: "sha256:cd77cbcce3f9da334c4a47f545237287fdf0074093068ca6af094f466eabc6a1",
  },
  {
    id: "SGV-02",
    action: conversationsList,
    canonicalActionBytes:
      '{"canonicalBody":null,"method":"GET","normalizedPath":"/api/conversations.list","orderedQueryPairs":[["limit","100"],["types","private_channel,public_channel"]],"origin":"https://slack.com","profile":"slack.provider-action.v1","selectedHeaders":[]}',
    actionDigest: "sha256:8d4a17110eb34906d05c95c7cf812d63af6711ce37de858d306989440b8f2b82",
  },
];
