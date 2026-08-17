import {
  buildGenericHttpAction,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  type GenericHttpOperationDescriptorV1,
  type GenericSegmentType,
  genericDescriptorAllowsExactPath,
  validateGenericHttpDescriptor,
} from "./generic-http-provider-action.js";
import {
  CanonError,
  decodeUtf8Strict,
  GITHUB_PROVIDER_ACTION_PROFILE,
  jcsStringify,
  strictParseJson,
} from "./provider-action.js";
import { assertRegisteredProfile } from "./provider-profile-registry.js";
import { containsSensitiveCredentialKey, isSensitiveCredentialKey } from "./sensitive-keys.js";
import { X_PROVIDER_ACTION_PROFILE } from "./x-provider-action.js";

export interface ConformanceCanonicalAction {
  profile: string;
  method: string;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: unknown;
}

export interface ProviderOperationTargetContext {
  operationKey: string;
  requestProfile: Record<string, unknown>;
}

function recoveredGenericScalar(value: string, type: GenericSegmentType): unknown {
  if (type !== "int") return value;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error("generic integer is not safe");
  return parsed;
}

/** Rebuild config-driven bytes from the persisted descriptor, not caller labels. */
function genericActionMatchesDescriptor(
  action: ConformanceCanonicalAction,
  operationKey: string,
  descriptor: GenericHttpOperationDescriptorV1,
): boolean {
  try {
    const pathParts = action.normalizedPath.split("/").slice(1);
    if (pathParts.length !== descriptor.pathTemplate.length) return false;
    const args: Record<string, unknown> = {};
    for (let i = 0; i < descriptor.pathTemplate.length; i++) {
      const param = descriptor.pathTemplate[i].param;
      if (!param) continue;
      args[param.name] = recoveredGenericScalar(decodeURIComponent(pathParts[i]), param.type);
    }
    const query = new Map((descriptor.query ?? []).map((item) => [item.name, item]));
    for (const [name, value] of action.orderedQueryPairs) {
      const spec = query.get(name);
      if (!spec || name in args) return false;
      args[name] = recoveredGenericScalar(value, spec.type);
    }
    if (action.canonicalBody !== null) {
      if (typeof action.canonicalBody !== "object" || Array.isArray(action.canonicalBody)) {
        return false;
      }
      for (const [name, value] of Object.entries(action.canonicalBody)) {
        if (name in args) return false;
        args[name] = value;
      }
    }
    const rebuilt = buildGenericHttpAction(operationKey, descriptor, action.method, args);
    return jcsStringify(rebuilt.action) === jcsStringify(action);
  } catch {
    return false;
  }
}

function pairsEqual(actual: Array<[string, string]>, expected: Array<[string, string]>): boolean {
  return jcsStringify(actual) === jcsStringify(expected);
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    jcsStringify(Object.keys(value).sort()) === jcsStringify([...keys].sort())
  );
}

function validGithubIssueQuery(pairs: Array<[string, string]>): boolean {
  const allowed = new Map<string, (value: string) => boolean>([
    ["direction", (value) => value === "asc" || value === "desc"],
    ["page", (value) => /^[1-9][0-9]{0,9}$/.test(value) && Number(value) <= 2147483647],
    ["per_page", (value) => /^(?:[1-9]|[1-9][0-9]|100)$/.test(value)],
    ["sort", (value) => ["created", "updated", "comments"].includes(value)],
    ["state", (value) => ["open", "closed", "all"].includes(value)],
  ]);
  let previous = "";
  for (const [name, value] of pairs) {
    const validator = allowed.get(name);
    if (!validator || name <= previous || !validator(value)) return false;
    previous = name;
  }
  return true;
}

function validTweetBody(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (!exactObject(value, Object.hasOwn(value, "reply") ? ["reply", "text"] : ["text"])) {
    return false;
  }
  if (typeof value.text !== "string" || value.text !== value.text.trim()) return false;
  if ([...value.text].length < 1 || [...value.text].length > 280) return false;
  if ("reply" in value) {
    if (!exactObject(value.reply, ["in_reply_to_tweet_id"])) return false;
    if (typeof value.reply.in_reply_to_tweet_id !== "string") return false;
    if (!/^[0-9]{1,25}$/.test(value.reply.in_reply_to_tweet_id)) return false;
  }
  return true;
}

/** Exact adapter-fixed reconstruction contract for every registered operation. */
function fixedActionMatchesOperation(
  action: ConformanceCanonicalAction,
  operationKey: string,
): boolean {
  const githubHeaders: Array<[string, string]> = [
    ["accept", "application/vnd.github+json"],
    ["x-github-api-version", "2022-11-28"],
  ];
  switch (operationKey) {
    case "github.issue.list":
      return (
        action.profile === GITHUB_PROVIDER_ACTION_PROFILE &&
        action.origin === "https://api.github.com" &&
        action.method === "GET" &&
        /^\/repos\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9._-]{1,100}\/issues$/.test(
          action.normalizedPath,
        ) &&
        validGithubIssueQuery(action.orderedQueryPairs) &&
        pairsEqual(action.selectedHeaders, githubHeaders) &&
        action.canonicalBody === null
      );
    case "github.pr.comment.create": {
      if (!exactObject(action.canonicalBody, ["body"])) return false;
      const body = action.canonicalBody.body;
      return (
        action.profile === GITHUB_PROVIDER_ACTION_PROFILE &&
        action.origin === "https://api.github.com" &&
        action.method === "POST" &&
        /^\/repos\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9._-]{1,100}\/issues\/[1-9][0-9]{0,9}\/comments$/.test(
          action.normalizedPath,
        ) &&
        Number(action.normalizedPath.split("/").at(-2)) <= 2147483647 &&
        action.orderedQueryPairs.length === 0 &&
        pairsEqual(action.selectedHeaders, [
          ["accept", "application/vnd.github+json"],
          ["content-type", "application/json"],
          ["x-github-api-version", "2022-11-28"],
        ]) &&
        typeof body === "string" &&
        body.length > 0 &&
        new TextEncoder().encode(body).byteLength <= 65536
      );
    }
    case "x.tweet.create":
      return (
        action.profile === X_PROVIDER_ACTION_PROFILE &&
        action.origin === "https://api.x.com" &&
        action.method === "POST" &&
        action.normalizedPath === "/2/tweets" &&
        action.orderedQueryPairs.length === 0 &&
        pairsEqual(action.selectedHeaders, [["content-type", "application/json"]]) &&
        validTweetBody(action.canonicalBody)
      );
    case "x.tweet.delete":
      return (
        action.profile === X_PROVIDER_ACTION_PROFILE &&
        action.origin === "https://api.x.com" &&
        action.method === "DELETE" &&
        /^\/2\/tweets\/[0-9]{1,25}$/.test(action.normalizedPath) &&
        action.orderedQueryPairs.length === 0 &&
        action.selectedHeaders.length === 0 &&
        action.canonicalBody === null
      );
    case "x.user.me.read":
      return (
        action.profile === X_PROVIDER_ACTION_PROFILE &&
        action.origin === "https://api.x.com" &&
        action.method === "GET" &&
        action.normalizedPath === "/2/users/me" &&
        pairsEqual(action.orderedQueryPairs, [["user.fields", "id,name,username"]]) &&
        action.selectedHeaders.length === 0 &&
        action.canonicalBody === null
      );
    default:
      return false;
  }
}

/** Enforce the adapter operation's exact target at the last pre-claim boundary. */
export function inspectProviderOperationTargetConformance(
  action: ConformanceCanonicalAction,
  context: ProviderOperationTargetContext,
): string[] {
  const violations: string[] = [];
  const exact = (origin: string, method: string, path: string | RegExp) => {
    if (action.origin !== origin) violations.push("operation-origin-mismatch");
    if (action.method !== method) violations.push("operation-method-mismatch");
    if (
      typeof path === "string" ? action.normalizedPath !== path : !path.test(action.normalizedPath)
    ) {
      violations.push("operation-path-mismatch");
    }
  };

  if (action.profile === GITHUB_PROVIDER_ACTION_PROFILE) {
    if (context.operationKey === "github.issue.list") {
      exact("https://api.github.com", "GET", /^\/repos\/[^/]+\/[^/]+\/issues$/);
    } else if (context.operationKey === "github.pr.comment.create") {
      exact(
        "https://api.github.com",
        "POST",
        /^\/repos\/[^/]+\/[^/]+\/issues\/[1-9][0-9]*\/comments$/,
      );
    } else {
      violations.push("operation-key-unsupported");
    }
    if (!fixedActionMatchesOperation(action, context.operationKey)) {
      violations.push("operation-action-mismatch");
    }
  } else if (action.profile === X_PROVIDER_ACTION_PROFILE) {
    if (context.operationKey === "x.tweet.create") {
      exact("https://api.x.com", "POST", "/2/tweets");
    } else if (context.operationKey === "x.tweet.delete") {
      exact("https://api.x.com", "DELETE", /^\/2\/tweets\/[0-9]{1,25}$/);
    } else if (context.operationKey === "x.user.me.read") {
      exact("https://api.x.com", "GET", "/2/users/me");
    } else {
      violations.push("operation-key-unsupported");
    }
    if (!fixedActionMatchesOperation(action, context.operationKey)) {
      violations.push("operation-action-mismatch");
    }
  } else if (action.profile === GENERIC_HTTP_PROVIDER_ACTION_PROFILE) {
    let descriptor: GenericHttpOperationDescriptorV1;
    try {
      if (context.requestProfile.profile !== GENERIC_HTTP_PROVIDER_ACTION_PROFILE) {
        throw new Error("profile mismatch");
      }
      descriptor = validateGenericHttpDescriptor(context.requestProfile.operationDescriptor);
    } catch {
      return ["operation-descriptor-invalid"];
    }
    if (action.origin !== descriptor.origin) violations.push("operation-origin-mismatch");
    if (!descriptor.methods.includes(action.method as never)) {
      violations.push("operation-method-mismatch");
    }
    if (!genericDescriptorAllowsExactPath(descriptor, action.normalizedPath)) {
      violations.push("operation-path-mismatch");
    }
    if (!genericActionMatchesDescriptor(action, context.operationKey, descriptor)) {
      violations.push("operation-descriptor-mismatch");
    }
  } else {
    violations.push("operation-profile-unsupported");
  }
  return [...new Set(violations)].sort();
}

const CANONICAL_ACTION_KEYS = Object.freeze([
  "canonicalBody",
  "method",
  "normalizedPath",
  "orderedQueryPairs",
  "origin",
  "profile",
  "selectedHeaders",
] as const);

function isStringPairArray(value: unknown): value is Array<[string, string]> {
  return (
    Array.isArray(value) &&
    value.every(
      (pair) =>
        Array.isArray(pair) &&
        pair.length === 2 &&
        typeof pair[0] === "string" &&
        typeof pair[1] === "string",
    )
  );
}

/**
 * Deserialize the exact canonical-action bytes consumed by governed dispatch.
 * This is deliberately shared by the proxy and the registry-driven conformance
 * harness so tests cannot validate a friendlier parser than production uses.
 *
 * The bytes must already be RFC-8785 canonical. That guarantees the snapshot
 * inspected here is byte-for-byte the snapshot whose digest/approval is stored;
 * reserialization, duplicate members, extra fields, and unsafe credential
 * carriers are rejected instead of being normalized away.
 */
export function parseCanonicalProviderActionBytes(
  bytes: Uint8Array,
  expectedProfile: string,
  allowedOrigins: readonly string[],
  operation: ProviderOperationTargetContext,
): ConformanceCanonicalAction {
  const text = decodeUtf8Strict(bytes);
  const parsed = strictParseJson(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "canonical action must be an object");
  }
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (JSON.stringify(keys) !== JSON.stringify(CANONICAL_ACTION_KEYS)) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "canonical action fields do not match");
  }
  if (
    typeof record.profile !== "string" ||
    typeof record.method !== "string" ||
    typeof record.origin !== "string" ||
    typeof record.normalizedPath !== "string" ||
    !isStringPairArray(record.orderedQueryPairs) ||
    !isStringPairArray(record.selectedHeaders)
  ) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "canonical action field type invalid");
  }
  assertRegisteredProfile(expectedProfile);
  assertRegisteredProfile(record.profile);
  const action = record as unknown as ConformanceCanonicalAction;
  const violations = [
    ...inspectProviderProfileConformance(expectedProfile, allowedOrigins, action),
    ...inspectProviderOperationTargetConformance(action, operation),
  ];
  if (violations.length > 0) {
    throw new CanonError(
      violations.includes("credential-header")
        ? "CANON_HEADER_CREDENTIAL_FORBIDDEN"
        : "CANON_JSON_SHAPE_INVALID",
      `canonical action conformance failed: ${violations.join(",")}`,
    );
  }
  if (jcsStringify(record) !== text) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "canonical action bytes are not canonical");
  }
  return action;
}

/**
 * Inspect the canonical output emitted by a production provider builder. The
 * harness is intentionally builder-agnostic: API tests feed it the executable
 * profile registry used by ingress/finalization, so a safe handwritten fixture
 * cannot mask an unsafe production builder.
 */
export function inspectProviderProfileConformance(
  expectedProfile: string,
  allowedOrigins: readonly string[],
  action: ConformanceCanonicalAction,
  credentialCanaries: readonly string[] = [],
): string[] {
  const violations: string[] = [];
  if (action.profile !== expectedProfile) violations.push("profile-mismatch");
  try {
    const parsed = new URL(action.origin);
    const labels = parsed.hostname.split(".");
    const dnsNameIsCanonical =
      parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.port === "" &&
      parsed.origin === action.origin &&
      parsed.hostname === parsed.hostname.toLowerCase() &&
      !parsed.hostname.endsWith(".") &&
      labels.length >= 2 &&
      labels.every(
        (label) =>
          label.length > 0 &&
          label.length <= 63 &&
          !label.startsWith("xn--") &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
      ) &&
      !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(parsed.hostname) &&
      !parsed.hostname.startsWith("[");
    if (!dnsNameIsCanonical) {
      violations.push("origin-not-canonical-https");
    }
  } catch {
    violations.push("origin-not-canonical-https");
  }
  if (allowedOrigins.length === 0) violations.push("origin-policy-missing");
  if (!allowedOrigins.includes(action.origin)) violations.push("origin-not-allowed");
  if (!/^(?:GET|POST|PUT|PATCH|DELETE|HEAD)$/.test(action.method)) {
    violations.push("method-not-canonical");
  }
  if (!action.normalizedPath.startsWith("/")) violations.push("path-not-absolute");

  for (const segment of action.normalizedPath.split("/").slice(1)) {
    let decoded = segment;
    // Decode to a fixed point instead of assuming how many intermediaries may
    // decode a path. Every changing decode consumes at least one `%XX` escape
    // and therefore strictly shortens the string, so the original length is a
    // conservative bound that cannot become an unbounded CPU loop.
    for (let depth = 0; depth <= segment.length; depth += 1) {
      let next: string;
      try {
        next = decodeURIComponent(decoded);
      } catch {
        violations.push("path-encoding-invalid");
        break;
      }
      if (next === "." || next === ".." || next.includes("/") || next.includes("\\")) {
        violations.push("path-traversal");
        break;
      }
      if (next === decoded) break;
      decoded = next;
    }
  }

  const queryNames = new Set<string>();
  for (const pair of action.orderedQueryPairs) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      violations.push("query-pair-invalid");
      continue;
    }
    if (queryNames.has(pair[0])) violations.push("query-duplicate");
    queryNames.add(pair[0]);
    if (isSensitiveCredentialKey(pair[0])) {
      violations.push("credential-query");
    }
  }

  const headerNames = new Set<string>();
  for (const pair of action.selectedHeaders) {
    if (!Array.isArray(pair) || pair.length !== 2) {
      violations.push("header-pair-invalid");
      continue;
    }
    const name = pair[0].toLowerCase();
    if (headerNames.has(name)) violations.push("header-duplicate");
    headerNames.add(name);
    if (isSensitiveCredentialKey(name)) violations.push("credential-header");
  }
  if (containsSensitiveCredentialKey(action.canonicalBody)) {
    violations.push("credential-body-field");
  }
  if (action.canonicalBody !== null && headerNames.has("content-type") === false) {
    violations.push("body-content-type-missing");
  }
  if (
    headerNames.has("content-type") &&
    !action.selectedHeaders.some(
      ([name, value]) => name.toLowerCase() === "content-type" && value === "application/json",
    )
  ) {
    violations.push("content-type-unsupported");
  }

  let canonical = "";
  try {
    canonical = jcsStringify(action as unknown as Record<string, unknown>);
  } catch {
    violations.push("jcs-failed");
  }
  for (const canary of credentialCanaries) {
    if (canary && canonical.includes(canary)) violations.push("credential-canary-present");
  }
  return [...new Set(violations)].sort();
}
