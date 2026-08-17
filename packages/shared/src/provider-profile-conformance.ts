import { CanonError, decodeUtf8Strict, jcsStringify, strictParseJson } from "./provider-action.js";
import { assertRegisteredProfile } from "./provider-profile-registry.js";
import { containsSensitiveCredentialKey, isSensitiveCredentialKey } from "./sensitive-keys.js";

export interface ConformanceCanonicalAction {
  profile: string;
  method: string;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: unknown;
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
  // Profile builders may deliberately allow provider-specific JSON media types
  // (for example GitHub vendor JSON), so this shared parser enforces every
  // profile-independent invariant and leaves the exact media allowlist to the
  // registered API builder.
  const violations = inspectProviderProfileConformance(
    expectedProfile,
    allowedOrigins,
    action,
  ).filter(
    (violation) =>
      violation !== "content-type-unsupported" &&
      // Existing digest-tamper probes deliberately produce this state and must
      // reach the signed digest comparison. The API builder remains the owner
      // of body/media coupling for newly created actions.
      violation !== "body-content-type-missing",
  );
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
  if (!/^(?:GET|POST|PUT|PATCH|DELETE)$/.test(action.method)) {
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
