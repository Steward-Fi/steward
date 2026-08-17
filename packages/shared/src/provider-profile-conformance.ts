import { jcsStringify } from "./provider-action.js";

const CREDENTIAL_HEADER =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-goog-api-key)$/i;

export interface ConformanceCanonicalAction {
  profile: string;
  method: string;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: unknown;
}

/**
 * Inspect the canonical output emitted by a production provider builder. The
 * harness is intentionally builder-agnostic: API tests feed it the executable
 * profile registry used by ingress/finalization, so a safe handwritten fixture
 * cannot mask an unsafe production builder.
 */
export function inspectProviderProfileConformance(
  expectedProfile: string,
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
  if (!/^(?:GET|POST|PUT|PATCH|DELETE)$/.test(action.method)) {
    violations.push("method-not-canonical");
  }
  if (!action.normalizedPath.startsWith("/")) violations.push("path-not-absolute");

  for (const segment of action.normalizedPath.split("/").slice(1)) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      violations.push("path-encoding-invalid");
      continue;
    }
    if (decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\")) {
      violations.push("path-traversal");
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
    if (CREDENTIAL_HEADER.test(name)) violations.push("credential-header");
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
