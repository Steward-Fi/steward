import { describeThrown, isSensitiveCredentialKey } from "@stwd/shared";
import type { StewardMcpConfig } from "./config.js";

export interface ProviderApi {
  request(path: string, init?: RequestInit): Promise<unknown>;
}

function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}

// Best-effort redaction (SEC-172): keyed fields AND free-text secret shapes.
// Coverage is deliberately conservative — over-broad patterns would redact
// legitimate tool output (tx hashes, ids) — so the first line of defense
// remains upstream errors not embedding secrets at all.
function isSensitiveProviderKey(key: string): boolean {
  // Use the repository-wide classifier so this MCP boundary cannot drift
  // behind newly recognized credential carrier names. Generic transaction
  // `signature` fields are public identifiers and must remain usable; only
  // request-authentication/HMAC signatures are credentials at this boundary.
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  return (
    isSensitiveCredentialKey(key) ||
    /passwd/i.test(key) ||
    normalized === "xstewardsignature" ||
    normalized.endsWith("requestsignature") ||
    normalized.endsWith("hmacsignature")
  );
}
function joinedLabelVariants(parts: readonly string[]): string[] {
  let variants = [parts[0]];
  for (const part of parts.slice(1)) {
    variants = variants.flatMap((prefix) => [
      `${prefix}-${part}`,
      `${prefix}_${part}`,
      `${prefix}${part}`,
    ]);
  }
  return variants;
}

const SECRET_LABELS = [
  "authorization",
  "auth",
  "token",
  "secret",
  "credential",
  "api-key",
  "api_key",
  "apikey",
  "cookie-header",
  "cookie_header",
  "cookieheader",
  "cookie",
  "password",
  "passphrase",
  "passwd",
  "private-key",
  "private_key",
  "privatekey",
  "jwt",
  "request-signature",
  "request_signature",
  "requestsignature",
  "hmac-signature",
  "hmac_signature",
  "hmacsignature",
  "x-steward-signature",
  "x-steward_signature",
  "x-stewardsignature",
  "x_steward-signature",
  "x_steward_signature",
  "x_stewardsignature",
  "xsteward-signature",
  "xsteward_signature",
  "xstewardsignature",
  "client-secret",
  "client_secret",
  "clientsecret",
  ...joinedLabelVariants(["access", "key"]),
  ...joinedLabelVariants(["access", "key", "id"]),
  ...joinedLabelVariants(["secret", "access", "key"]),
  "session-id",
  "session_id",
  "sessionid",
  "session-cookie",
  "session_cookie",
  "sessioncookie",
  "signing-key",
  "signing_key",
  "signingkey",
  "encryption-key",
  "encryption_key",
  "encryptionkey",
  "mnemonic",
  "seed-phrase",
  "seed_phrase",
  "seedphrase",
  "recovery-phrase",
  "recovery_phrase",
  "recoveryphrase",
  "pat",
] as const;

const SECRET_LABELS_BY_FIRST = new Map<number, string[]>();
for (const label of ["bearer", ...SECRET_LABELS].sort((a, b) => b.length - a.length)) {
  const first = label.charCodeAt(0);
  const entries = SECRET_LABELS_BY_FIRST.get(first) ?? [];
  entries.push(label);
  SECRET_LABELS_BY_FIRST.set(first, entries);
}

type TextRange = { start: number; end: number };
const MAX_PROVIDER_TEXT_LENGTH = 1_048_576;

function isAsciiAlphaNumeric(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a)
  );
}

function isWordCode(code: number): boolean {
  return isAsciiAlphaNumeric(code) || code === 0x5f;
}

function isBase64UrlCode(code: number): boolean {
  return isAsciiAlphaNumeric(code) || code === 0x2d || code === 0x5f;
}

function isSecretValueDelimiter(value: string, index: number): boolean {
  const char = value[index];
  return char.trim().length === 0 || char === "," || char === '"' || char === "'" || char === "}";
}

function asciiStartsWithIgnoreCase(value: string, index: number, expected: string): boolean {
  if (index + expected.length > value.length) return false;
  for (let offset = 0; offset < expected.length; offset += 1) {
    let code = value.charCodeAt(index + offset);
    if (code >= 0x41 && code <= 0x5a) code += 0x20;
    if (code !== expected.charCodeAt(offset)) return false;
  }
  return true;
}

function asciiIndexOfIgnoreCase(value: string, expected: string, from: number): number {
  for (let index = from; index + expected.length <= value.length; index += 1) {
    if (asciiStartsWithIgnoreCase(value, index, expected)) return index;
  }
  return -1;
}

function addPrefixedTokenRange(
  value: string,
  ranges: TextRange[],
  start: number,
  prefixLength: number,
  minimumSuffix: number,
  suffixCode: (code: number) => boolean,
): number | undefined {
  if (start > 0 && isWordCode(value.charCodeAt(start - 1))) return undefined;
  let end = start + prefixLength;
  while (end < value.length && suffixCode(value.charCodeAt(end))) end += 1;
  if (end - (start + prefixLength) < minimumSuffix) return undefined;
  ranges.push({ start, end });
  return end;
}

function collectStructuredSecretRanges(value: string, ranges: TextRange[]): void {
  for (let index = 0; index < value.length; index += 1) {
    if (asciiStartsWithIgnoreCase(value, index, "eyj")) {
      let end = index + 3;
      const firstStart = end;
      while (end < value.length && isBase64UrlCode(value.charCodeAt(end))) end += 1;
      if (end > firstStart && value.charCodeAt(end) === 0x2e) {
        end += 1;
        const secondStart = end;
        while (end < value.length && isBase64UrlCode(value.charCodeAt(end))) end += 1;
        if (end > secondStart && value.charCodeAt(end) === 0x2e) {
          end += 1;
          while (end < value.length && isBase64UrlCode(value.charCodeAt(end))) end += 1;
          ranges.push({ start: index, end });
          index = end - 1;
          continue;
        }
      }
      // A nested `eyj` in the same uninterrupted base64url candidate cannot
      // begin another independently delimited credential. Skip the candidate
      // once so malformed near-misses remain linear.
      index = end - 1;
      continue;
    }
    let tokenEnd: number | undefined;
    if (asciiStartsWithIgnoreCase(value, index, "sk-")) {
      tokenEnd = addPrefixedTokenRange(value, ranges, index, 3, 8, isBase64UrlCode);
    } else if (
      asciiStartsWithIgnoreCase(value, index, "ghp_") ||
      asciiStartsWithIgnoreCase(value, index, "gho_")
    ) {
      tokenEnd = addPrefixedTokenRange(value, ranges, index, 4, 8, isAsciiAlphaNumeric);
    } else if (
      ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"].some((prefix) =>
        asciiStartsWithIgnoreCase(value, index, prefix),
      )
    ) {
      tokenEnd = addPrefixedTokenRange(
        value,
        ranges,
        index,
        5,
        8,
        (code) => isAsciiAlphaNumeric(code) || code === 0x2d,
      );
    } else if (
      asciiStartsWithIgnoreCase(value, index, "akia") ||
      asciiStartsWithIgnoreCase(value, index, "asia")
    ) {
      const end = index + 20;
      if (
        (index === 0 || !isWordCode(value.charCodeAt(index - 1))) &&
        end <= value.length &&
        Array.from(value.slice(index + 4, end)).every((char) => {
          const code = char.charCodeAt(0);
          return isAsciiAlphaNumeric(code);
        }) &&
        (end === value.length || !isWordCode(value.charCodeAt(end)))
      ) {
        ranges.push({ start: index, end });
        tokenEnd = end;
      }
    }
    if (tokenEnd !== undefined) index = tokenEnd - 1;
  }
}

function collectLabeledSecretRanges(value: string, ranges: TextRange[]): void {
  for (let start = 0; start < value.length; start += 1) {
    let first = value.charCodeAt(start);
    if (first >= 0x41 && first <= 0x5a) first += 0x20;
    const labels = SECRET_LABELS_BY_FIRST.get(first);
    if (!labels) continue;
    for (const label of labels) {
      if (!asciiStartsWithIgnoreCase(value, start, label)) continue;
      let cursor = start + label.length;
      const whitespaceStart = cursor;
      while (cursor < value.length && value[cursor].trim().length === 0) cursor += 1;
      if (label === "bearer") {
        if (cursor === whitespaceStart) continue;
      } else {
        const afterWhitespace = cursor;
        if (value[cursor] === '"' || value[cursor] === "'") cursor += 1;
        while (cursor < value.length && value[cursor].trim().length === 0) cursor += 1;
        if (value[cursor] === ":" || value[cursor] === "=") {
          cursor += 1;
          while (cursor < value.length && value[cursor].trim().length === 0) cursor += 1;
          if (value[cursor] === '"' || value[cursor] === "'") cursor += 1;
        } else if (afterWhitespace === whitespaceStart) {
          continue;
        } else {
          cursor = afterWhitespace;
        }
      }
      const secretStart = cursor;
      while (cursor < value.length && !isSecretValueDelimiter(value, cursor)) cursor += 1;
      if (cursor > secretStart) {
        ranges.push({ start, end: cursor });
        start = cursor - 1;
        break;
      }
    }
  }
}

function collectArmoredKeyRanges(value: string, ranges: TextRange[]): void {
  const markers = [
    ["-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"],
    ["-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----"],
    ["-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"],
    ["-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"],
    ["-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----"],
    ["-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"],
    ["-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"],
  ] as const;
  for (let start = 0; start < value.length; start += 1) {
    for (const [begin, endMarker] of markers) {
      if (!asciiStartsWithIgnoreCase(value, start, begin.toLowerCase())) continue;
      const markerStart = asciiIndexOfIgnoreCase(
        value,
        endMarker.toLowerCase(),
        start + begin.length,
      );
      const end = markerStart === -1 ? value.length : markerStart + endMarker.length;
      ranges.push({ start, end });
      start = end - 1;
      break;
    }
  }
}

function redactSecretText(value: string): string {
  if (value.length > MAX_PROVIDER_TEXT_LENGTH) return "[redacted]";
  const ranges: TextRange[] = [];
  collectArmoredKeyRanges(value, ranges);
  collectLabeledSecretRanges(value, ranges);
  collectStructuredSecretRanges(value, ranges);
  if (ranges.length === 0) return value;
  ranges.sort((a, b) => a.start - b.start || a.end - b.end);
  const parts: string[] = [];
  let cursor = 0;
  for (const range of ranges) {
    if (range.end <= cursor) continue;
    if (range.start > cursor) parts.push(value.slice(cursor, range.start));
    parts.push("[redacted]");
    cursor = range.end;
  }
  if (cursor < value.length) parts.push(value.slice(cursor));
  return parts.join("");
}

export function sanitizeProviderPayload(
  value: unknown,
  depth = 0,
  ancestors = new Set<object>(),
): unknown {
  if (depth > 20) return "[redacted]";
  if (typeof value === "string") return redactSecretText(value);
  if (value && typeof value === "object") {
    // Untrusted provider values must not execute accessors during a scrub, and
    // cycles fail closed instead of being traversed repeatedly to the limit.
    if (ancestors.has(value)) return "[redacted]";
    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        return value.map((item) => sanitizeProviderPayload(item, depth + 1, ancestors));
      }
      const clean: Record<string, unknown> = {};
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (!descriptor.enumerable) continue;
        clean[key] =
          isSensitiveProviderKey(key) || !("value" in descriptor)
            ? "[redacted]"
            : sanitizeProviderPayload(descriptor.value, depth + 1, ancestors);
      }
      return clean;
    } finally {
      ancestors.delete(value);
    }
  }
  return value;
}

export class ProviderApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly data?: unknown,
  ) {
    super(message);
    this.name = "ProviderApiError";
  }
}

export function createProviderApi(config: StewardMcpConfig): ProviderApi {
  const baseUrl = stripTrailingSlashes(config.baseUrl);
  return {
    async request(path, init = {}) {
      const headers = new Headers(init.headers);
      headers.set("Accept", "application/json");
      if (init.body !== undefined) headers.set("Content-Type", "application/json");
      if (config.bearerToken) headers.set("Authorization", `Bearer ${config.bearerToken}`);
      else if (config.apiKey) headers.set("X-Steward-Key", config.apiKey);
      if (config.tenantId) headers.set("X-Steward-Tenant", config.tenantId);

      let response: Response;
      try {
        response = await fetch(`${baseUrl}${path}`, {
          ...init,
          headers,
          signal: init.signal ?? AbortSignal.timeout(15_000),
        });
      } catch (err) {
        throw new ProviderApiError(`Provider API request failed: ${describeThrown(err)}`, 0);
      }
      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        payload = { error: "UPSTREAM_RESPONSE_INVALID" };
      }
      const clean = sanitizeProviderPayload(payload);
      if (!response.ok) {
        const message =
          clean &&
          typeof clean === "object" &&
          typeof (clean as Record<string, unknown>).error === "string"
            ? ((clean as Record<string, unknown>).error as string)
            : `Provider API request failed with HTTP ${response.status}`;
        throw new ProviderApiError(message, response.status, clean);
      }
      return clean;
    },
  };
}
