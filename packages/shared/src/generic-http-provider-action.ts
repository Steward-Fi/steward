/**
 * generic-http-provider-action.ts - the `generic-http.provider-action.v1`
 * canonicalization profile + operator-authored operation descriptor.
 *
 * This module is the config-driven sibling of `github.provider-action.v1`
 * (provider-action.ts) and `x.provider-action.v1` (x-provider-action.ts). Where
 * those two hardcode a single origin/host and a fixed set of operations, this
 * profile lets an operator DECLARE a governed HTTP operation for an arbitrary
 * public HTTPS host via config only (issue #201): allowed origin, method
 * allowlist, a path template with TYPED named segments, typed allowlisted query
 * params, allowlisted (never-credential) request headers, and a strict body
 * schema. The descriptor drives argument validation the same way the github
 * adapter's hand-written validators do, with no bespoke adapter package per host.
 *
 * SECURITY POSTURE. Every function here is on the attack surface and inherits
 * the fail-closed discipline of provider-action.ts:
 *   - The descriptor itself is validated STRICTLY at authoring time
 *     (`validateGenericHttpDescriptor`): an origin that is not an absolute https
 *     URL with a real DNS host is REJECTED; a credential/hop-by-hop/forwarding
 *     header in the header allowlist is REJECTED; a path template whose literal
 *     framing is traversal-ambiguous is REJECTED. A descriptor that does not
 *     pass validation can never reach canonicalization.
 *   - Argument canonicalization (`buildGenericHttpAction`) fills TYPED segments
 *     (string-with-regex, int, uuid) and query params from VALIDATED scalar
 *     values, encodes every dynamic segment with `encodeRfc3986`, and re-runs
 *     the whole raw action through the ONE shared canonicalizer
 *     (`canonicalizeRawInternalAction` semantics), so a segment can never carry
 *     `/`, `..`, or an encoded delimiter, pre- OR post-decode.
 *   - Credential headers are provably excluded from the digest: they are never
 *     admitted into `selectedHeaders`, and the descriptor validator rejects them
 *     from the allowlist, so `canonicalActionBytes` cannot contain one.
 *
 * The canonical action shape is byte-identical framing to the github/x actions
 * (same field set; only the `profile`/`origin` string VALUES differ), so the
 * shared JCS serializer produces the digest on the exact same path. This module
 * imports the shared primitives; it never re-implements JCS, hashing, path
 * normalization, query canonicalization, method canonicalization, or the
 * content-type matrix.
 */

import {
  CanonError,
  type CanonicalMethod,
  canonicalizeContentType,
  canonicalizeHeaders,
  canonicalizeMethod,
  canonicalizeQueryPairs,
  encodeRfc3986,
  type JsonValue,
  jcsStringify,
  normalizePath,
  type QueryPair,
  sha256HexPrefixed,
} from "./provider-action.js";

// ─────────────────────────────────────────────────────────────────────────────
// Profile constants
// ─────────────────────────────────────────────────────────────────────────────

export const GENERIC_HTTP_PROVIDER_ACTION_PROFILE = "generic-http.provider-action.v1" as const;

/**
 * The fully-canonical generic-http provider action. Structurally identical to
 * {@link GithubCanonicalActionV1} / {@link XCanonicalActionV1}: the shared JCS
 * framing depends only on the field set (which is the same), so digests are
 * computed on the same path. Only `profile` and `origin` string values differ,
 * and `origin` is the descriptor-declared canonical origin (not a hardcoded
 * host).
 */
export interface GenericHttpCanonicalActionV1 {
  profile: typeof GENERIC_HTTP_PROVIDER_ACTION_PROFILE;
  method: CanonicalMethod;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: null | JsonValue;
}

// ─────────────────────────────────────────────────────────────────────────────
// Descriptor error codes (a stable subset/superset of CANON_*)
//
// Descriptor VALIDATION failures use the DESCRIPTOR_* family so a
// mis-authored operator config is distinguishable from a per-request canon
// deny. These are wire-stable; never rename, only add.
// ─────────────────────────────────────────────────────────────────────────────

export const GENERIC_DESCRIPTOR_ERROR_CODES = [
  "CANON_DESCRIPTOR_SHAPE_INVALID",
  "CANON_DESCRIPTOR_PROFILE_INVALID",
  "CANON_DESCRIPTOR_ORIGIN_INVALID",
  "CANON_DESCRIPTOR_METHOD_INVALID",
  "CANON_DESCRIPTOR_PATH_TEMPLATE_INVALID",
  "CANON_DESCRIPTOR_SEGMENT_INVALID",
  "CANON_DESCRIPTOR_QUERY_INVALID",
  "CANON_DESCRIPTOR_HEADER_INVALID",
  "CANON_DESCRIPTOR_HEADER_CREDENTIAL_FORBIDDEN",
  "CANON_DESCRIPTOR_BODY_SCHEMA_INVALID",
  "CANON_DESCRIPTOR_POLICY_ARG_INVALID",
  "CANON_DESCRIPTOR_SUMMARY_INVALID",
  "CANON_DESCRIPTOR_PROTO_POLLUTION",
] as const;

export type GenericDescriptorErrorCode = (typeof GENERIC_DESCRIPTOR_ERROR_CODES)[number];

/** A descriptor-validation deny with a stable code. Never a thrown 500. */
export class GenericDescriptorError extends Error {
  readonly code: GenericDescriptorErrorCode;
  constructor(code: GenericDescriptorErrorCode, message?: string) {
    super(message ?? code);
    this.name = "GenericDescriptorError";
    this.code = code;
  }
}

export function isGenericDescriptorError(e: unknown): e is GenericDescriptorError {
  return e instanceof GenericDescriptorError;
}

function descriptorFail(code: GenericDescriptorErrorCode, message?: string): never {
  throw new GenericDescriptorError(code, message);
}

// ─────────────────────────────────────────────────────────────────────────────
// Descriptor model (operator-authored, stored per provider_operations row)
// ─────────────────────────────────────────────────────────────────────────────

/** A typed named path segment. `encodeURIComponent`-safe, traversal-proof. */
export type GenericSegmentType = "string" | "int" | "uuid";

export interface GenericPathSegmentSpec {
  /** Literal path segment (no dynamic value). */
  literal?: string;
  /** Dynamic named parameter drawn from validated args. */
  param?: {
    name: string;
    type: GenericSegmentType;
    /** For type=string only: an anchored regex the decoded value must match. */
    pattern?: string;
  };
}

/** A typed allowlisted query parameter. */
export interface GenericQueryParamSpec {
  name: string;
  type: GenericSegmentType;
  /** For type=string only: an anchored regex the value must match. */
  pattern?: string;
  required?: boolean;
  /** For type=int only: inclusive bounds. */
  min?: number;
  max?: number;
}

/** A typed allowlisted body field (scalar). */
export type GenericBodyFieldType = "string" | "int" | "bool" | "decimal-string";

export interface GenericBodyFieldSpec {
  name: string;
  type: GenericBodyFieldType;
  required?: boolean;
  pattern?: string;
  min?: number;
  max?: number;
  maxBytes?: number;
}

/** Which validated scalar becomes a policyArg / safe-summary field. */
export interface GenericProjectionSpec {
  /** Names of validated SEGMENT/QUERY/BODY scalars projected into policyArgs. */
  policyArgs: string[];
  /** Names of validated scalars projected into the non-authoritative summary. */
  safeSummary: string[];
}

export interface GenericHttpOperationDescriptorV1 {
  profile: typeof GENERIC_HTTP_PROVIDER_ACTION_PROFILE;
  /** Absolute https origin, e.g. "https://api.example.com". */
  origin: string;
  /** Allowed HTTP methods (subset of the profile method set). */
  methods: CanonicalMethod[];
  /** Path template as an ordered list of literal/param segments. */
  pathTemplate: GenericPathSegmentSpec[];
  /** Typed allowlisted query params (absent list => no query params allowed). */
  query?: GenericQueryParamSpec[];
  /** Allowlisted request header names (values fixed by the descriptor). */
  headers?: Array<{ name: string; value: string }>;
  /** Body schema (only for body-bearing methods); absent => no body. */
  body?: {
    contentType: "application/json";
    fields: GenericBodyFieldSpec[];
  };
  /** Projection of validated scalars into policyArgs + safe summary. */
  projection: GenericProjectionSpec;
}

// ─────────────────────────────────────────────────────────────────────────────
// Descriptor validation (authoring-time, fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

const PROFILE_METHODS: ReadonlySet<string> = new Set([
  "GET",
  "POST",
  "PATCH",
  "PUT",
  "DELETE",
  "HEAD",
]);

const BODY_METHODS: ReadonlySet<CanonicalMethod> = new Set(["POST", "PUT", "PATCH"]);
const BODYLESS_METHODS: ReadonlySet<CanonicalMethod> = new Set(["GET", "HEAD", "DELETE"]);

/**
 * Header names an operator may NEVER declare in a generic descriptor. Mirrors
 * the profile FORBIDDEN set (provider-action.ts): credential, hop-by-hop,
 * forwarding, and method-override headers. A descriptor that lists any of these
 * is rejected at authoring time so a credential header can never enter the
 * digest or the outbound request.
 */
const FORBIDDEN_HEADER_PREFIXES = ["x-steward-"];
const FORBIDDEN_HEADERS: ReadonlySet<string> = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "host",
  "connection",
  "content-length",
  "content-type",
  "transfer-encoding",
  "trailer",
  "te",
  "upgrade",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
  "x-original-url",
  "x-original-host",
  "x-http-method-override",
  "x-method-override",
]);

const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
const PARAM_NAME_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const QUERY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PROTO_POLLUTION_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

/** Reject any prototype-pollution key anywhere in a plain object graph. */
function assertNoProtoPollution(v: unknown, where: string): void {
  if (v === null || typeof v !== "object") return;
  if (Array.isArray(v)) {
    for (const item of v) assertNoProtoPollution(item, where);
    return;
  }
  for (const key of Object.keys(v as Record<string, unknown>)) {
    if (PROTO_POLLUTION_KEYS.has(key))
      descriptorFail("CANON_DESCRIPTOR_PROTO_POLLUTION", `forbidden key '${key}' in ${where}`);
    assertNoProtoPollution((v as Record<string, unknown>)[key], where);
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * Validate the operator-declared origin: MUST be an absolute https URL whose
 * host is a real DNS name (no IP literal, no userinfo, no port other than 443,
 * no wildcard). Returns the canonical origin string (`https://host`), which is
 * the exact `origin` the canonical action stamps. Mirrors the github/x origin
 * canonicalizer posture; the only difference is the host is descriptor-declared
 * rather than a fixed literal.
 */
export function canonicalizeGenericOrigin(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0)
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "origin must be a non-empty string");
  const s = raw as string;
  if (/[\u0000-\u0020\u007f]/.test(s))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "control/space in origin");

  const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(s);
  if (!schemeMatch)
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "origin missing scheme://");
  const scheme = schemeMatch[1].toLowerCase();
  if (scheme !== "https")
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", `scheme '${scheme}' not https`);

  const rest = s.slice(schemeMatch[0].length);
  if (rest.includes("@"))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "userinfo not allowed");
  if (rest.includes("?"))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "query not allowed in origin");
  if (rest.includes("#"))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "fragment not allowed in origin");

  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);
  if (path !== "" && path !== "/")
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "origin path must be empty or '/'");

  if (authority.includes("[") || authority.includes("]"))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "IP literal host");

  let host = authority;
  const colon = authority.lastIndexOf(":");
  if (colon !== -1) {
    const portStr = authority.slice(colon + 1);
    host = authority.slice(0, colon);
    if (!/^[0-9]+$/.test(portStr))
      descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "invalid port");
    if (portStr !== "443")
      descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", `nondefault port ${portStr}`);
  }

  if (/%/.test(host))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "percent escape in host");
  if (/[^\x00-\x7f]/.test(host))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "non-ASCII host (punycode required)");
  let h = host.toLowerCase();
  if (h.endsWith(".."))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "multiple terminal dots");
  if (h.endsWith(".")) h = h.slice(0, -1);
  if (h.startsWith("["))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "IP literal host");
  if (/^[0-9]+(\.[0-9]+)*$/.test(h))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "numeric/IPv4 host");
  if (h.includes("*"))
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "wildcard host not allowed");
  const labels = h.split(".");
  if (labels.length < 2)
    descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", "host must have at least two DNS labels");
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
      descriptorFail("CANON_DESCRIPTOR_ORIGIN_INVALID", `invalid DNS label '${label}'`);
  }
  return `https://${h}`;
}

function validatePattern(pattern: unknown, where: string): string {
  if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > 512)
    descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `${where}: pattern must be a bounded string`);
  const p = pattern as string;
  // Must be fully anchored so a partial match cannot smuggle a delimiter.
  if (!p.startsWith("^") || !p.endsWith("$"))
    descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `${where}: pattern must be anchored ^...$`);
  // Reject patterns that could admit a path/query delimiter or dot-segment.
  if (/[\/\\]/.test(p))
    descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `${where}: pattern must not contain / or \\`);
  try {
    // Construct to prove it compiles; not used for match here.
    new RegExp(p);
  } catch {
    descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `${where}: pattern does not compile`);
  }
  return p;
}

function validateSegmentType(t: unknown, where: string): GenericSegmentType {
  if (t !== "string" && t !== "int" && t !== "uuid")
    descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `${where}: type must be string|int|uuid`);
  return t as GenericSegmentType;
}

/**
 * Validate an operator-authored descriptor object. Throws
 * {@link GenericDescriptorError} on any violation. Returns a NORMALIZED
 * descriptor (origin canonicalized, header names lowercased) that
 * {@link buildGenericHttpAction} consumes. This is the ONLY gate a descriptor
 * passes before it can govern requests; an unregistered/invalid descriptor
 * never reaches canonicalization.
 */
export function validateGenericHttpDescriptor(
  raw: unknown,
): GenericHttpOperationDescriptorV1 {
  if (!isPlainObject(raw))
    descriptorFail("CANON_DESCRIPTOR_SHAPE_INVALID", "descriptor must be a plain object");
  assertNoProtoPollution(raw, "descriptor");
  const d = raw as Record<string, unknown>;

  if (d.profile !== GENERIC_HTTP_PROVIDER_ACTION_PROFILE)
    descriptorFail("CANON_DESCRIPTOR_PROFILE_INVALID", "profile mismatch");

  const origin = canonicalizeGenericOrigin(d.origin);

  // Methods
  if (!Array.isArray(d.methods) || d.methods.length === 0)
    descriptorFail("CANON_DESCRIPTOR_METHOD_INVALID", "methods must be a non-empty array");
  const methods: CanonicalMethod[] = [];
  const seenMethods = new Set<string>();
  for (const m of d.methods) {
    if (typeof m !== "string" || !PROFILE_METHODS.has(m))
      descriptorFail("CANON_DESCRIPTOR_METHOD_INVALID", `invalid method '${String(m)}'`);
    if (seenMethods.has(m))
      descriptorFail("CANON_DESCRIPTOR_METHOD_INVALID", `duplicate method '${m}'`);
    seenMethods.add(m);
    methods.push(m as CanonicalMethod);
  }

  // Path template
  if (!Array.isArray(d.pathTemplate) || d.pathTemplate.length === 0)
    descriptorFail("CANON_DESCRIPTOR_PATH_TEMPLATE_INVALID", "pathTemplate must be non-empty");
  const pathTemplate: GenericPathSegmentSpec[] = [];
  const paramNames = new Set<string>();
  for (const segRaw of d.pathTemplate) {
    if (!isPlainObject(segRaw))
      descriptorFail("CANON_DESCRIPTOR_PATH_TEMPLATE_INVALID", "path segment must be an object");
    const seg = segRaw as Record<string, unknown>;
    const hasLiteral = "literal" in seg && seg.literal !== undefined;
    const hasParam = "param" in seg && seg.param !== undefined;
    if (hasLiteral === hasParam)
      descriptorFail(
        "CANON_DESCRIPTOR_PATH_TEMPLATE_INVALID",
        "path segment must have exactly one of literal|param",
      );
    if (hasLiteral) {
      if (typeof seg.literal !== "string" || seg.literal.length === 0)
        descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", "literal segment must be a nonempty string");
      const lit = seg.literal as string;
      // A literal segment is framed verbatim; it must itself be a single safe
      // segment (no delimiter, no dot-segment, only unreserved-ish chars).
      if (
        lit.includes("/") ||
        lit.includes("\\") ||
        lit === "." ||
        lit === ".." ||
        lit.includes("%") ||
        /[\u0000-\u0020\u007f]/.test(lit) ||
        /[^\x21-\x7e]/.test(lit)
      )
        descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `unsafe literal segment '${lit}'`);
      pathTemplate.push({ literal: lit });
    } else {
      const param = seg.param;
      if (!isPlainObject(param))
        descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", "param must be an object");
      const p = param as Record<string, unknown>;
      if (typeof p.name !== "string" || !PARAM_NAME_RE.test(p.name))
        descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `invalid param name '${String(p.name)}'`);
      if (paramNames.has(p.name))
        descriptorFail("CANON_DESCRIPTOR_SEGMENT_INVALID", `duplicate param name '${p.name}'`);
      paramNames.add(p.name);
      const type = validateSegmentType(p.type, `segment '${p.name}'`);
      const out: GenericPathSegmentSpec = { param: { name: p.name, type } };
      if (type === "string") {
        if (!("pattern" in p) || p.pattern === undefined)
          descriptorFail(
            "CANON_DESCRIPTOR_SEGMENT_INVALID",
            `string segment '${p.name}' requires a pattern`,
          );
        (out.param as { pattern?: string }).pattern = validatePattern(
          p.pattern,
          `segment '${p.name}'`,
        );
      } else if ("pattern" in p && p.pattern !== undefined) {
        descriptorFail(
          "CANON_DESCRIPTOR_SEGMENT_INVALID",
          `pattern only valid on string segment '${p.name}'`,
        );
      }
      pathTemplate.push(out);
    }
  }

  // Query params
  let query: GenericQueryParamSpec[] | undefined;
  if ("query" in d && d.query !== undefined) {
    if (!Array.isArray(d.query))
      descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", "query must be an array");
    query = [];
    const seenQ = new Set<string>();
    for (const qRaw of d.query) {
      if (!isPlainObject(qRaw))
        descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", "query param must be an object");
      const q = qRaw as Record<string, unknown>;
      if (typeof q.name !== "string" || !QUERY_NAME_RE.test(q.name))
        descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `invalid query name '${String(q.name)}'`);
      if (seenQ.has(q.name))
        descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `duplicate query name '${q.name}'`);
      seenQ.add(q.name);
      const type = validateSegmentType(q.type, `query '${q.name}'`);
      const spec: GenericQueryParamSpec = { name: q.name, type };
      if ("required" in q && q.required !== undefined) {
        if (typeof q.required !== "boolean")
          descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `query '${q.name}' required must be bool`);
        spec.required = q.required;
      }
      if (type === "string") {
        if (!("pattern" in q) || q.pattern === undefined)
          descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `query '${q.name}' requires a pattern`);
        spec.pattern = validatePattern(q.pattern, `query '${q.name}'`);
      } else if ("pattern" in q && q.pattern !== undefined) {
        descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `pattern only on string query '${q.name}'`);
      }
      if (type === "int") {
        if ("min" in q && q.min !== undefined) {
          if (typeof q.min !== "number" || !Number.isSafeInteger(q.min))
            descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `query '${q.name}' min invalid`);
          spec.min = q.min;
        }
        if ("max" in q && q.max !== undefined) {
          if (typeof q.max !== "number" || !Number.isSafeInteger(q.max))
            descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `query '${q.name}' max invalid`);
          spec.max = q.max;
        }
        if (spec.min !== undefined && spec.max !== undefined && spec.min > spec.max)
          descriptorFail("CANON_DESCRIPTOR_QUERY_INVALID", `query '${q.name}' min>max`);
      }
      query.push(spec);
    }
  }

  // Headers
  let headers: Array<{ name: string; value: string }> | undefined;
  if ("headers" in d && d.headers !== undefined) {
    if (!Array.isArray(d.headers))
      descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", "headers must be an array");
    headers = [];
    const seenH = new Set<string>();
    for (const hRaw of d.headers) {
      if (!isPlainObject(hRaw))
        descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", "header must be an object");
      const hd = hRaw as Record<string, unknown>;
      if (typeof hd.name !== "string")
        descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", "header name must be a string");
      const name = (hd.name as string).toLowerCase();
      if (!HEADER_NAME_RE.test(name))
        descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", `invalid header name '${hd.name}'`);
      if (
        FORBIDDEN_HEADERS.has(name) ||
        FORBIDDEN_HEADER_PREFIXES.some((pre) => name.startsWith(pre))
      )
        descriptorFail(
          "CANON_DESCRIPTOR_HEADER_CREDENTIAL_FORBIDDEN",
          `forbidden header '${name}' in descriptor`,
        );
      if (seenH.has(name))
        descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", `duplicate header '${name}'`);
      seenH.add(name);
      if (typeof hd.value !== "string" || hd.value.length === 0 || hd.value.length > 1024)
        descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", `invalid header value for '${name}'`);
      for (let i = 0; i < (hd.value as string).length; i++) {
        const c = (hd.value as string).charCodeAt(i);
        if (c === 0x09 || c === 0x0a || c === 0x0d || c < 0x20 || c === 0x7f)
          descriptorFail("CANON_DESCRIPTOR_HEADER_INVALID", `control char in header '${name}'`);
      }
      headers.push({ name, value: hd.value as string });
    }
  }

  // Body
  let body: { contentType: "application/json"; fields: GenericBodyFieldSpec[] } | undefined;
  const hasBodyMethod = methods.some((m) => BODY_METHODS.has(m));
  if ("body" in d && d.body !== undefined) {
    if (!isPlainObject(d.body))
      descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", "body must be an object");
    const b = d.body as Record<string, unknown>;
    if (b.contentType !== "application/json")
      descriptorFail(
        "CANON_DESCRIPTOR_BODY_SCHEMA_INVALID",
        "body.contentType must be application/json",
      );
    if (!Array.isArray(b.fields))
      descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", "body.fields must be an array");
    const fields: GenericBodyFieldSpec[] = [];
    const seenF = new Set<string>();
    for (const fRaw of b.fields) {
      if (!isPlainObject(fRaw))
        descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", "body field must be an object");
      const f = fRaw as Record<string, unknown>;
      if (typeof f.name !== "string" || !PARAM_NAME_RE.test(f.name))
        descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `invalid body field '${String(f.name)}'`);
      if (seenF.has(f.name))
        descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `duplicate body field '${f.name}'`);
      seenF.add(f.name);
      if (
        f.type !== "string" &&
        f.type !== "int" &&
        f.type !== "bool" &&
        f.type !== "decimal-string"
      )
        descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `invalid body field type '${f.name}'`);
      const spec: GenericBodyFieldSpec = { name: f.name, type: f.type as GenericBodyFieldType };
      if ("required" in f && f.required !== undefined) {
        if (typeof f.required !== "boolean")
          descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' required must be bool`);
        spec.required = f.required;
      }
      if (f.type === "string") {
        if (!("pattern" in f) || f.pattern === undefined)
          descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' requires a pattern`);
        // Body patterns may contain / (JSON string value, not a path), so use a
        // looser anchored check.
        if (
          typeof f.pattern !== "string" ||
          f.pattern.length === 0 ||
          f.pattern.length > 512 ||
          !(f.pattern as string).startsWith("^") ||
          !(f.pattern as string).endsWith("$")
        )
          descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' pattern invalid`);
        try {
          new RegExp(f.pattern as string);
        } catch {
          descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' pattern no compile`);
        }
        spec.pattern = f.pattern as string;
        if ("maxBytes" in f && f.maxBytes !== undefined) {
          if (typeof f.maxBytes !== "number" || !Number.isSafeInteger(f.maxBytes) || f.maxBytes <= 0)
            descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' maxBytes invalid`);
          spec.maxBytes = f.maxBytes;
        }
      } else if ("pattern" in f && f.pattern !== undefined && f.type !== "decimal-string") {
        descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `pattern only on string body '${f.name}'`);
      }
      if (f.type === "int") {
        if ("min" in f && f.min !== undefined) {
          if (typeof f.min !== "number" || !Number.isSafeInteger(f.min))
            descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' min invalid`);
          spec.min = f.min;
        }
        if ("max" in f && f.max !== undefined) {
          if (typeof f.max !== "number" || !Number.isSafeInteger(f.max))
            descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' max invalid`);
          spec.max = f.max;
        }
        if (spec.min !== undefined && spec.max !== undefined && spec.min > spec.max)
          descriptorFail("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID", `body '${f.name}' min>max`);
      }
      fields.push(spec);
    }
    body = { contentType: "application/json", fields };
  }
  if (body && !hasBodyMethod)
    descriptorFail(
      "CANON_DESCRIPTOR_BODY_SCHEMA_INVALID",
      "body declared but no body-bearing method",
    );
  if (!body && hasBodyMethod && methods.every((m) => BODY_METHODS.has(m)))
    descriptorFail(
      "CANON_DESCRIPTOR_BODY_SCHEMA_INVALID",
      "body-bearing method requires a body schema",
    );

  // Projection
  if (!isPlainObject(d.projection))
    descriptorFail("CANON_DESCRIPTOR_POLICY_ARG_INVALID", "projection must be an object");
  const proj = d.projection as Record<string, unknown>;
  const knownScalars = new Set<string>([...paramNames]);
  if (query) for (const q of query) knownScalars.add(q.name);
  if (body) for (const f of body.fields) knownScalars.add(f.name);
  const validateNameList = (
    listRaw: unknown,
    code: GenericDescriptorErrorCode,
    label: string,
  ): string[] => {
    if (!Array.isArray(listRaw))
      descriptorFail(code, `${label} must be an array`);
    const seen = new Set<string>();
    const out: string[] = [];
    for (const n of listRaw as unknown[]) {
      if (typeof n !== "string" || !knownScalars.has(n))
        descriptorFail(code, `${label} references unknown scalar '${String(n)}'`);
      if (seen.has(n)) descriptorFail(code, `${label} duplicate '${n}'`);
      seen.add(n);
      out.push(n);
    }
    return out;
  };
  const projection: GenericProjectionSpec = {
    policyArgs: validateNameList(proj.policyArgs, "CANON_DESCRIPTOR_POLICY_ARG_INVALID", "policyArgs"),
    safeSummary: validateNameList(proj.safeSummary, "CANON_DESCRIPTOR_SUMMARY_INVALID", "safeSummary"),
  };

  return {
    profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
    origin,
    methods,
    pathTemplate,
    ...(query ? { query } : {}),
    ...(headers ? { headers } : {}),
    ...(body ? { body } : {}),
    projection,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument validation + canonical action construction (per-request)
// ─────────────────────────────────────────────────────────────────────────────

/** The result of validating + canonicalizing generic-http operation args. */
export interface GenericHttpActionBuild {
  operationKey: string;
  method: CanonicalMethod;
  action: GenericHttpCanonicalActionV1;
  safeSummary: Record<string, unknown>;
  policyArgs: Record<string, unknown>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INT_RE = /^(0|-?[1-9][0-9]*)$/;

function argError(message: string): never {
  throw new CanonError("CANON_FIELD_TYPE_INVALID", message);
}

/** Validate a single scalar value against a typed spec; return its string form. */
function validateScalarValue(
  value: unknown,
  type: GenericSegmentType | GenericBodyFieldType,
  name: string,
  opts: { pattern?: string; min?: number; max?: number; maxBytes?: number },
): { stringForm: string; scalar: string | number | boolean } {
  switch (type) {
    case "uuid": {
      if (typeof value !== "string" || !UUID_RE.test(value))
        throw new CanonError("CANON_PATH_SEGMENT_INVALID", `invalid uuid '${name}'`);
      return { stringForm: value, scalar: value };
    }
    case "int": {
      if (typeof value !== "number" || !Number.isInteger(value))
        throw new CanonError("CANON_NUMBER_FORMAT_UNSUPPORTED", `${name} must be an integer`);
      if (!Number.isSafeInteger(value))
        throw new CanonError("CANON_NUMBER_UNSAFE", `${name} not a safe integer`);
      if (opts.min !== undefined && value < opts.min)
        throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", `${name} < min`);
      if (opts.max !== undefined && value > opts.max)
        throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", `${name} > max`);
      return { stringForm: String(value), scalar: value };
    }
    case "bool": {
      if (typeof value !== "boolean")
        argError(`${name} must be a boolean`);
      return { stringForm: String(value), scalar: value as boolean };
    }
    case "decimal-string": {
      if (typeof value !== "string" || !/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(value))
        throw new CanonError("CANON_DECIMAL_STRING_INVALID", `invalid decimal '${name}'`);
      return { stringForm: value, scalar: value };
    }
    case "string": {
      if (typeof value !== "string")
        argError(`${name} must be a string`);
      const v = value as string;
      // Reject lone surrogates.
      for (let i = 0; i < v.length; i++) {
        const c = v.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
          const nxt = v.charCodeAt(i + 1);
          if (!(nxt >= 0xdc00 && nxt <= 0xdfff))
            throw new CanonError("CANON_UNICODE_INVALID", `lone surrogate in '${name}'`);
          i++;
        } else if (c >= 0xdc00 && c <= 0xdfff) {
          throw new CanonError("CANON_UNICODE_INVALID", `lone surrogate in '${name}'`);
        }
      }
      if (opts.pattern && !new RegExp(opts.pattern).test(v))
        throw new CanonError("CANON_PATH_SEGMENT_INVALID", `'${name}' fails pattern`);
      if (opts.maxBytes !== undefined && Buffer.from(v, "utf8").length > opts.maxBytes)
        argError(`${name} exceeds maxBytes`);
      return { stringForm: v, scalar: v };
    }
    default:
      argError(`unsupported type for '${name}'`);
  }
}

/**
 * Assert a decoded path-segment value is traversal-proof: after building it into
 * the path, it must be a single safe segment. Because we frame segments as
 * `encodeRfc3986(value)` for the DYNAMIC parts, `/`, `.`, backslash, and percent
 * are all encoded, so `normalizePath` never sees a delimiter or dot-segment.
 * This double-checks the decoded value can never itself be `.` or `..` and
 * carries no delimiter that could survive a decode round trip.
 */
function assertSafeSegmentValue(value: string, name: string): void {
  if (value.length === 0)
    throw new CanonError("CANON_PATH_SEGMENT_INVALID", `empty segment '${name}'`);
  if (value === "." || value === "..")
    throw new CanonError("CANON_PATH_TRAVERSAL", `dot segment '${name}'`);
  if (value.includes("/") || value.includes("\\"))
    throw new CanonError("CANON_PATH_SEGMENT_INVALID", `delimiter in segment '${name}'`);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x00 || c < 0x20 || c === 0x7f)
      throw new CanonError("CANON_PATH_FORBIDDEN_BYTE", `control byte in segment '${name}'`);
  }
}

/**
 * Validate + canonicalize the arguments for a generic-http operation against a
 * VALIDATED descriptor. Throws {@link CanonError} (never a 500) on any argument
 * or canonicalization ambiguity. The descriptor MUST already have passed
 * {@link validateGenericHttpDescriptor}.
 */
export function buildGenericHttpAction(
  operationKey: string,
  descriptor: GenericHttpOperationDescriptorV1,
  rawMethod: unknown,
  rawArgs: unknown,
): GenericHttpActionBuild {
  const method = canonicalizeMethod(typeof rawMethod === "string" ? rawMethod : "");
  if (!descriptor.methods.includes(method))
    throw new CanonError("CANON_METHOD_UNSUPPORTED", `method '${method}' not in descriptor`);

  if (typeof rawArgs !== "object" || rawArgs === null || Array.isArray(rawArgs))
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "arguments must be a JSON object");
  const args = rawArgs as Record<string, unknown>;
  for (const k of Object.keys(args)) {
    if (PROTO_POLLUTION_KEYS.has(k))
      throw new CanonError("CANON_JSON_SHAPE_INVALID", `forbidden arg key '${k}'`);
  }

  // Track which arg names are consumed so an unknown/extra arg denies.
  const consumed = new Set<string>();
  const scalars = new Map<string, string | number | boolean>();

  // ── Path segments ──
  const pathParts: string[] = [];
  for (const seg of descriptor.pathTemplate) {
    if (seg.literal !== undefined) {
      pathParts.push(seg.literal);
      continue;
    }
    const p = seg.param as { name: string; type: GenericSegmentType; pattern?: string };
    if (!(p.name in args) || args[p.name] === undefined)
      throw new CanonError("CANON_REQUIRED_FIELD_MISSING", `missing segment arg '${p.name}'`);
    const { stringForm, scalar } = validateScalarValue(args[p.name], p.type, p.name, {
      pattern: p.pattern,
    });
    assertSafeSegmentValue(stringForm, p.name);
    // Dynamic segment is percent-encoded (traversal-proof: / . \ % all escape).
    pathParts.push(encodeRfc3986(stringForm));
    consumed.add(p.name);
    scalars.set(p.name, scalar);
  }
  const path = `/${pathParts.join("/")}`;

  // ── Query ──
  const query: QueryPair[] = [];
  if (descriptor.query) {
    for (const q of descriptor.query) {
      const present = q.name in args && args[q.name] !== undefined;
      if (!present) {
        if (q.required)
          throw new CanonError("CANON_REQUIRED_FIELD_MISSING", `missing query arg '${q.name}'`);
        continue;
      }
      const { stringForm, scalar } = validateScalarValue(args[q.name], q.type, q.name, {
        pattern: q.pattern,
        min: q.min,
        max: q.max,
      });
      query.push([q.name, stringForm]);
      consumed.add(q.name);
      scalars.set(q.name, scalar);
    }
  }

  // ── Headers ──
  const headers: Array<[string, string]> = [];
  if (descriptor.headers) {
    for (const h of descriptor.headers) headers.push([h.name, h.value]);
  }

  // ── Body ──
  let contentType: string | undefined;
  let body: JsonValue | undefined;
  if (descriptor.body && BODY_METHODS.has(method)) {
    contentType = descriptor.body.contentType;
    const obj: Record<string, JsonValue> = {};
    for (const f of descriptor.body.fields) {
      const present = f.name in args && args[f.name] !== undefined;
      if (!present) {
        if (f.required)
          throw new CanonError("CANON_REQUIRED_FIELD_MISSING", `missing body field '${f.name}'`);
        continue;
      }
      const { scalar } = validateScalarValue(args[f.name], f.type, f.name, {
        pattern: f.pattern,
        min: f.min,
        max: f.max,
        maxBytes: f.maxBytes,
      });
      obj[f.name] = scalar as JsonValue;
      consumed.add(f.name);
      scalars.set(f.name, scalar);
    }
    body = obj;
  }

  // Any argument not consumed by a declared segment/query/body field denies.
  for (const k of Object.keys(args)) {
    if (!consumed.has(k))
      throw new CanonError("CANON_UNKNOWN_FIELD", `unknown argument '${k}'`);
  }

  // ── Canonicalize via the shared primitives (byte-identical framing) ──
  const canonicalOrigin = canonicalizeGenericOrigin(descriptor.origin);
  const normalizedPath = normalizePath(path);
  const orderedQueryPairs = canonicalizeQueryPairs(query);
  const selectedHeaders = canonicalizeGenericHeaders(headers);

  let canonicalBody: JsonValue | null = null;
  if (BODYLESS_METHODS.has(method)) {
    if (body !== undefined || contentType !== undefined)
      throw new CanonError("CANON_BODY_FORBIDDEN", `${method} must not carry a body`);
  } else {
    if (body === undefined || contentType === undefined)
      throw new CanonError("CANON_BODY_REQUIRED", `${method} requires a body`);
    const media = canonicalizeContentType(contentType);
    if (media !== "application/json")
      throw new CanonError(
        "CANON_BODY_CONTENT_TYPE_UNSUPPORTED",
        "generic-http body must be application/json",
      );
    if (selectedHeaders.some(([n]) => n === "content-type"))
      throw new CanonError("CANON_HEADER_DUPLICATE", "content-type both header and body media");
    selectedHeaders.push(["content-type", media]);
    selectedHeaders.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    canonicalBody = body;
  }

  const action: GenericHttpCanonicalActionV1 = {
    profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
    method,
    origin: canonicalOrigin,
    normalizedPath,
    orderedQueryPairs,
    selectedHeaders,
    canonicalBody,
  };

  // ── Projection (policyArgs + safe summary from VALIDATED scalars only) ──
  const policyArgs: Record<string, unknown> = {};
  for (const n of descriptor.projection.policyArgs) {
    if (scalars.has(n)) policyArgs[n] = scalars.get(n);
  }
  const safeSummary: Record<string, unknown> = { operation: operationKey, method };
  for (const n of descriptor.projection.safeSummary) {
    if (scalars.has(n)) safeSummary[n] = scalars.get(n);
  }

  return { operationKey, method, action, safeSummary, policyArgs };
}

/**
 * Canonicalize the descriptor-declared headers through the SHARED header
 * primitive, but with the generic-http allowlist = exactly the header names the
 * descriptor declared. The shared `canonicalizeHeaders` enforces the github
 * allowlist, so we cannot reuse it directly; instead we validate/format each
 * header here with the same posture (credential-forbidden already enforced at
 * descriptor time; re-checked here fail-closed) and sort by name.
 */
function canonicalizeGenericHeaders(
  raw: ReadonlyArray<[string, string]>,
): Array<[string, string]> {
  const byName = new Map<string, string>();
  for (const [rawName, rawValue] of raw) {
    const name = rawName.toLowerCase();
    if (!HEADER_NAME_RE.test(name))
      throw new CanonError("CANON_HEADER_INVALID", `invalid header name '${rawName}'`);
    if (
      FORBIDDEN_HEADERS.has(name) ||
      FORBIDDEN_HEADER_PREFIXES.some((pre) => name.startsWith(pre))
    )
      throw new CanonError("CANON_HEADER_CREDENTIAL_FORBIDDEN", `forbidden header '${name}'`);
    if (byName.has(name)) throw new CanonError("CANON_HEADER_DUPLICATE", `duplicate header '${name}'`);
    const value = rawValue.replace(/^[ \t]+/, "").replace(/[ \t]+$/, "");
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (c === 0x09 || c === 0x0a || c === 0x0d || c < 0x20 || c === 0x7f)
        throw new CanonError("CANON_HEADER_INVALID", "control/fold char in header value");
    }
    byName.set(name, value);
  }
  return [...byName.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([n, v]) => [n, v] as [string, string]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical action bytes + digest (generic-http)
// ─────────────────────────────────────────────────────────────────────────────

function toGenericCanonicalActionObject(
  a: GenericHttpCanonicalActionV1,
): Record<string, unknown> {
  return {
    profile: a.profile,
    method: a.method,
    origin: a.origin,
    normalizedPath: a.normalizedPath,
    orderedQueryPairs: a.orderedQueryPairs.map(([n, v]) => [n, v]),
    selectedHeaders: a.selectedHeaders.map(([n, v]) => [n, v]),
    canonicalBody: a.canonicalBody,
  };
}

/** `canonicalActionBytes` for a generic-http action as a UTF-8 string. */
export function genericHttpCanonicalActionBytes(a: GenericHttpCanonicalActionV1): string {
  return jcsStringify(toGenericCanonicalActionObject(a));
}

/** `actionDigest` = sha256: hex of the generic-http canonical action bytes. */
export function computeGenericHttpActionDigest(a: GenericHttpCanonicalActionV1): string {
  return sha256HexPrefixed(genericHttpCanonicalActionBytes(a));
}
