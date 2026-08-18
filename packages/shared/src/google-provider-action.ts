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
  sha256HexPrefixed,
} from "./provider-action.js";

export const GOOGLE_PROVIDER_ACTION_PROFILE = "google.provider-action.v1" as const;
export const GOOGLE_ALLOWED_ORIGINS = [
  "https://gmail.googleapis.com",
  "https://www.googleapis.com",
] as const;

export interface GoogleCanonicalActionV1 {
  profile: typeof GOOGLE_PROVIDER_ACTION_PROFILE;
  method: CanonicalMethod;
  origin: (typeof GOOGLE_ALLOWED_ORIGINS)[number];
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: JsonValue | null;
}

export interface RawInternalGoogleAction {
  method: string;
  origin: string;
  path: string;
  query?: ReadonlyArray<QueryPair>;
  headers?: ReadonlyArray<[string, string]>;
  contentType?: string;
  body?: JsonValue;
}

export function canonicalizeGoogleOrigin(origin: string): GoogleCanonicalActionV1["origin"] {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new CanonError("CANON_ORIGIN_INVALID", "invalid Google origin");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/")
    throw new CanonError("CANON_ORIGIN_INVALID", "Google origin must contain only scheme and host");
  const canonical = `${parsed.protocol}//${parsed.host}`;
  if (!(GOOGLE_ALLOWED_ORIGINS as readonly string[]).includes(canonical))
    throw new CanonError("CANON_ORIGIN_NOT_ALLOWED", "Google origin is not allowlisted");
  return canonical as GoogleCanonicalActionV1["origin"];
}

export function canonicalizeRawInternalGoogleAction(
  raw: RawInternalGoogleAction,
): GoogleCanonicalActionV1 {
  const method = canonicalizeMethod(raw.method);
  const origin = canonicalizeGoogleOrigin(raw.origin);
  const normalizedPath = normalizePath(raw.path);
  const orderedQueryPairs = canonicalizeQueryPairs(raw.query ?? []);
  if (raw.headers?.length)
    throw new CanonError("CANON_HEADER_UNSUPPORTED", "Google actions carry no caller headers");
  const selectedHeaders: Array<[string, string]> = [];
  const hasBody = raw.body !== undefined;
  if (method === "GET" || method === "HEAD") {
    if (hasBody || raw.contentType !== undefined)
      throw new CanonError("CANON_BODY_FORBIDDEN", `${method} must not carry a body`);
  } else if (method === "POST") {
    if (!hasBody) throw new CanonError("CANON_BODY_REQUIRED", "POST requires a body");
    if (raw.contentType === undefined)
      throw new CanonError("CANON_BODY_CONTENT_TYPE_REQUIRED", "body present without content-type");
    const media = canonicalizeContentType(raw.contentType);
    if (media !== "application/json")
      throw new CanonError("CANON_BODY_CONTENT_TYPE_UNSUPPORTED", "Google bodies must be JSON");
    if (raw.body === null || typeof raw.body !== "object" || Array.isArray(raw.body))
      throw new CanonError("CANON_JSON_SHAPE_INVALID", "body must be an object");
    selectedHeaders.push(["content-type", media]);
  } else {
    throw new CanonError("CANON_METHOD_UNSUPPORTED", "Google profile supports GET and POST only");
  }
  return {
    profile: GOOGLE_PROVIDER_ACTION_PROFILE,
    method,
    origin,
    normalizedPath,
    orderedQueryPairs,
    selectedHeaders,
    canonicalBody: hasBody ? raw.body! : null,
  };
}

export function googleCanonicalActionBytes(a: GoogleCanonicalActionV1): string {
  return jcsStringify({
    profile: a.profile,
    method: a.method,
    origin: a.origin,
    normalizedPath: a.normalizedPath,
    orderedQueryPairs: a.orderedQueryPairs,
    selectedHeaders: a.selectedHeaders,
    canonicalBody: a.canonicalBody,
  });
}
export function computeGoogleActionDigest(a: GoogleCanonicalActionV1): string {
  return sha256HexPrefixed(googleCanonicalActionBytes(a));
}

// Fixed cross-package corpus. Values are literals, never derived at module load.
export const GOOGLE_GOLDEN_VECTORS = [
  {
    id: "GGV-01",
    canonicalActionBytes:
      '{"canonicalBody":null,"method":"GET","normalizedPath":"/calendar/v3/calendars/primary/events","orderedQueryPairs":[["maxResults","10"]],"origin":"https://www.googleapis.com","profile":"google.provider-action.v1","selectedHeaders":[]}',
    actionDigest: "sha256:580a1ae4063c6ac499a89640f7415db7970ff6c05783c092b14a1f9bc0ea7dc0",
  },
  {
    id: "GGV-02",
    canonicalActionBytes:
      '{"canonicalBody":{"raw":"dGVzdA"},"method":"POST","normalizedPath":"/gmail/v1/users/me/messages/send","orderedQueryPairs":[],"origin":"https://gmail.googleapis.com","profile":"google.provider-action.v1","selectedHeaders":[["content-type","application/json"]]}',
    actionDigest: "sha256:950a6e1c2937477571bb84078f76d411c18b8f694f8e1a04d850ee39d6cc7e4b",
  },
] as const;
