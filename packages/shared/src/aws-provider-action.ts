import {
  CanonError,
  type CanonicalMethod,
  type JsonValue,
  jcsStringify,
  sha256HexPrefixed,
  strictParseJson,
} from "./provider-action.js";

export const AWS_PROVIDER_ACTION_PROFILE = "aws.provider-action.v1" as const;
export type AwsRegion = string;

export interface AwsCanonicalActionV1 {
  profile: typeof AWS_PROVIDER_ACTION_PROFILE;
  method: CanonicalMethod;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: Record<string, JsonValue>;
}

const EC2_API_VERSION = "2016-11-15" as const;

function queryEncode(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** Deterministically serialize an approved AWS EC2 action for the Query API. */
export function serializeAwsEc2QueryBody(action: AwsCanonicalActionV1): string {
  const body = action.canonicalBody;
  const operation = body.Action;
  if (
    action.profile !== AWS_PROVIDER_ACTION_PROFILE ||
    action.method !== "POST" ||
    action.normalizedPath !== "/" ||
    action.orderedQueryPairs.length !== 0 ||
    body.Version !== EC2_API_VERSION ||
    (operation !== "DescribeInstances" && operation !== "StopInstances")
  ) {
    throw new CanonError("CANON_PROFILE_UNSUPPORTED", "invalid AWS EC2 canonical action");
  }
  const allowed =
    operation === "DescribeInstances"
      ? new Set(["Action", "Version", "InstanceIds"])
      : new Set(["Action", "Version", "InstanceIds", "Force", "Hibernate", "DryRun"]);
  if (Object.keys(body).some((key) => !allowed.has(key))) {
    throw new CanonError("CANON_UNKNOWN_FIELD", "unknown AWS EC2 canonical body field");
  }
  const ids = body.InstanceIds;
  if (ids !== undefined && (!Array.isArray(ids) || ids.some((id) => typeof id !== "string"))) {
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "invalid AWS EC2 instance id list");
  }
  if (operation === "StopInstances" && (!Array.isArray(ids) || ids.length === 0)) {
    throw new CanonError("CANON_REQUIRED_FIELD_MISSING", "StopInstances requires instance ids");
  }
  const pairs: Array<[string, string]> = [
    ["Action", operation],
    ["Version", EC2_API_VERSION],
  ];
  for (const [index, id] of (ids ?? []).entries()) {
    pairs.push([`InstanceId.${index + 1}`, id as string]);
  }
  for (const field of ["DryRun", "Force", "Hibernate"] as const) {
    const value = body[field];
    if (value !== undefined) {
      if (typeof value !== "boolean") {
        throw new CanonError("CANON_FIELD_TYPE_INVALID", `${field} must be boolean`);
      }
      pairs.push([field, String(value)]);
    }
  }
  pairs.sort(([a], [b]) => a.localeCompare(b));
  return pairs.map(([name, value]) => `${queryEncode(name)}=${queryEncode(value)}`).join("&");
}

const REGION_RE = /^[a-z]{2}(?:-[a-z0-9]+){1,3}-[1-9][0-9]?$/;

export function validateAwsRegion(value: unknown): AwsRegion {
  if (typeof value !== "string" || !REGION_RE.test(value)) {
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "region is not a valid AWS region");
  }
  return value;
}

export function awsEc2Origin(region: AwsRegion): string {
  return `https://ec2.${region}.amazonaws.com`;
}

/** Derive the one permitted origin without trusting the action's origin verbatim. */
export function awsEc2AllowedOriginFromCanonicalBytes(bytes: Uint8Array): string {
  const parsed = strictParseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "AWS canonical action must be an object");
  }
  const origin = (parsed as Record<string, unknown>).origin;
  if (typeof origin !== "string") {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "AWS canonical origin is invalid");
  }
  const match = /^https:\/\/ec2\.([a-z]{2}(?:-[a-z0-9]+){1,3}-[1-9][0-9]?)\.amazonaws\.com$/.exec(
    origin,
  );
  if (!match) {
    throw new CanonError(
      "CANON_JSON_SHAPE_INVALID",
      "AWS canonical origin is not EC2 region-bound",
    );
  }
  const expected = awsEc2Origin(validateAwsRegion(match[1]));
  if (origin !== expected) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "AWS canonical origin is not canonical");
  }
  return expected;
}

export function awsCanonicalActionBytes(action: AwsCanonicalActionV1): string {
  return jcsStringify(action);
}

export function computeAwsActionDigest(action: AwsCanonicalActionV1): string {
  return sha256HexPrefixed(awsCanonicalActionBytes(action));
}
