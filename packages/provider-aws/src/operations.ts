import {
  AWS_PROVIDER_ACTION_PROFILE,
  type AwsCanonicalActionV1,
  awsEc2Origin,
  CanonError,
  type JsonValue,
  validateAwsRegion,
} from "@stwd/shared";

export const AWS_OPERATION_KEYS = ["aws.ec2.DescribeInstances", "aws.ec2.StopInstances"] as const;
export type AwsOperationKey = (typeof AWS_OPERATION_KEYS)[number];

export interface AwsActionBuild {
  operationKey: AwsOperationKey;
  method: "POST";
  action: AwsCanonicalActionV1;
  safeSummary: Record<string, unknown>;
  policyArgs: Record<string, unknown>;
}

export function isAwsOperationKey(value: unknown): value is AwsOperationKey {
  return typeof value === "string" && (AWS_OPERATION_KEYS as readonly string[]).includes(value);
}

function objectArgs(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "arguments must be an object");
  }
  return raw as Record<string, unknown>;
}

function rejectUnknown(args: Record<string, unknown>, allowed: Set<string>): void {
  for (const key of Object.keys(args)) {
    if (!allowed.has(key)) throw new CanonError("CANON_UNKNOWN_FIELD", `unknown argument '${key}'`);
  }
}

function instanceIds(value: unknown, required: boolean): string[] {
  if (value === undefined && !required) return [];
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "instanceIds must contain 1..100 ids");
  }
  const seen = new Set<string>();
  const ids = value.map((id) => {
    if (typeof id !== "string" || !/^i-[0-9a-f]{8,17}$/.test(id) || seen.has(id)) {
      throw new CanonError(
        "CANON_FIELD_TYPE_INVALID",
        "instanceIds contains an invalid or duplicate id",
      );
    }
    seen.add(id);
    return id;
  });
  return ids.sort();
}

function optionalBoolean(value: unknown, name: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean")
    throw new CanonError("CANON_FIELD_TYPE_INVALID", `${name} must be boolean`);
  return value;
}

function action(
  region: string,
  operation: "DescribeInstances" | "StopInstances",
  body: Record<string, JsonValue>,
): AwsCanonicalActionV1 {
  return {
    profile: AWS_PROVIDER_ACTION_PROFILE,
    method: "POST",
    origin: awsEc2Origin(region),
    normalizedPath: "/",
    orderedQueryPairs: [],
    selectedHeaders: [["content-type", "application/x-www-form-urlencoded; charset=UTF-8"]],
    canonicalBody: { Action: operation, Version: "2016-11-15", ...body },
  };
}

export function buildAwsAction(operationKey: AwsOperationKey, raw: unknown): AwsActionBuild {
  const args = objectArgs(raw);
  if (!("region" in args))
    throw new CanonError("CANON_REQUIRED_FIELD_MISSING", "region is required");
  const region = validateAwsRegion(args.region);
  if (operationKey === "aws.ec2.DescribeInstances") {
    rejectUnknown(args, new Set(["region", "instanceIds"]));
    const ids = instanceIds(args.instanceIds, false);
    const body: Record<string, JsonValue> = {};
    if (ids.length) body.InstanceIds = ids;
    return {
      operationKey,
      method: "POST",
      action: action(region, "DescribeInstances", body),
      safeSummary: { operation: operationKey, region, instanceIds: ids },
      policyArgs: { region, instanceIds: ids },
    };
  }
  if (operationKey === "aws.ec2.StopInstances") {
    rejectUnknown(args, new Set(["region", "instanceIds", "force", "hibernate", "dryRun"]));
    const ids = instanceIds(args.instanceIds, true);
    const force = optionalBoolean(args.force, "force");
    const hibernate = optionalBoolean(args.hibernate, "hibernate");
    const dryRun = optionalBoolean(args.dryRun, "dryRun");
    const body: Record<string, JsonValue> = { InstanceIds: ids };
    if (force !== undefined) body.Force = force;
    if (hibernate !== undefined) body.Hibernate = hibernate;
    if (dryRun !== undefined) body.DryRun = dryRun;
    const optionalArgs = {
      ...(force !== undefined ? { force } : {}),
      ...(hibernate !== undefined ? { hibernate } : {}),
      ...(dryRun !== undefined ? { dryRun } : {}),
    };
    return {
      operationKey,
      method: "POST",
      action: action(region, "StopInstances", body),
      safeSummary: { operation: operationKey, region, instanceIds: ids, ...optionalArgs },
      policyArgs: { region, instanceIds: ids, ...optionalArgs },
    };
  }
  throw new CanonError("CANON_PROFILE_UNSUPPORTED", `unknown operation '${String(operationKey)}'`);
}
