import { describe, expect, test } from "bun:test";
import {
  CanonError,
  computeAwsActionDigest,
  computeProviderPolicyInputDigest,
  jcsStringify,
  serializeAwsEc2QueryBody,
} from "@stwd/shared";
import { buildAwsAction } from "../operations";

describe("AWS governed operation adapter", () => {
  test("DescribeInstances is deterministic and region is a policy argument", () => {
    const first = buildAwsAction("aws.ec2.DescribeInstances", {
      region: "us-west-2",
      instanceIds: ["i-1234567890abcdef0", "i-0123456789abcdef0"],
    });
    const reordered = buildAwsAction("aws.ec2.DescribeInstances", {
      instanceIds: ["i-0123456789abcdef0", "i-1234567890abcdef0"],
      region: "us-west-2",
    });
    expect(first).toEqual(reordered);
    expect(first.action.origin).toBe("https://ec2.us-west-2.amazonaws.com");
    expect(first.action.selectedHeaders).toContainEqual([
      "content-type",
      "application/x-www-form-urlencoded; charset=UTF-8",
    ]);
    expect(serializeAwsEc2QueryBody(first.action)).toBe(
      "Action=DescribeInstances&InstanceId.1=i-0123456789abcdef0&InstanceId.2=i-1234567890abcdef0&Version=2016-11-15",
    );
    expect(first.policyArgs.region).toBe("us-west-2");
    expect(computeAwsActionDigest(first.action)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("StopInstances binds exact ids and consequential switches", () => {
    const result = buildAwsAction("aws.ec2.StopInstances", {
      region: "eu-central-1",
      instanceIds: ["i-12345678"],
      force: true,
      dryRun: false,
    });
    expect(result.action.canonicalBody).toEqual({
      Action: "StopInstances",
      Version: "2016-11-15",
      InstanceIds: ["i-12345678"],
      Force: true,
      DryRun: false,
    });
    expect(result.safeSummary).not.toHaveProperty("credentials");
    expect(serializeAwsEc2QueryBody(result.action)).toBe(
      "Action=StopInstances&DryRun=false&Force=true&InstanceId.1=i-12345678&Version=2016-11-15",
    );
  });

  test("StopInstances omits absent optional switches from strict policy and summary JSON", () => {
    const result = buildAwsAction("aws.ec2.StopInstances", {
      region: "us-west-2",
      instanceIds: ["i-12345678"],
    });
    expect(result.policyArgs).toEqual({
      region: "us-west-2",
      instanceIds: ["i-12345678"],
    });
    expect(result.safeSummary).toEqual({
      operation: "aws.ec2.StopInstances",
      region: "us-west-2",
      instanceIds: ["i-12345678"],
    });
    expect(() => computeProviderPolicyInputDigest(result.policyArgs)).not.toThrow();
    expect(() => jcsStringify(result.safeSummary)).not.toThrow();
  });

  test("rejects unknown fields, duplicate ids, traversal-like ids, and invalid regions", () => {
    const cases: Array<() => unknown> = [
      () => buildAwsAction("aws.ec2.DescribeInstances", { region: "us-east-1", roleArn: "x" }),
      () =>
        buildAwsAction("aws.ec2.StopInstances", {
          region: "us-east-1",
          instanceIds: ["i-12345678", "i-12345678"],
        }),
      () =>
        buildAwsAction("aws.ec2.StopInstances", {
          region: "us-east-1",
          instanceIds: ["../metadata"],
        }),
      () => buildAwsAction("aws.ec2.DescribeInstances", { region: "localhost" }),
    ];
    for (const invoke of cases) expect(invoke).toThrow(CanonError);
  });
});
