import { describe, expect, test } from "bun:test";
import { injectAwsSigV4AtFinalBoundary, parseAwsCredentials, signAwsSigV4 } from "../sigv4";

const credentials = {
  accessKeyId: "AKIDEXAMPLE123456",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
};

describe("AWS SigV4 final-boundary signer", () => {
  test("matches AWS IAM ListUsers official documentation vector", () => {
    const signed = signAwsSigV4({
      method: "GET",
      url: new URL("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"),
      headers: new Headers({ "content-type": "application/x-www-form-urlencoded; charset=utf-8" }),
      body: new Uint8Array(),
      service: "iam",
      region: "us-east-1",
      credentials,
      now: new Date("2015-08-30T12:36:00.000Z"),
    });
    expect(signed.signature).toBe(
      "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
    expect(signed.canonicalRequest).toContain("Action=ListUsers&Version=2010-05-08\ncontent-type:");
  });

  test("signs final EC2 bytes, overwrites attacker auth fields, and includes a session token", () => {
    const body = new TextEncoder().encode(
      "Action=StopInstances&InstanceId.1=i-12345678&Version=2016-11-15",
    );
    const headers = new Headers({
      authorization: "Bearer attacker",
      "x-amz-date": "19700101T000000Z",
      "x-amz-content-sha256": "attacker-controlled-hash",
      "x-amz-security-token": "attacker",
      "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    });
    const signed = signAwsSigV4({
      method: "POST",
      url: new URL("https://ec2.us-west-2.amazonaws.com/"),
      headers,
      body,
      service: "ec2",
      region: "us-west-2",
      credentials: { ...credentials, sessionToken: "SESSION-CANARY" },
      now: new Date("2026-08-16T12:00:00.000Z"),
    });
    expect(signed.headers.get("authorization")).toStartWith("AWS4-HMAC-SHA256 Credential=");
    expect(signed.headers.get("x-amz-security-token")).toBe("SESSION-CANARY");
    expect(signed.headers.has("x-amz-content-sha256")).toBe(false);
    expect(signed.headers.get("x-amz-date")).toBe("20260816T120000Z");
    expect(signed.canonicalRequest).toEndWith(
      "aeb17be8c579f97defe4837cb77db9df0d1c332256927d0f9a22bb8c6941f5c7",
    );
    expect(signed.canonicalRequest).not.toContain(credentials.secretAccessKey);
    expect(signed.stringToSign).not.toContain("SESSION-CANARY");
  });

  test("rejects host/region confusion and malformed clocks before signing", () => {
    const base = {
      method: "POST",
      headers: new Headers(),
      body: new Uint8Array(),
      service: "ec2",
      region: "us-west-2",
      credentials,
    } as const;
    expect(() =>
      signAwsSigV4({ ...base, url: new URL("https://ec2.us-east-1.amazonaws.com/") }),
    ).toThrow("does not match");
    expect(() =>
      signAwsSigV4({
        ...base,
        url: new URL("https://ec2.us-west-2.amazonaws.com/"),
        now: new Date(Number.NaN),
      }),
    ).toThrow("clock is invalid");
  });

  test("credential parser is strict and returns only the credential schema", () => {
    expect(() =>
      parseAwsCredentials(
        '{"accessKeyId":"AKIDEXAMPLE123456","accessKeyId":"ATTACKER00000000","secretAccessKey":"secret-key-material"}',
      ),
    ).toThrow();
    expect(() =>
      parseAwsCredentials(JSON.stringify({ ...credentials, roleArn: "attacker" })),
    ).toThrow("unknown field");
    expect(() =>
      parseAwsCredentials(JSON.stringify({ ...credentials, sessionToken: "bad\u0000token" })),
    ).toThrow("session token is invalid");
    expect(parseAwsCredentials(JSON.stringify({ ...credentials, sessionToken: "TOKEN" }))).toEqual({
      ...credentials,
      sessionToken: "TOKEN",
    });
  });

  test("production final-boundary helper binds authority, route, bytes, and leak canaries", () => {
    const credentialSecret = JSON.stringify({ ...credentials, sessionToken: "SESSION-CANARY" });
    const body = new TextEncoder().encode(
      "Action=StopInstances&InstanceId.1=i-12345678&Version=2016-11-15",
    );
    const result = injectAwsSigV4AtFinalBoundary({
      authorityMode: "governed_v2",
      routeHostPattern: "ec2.us-west-2.amazonaws.com",
      routePathPattern: "/",
      method: "POST",
      url: new URL("https://ec2.us-west-2.amazonaws.com/"),
      headers: new Headers({
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
      }),
      body,
      service: "ec2",
      region: "us-west-2",
      credentialSecret,
    });
    expect(result.headers.get("authorization")).toStartWith("AWS4-HMAC-SHA256");
    expect(result.sensitiveValues).toContain(credentials.secretAccessKey);
    expect(result.sensitiveValues).toContain("SESSION-CANARY");
    expect(JSON.stringify({ ok: true })).not.toContain(result.sensitiveValues[0]);

    for (const mutation of [
      { authorityMode: "legacy" },
      { routeHostPattern: "*.amazonaws.com" },
      { routePathPattern: "/anything" },
      { method: "GET" },
      { service: "s3" },
      { region: "us-east-1" },
    ]) {
      expect(() =>
        injectAwsSigV4AtFinalBoundary({
          authorityMode: "governed_v2",
          routeHostPattern: "ec2.us-west-2.amazonaws.com",
          routePathPattern: "/",
          method: "POST",
          url: new URL("https://ec2.us-west-2.amazonaws.com/"),
          headers: new Headers(),
          body,
          service: "ec2",
          region: "us-west-2",
          credentialSecret,
          ...mutation,
        }),
      ).toThrow();
    }
    expect(() =>
      injectAwsSigV4AtFinalBoundary({
        authorityMode: "governed_v2",
        routeHostPattern: "ec2.us-west-2.amazonaws.com",
        routePathPattern: "/",
        method: "POST",
        url: new URL("https://ec2.us-west-2.amazonaws.com/?Action=StopInstances"),
        headers: new Headers(),
        body,
        service: "ec2",
        region: "us-west-2",
        credentialSecret,
      }),
    ).toThrow(/does not match/);
  });
});
