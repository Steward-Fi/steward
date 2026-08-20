import { createHash, createHmac } from "node:crypto";
import { strictParseJson } from "@stwd/shared";

export interface AwsSigV4Credentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface AwsSigV4Input {
  method: string;
  url: URL;
  headers: Headers;
  body: Uint8Array;
  service: string;
  region: string;
  credentials: AwsSigV4Credentials;
  now?: Date;
}

export interface AwsFinalBoundaryInput {
  authorityMode: string;
  routeHostPattern: string;
  routePathPattern: string | null;
  method: string;
  url: URL;
  headers: Headers;
  body: Uint8Array;
  service: unknown;
  region: unknown;
  credentialSecret: string;
}

const ACCESS_KEY_RE = /^[A-Z0-9]{16,128}$/;
const REGION_RE = /^[a-z]{2}(?:-[a-z0-9]+){1,3}-[1-9][0-9]?$/;

export function parseAwsCredentials(value: string): AwsSigV4Credentials {
  let parsed: unknown;
  try {
    parsed = strictParseJson(value);
  } catch {
    throw new Error("AWS credential secret must be valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("AWS credential secret must be an object");
  }
  const record = parsed as Record<string, unknown>;
  if (
    Object.keys(record).some(
      (key) => !["accessKeyId", "secretAccessKey", "sessionToken"].includes(key),
    )
  ) {
    throw new Error("AWS credential secret contains an unknown field");
  }
  if (typeof record.accessKeyId !== "string" || !ACCESS_KEY_RE.test(record.accessKeyId)) {
    throw new Error("AWS access key id is invalid");
  }
  if (
    typeof record.secretAccessKey !== "string" ||
    record.secretAccessKey.length < 16 ||
    record.secretAccessKey.length > 256 ||
    /[^\x21-\x7e]/.test(record.secretAccessKey)
  ) {
    throw new Error("AWS secret access key is invalid");
  }
  if (
    record.sessionToken !== undefined &&
    (typeof record.sessionToken !== "string" ||
      record.sessionToken.length < 1 ||
      record.sessionToken.length > 8192 ||
      /[^\x21-\x7e]/.test(record.sessionToken))
  ) {
    throw new Error("AWS session token is invalid");
  }
  return {
    accessKeyId: record.accessKeyId,
    secretAccessKey: record.secretAccessKey,
    ...(record.sessionToken ? { sessionToken: record.sessionToken } : {}),
  };
}

function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function hmac(key: string | Buffer, value: string): Buffer {
  return createHmac("sha256", key).update(value, "utf8").digest();
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function canonicalQuery(url: URL): string {
  const pairs = [...url.searchParams.entries()].map(
    ([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)] as const,
  );
  pairs.sort(([ak, av], [bk, bv]) => (ak === bk ? av.localeCompare(bv) : ak.localeCompare(bk)));
  return pairs.map(([key, value]) => `${key}=${value}`).join("&");
}

function canonicalUri(pathname: string): string {
  return (
    pathname
      .split("/")
      .map((segment) => encodeRfc3986(decodeURIComponent(segment)))
      .join("/") || "/"
  );
}

function awsTimestamp(now: Date): { amzDate: string; date: string } {
  if (!Number.isFinite(now.getTime())) throw new Error("SigV4 signing clock is invalid");
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amzDate, date: amzDate.slice(0, 8) };
}

export function signAwsSigV4(input: AwsSigV4Input): {
  headers: Headers;
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
} {
  const { url, credentials } = input;
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash) {
    throw new Error("SigV4 target must be a credential-free HTTPS origin");
  }
  if (input.service !== "ec2" && input.service !== "iam")
    throw new Error("SigV4 service is unsupported");
  if (!REGION_RE.test(input.region)) throw new Error("SigV4 region is invalid");
  if (input.service === "ec2" && url.hostname !== `ec2.${input.region}.amazonaws.com`) {
    throw new Error("SigV4 target host does not match the bound service and region");
  }
  const headers = new Headers(input.headers);
  headers.delete("authorization");
  for (const name of [...headers.keys()]) {
    if (name.startsWith("x-amz-")) headers.delete(name);
  }
  headers.set("host", url.host);
  const { amzDate, date } = awsTimestamp(input.now ?? new Date());
  headers.set("x-amz-date", amzDate);
  if (credentials.sessionToken) headers.set("x-amz-security-token", credentials.sessionToken);

  const signable = [...headers.entries()]
    .filter(([name]) => name === "host" || name === "content-type" || name.startsWith("x-amz-"))
    .map(([name, value]) => [name.toLowerCase(), value.trim().replace(/\s+/g, " ")] as const)
    .sort(([a], [b]) => a.localeCompare(b));
  const signedHeaders = signable.map(([name]) => name).join(";");
  const canonicalHeaders = `${signable.map(([name, value]) => `${name}:${value}`).join("\n")}\n`;
  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri(url.pathname),
    canonicalQuery(url),
    canonicalHeaders,
    signedHeaders,
    sha256Hex(input.body),
  ].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const dateKey = hmac(`AWS4${credentials.secretAccessKey}`, date);
  const regionKey = hmac(dateKey, input.region);
  const serviceKey = hmac(regionKey, input.service);
  const signingKey = hmac(serviceKey, "aws4_request");
  const signature = createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");
  headers.set(
    "authorization",
    `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  );
  return { headers, canonicalRequest, stringToSign, signature };
}

/**
 * Production dispatch boundary for SigV4. This accepts the fully-resolved URL,
 * headers and exact body bytes, then rechecks every persisted route binding
 * before parsing the secret and signing. Nothing upstream may provide a date,
 * signature, session token, service, region, or host that survives this call.
 */
export function injectAwsSigV4AtFinalBoundary(input: AwsFinalBoundaryInput): {
  headers: Headers;
  sensitiveValues: string[];
} {
  if (input.authorityMode !== "governed_v2") {
    throw new Error("SigV4 injection requires governed_v2 authority");
  }
  if (input.service !== "ec2" || typeof input.region !== "string") {
    throw new Error("Invalid SigV4 route configuration");
  }
  const expectedHost = `ec2.${input.region}.amazonaws.com`;
  if (
    input.routeHostPattern !== expectedHost ||
    input.url.hostname !== expectedHost ||
    input.routePathPattern !== "/" ||
    input.url.pathname !== "/" ||
    input.url.search !== "" ||
    input.method !== "POST"
  ) {
    throw new Error("SigV4 route does not match its bound AWS endpoint");
  }
  const credentials = parseAwsCredentials(input.credentialSecret);
  const signed = signAwsSigV4({
    method: input.method,
    url: input.url,
    headers: input.headers,
    body: input.body,
    service: input.service,
    region: input.region,
    credentials,
  });
  return {
    headers: signed.headers,
    sensitiveValues: [
      credentials.accessKeyId,
      credentials.secretAccessKey,
      credentials.sessionToken ?? "",
      signed.headers.get("authorization") ?? "",
      input.credentialSecret,
    ].filter(Boolean),
  };
}
