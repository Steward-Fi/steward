import { randomUUID } from "node:crypto";
import type { LookupAddress } from "node:dns";
import type { RequestOptions } from "node:http";
import { isIP, type LookupFunction } from "node:net";
import type { WebhookEvent } from "@stwd/shared";

import type { WebhookConfig, WebhookDeliveryResult, WebhookDispatcherOptions } from "./types";

// Signature scheme version. v2 binds timestamp + deliveryId + event type into the HMAC.
const SIGNATURE_SCHEME = "v2";

// Canonical signed material. deliveryId and eventType are length-prefixed
// (`<len>:<value>`) so field boundaries cannot be shifted — event types and
// bodies contain '.', and a plain `.`-join would let an attacker re-split a
// captured signature (e.g. eventType "a.b"+body "c" vs "a"+body "b.c") to forge
// a colliding-but-valid message. body is last/unbounded so needs no prefix.
function canonicalSignedPayload(
  timestamp: string,
  deliveryId: string,
  eventType: string,
  body: string,
): string {
  return `${SIGNATURE_SCHEME}:${timestamp}.${deliveryId.length}:${deliveryId}.${eventType.length}:${eventType}.${body}`;
}

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_DELAY_MS = 1_000;
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const ALLOW_PRIVATE_WEBHOOK_NETWORKS =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
    ?.STEWARD_ALLOW_PRIVATE_WEBHOOK_NETWORKS === "true";

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const secretBytes = encoder.encode(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes.buffer.slice(
      secretBytes.byteOffset,
      secretBytes.byteOffset + secretBytes.byteLength,
    ) as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const payloadBytes = encoder.encode(payload);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    payloadBytes.buffer.slice(
      payloadBytes.byteOffset,
      payloadBytes.byteOffset + payloadBytes.byteLength,
    ) as ArrayBuffer,
  );

  return toHex(signature);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function shouldRetry(statusCode?: number): boolean {
  return statusCode === undefined || statusCode >= 500;
}

function isNonPublicIpv4(address: string): boolean {
  const octets = address.split(".").map((part) => Number(part));
  if (
    octets.length !== 4 ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return false;
  }
  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 88 && octets[2] === 99) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && octets[2] === 100) ||
    (a === 203 && b === 0 && octets[2] === 113) ||
    a >= 224
  );
}

function mappedIpv4FromIpv6(address: string): string | null {
  const normalized = address.toLowerCase();
  const dotted = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return dotted[1];

  const hex = normalized.match(/^(?:::ffff:|0:0:0:0:0:ffff:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (!hex) return null;
  const high = Number.parseInt(hex[1], 16);
  const low = Number.parseInt(hex[2], 16);
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function expandIpv6Words(address: string): number[] | null {
  const normalized = address.toLowerCase();
  const halves = normalized.split("::");
  if (halves.length > 2) return null;

  const parseWords = (part: string): number[] | null => {
    if (!part) return [];
    const words = part.split(":");
    const parsed = words.map((word) => {
      if (!/^[0-9a-f]{1,4}$/.test(word)) return Number.NaN;
      return Number.parseInt(word, 16);
    });
    return parsed.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)
      ? null
      : parsed;
  };

  const left = parseWords(halves[0]);
  const right = parseWords(halves[1] ?? "");
  if (!left || !right) return null;

  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function embeddedIpv4FromIpv6(address: string): string | null {
  const words = expandIpv6Words(address);
  if (!words || words.length !== 8) return null;

  const fromWords = (high: number, low: number) =>
    [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");

  const isNat64WellKnown =
    words[0] === 0x64 &&
    words[1] === 0xff9b &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0;
  if (isNat64WellKnown) return fromWords(words[6], words[7]);

  const isNat64LocalUse =
    words[0] === 0x64 && words[1] === 0xff9b && words[2] === 1 && words[3] === 0;
  if (isNat64LocalUse) return fromWords(words[6], words[7]);

  if (words[0] === 0x2002) return fromWords(words[1], words[2]);
  return null;
}

function isNonPublicIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  const ipv4Mapped = mappedIpv4FromIpv6(normalized);
  if (ipv4Mapped) return isNonPublicIpv4(ipv4Mapped);
  const ipv4Embedded = embeddedIpv4FromIpv6(normalized);
  if (ipv4Embedded) return isNonPublicIpv4(ipv4Embedded);
  const words = expandIpv6Words(normalized);
  if (words?.[0] === 0x2001 && (words[1] === 0 || words[1] === 0xdb8)) return true;
  if (words?.[0] !== undefined && (words[0] & 0xffc0) === 0xfe80) return true;
  if (words?.[0] !== undefined && (words[0] & 0xffc0) === 0xfec0) return true;
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("ff")
  );
}

function assertPublicWebhookHostname(hostname: string): void {
  if (!hostname) throw new Error("Webhook URL must include a host");
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error("Webhook host must resolve to a public address");
  }

  const literalVersion = isIP(hostname);
  if (literalVersion === 4 && isNonPublicIpv4(hostname)) {
    throw new Error("Webhook host must resolve to a public address");
  }
  if (literalVersion === 6 && isNonPublicIpv6(hostname)) {
    throw new Error("Webhook host must resolve to a public address");
  }
}

function assertPublicAddress(address: string, family?: number): void {
  if (
    (family === 4 && isNonPublicIpv4(address)) ||
    (family === 6 && isNonPublicIpv6(address)) ||
    (family !== 4 && family !== 6 && (isNonPublicIpv4(address) || isNonPublicIpv6(address)))
  ) {
    throw new Error("Webhook host must resolve to a public address");
  }
}

function createPublicLookup(baseLookup?: LookupFunction): LookupFunction {
  return (hostname, options, callback) => {
    void (async () => {
      try {
        const normalizedHostname = hostname.replace(/^\[|\]$/g, "").toLowerCase();
        assertPublicWebhookHostname(normalizedHostname);
        if (baseLookup) {
          baseLookup(hostname, options, (error, address, family) => {
            if (error) {
              callback(error, address as never, family as never);
              return;
            }
            try {
              if (Array.isArray(address)) {
                for (const entry of address as LookupAddress[]) {
                  assertPublicAddress(entry.address, entry.family);
                }
                callback(null, address as never, family as never);
                return;
              }
              assertPublicAddress(address, family);
              callback(null, address, family);
            } catch (lookupError) {
              callback(lookupError as NodeJS.ErrnoException, "" as never, 0 as never);
            }
          });
          return;
        }
        const { lookup } = await import("node:dns/promises");
        const family = typeof options === "object" && options.family ? options.family : undefined;
        const addresses = await lookup(hostname, {
          all: true,
          family,
          verbatim: true,
        });
        if (addresses.length === 0) throw new Error("Webhook host did not resolve");
        for (const entry of addresses as LookupAddress[]) {
          assertPublicAddress(entry.address, entry.family);
        }
        const selected = addresses[0];
        callback(null, selected.address, selected.family);
      } catch (error) {
        callback(error as NodeJS.ErrnoException, "" as never, 0 as never);
      }
    })();
  };
}

async function postWebhook(
  url: string,
  init: {
    headers: Record<string, string>;
    body: string;
    timeoutMs: number;
    allowPrivateNetwork: boolean;
    allowInsecureHttp: boolean;
    lookup?: LookupFunction;
  },
): Promise<{ status: number; ok: boolean }> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Webhook URL must use https");
  }
  if (parsed.protocol === "http:" && !init.allowInsecureHttp) {
    throw new Error("Webhook URL must use https");
  }

  const transport =
    parsed.protocol === "https:" ? await import("node:https") : await import("node:http");
  const options: RequestOptions = {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : undefined,
    path: `${parsed.pathname}${parsed.search}`,
    method: "POST",
    headers: {
      ...init.headers,
      "Content-Length": new TextEncoder().encode(init.body).length.toString(),
    },
  };
  if (!init.allowPrivateNetwork) {
    options.lookup = createPublicLookup(init.lookup);
  } else if (init.lookup) {
    options.lookup = init.lookup;
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let responseBytes = 0;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const finish = <T>(fn: (value: T) => void, value: T) => {
      if (settled) return;
      settled = true;
      if (deadline) clearTimeout(deadline);
      fn(value);
    };
    const fail = (error: Error) => {
      finish(reject, error);
      request.destroy(error);
    };
    const request = transport.request(options, (response) => {
      response.on("data", (chunk: Buffer | string) => {
        responseBytes +=
          typeof chunk === "string" ? new TextEncoder().encode(chunk).length : chunk.length;
        if (responseBytes > MAX_RESPONSE_BYTES) {
          fail(new Error("Webhook response exceeded maximum size"));
        }
      });
      response.on("end", () => {
        const status = response.statusCode ?? 0;
        finish(resolve, { status, ok: status >= 200 && status < 300 });
      });
      response.on("error", (error) => finish(reject, error));
      response.on("aborted", () => finish(reject, new Error("Webhook response aborted")));
    });

    request.setTimeout(init.timeoutMs, () => {
      fail(new Error("Webhook delivery timed out"));
    });
    request.on("error", (error) => finish(reject, error));
    deadline = setTimeout(() => {
      fail(new Error("Webhook delivery timed out"));
    }, init.timeoutMs);
    request.write(init.body);
    request.end();
  });
}

function normalizeWebhook(webhook: WebhookConfig | string): WebhookConfig {
  if (typeof webhook !== "string") {
    return webhook;
  }

  const secret = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env?.STEWARD_WEBHOOK_SECRET;
  if (!secret) {
    throw new Error(
      "Webhook secret is required. Pass a WebhookConfig or set STEWARD_WEBHOOK_SECRET.",
    );
  }

  return { url: webhook, secret };
}

export class WebhookDispatcher {
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;
  private readonly timeoutMs: number;
  private readonly allowPrivateNetwork: boolean;
  private readonly allowInsecureHttp: boolean;
  private readonly lookup?: LookupFunction;

  constructor(options: WebhookDispatcherOptions = {}) {
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.allowPrivateNetwork = options.allowPrivateNetwork ?? ALLOW_PRIVATE_WEBHOOK_NETWORKS;
    this.allowInsecureHttp = options.allowInsecureHttp ?? false;
    this.lookup = options.lookup;
  }

  async dispatch(
    event: WebhookEvent,
    webhook: WebhookConfig | string,
  ): Promise<WebhookDeliveryResult> {
    const config = normalizeWebhook(webhook);

    if (config.events && !config.events.includes(event.type)) {
      return {
        success: true,
        attempts: 0,
      };
    }

    // Stable delivery id is fixed here and reused across retries so a receiver
    // can dedup a retry vs. a fresh event.
    const eventWithMeta = event as WebhookEvent & { deliveryId?: unknown; signedAt?: unknown };
    const deliveryId =
      typeof eventWithMeta.deliveryId === "string" && eventWithMeta.deliveryId.trim()
        ? eventWithMeta.deliveryId
        : randomUUID();
    const timestamp = (
      typeof eventWithMeta.signedAt === "number" && Number.isFinite(eventWithMeta.signedAt)
        ? Math.floor(eventWithMeta.signedAt)
        : Math.floor(Date.now() / 1000)
    ).toString();
    // Mutate the event so persistent-queue re-dispatch reuses the same id + timestamp.
    eventWithMeta.deliveryId = deliveryId;
    eventWithMeta.signedAt = Number(timestamp);

    const body = JSON.stringify(event);
    let attempts = 0;
    let lastStatusCode: number | undefined;
    let lastError: string | undefined;

    while (attempts <= this.maxRetries) {
      attempts += 1;

      // Sign the per-attempt freshness timestamp while keeping the delivery id
      // stable for idempotent receivers.
      const sentAt = Math.floor(Date.now() / 1000).toString();
      const signature = `${SIGNATURE_SCHEME}=${await signPayload(
        canonicalSignedPayload(sentAt, deliveryId, event.type, body),
        config.secret,
      )}`;

      try {
        const response = await postWebhook(config.url, {
          headers: {
            "Content-Type": "application/json",
            "X-Steward-Event": event.type,
            "X-Steward-Timestamp": sentAt,
            "X-Steward-Sent-At": sentAt,
            "X-Steward-Signature": signature,
            "X-Steward-Delivery-Id": deliveryId,
          },
          body,
          timeoutMs: this.timeoutMs,
          allowPrivateNetwork: this.allowPrivateNetwork,
          allowInsecureHttp: this.allowInsecureHttp,
          lookup: this.lookup,
        });

        lastStatusCode = response.status;

        if (response.ok) {
          return {
            success: true,
            statusCode: response.status,
            attempts,
            deliveredAt: new Date(),
            deliveryId,
          };
        }

        lastError = `Webhook responded with status ${response.status}`;
        if (!shouldRetry(response.status) || attempts > this.maxRetries) {
          break;
        }
      } catch (error) {
        lastError = error instanceof Error ? error.message : "Unknown webhook delivery error";
        if (attempts > this.maxRetries) {
          break;
        }
      }

      await sleep(this.retryDelayMs * 2 ** (attempts - 1));
    }

    return {
      success: false,
      statusCode: lastStatusCode,
      attempts,
      error: lastError,
      deliveryId,
    };
  }
}
