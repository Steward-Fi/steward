/**
 * PushAdapter — outbound mobile notification seam.
 *
 * The mock records deliveries in memory and never calls APNs/FCM/Expo. Real
 * providers can be registered through AdapterRegistry under the "push" category.
 */

import { Buffer } from "node:buffer";
import { createSign } from "node:crypto";
import { AdapterValidationError, type BaseAdapter } from "../types.js";
import { assertId } from "../validation.js";

export type PushProvider = "expo" | "apns" | "fcm";
export type PushPlatform = "ios" | "android";

export interface PushSubscriptionTarget {
  readonly id: string;
  readonly userId: string;
  readonly provider: PushProvider;
  readonly token: string;
  readonly platform?: PushPlatform | null;
}

export interface PushMessage {
  readonly title: string;
  readonly body: string;
  readonly data?: Record<string, string>;
  readonly sound?: "default" | "none";
  readonly badge?: number;
  readonly collapseId?: string;
}

export interface PushSendRequest {
  readonly target: PushSubscriptionTarget;
  readonly message: PushMessage;
  readonly tenantId?: string | null;
  readonly event?: string;
  readonly idempotencyKey?: string;
}

export interface PushDeliveryResult {
  readonly ok: boolean;
  readonly provider: string;
  readonly subscriptionId: string;
  readonly providerMessageId?: string;
  readonly error?: string;
  readonly retryable?: boolean;
  readonly deliveredAt: number;
}

export interface PushAdapter extends BaseAdapter {
  readonly category: "push";
  send(request: PushSendRequest): Promise<PushDeliveryResult>;
}

export type PushFetch = (
  input: string,
  init: {
    method: "POST";
    headers: Record<string, string>;
    body: string;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

function assertPushProvider(value: unknown): PushProvider {
  if (value === "expo" || value === "apns" || value === "fcm") return value;
  throw new AdapterValidationError("push provider must be expo, apns, or fcm");
}

function assertPushToken(value: unknown, provider: PushProvider): string {
  const token = assertId(value, "token", 4096);
  if (/\s/.test(token)) throw new AdapterValidationError("push token must not contain whitespace");
  if (provider === "apns" && !/^[0-9a-f]{64}$/i.test(token)) {
    throw new AdapterValidationError("APNs push tokens must be 64 hex characters");
  }
  if (provider === "expo" && !/^(ExponentPushToken|ExpoPushToken)\[[^\]]+\]$/.test(token)) {
    throw new AdapterValidationError("Expo push token is invalid");
  }
  return token;
}

function assertPushMessage(message: PushMessage): PushMessage {
  const title = assertId(message.title, "title", 120);
  const body = assertId(message.body, "body", 2048);
  if (message.badge !== undefined && (!Number.isInteger(message.badge) || message.badge < 0)) {
    throw new AdapterValidationError("badge must be a non-negative integer");
  }
  if (message.data !== undefined) {
    for (const [key, value] of Object.entries(message.data)) {
      assertId(key, "data key", 128);
      assertId(value, `data.${key}`, 2048);
    }
  }
  return {
    title,
    body,
    ...(message.data ? { data: message.data } : {}),
    ...(message.sound ? { sound: message.sound } : {}),
    ...(message.badge !== undefined ? { badge: message.badge } : {}),
    ...(message.collapseId ? { collapseId: assertId(message.collapseId, "collapseId", 128) } : {}),
  };
}

export class MockPushAdapter implements PushAdapter {
  readonly category = "push" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private readonly deliveries: PushDeliveryResult[] = [];
  private now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async send(request: PushSendRequest): Promise<PushDeliveryResult> {
    const provider = assertPushProvider(request.target.provider);
    const subscriptionId = assertId(request.target.id, "subscriptionId", 128);
    assertId(request.target.userId, "userId", 128);
    assertPushToken(request.target.token, provider);
    assertPushMessage(request.message);
    if (request.tenantId !== undefined && request.tenantId !== null) {
      assertId(request.tenantId, "tenantId", 128);
    }
    if (request.event !== undefined) assertId(request.event, "event", 128);
    if (request.idempotencyKey !== undefined) {
      assertId(request.idempotencyKey, "idempotencyKey", 256);
    }

    const result: PushDeliveryResult = {
      ok: true,
      provider: this.provider,
      subscriptionId,
      providerMessageId: `mock-push-${this.deliveries.length + 1}`,
      deliveredAt: this.now(),
    };
    this.deliveries.push(result);
    return result;
  }

  listDeliveries(): PushDeliveryResult[] {
    return [...this.deliveries];
  }
}

export interface ExpoPushAdapterOptions {
  readonly accessToken?: string;
  readonly endpoint?: string;
  readonly fetch?: PushFetch;
  readonly now?: () => number;
}

interface ExpoPushTicket {
  readonly status?: unknown;
  readonly id?: unknown;
  readonly message?: unknown;
  readonly details?: { readonly error?: unknown } | null;
}

export class ExpoPushAdapter implements PushAdapter {
  readonly category = "push" as const;
  readonly provider = "expo";
  readonly enabled = true;

  private readonly accessToken?: string;
  private readonly endpoint: string;
  private readonly fetch: PushFetch;
  private readonly now: () => number;

  constructor(options?: ExpoPushAdapterOptions) {
    this.accessToken = options?.accessToken;
    this.endpoint = options?.endpoint ?? "https://exp.host/--/api/v2/push/send";
    this.fetch = options?.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = options?.now ?? (() => Date.now());
  }

  async send(request: PushSendRequest): Promise<PushDeliveryResult> {
    const provider = assertPushProvider(request.target.provider);
    if (provider !== "expo") {
      throw new AdapterValidationError("ExpoPushAdapter only supports Expo push tokens");
    }
    const subscriptionId = assertId(request.target.id, "subscriptionId", 128);
    assertId(request.target.userId, "userId", 128);
    const token = assertPushToken(request.target.token, provider);
    const message = assertPushMessage(request.message);
    if (request.tenantId !== undefined && request.tenantId !== null) {
      assertId(request.tenantId, "tenantId", 128);
    }
    if (request.event !== undefined) assertId(request.event, "event", 128);
    if (request.idempotencyKey !== undefined) {
      assertId(request.idempotencyKey, "idempotencyKey", 256);
    }

    const headers: Record<string, string> = {
      Accept: "application/json",
      "Accept-Encoding": "gzip, deflate",
      "Content-Type": "application/json",
    };
    if (this.accessToken) headers.Authorization = `Bearer ${this.accessToken}`;

    const response = await this.fetch(this.endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        to: token,
        title: message.title,
        body: message.body,
        ...(message.data ? { data: message.data } : {}),
        ...(message.sound === "none"
          ? { sound: null }
          : message.sound
            ? { sound: message.sound }
            : {}),
        ...(message.badge !== undefined ? { badge: message.badge } : {}),
        ...(message.collapseId ? { channelId: message.collapseId } : {}),
      }),
    });

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      payload = await response.text();
    }

    if (!response.ok) {
      return {
        ok: false,
        provider: this.provider,
        subscriptionId,
        error:
          stringifyExpoError(payload) || `Expo push request failed with status ${response.status}`,
        retryable: response.status >= 500 || response.status === 429,
        deliveredAt: this.now(),
      };
    }

    const ticket = extractExpoTicket(payload);
    if (ticket?.status === "ok" && typeof ticket.id === "string") {
      return {
        ok: true,
        provider: this.provider,
        subscriptionId,
        providerMessageId: ticket.id,
        deliveredAt: this.now(),
      };
    }

    const errorCode = typeof ticket?.details?.error === "string" ? ticket.details.error : undefined;
    return {
      ok: false,
      provider: this.provider,
      subscriptionId,
      error:
        (typeof ticket?.message === "string" ? ticket.message : undefined) ??
        errorCode ??
        stringifyExpoError(payload) ??
        "Expo push request did not return a ticket",
      retryable: isRetryableExpoError(errorCode),
      deliveredAt: this.now(),
    };
  }
}

export interface ApnsPushAdapterOptions {
  readonly teamId: string;
  readonly keyId: string;
  readonly bundleId: string;
  readonly privateKey?: string;
  readonly jwtProvider?: () => string | Promise<string>;
  readonly endpoint?: string;
  readonly fetch?: PushFetch;
  readonly now?: () => number;
}

export class ApnsPushAdapter implements PushAdapter {
  readonly category = "push" as const;
  readonly provider = "apns";
  readonly enabled = true;

  private readonly options: ApnsPushAdapterOptions;
  private readonly endpoint: string;
  private readonly fetch: PushFetch;
  private readonly now: () => number;

  constructor(options: ApnsPushAdapterOptions) {
    this.options = options;
    this.endpoint = options.endpoint ?? "https://api.push.apple.com";
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? (() => Date.now());
    assertId(options.teamId, "teamId", 32);
    assertId(options.keyId, "keyId", 32);
    assertId(options.bundleId, "bundleId", 128);
    if (!options.privateKey && !options.jwtProvider) {
      throw new AdapterValidationError("APNs requires privateKey or jwtProvider");
    }
  }

  async send(request: PushSendRequest): Promise<PushDeliveryResult> {
    const provider = assertPushProvider(request.target.provider);
    if (provider !== "apns")
      throw new AdapterValidationError("ApnsPushAdapter only supports APNs push tokens");
    const subscriptionId = assertId(request.target.id, "subscriptionId", 128);
    assertId(request.target.userId, "userId", 128);
    const token = assertPushToken(request.target.token, provider);
    const message = assertPushMessage(request.message);
    const jwt = await this.jwt();
    const response = await this.fetch(`${this.endpoint}/3/device/${token}`, {
      method: "POST",
      headers: {
        Authorization: `bearer ${jwt}`,
        "Content-Type": "application/json",
        "apns-topic": this.options.bundleId,
        "apns-push-type": "alert",
        "apns-priority": "10",
        ...(message.collapseId ? { "apns-collapse-id": message.collapseId } : {}),
      },
      body: JSON.stringify({
        aps: {
          alert: { title: message.title, body: message.body },
          ...(message.sound === "default" ? { sound: "default" } : {}),
          ...(message.badge !== undefined ? { badge: message.badge } : {}),
        },
        ...(message.data ? { data: message.data } : {}),
      }),
    });
    const payload = await parseProviderPayload(response);
    if (response.ok) {
      return {
        ok: true,
        provider: this.provider,
        subscriptionId,
        providerMessageId: responseHeader(payload.headers, "apns-id"),
        deliveredAt: this.now(),
      };
    }
    const reason = apnsReason(payload.body);
    return {
      ok: false,
      provider: this.provider,
      subscriptionId,
      error: reason ?? `APNs request failed with status ${response.status}`,
      retryable: response.status === 429 || response.status >= 500,
      deliveredAt: this.now(),
    };
  }

  private async jwt(): Promise<string> {
    if (this.options.jwtProvider) return this.options.jwtProvider();
    const header = base64Url(JSON.stringify({ alg: "ES256", kid: this.options.keyId }));
    const payload = base64Url(
      JSON.stringify({ iss: this.options.teamId, iat: Math.floor(this.now() / 1000) }),
    );
    const signingInput = `${header}.${payload}`;
    const signer = createSign("SHA256");
    signer.update(signingInput);
    signer.end();
    const signature = signer.sign({ key: this.options.privateKey!, dsaEncoding: "ieee-p1363" });
    return `${signingInput}.${base64Url(signature)}`;
  }
}

export interface FcmPushAdapterOptions {
  readonly projectId: string;
  readonly accessToken?: string;
  readonly accessTokenProvider?: () => string | Promise<string>;
  readonly endpoint?: string;
  readonly fetch?: PushFetch;
  readonly now?: () => number;
}

export class FcmPushAdapter implements PushAdapter {
  readonly category = "push" as const;
  readonly provider = "fcm";
  readonly enabled = true;

  private readonly options: FcmPushAdapterOptions;
  private readonly fetch: PushFetch;
  private readonly now: () => number;

  constructor(options: FcmPushAdapterOptions) {
    this.options = options;
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? (() => Date.now());
    assertId(options.projectId, "projectId", 128);
    if (!options.accessToken && !options.accessTokenProvider) {
      throw new AdapterValidationError("FCM requires accessToken or accessTokenProvider");
    }
  }

  async send(request: PushSendRequest): Promise<PushDeliveryResult> {
    const provider = assertPushProvider(request.target.provider);
    if (provider !== "fcm")
      throw new AdapterValidationError("FcmPushAdapter only supports FCM push tokens");
    const subscriptionId = assertId(request.target.id, "subscriptionId", 128);
    assertId(request.target.userId, "userId", 128);
    const token = assertPushToken(request.target.token, provider);
    const message = assertPushMessage(request.message);
    const accessToken = await this.accessToken();
    const response = await this.fetch(
      this.options.endpoint ??
        `https://fcm.googleapis.com/v1/projects/${this.options.projectId}/messages:send`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: {
            token,
            notification: { title: message.title, body: message.body },
            ...(message.data ? { data: message.data } : {}),
            ...(message.collapseId ? { android: { collapse_key: message.collapseId } } : {}),
            ...(message.badge !== undefined
              ? { apns: { payload: { aps: { badge: message.badge } } } }
              : {}),
          },
        }),
      },
    );
    const payload = await parseProviderPayload(response);
    if (response.ok) {
      return {
        ok: true,
        provider: this.provider,
        subscriptionId,
        providerMessageId: fcmMessageName(payload.body),
        deliveredAt: this.now(),
      };
    }
    const code = fcmErrorCode(payload.body);
    return {
      ok: false,
      provider: this.provider,
      subscriptionId,
      error: fcmErrorMessage(payload.body) ?? `FCM request failed with status ${response.status}`,
      retryable:
        response.status === 429 ||
        response.status >= 500 ||
        code === "UNAVAILABLE" ||
        code === "RESOURCE_EXHAUSTED",
      deliveredAt: this.now(),
    };
  }

  private async accessToken(): Promise<string> {
    if (this.options.accessTokenProvider) return this.options.accessTokenProvider();
    return this.options.accessToken!;
  }
}

function extractExpoTicket(payload: unknown): ExpoPushTicket | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const data = (payload as { data?: unknown }).data;
  if (Array.isArray(data)) return data[0] as ExpoPushTicket | undefined;
  if (data && typeof data === "object") return data as ExpoPushTicket;
  return undefined;
}

function stringifyExpoError(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object")
    return typeof payload === "string" ? payload : undefined;
  const maybeErrors = (payload as { errors?: unknown }).errors;
  if (Array.isArray(maybeErrors) && maybeErrors.length > 0) {
    const first = maybeErrors[0] as { message?: unknown; code?: unknown };
    if (typeof first.message === "string") return first.message;
    if (typeof first.code === "string") return first.code;
  }
  const maybeMessage =
    (payload as { message?: unknown; error?: unknown }).message ??
    (payload as { error?: unknown }).error;
  return typeof maybeMessage === "string" ? maybeMessage : undefined;
}

function isRetryableExpoError(errorCode: string | undefined): boolean {
  return (
    errorCode === "MessageRateExceeded" ||
    errorCode === "MessageTooBig" ||
    errorCode === "ProviderUnavailable" ||
    errorCode === "ExpoError"
  );
}

async function parseProviderPayload(
  response: Awaited<ReturnType<PushFetch>>,
): Promise<{ headers: HeadersLike; body: unknown }> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = await response.text();
  }
  return { headers: response as HeadersLike, body };
}

interface HeadersLike {
  readonly headers?: { get(name: string): string | null | undefined } | Record<string, string>;
}

function responseHeader(source: HeadersLike, name: string): string | undefined {
  const headers = source.headers;
  if (!headers) return undefined;
  if ("get" in headers && typeof headers.get === "function") return headers.get(name) ?? undefined;
  const record = headers as Record<string, string>;
  return record[name] ?? record[name.toLowerCase()];
}

function apnsReason(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object")
    return typeof payload === "string" ? payload : undefined;
  const reason = (payload as { reason?: unknown }).reason;
  return typeof reason === "string" ? reason : undefined;
}

function fcmMessageName(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const name = (payload as { name?: unknown }).name;
  return typeof name === "string" ? name : undefined;
}

function fcmErrorMessage(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object")
    return typeof payload === "string" ? payload : undefined;
  const error = (payload as { error?: { message?: unknown } }).error;
  return typeof error?.message === "string" ? error.message : undefined;
}

function fcmErrorCode(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const error = (payload as { error?: { status?: unknown } }).error;
  return typeof error?.status === "string" ? error.status : undefined;
}

function base64Url(value: string | Buffer): string {
  const buffer = typeof value === "string" ? Buffer.from(value) : value;
  return (buffer as unknown as { toString(encoding: string): string })
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
