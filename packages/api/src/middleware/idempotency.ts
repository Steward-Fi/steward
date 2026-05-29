import { createMiddleware } from "hono/factory";
import type { ApiResponse, AppVariables } from "../services/context";
import { getRedisClient } from "./redis";

type IdempotencyStatus = "processing" | "completed";

type IdempotencyEntry = {
  fingerprint: string;
  status: IdempotencyStatus;
  createdAt: number;
  expiresAt: number;
  response?: {
    status: number;
    headers: [string, string][];
    body: ArrayBuffer;
  };
};

export type IdempotencyStore = {
  get(key: string): Promise<IdempotencyEntry | undefined>;
  reserve?(
    key: string,
    entry: Omit<IdempotencyEntry, "status" | "response">,
  ): Promise<IdempotencyEntry | undefined>;
  setProcessing(key: string, entry: Omit<IdempotencyEntry, "status" | "response">): Promise<void>;
  setCompleted(key: string, response?: NonNullable<IdempotencyEntry["response"]>): Promise<void>;
  delete(key: string): Promise<void>;
};

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 10_000;
const IDEMPOTENCY_KEY_RE = /^[\x21-\x7e]{8,255}$/;

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sha256Hex(input: string | ArrayBuffer): Promise<string> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function responseHeadersForReplay(headers: Headers): [string, string][] {
  const pairs: [string, string][] = [];
  headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (lower === "set-cookie" || lower === "content-encoding" || lower === "content-length") {
      return;
    }
    pairs.push([key, value]);
  });
  return pairs;
}

function bytesToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): ArrayBuffer {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

type SerializedIdempotencyEntry = Omit<IdempotencyEntry, "response"> & {
  response?: Omit<NonNullable<IdempotencyEntry["response"]>, "body"> & { bodyBase64: string };
};

function serializeEntry(entry: IdempotencyEntry): string {
  const serialized: SerializedIdempotencyEntry = {
    fingerprint: entry.fingerprint,
    status: entry.status,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    response: entry.response
      ? {
          status: entry.response.status,
          headers: entry.response.headers,
          bodyBase64: bytesToBase64(entry.response.body),
        }
      : undefined,
  };
  return JSON.stringify(serialized);
}

function parseEntry(value: string | null): IdempotencyEntry | undefined {
  if (!value) return undefined;
  const parsed = JSON.parse(value) as SerializedIdempotencyEntry;
  if (
    typeof parsed.fingerprint !== "string" ||
    (parsed.status !== "processing" && parsed.status !== "completed") ||
    typeof parsed.createdAt !== "number" ||
    typeof parsed.expiresAt !== "number"
  ) {
    return undefined;
  }
  return {
    fingerprint: parsed.fingerprint,
    status: parsed.status,
    createdAt: parsed.createdAt,
    expiresAt: parsed.expiresAt,
    response: parsed.response
      ? {
          status: parsed.response.status,
          headers: parsed.response.headers,
          body: base64ToBytes(parsed.response.bodyBase64),
        }
      : undefined,
  };
}

export class MemoryIdempotencyStore implements IdempotencyStore {
  private entries = new Map<string, IdempotencyEntry>();

  constructor(private readonly maxEntries = DEFAULT_MAX_ENTRIES) {}

  async get(key: string): Promise<IdempotencyEntry | undefined> {
    const now = Date.now();
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= now) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }

  async setProcessing(
    key: string,
    entry: Omit<IdempotencyEntry, "status" | "response">,
  ): Promise<void> {
    await this.reserve(key, entry);
  }

  async reserve(
    key: string,
    entry: Omit<IdempotencyEntry, "status" | "response">,
  ): Promise<IdempotencyEntry | undefined> {
    this.collectExpired();
    const existing = this.entries.get(key);
    if (existing) return existing;
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (!oldest) break;
      this.entries.delete(oldest);
    }
    this.entries.set(key, { ...entry, status: "processing" });
    return undefined;
  }

  async setCompleted(
    key: string,
    response?: NonNullable<IdempotencyEntry["response"]>,
  ): Promise<void> {
    const entry = await this.get(key);
    if (!entry) return;
    this.entries.set(key, { ...entry, status: "completed", response });
  }

  async delete(key: string): Promise<void> {
    this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }

  private collectExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries.entries()) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }
}

export class RedisIdempotencyStore implements IdempotencyStore {
  private readonly fallback = new MemoryIdempotencyStore(
    parsePositiveInt(process.env.STEWARD_IDEMPOTENCY_MAX_ENTRIES, DEFAULT_MAX_ENTRIES),
  );

  private client() {
    const redis = getRedisClient();
    if (redis) return redis;
    if (process.env.NODE_ENV !== "production") return null;
    throw new Error("Durable idempotency store unavailable");
  }

  async get(key: string): Promise<IdempotencyEntry | undefined> {
    const redis = this.client();
    if (!redis) return this.fallback.get(key);
    return parseEntry(await redis.get(`idempotency:${key}`));
  }

  async setProcessing(
    key: string,
    entry: Omit<IdempotencyEntry, "status" | "response">,
  ): Promise<void> {
    await this.reserve(key, entry);
  }

  async reserve(
    key: string,
    entry: Omit<IdempotencyEntry, "status" | "response">,
  ): Promise<IdempotencyEntry | undefined> {
    const redis = this.client();
    if (!redis) return this.fallback.reserve(key, entry);
    const redisKey = `idempotency:${key}`;
    const value = serializeEntry({ ...entry, status: "processing" });
    const ttlMs = Math.max(1, entry.expiresAt - Date.now());
    const reserved = await redis.set(redisKey, value, "PX", ttlMs, "NX");
    if (reserved) return undefined;
    return this.get(key);
  }

  async setCompleted(
    key: string,
    response?: NonNullable<IdempotencyEntry["response"]>,
  ): Promise<void> {
    const redis = this.client();
    if (!redis) return this.fallback.setCompleted(key, response);
    const existing = await this.get(key);
    if (!existing) return;
    const ttlMs = Math.max(1, existing.expiresAt - Date.now());
    await redis.set(
      `idempotency:${key}`,
      serializeEntry({ ...existing, status: "completed", response }),
      "PX",
      ttlMs,
    );
  }

  async delete(key: string): Promise<void> {
    const redis = this.client();
    if (!redis) return this.fallback.delete(key);
    await redis.del(`idempotency:${key}`);
  }
}

export const defaultIdempotencyStore = new RedisIdempotencyStore();

async function buildFingerprint(request: Request): Promise<string> {
  const url = new URL(request.url);
  const body = await request.clone().arrayBuffer();
  const bodyHash = await sha256Hex(body);
  const authHash = await sha256Hex(request.headers.get("authorization") ?? "");
  const apiKeyHash = await sha256Hex(request.headers.get("x-steward-key") ?? "");
  const signerIdHash = await sha256Hex(request.headers.get("x-steward-signer-id") ?? "");
  const signerSecretHash = await sha256Hex(request.headers.get("x-steward-signer-secret") ?? "");
  const quorumIdHash = await sha256Hex(request.headers.get("x-steward-key-quorum-id") ?? "");
  const quorumCredentialsHash = await sha256Hex(
    request.headers.get("x-steward-key-quorum-credentials") ?? "",
  );
  const tenant = request.headers.get("x-steward-tenant") ?? "";
  return [
    request.method.toUpperCase(),
    url.pathname,
    url.search,
    tenant,
    authHash,
    apiKeyHash,
    signerIdHash,
    signerSecretHash,
    quorumIdHash,
    quorumCredentialsHash,
    bodyHash,
  ].join("\n");
}

async function buildStorageKey(request: Request, key: string): Promise<string> {
  const tenant = request.headers.get("x-steward-tenant") ?? "";
  const authHash = await sha256Hex(request.headers.get("authorization") ?? "");
  const apiKeyHash = await sha256Hex(request.headers.get("x-steward-key") ?? "");
  const platformKeyHash = await sha256Hex(request.headers.get("x-steward-platform-key") ?? "");
  const signerIdHash = await sha256Hex(request.headers.get("x-steward-signer-id") ?? "");
  const signerSecretHash = await sha256Hex(request.headers.get("x-steward-signer-secret") ?? "");
  const quorumIdHash = await sha256Hex(request.headers.get("x-steward-key-quorum-id") ?? "");
  const quorumCredentialsHash = await sha256Hex(
    request.headers.get("x-steward-key-quorum-credentials") ?? "",
  );
  return sha256Hex(
    [
      tenant,
      authHash,
      apiKeyHash,
      platformKeyHash,
      signerIdHash,
      signerSecretHash,
      quorumIdHash,
      quorumCredentialsHash,
      key,
    ].join("\n"),
  );
}

function replayResponse(entry: IdempotencyEntry): Response {
  if (!entry.response) {
    return Response.json(
      { ok: false, error: "Idempotency key has already been used" },
      {
        status: 409,
        headers: { "Retry-After": "1" },
      },
    );
  }

  const headers = new Headers(entry.response.headers);
  headers.set("Idempotency-Replayed", "true");
  return new Response(entry.response.body.slice(0), {
    status: entry.response.status,
    headers,
  });
}

function hasIdempotencyAuthMaterial(request: Request, signatureVerified: boolean): boolean {
  return Boolean(
    request.headers.get("authorization") ||
      request.headers.get("x-steward-key") ||
      request.headers.get("x-steward-platform-key") ||
      (signatureVerified && request.headers.get("x-steward-signature")),
  );
}

function isAuthTokenResponseReplaySuppressedPath(pathname: string): boolean {
  return pathname === "/auth" || pathname.startsWith("/auth/");
}

function hasReplaySafeAuthenticatedContext(c: { get: (key: keyof AppVariables) => unknown }) {
  if (c.get("requestSignatureVerified")) return true;
  const authType = c.get("authType");
  if (authType === "api-key" || authType === "agent-token" || c.get("platformKeyHash")) {
    return true;
  }
  if (authType !== "session-jwt") return false;
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= 5 * 60_000
  );
}

export function idempotencyMiddleware(options?: { store?: IdempotencyStore; ttlMs?: number }) {
  const store = options?.store ?? defaultIdempotencyStore;
  const ttlMs =
    options?.ttlMs ?? parsePositiveInt(process.env.STEWARD_IDEMPOTENCY_TTL_MS, DEFAULT_TTL_MS);

  return createMiddleware<{ Variables: AppVariables }>(async (c, next) => {
    if (!MUTATING_METHODS.has(c.req.method.toUpperCase())) return next();

    const key = c.req.header("Idempotency-Key");
    if (!key) return next();
    if (!hasIdempotencyAuthMaterial(c.req.raw, Boolean(c.get("requestSignatureVerified")))) {
      return next();
    }
    if (!hasReplaySafeAuthenticatedContext(c)) return next();
    if (!IDEMPOTENCY_KEY_RE.test(key)) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid Idempotency-Key header" }, 400);
    }

    const [fingerprint, storageKey] = await Promise.all([
      buildFingerprint(c.req.raw),
      buildStorageKey(c.req.raw, key),
    ]);
    const reservation = {
      fingerprint,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttlMs,
    };
    let existing: IdempotencyEntry | undefined;
    try {
      existing = store.reserve
        ? await store.reserve(storageKey, reservation)
        : await (async () => {
            const current = await store.get(storageKey);
            if (!current) await store.setProcessing(storageKey, reservation);
            return current;
          })();
    } catch {
      return c.json<ApiResponse>(
        { ok: false, error: "Durable idempotency store unavailable" },
        503,
      );
    }
    if (existing) {
      if (!timingSafeEqualString(existing.fingerprint, fingerprint)) {
        return c.json<ApiResponse>(
          { ok: false, error: "Idempotency-Key was already used for a different request" },
          409,
        );
      }
      if (existing.status === "completed") return replayResponse(existing);
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency key is already processing" },
        409,
        { "Retry-After": "1" },
      );
    }

    try {
      await next();
      try {
        if (isAuthTokenResponseReplaySuppressedPath(c.req.path)) {
          await store.setCompleted(storageKey);
        } else {
          const response = c.res.clone();
          await store.setCompleted(storageKey, {
            status: response.status,
            headers: responseHeadersForReplay(response.headers),
            body: await response.arrayBuffer(),
          });
        }
      } catch {
        console.error("[steward:idempotency] Failed to persist completed response");
      }
      c.header("Idempotency-Replayed", "false");
    } catch (error) {
      try {
        await store.delete(storageKey);
      } catch {
        console.error("[steward:idempotency] Failed to release idempotency reservation");
      }
      throw error;
    }
  });
}
