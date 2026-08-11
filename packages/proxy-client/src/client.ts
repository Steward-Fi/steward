/**
 * StewardProxyClient — agent-side HTTP client for the Steward proxy.
 *
 * The proxy sits between an agent and external APIs. Agents never hold the
 * upstream API keys: they send requests here with a Bearer JWT (api:proxy
 * scope) and, when request signing is enabled, an HMAC proof-of-possession
 * signature. The proxy matches a credential route, decrypts the secret, injects
 * it as the configured header, forwards upstream, and scrubs the credential
 * from the response.
 *
 * This client is a thin, generic `fetch` wrapper. It:
 *   - attaches `Authorization: Bearer <token>`
 *   - when a `signingSecret` is configured, computes the HMAC
 *     `X-Steward-Signature` + `X-Steward-Request-Timestamp` headers per the
 *     proxy's canonical form (see ./signature.ts)
 *   - auto-generates an `Idempotency-Key` (crypto.randomUUID) for mutating
 *     methods (POST/PUT/PATCH/DELETE) when the caller did not supply one
 *
 * It is intentionally NOT vendor-specific: there is no openaiChat() helper.
 * Callers build the path (e.g. "/openai/v1/chat/completions") and body.
 */

import { signProxyRequest } from "./signature";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SIGNATURE_MAX_AGE_MS = 5 * 60_000;

export interface StewardProxyClientOptions {
  /** Base URL of the proxy, e.g. https://proxy.example.com */
  proxyUrl: string;
  /** api:proxy-scoped agent JWT. */
  token: string;
  /**
   * HMAC secret for request signing. Required when the proxy runs with request
   * signing enabled (production). One of the values configured in
   * STEWARD_PROXY_REQUEST_SIGNING_SECRET(S).
   */
  signingSecret?: string;
  /**
   * tenantId + agentId are bound into the signature canonical form and MUST
   * match the JWT claims the proxy derives. Required when signingSecret is set.
   */
  tenantId?: string;
  agentId?: string;
  /**
   * When true (default in production-like usage), reject non-https proxyUrl.
   * Defaults to true when NODE_ENV === "production", false otherwise so local
   * http proxies work in dev/test.
   */
  requireHttps?: boolean;
  /** Injectable fetch for testing. Defaults to global fetch. */
  fetch?: typeof fetch;
}

export interface ProxyHealth {
  ok: boolean;
  service?: string;
  version?: string;
  aliases?: string[];
  [key: string]: unknown;
}

function normalizeBaseUrl(proxyUrl: string): string {
  return proxyUrl.endsWith("/") ? proxyUrl.slice(0, -1) : proxyUrl;
}

function joinPath(base: string, path: string): string {
  return path.startsWith("/") ? `${base}${path}` : `${base}/${path}`;
}

async function bodyToSignable(
  body: BodyInit | null | undefined,
): Promise<string | ArrayBuffer | Uint8Array> {
  if (body === null || body === undefined) return "";
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return body;
  // Blobs / URLSearchParams / FormData etc. would need buffering that changes
  // the outbound representation, so require a pre-serialized body for signed
  // requests. Callers should JSON.stringify before calling.
  throw new Error(
    "Signed proxy requests require a string, Uint8Array, or ArrayBuffer body. Serialize before calling.",
  );
}

export class StewardProxyClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly signingSecret?: string;
  private readonly tenantId?: string;
  private readonly agentId?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: StewardProxyClientOptions) {
    if (!options.proxyUrl) throw new Error("proxyUrl is required");
    if (!options.token) throw new Error("token is required");

    const requireHttps = options.requireHttps ?? process.env.NODE_ENV === "production";
    if (requireHttps && !/^https:\/\//i.test(options.proxyUrl)) {
      throw new Error("proxyUrl must be https in production");
    }

    if (options.signingSecret && (!options.tenantId || !options.agentId)) {
      throw new Error("tenantId and agentId are required when signingSecret is set");
    }

    this.baseUrl = normalizeBaseUrl(options.proxyUrl);
    this.token = options.token;
    this.signingSecret = options.signingSecret;
    this.tenantId = options.tenantId;
    this.agentId = options.agentId;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  /**
   * Generic proxied fetch. `path` is the proxy-relative path (alias or /proxy/…),
   * e.g. "/openai/v1/chat/completions". Attaches auth, idempotency, and (when
   * configured) the request signature.
   */
  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);

    headers.set("authorization", `Bearer ${this.token}`);

    // Auto idempotency key for mutating methods, if the caller did not set one.
    if (MUTATING_METHODS.has(method) && !headers.has("idempotency-key")) {
      headers.set("idempotency-key", crypto.randomUUID());
    }

    if (this.signingSecret && this.tenantId && this.agentId) {
      const timestamp = String(Math.floor(Date.now() / 1000));
      headers.set("x-steward-request-timestamp", timestamp);

      const signable = await bodyToSignable(init.body ?? null);
      const signature = await signProxyRequest(
        {
          method,
          url: joinPath(this.baseUrl, path),
          tenantId: this.tenantId,
          agentId: this.agentId,
          timestamp,
          idempotencyKey: headers.get("idempotency-key") ?? undefined,
          body: signable,
        },
        this.signingSecret,
      );
      headers.set("x-steward-signature", signature);
    }

    return this.fetchImpl(joinPath(this.baseUrl, path), { ...init, method, headers });
  }

  /** GET /health — unauthenticated liveness probe. */
  async proxyHealth(): Promise<ProxyHealth> {
    const res = await this.fetchImpl(joinPath(this.baseUrl, "/health"), { method: "GET" });
    return (await res.json()) as ProxyHealth;
  }
}

export { SIGNATURE_MAX_AGE_MS };
