export type ApiClientOptions = {
  baseUrl?: string;
  tenantId?: string;
  token?: string;
  platformKey?: string;
  /**
   * Raw tenant API key. Sent as `X-Steward-Key` alongside `X-Steward-Tenant`,
   * which the API's tenantAuth accepts as an `api-key` machine credential.
   * This is what lets the operator CLI drive agent/secret/policy/approval
   * routes non-interactively (api-key auth bypasses the human session MFA
   * step-up that a browser owner session would require).
   */
  tenantKey?: string;
  fetchImpl?: typeof fetch;
};

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const API_REQUEST_TIMEOUT_MS = 10_000;
const API_RESPONSE_MAX_BYTES = 1024 * 1024;

async function readBoundedResponse(res: Response): Promise<string> {
  const declared = res.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > API_RESPONSE_MAX_BYTES) {
      void res.body?.cancel().catch(() => {});
      throw new Error("Steward API response exceeded the 1 MiB limit");
    }
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > API_RESPONSE_MAX_BYTES) {
        void reader.cancel().catch(() => {});
        throw new Error("Steward API response exceeded the 1 MiB limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function normalizeBaseUrl(value: string | undefined): string {
  const raw = (value || process.env.STEWARD_API_URL || "http://127.0.0.1:3200").replace(/\/+$/, "");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("STEWARD_API_URL must be a valid absolute URL");
  }
  if (url.username || url.password) {
    throw new Error("STEWARD_API_URL must not contain embedded credentials");
  }
  const loopback =
    url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("STEWARD_API_URL must use HTTPS unless it targets loopback");
  }
  return raw;
}

export class StewardApiClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly tenantId?: string;
  private readonly token?: string;
  private readonly platformKey?: string;
  private readonly tenantKey?: string;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.tenantId = options.tenantId ?? process.env.STEWARD_TENANT_ID;
    this.token = options.token ?? process.env.STEWARD_TOKEN ?? process.env.STEWARD_API_TOKEN;
    this.platformKey = options.platformKey ?? process.env.STEWARD_PLATFORM_KEY;
    this.tenantKey = options.tenantKey ?? process.env.STEWARD_TENANT_KEY;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    options: { platform?: boolean; tenant?: boolean } = {},
  ): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (options.platform) {
      if (!this.platformKey) throw new Error("STEWARD_PLATFORM_KEY or --platform-key is required");
      headers["X-Steward-Platform-Key"] = this.platformKey;
    } else if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    } else if (this.tenantKey) {
      // Tenant API key path: X-Steward-Key + X-Steward-Tenant -> api-key auth.
      headers["X-Steward-Key"] = this.tenantKey;
    }
    if (options.tenant !== false && this.tenantId) headers["X-Steward-Tenant"] = this.tenantId;

    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(API_REQUEST_TIMEOUT_MS),
    });
    const text = await readBoundedResponse(res);
    const parsed = text ? safeJson(text) : null;
    if (!res.ok) {
      const message =
        parsed && typeof parsed === "object" && "error" in parsed
          ? String((parsed as { error: unknown }).error)
          : `${method} ${path} failed with HTTP ${res.status}`;
      throw new ApiError(message, res.status, parsed ?? text);
    }
    if (parsed && typeof parsed === "object" && "ok" in parsed && "data" in parsed) {
      return (parsed as { data: T }).data;
    }
    return parsed as T;
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
