export type ApiClientOptions = {
  baseUrl?: string;
  tenantId?: string;
  token?: string;
  platformKey?: string;
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

function normalizeBaseUrl(value: string | undefined): string {
  return (value || process.env.STEWARD_API_URL || "http://127.0.0.1:3200").replace(/\/+$/, "");
}

export class StewardApiClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly tenantId?: string;
  private readonly token?: string;
  private readonly platformKey?: string;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.tenantId = options.tenantId ?? process.env.STEWARD_TENANT_ID;
    this.token = options.token ?? process.env.STEWARD_TOKEN ?? process.env.STEWARD_API_TOKEN;
    this.platformKey = options.platformKey ?? process.env.STEWARD_PLATFORM_KEY;
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
    }
    if (options.tenant !== false && this.tenantId) headers["X-Steward-Tenant"] = this.tenantId;

    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
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
