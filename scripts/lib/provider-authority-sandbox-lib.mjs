import { createSign } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";

export const REQUIRED_ENV = [
  "GITHUB_APP_ID",
  "GITHUB_APP_INSTALLATION_ID",
  "GITHUB_APP_PRIVATE_KEY",
  "STEWARD_SANDBOX_GITHUB_OWNER",
  "STEWARD_SANDBOX_GITHUB_REPO",
  "STEWARD_SANDBOX_GITHUB_PR_NUMBER",
  "STEWARD_API_URL",
  "STEWARD_TENANT_ID",
  "STEWARD_AGENT_JWT",
  "STEWARD_APPROVER_JWT",
  "STEWARD_SANDBOX_WORKSPACE_ID",
  "STEWARD_SANDBOX_PROVIDER_ACCOUNT_ID",
  "STEWARD_SANDBOX_SECRET_ID",
  "STEWARD_AUDIT_SIGNING_KEY_FINGERPRINT",
  "DATABASE_URL",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_EXECUTION_AUTH_SECRET",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_AUDIT_SIGNING_KEY",
];

export const GITHUB_API_BASE = "https://api.github.com";

const PLACEHOLDER_RE = /(change[-_]?me|placeholder|example|your[-_]|xxx+|todo)/i;
const REQUIRED_BUILD_OUTPUTS = [
  "packages/shared/dist/index.js",
  "packages/redis/dist/index.js",
  "packages/attestation/dist/index.js",
];
const REQUEST_TIMEOUT_MS = 10_000;
const RESPONSE_MAX_BYTES = 1024 * 1024;

export function validateServiceUrl(name, value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid absolute URL`);
  }
  if (url.username || url.password) throw new Error(`${name} must not contain credentials`);
  const loopback =
    url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(`${name} must use HTTPS unless it targets loopback`);
  }
  return url.toString().replace(/\/$/, "");
}

export function validateBuildPrerequisites(root) {
  const missing = REQUIRED_BUILD_OUTPUTS.filter((path) => !existsSync(join(root, path)));
  if (missing.length) {
    throw new Error(
      `workspace build outputs missing (${missing.join(", ")}); run: bunx turbo run build --filter=@stwd/proxy...`,
    );
  }
}

const DISPATCH_ENV_KEYS = new Set([
  "PATH",
  "HOME",
  "TMPDIR",
  "NODE_ENV",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "DATABASE_DRIVER",
  "DATABASE_URL",
  "REDIS_DRIVER",
  "REDIS_URL",
  "REDIS_REQUIRED",
  "KV_REST_API_URL",
  "KV_REST_API_TOKEN",
  "UPSTASH_REDIS_REST_URL",
  "UPSTASH_REDIS_REST_TOKEN",
  "STEWARD_DB_MODE",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_KDF_SALT",
  "STEWARD_KMS_PROVIDER",
  "STEWARD_KMS_KEY_ID",
  "STEWARD_AWS_KMS_KEY_ARN",
  "STEWARD_AWS_REGION",
  "AWS_REGION",
  "STEWARD_PKCS11_MODULE",
  "STEWARD_PKCS11_PIN",
  "STEWARD_PKCS11_KEY_LABEL",
  "STEWARD_EXECUTION_AUTH_SECRET",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_AUDIT_SIGNING_KEY",
  "STEWARD_SECRET_ROUTE_ALLOWED_HOSTS",
  "STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES",
  "STEWARD_PROXY_IDEMPOTENCY_TTL_MS",
  "STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT",
  "STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT",
  "STEWARD_PROXY_MAX_SPEND_BODY_BYTES",
  "STEWARD_PROXY_RESPONSE_BYTES",
  "STEWARD_PROXY_STREAM_DURATION_MS",
  "STEWARD_PROXY_UPSTREAM_TIMEOUT_MS",
  "STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL",
]);

/** Least-privilege child env: notably excludes App keys, provider tokens, and JWTs. */
export function buildDispatchEnvironment(env, pauseAfterUpstream = false) {
  const selected = {};
  for (const key of DISPATCH_ENV_KEYS) {
    if (typeof env[key] === "string") selected[key] = env[key];
  }
  if (pauseAfterUpstream) selected.STEWARD_SANDBOX_AFTER_UPSTREAM_PAUSE_MS = "30000";
  return selected;
}

export function validateEnvironment(env) {
  const missing = [];
  const placeholders = [];
  for (const key of REQUIRED_ENV) {
    const value = env[key];
    if (typeof value !== "string" || value.trim() === "") missing.push(key);
    else if (key.endsWith("PRIVATE_KEY") || key === "STEWARD_AUDIT_SIGNING_KEY") {
      if (!value.includes("PRIVATE KEY")) placeholders.push(`${key} (not a PEM)`);
    } else if (PLACEHOLDER_RE.test(value)) placeholders.push(key);
  }
  if (missing.length || placeholders.length) {
    const parts = [];
    if (missing.length) parts.push(`missing required env: ${missing.join(", ")}`);
    if (placeholders.length) parts.push(`placeholder value(s): ${placeholders.join(", ")}`);
    throw new Error(parts.join("; "));
  }
  const stewardBase = validateServiceUrl("STEWARD_API_URL", env.STEWARD_API_URL);
  const stewardUrl = new URL(stewardBase);
  if (stewardUrl.search || stewardUrl.hash) {
    throw new Error("STEWARD_API_URL must not contain a query or fragment");
  }
  // This acceptance is specifically for github.com. An inherited API override
  // must never redirect an App JWT or installation token to an arbitrary host.
  if (
    env.GITHUB_API_URL &&
    validateServiceUrl("GITHUB_API_URL", env.GITHUB_API_URL) !== GITHUB_API_BASE
  ) {
    throw new Error("GITHUB_API_URL must be https://api.github.com for the Gate D sandbox");
  }
}

const b64url = (value) => Buffer.from(value).toString("base64url");

export function mintGithubAppJwt(appId, privateKey, now = Math.floor(Date.now() / 1000)) {
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({ iat: now - 30, exp: now + 540, iss: appId }));
  const unsigned = `${head}.${body}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  return `${unsigned}.${signer.sign(privateKey).toString("base64url")}`;
}

export async function requestJson(url, options, fetchImpl = fetch) {
  const response = await fetchImpl(url, {
    ...options,
    // Never forward an authorization header across an unexpected redirect.
    redirect: options?.redirect ?? "error",
    signal: options?.signal ?? AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > RESPONSE_MAX_BYTES) {
      void response.body?.cancel().catch(() => {});
      throw new Error("HTTP response exceeded the 1 MiB sandbox limit");
    }
  }
  let text = "";
  if (response.body) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > RESPONSE_MAX_BYTES) {
          void reader.cancel().catch(() => {});
          throw new Error("HTTP response exceeded the 1 MiB sandbox limit");
        }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
    } finally {
      reader.releaseLock();
    }
  }
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { unparseable: true };
    }
  }
  return { response, body };
}

export async function mintInstallationCredential(env, fetchImpl = fetch) {
  const jwt = mintGithubAppJwt(env.GITHUB_APP_ID, env.GITHUB_APP_PRIVATE_KEY);
  const base = validateServiceUrl("GITHUB_API_URL", env.GITHUB_API_URL ?? "https://api.github.com");
  const { response, body } = await requestJson(
    `${base}/app/installations/${encodeURIComponent(env.GITHUB_APP_INSTALLATION_ID)}/access_tokens`,
    {
      method: "POST",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${jwt}`,
        "user-agent": "steward-gate-d-sandbox",
        "x-github-api-version": "2022-11-28",
      },
    },
    fetchImpl,
  );
  if (!response.ok || typeof body?.token !== "string") {
    throw new Error(`GitHub installation token mint failed (${response.status})`);
  }
  const expiresAt = Date.parse(body.expires_at);
  const remainingMs = expiresAt - Date.now();
  if (!Number.isFinite(expiresAt) || remainingMs <= 0 || remainingMs > 65 * 60 * 1000) {
    throw new Error("GitHub installation token did not have the expected short lifetime");
  }
  return {
    token: body.token,
    expiresAt: body.expires_at,
    permissions: body.permissions ?? null,
    repositorySelection: body.repository_selection ?? null,
  };
}

export async function mintInstallationToken(env, fetchImpl = fetch) {
  return (await mintInstallationCredential(env, fetchImpl)).token;
}

export async function verifyInstallationScope(
  { token, permissions, repositorySelection },
  { owner, repo, apiBase = GITHUB_API_BASE, fetchImpl = fetch },
) {
  const expectedPermissions = { issues: "write", metadata: "read" };
  if (
    repositorySelection !== "selected" ||
    JSON.stringify(Object.fromEntries(Object.entries(permissions ?? {}).sort())) !==
      JSON.stringify(expectedPermissions)
  ) {
    throw new Error(
      "GitHub App installation permissions are not exactly metadata:read + issues:write",
    );
  }
  const { response, body } = await requestJson(
    `${apiBase.replace(/\/$/, "")}/installation/repositories?per_page=100`,
    {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "user-agent": "steward-gate-d-sandbox",
        "x-github-api-version": "2022-11-28",
      },
    },
    fetchImpl,
  );
  const expected = `${owner}/${repo}`.toLowerCase();
  if (
    !response.ok ||
    body?.total_count !== 1 ||
    !Array.isArray(body.repositories) ||
    body.repositories.length !== 1 ||
    body.repositories[0]?.full_name?.toLowerCase() !== expected
  ) {
    throw new Error("GitHub App installation must be limited to the one declared sandbox repo");
  }
}

export async function revokeInstallationToken(token, fetchImpl = fetch) {
  const response = await fetchImpl(`${GITHUB_API_BASE}/installation/token`, {
    method: "DELETE",
    redirect: "error",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "user-agent": "steward-gate-d-sandbox",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (response.status !== 204) {
    throw new Error(`GitHub installation token revocation failed (${response.status})`);
  }
}

export function parseRetryAfter(value, capMs, now = Date.now()) {
  if (!value) return 0;
  const seconds = Number(value);
  const requested = Number.isFinite(seconds)
    ? Math.max(0, seconds * 1000)
    : Math.max(0, Date.parse(value) - now);
  return Number.isFinite(requested) ? Math.min(requested, capMs) : 0;
}

export function classifyGithubResponse(status, headers = new Headers()) {
  const rateLimited403 =
    status === 403 && (headers.has("retry-after") || headers.get("x-ratelimit-remaining") === "0");
  if (status === 429 || rateLimited403)
    return {
      classification: "rate_limited",
      retryAfter: headers.get("retry-after"),
      boundedFailure: true,
    };
  if (status >= 500) return { classification: "upstream_failure", boundedFailure: true };
  if (status >= 400) return { classification: "request_failure", boundedFailure: true };
  return { classification: "ok", boundedFailure: false };
}

export function isLiveRateLimitObservation(observation) {
  return observation?.classification === "rate_limited" && observation.retryAfter !== null;
}

/** Bounded, read-only reconciliation; this function never writes provider data. */
export async function reconcileGithubMarker({
  apiBase = GITHUB_API_BASE,
  owner,
  repo,
  pullNumber,
  marker,
  token,
  maxAttempts = 3,
  maxPages = 3,
  retryAfterCapMs = 2_000,
  fetchImpl = fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const validatedApiBase = validateServiceUrl("GITHUB_API_URL", apiBase);
  let requests = 0;
  let rateLimited = false;
  const observations = [];
  let paginationBoundExhausted = false;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    for (let page = 1; page <= maxPages; page++) {
      requests++;
      const url = `${validatedApiBase}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${encodeURIComponent(pullNumber)}/comments?per_page=100&page=${page}`;
      const { response, body: rows } = await requestJson(
        url,
        {
          headers: {
            accept: "application/vnd.github+json",
            authorization: `Bearer ${token}`,
            "user-agent": "steward-gate-d-sandbox",
            "x-github-api-version": "2022-11-28",
          },
        },
        fetchImpl,
      );
      const classification = classifyGithubResponse(response.status, response.headers);
      observations.push({
        attempt,
        page,
        status: response.status,
        classification: classification.classification,
        retryAfter: classification.retryAfter ?? null,
      });
      if (classification.classification === "rate_limited") {
        rateLimited = true;
        await sleep(parseRetryAfter(classification.retryAfter, retryAfterCapMs));
        break;
      }
      if (!response.ok) return { outcome: "indeterminate", requests, observations, classification };
      if (!Array.isArray(rows))
        return {
          outcome: "indeterminate",
          requests,
          observations,
          classification: { classification: "invalid_response" },
        };
      const found = rows.find((row) => typeof row?.body === "string" && row.body.includes(marker));
      if (found) return { outcome: "found", requests, observations, commentId: found.id ?? null };
      if (rows.length < 100) break;
      if (page === maxPages) paginationBoundExhausted = true;
    }
    if (attempt < maxAttempts) await sleep(Math.min(250 * attempt, retryAfterCapMs));
  }
  if (rateLimited) {
    return {
      outcome: "indeterminate",
      requests,
      observations,
      classification: { classification: "rate_limited", boundedFailure: true },
    };
  }
  if (paginationBoundExhausted) {
    return {
      outcome: "indeterminate",
      requests,
      observations,
      classification: { classification: "pagination_bound_exhausted", boundedFailure: true },
    };
  }
  return { outcome: "definitive_miss", requests, observations };
}

export function scrub(value, secrets) {
  let text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  for (const secret of new Set(secrets.filter((v) => typeof v === "string" && v.length >= 4)))
    text = text.split(secret).join("[REDACTED]");
  return text
    .replace(/Bearer\s+[A-Za-z0-9._~-]+/gi, "Bearer [REDACTED]")
    .replace(/(?:gh[psuor]_|github_pat_)[A-Za-z0-9_]+/gi, "[REDACTED_GITHUB_TOKEN]")
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[REDACTED_PEM]");
}
