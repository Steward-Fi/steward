#!/usr/bin/env bun

import { randomBytes } from "node:crypto";

const CONFIRMATION = "DELETE_DISPOSABLE_STAGING_ACCOUNT";

type FetchLike = typeof fetch;

export type AccountDeletionCanaryConfig = {
  baseUrl: string;
  expectedHost: string;
  platformKey: string;
};

type JsonRecord = Record<string, unknown>;

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function parseAccountDeletionCanaryConfig(
  env: Record<string, string | undefined>,
): AccountDeletionCanaryConfig {
  if (required(env, "STEWARD_CANARY_CONFIRM") !== CONFIRMATION) {
    throw new Error(`STEWARD_CANARY_CONFIRM must exactly equal ${CONFIRMATION}`);
  }

  const rawBaseUrl = required(env, "STEWARD_CANARY_BASE_URL");
  const expectedHost = required(env, "STEWARD_CANARY_EXPECTED_HOST").toLowerCase();
  const platformKey = required(env, "STEWARD_CANARY_PLATFORM_KEY");
  const parsed = new URL(rawBaseUrl);
  const isLoopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost";

  if (!isLoopback && parsed.protocol !== "https:") {
    throw new Error("remote canary targets must use HTTPS");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("STEWARD_CANARY_BASE_URL must not contain credentials, query, or fragment");
  }
  if (parsed.hostname.toLowerCase() !== expectedHost) {
    throw new Error(
      `canary host mismatch: expected ${expectedHost}, received ${parsed.hostname.toLowerCase()}`,
    );
  }

  parsed.pathname = parsed.pathname.replace(/\/$/, "");
  return { baseUrl: parsed.toString().replace(/\/$/, ""), expectedHost, platformKey };
}

function object(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} returned an invalid JSON object`);
  }
  return value as JsonRecord;
}

function stringField(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} is missing`);
  }
  return value;
}

function canaryTenantId(): string {
  return `account-delete-canary-${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
}

export async function runAccountDeletionCanary(
  config: AccountDeletionCanaryConfig,
  fetchImpl: FetchLike = fetch,
  report: (message: string) => void = console.log,
): Promise<void> {
  const tenantId = canaryTenantId();
  const platformHeaders = {
    "Content-Type": "application/json",
    "X-Steward-Platform-Key": config.platformKey,
  };
  let tenantCreated = false;
  let testAccountEnabled = false;
  let testEmail: string | undefined;
  let emailProvenUnused = false;
  let userId: string | undefined;
  let personalTenantId: string | undefined;
  let refreshToken: string | undefined;
  let userDeleted = false;
  let tenantDeleted = false;

  async function request(
    path: string,
    init: RequestInit = {},
    expectedStatuses: number[] = [200],
  ): Promise<{ status: number; body: JsonRecord }> {
    const response = await fetchImpl(`${config.baseUrl}${path}`, {
      ...init,
      signal: AbortSignal.timeout(30_000),
    });
    let parsed: unknown = {};
    const text = await response.text();
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error(`${init.method ?? "GET"} ${path} returned non-JSON (${response.status})`);
      }
    }
    const body = object(parsed, `${init.method ?? "GET"} ${path}`);
    if (!expectedStatuses.includes(response.status)) {
      const error = typeof body.error === "string" ? `: ${body.error}` : "";
      throw new Error(`${init.method ?? "GET"} ${path} returned ${response.status}${error}`);
    }
    return { status: response.status, body };
  }

  async function platformRequest(
    path: string,
    init: RequestInit = {},
    expectedStatuses: number[] = [200],
  ) {
    const response = await request(
      `/platform${path}`,
      { ...init, headers: { ...platformHeaders, ...(init.headers ?? {}) } },
      expectedStatuses,
    );
    if (response.status >= 200 && response.status < 300 && response.body.ok !== true) {
      throw new Error(`${init.method ?? "GET"} /platform${path} did not return ok=true`);
    }
    return response;
  }

  report(`target verified: ${config.expectedHost}`);
  const ready = await request("/ready");
  if (ready.body.status !== "ready") throw new Error("target is not ready");
  report("readiness: PASS");

  try {
    // Mark cleanup ownership before each create/enable request: a response can
    // be lost after the server commits, and cleanup must still be attempted.
    tenantCreated = true;
    await platformRequest(
      "/tenants",
      {
        method: "POST",
        body: JSON.stringify({ id: tenantId, name: "Disposable account deletion canary" }),
      },
      [201],
    );
    report("disposable tenant creation: PASS");

    testAccountEnabled = true;
    const enabled = await platformRequest(`/tenants/${tenantId}/test-account`, {
      method: "POST",
    });
    const enabledData = object(enabled.body.data, "test-account data");
    const testAccount = object(enabledData.testAccount, "test-account credentials");
    const email = stringField(testAccount.email, "test-account email");
    testEmail = email;
    const otp = stringField(testAccount.otp, "test-account OTP");
    report("one-time test account enablement: PASS");

    const priorIdentity = await platformRequest(`/users/lookup?email=${encodeURIComponent(email)}`);
    const priorIdentityData = object(priorIdentity.body.data, "pre-auth identity lookup");
    if (priorIdentityData.user !== null) {
      throw new Error("generated test-account email already belongs to a user; refusing deletion");
    }
    emailProvenUnused = true;
    report("pre-existing identity collision check: PASS");

    const authenticated = await request("/auth/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId, email, otp }),
    });
    const authenticatedUser = object(authenticated.body.user, "authenticated user");
    userId = stringField(authenticatedUser.id, "authenticated user id");
    refreshToken = stringField(authenticated.body.refreshToken, "refresh token");
    personalTenantId = `personal-${userId}`;
    report("real auth and personal-tenant provisioning: PASS");

    const identity = await platformRequest(`/users/${userId}`);
    const identityData = object(identity.body.data, "platform identity");
    const tenantIds = identityData.tenantIds;
    if (
      !Array.isArray(tenantIds) ||
      !tenantIds.includes(tenantId) ||
      !tenantIds.includes(personalTenantId)
    ) {
      throw new Error("authenticated identity is missing its canary or canonical personal tenant");
    }
    report("canonical tenant topology: PASS");

    const deactivated = await platformRequest(`/users/${userId}/deactivate`, {
      method: "PATCH",
      body: JSON.stringify({ deactivated: true }),
    });
    const deactivatedData = object(deactivated.body.data, "deactivation data");
    if (deactivatedData.deactivatedAt === null || deactivatedData.deactivatedAt === undefined) {
      throw new Error("user was not marked deactivated");
    }
    report("deactivation and token revocation: PASS");

    const revokedRefresh = await request(
      "/auth/refresh",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken }),
      },
      [401],
    );
    if (revokedRefresh.body.error !== "Invalid or expired refresh token") {
      throw new Error("deactivated user's refresh token was not rejected as invalid");
    }
    refreshToken = undefined;
    report("refresh-token invalidation: PASS");

    const premature = await platformRequest(`/users/${userId}`, { method: "DELETE" }, [409]);
    if (premature.body.error !== "Cannot delete the sole active tenant owner") {
      throw new Error("premature identity deletion did not fail with the personal-owner guard");
    }
    report("personal-owner deletion guard: PASS");

    await platformRequest(`/tenants/${personalTenantId}`, { method: "DELETE" });
    report("personal tenant deletion: PASS");

    await platformRequest(`/users/${userId}`, { method: "DELETE" });
    userDeleted = true;
    report("identity cascade deletion: PASS");

    const missing = await platformRequest(`/users/${userId}`, {}, [404]);
    if (missing.body.error !== "User not found") {
      throw new Error("deleted identity did not return the expected not-found response");
    }
    report("post-deletion identity absence: PASS");

    await platformRequest(`/tenants/${tenantId}/test-account`, { method: "DELETE" });
    testAccountEnabled = false;
    await platformRequest(`/tenants/${tenantId}`, { method: "DELETE" });
    tenantDeleted = true;
    report("disposable canary cleanup: PASS");
  } finally {
    // Cleanup is restricted to the unique tenant and user created in this run.
    // If auth committed but its response was lost, recover only an identity
    // whose email was proven absent beforehand and which joined this run's
    // unique tenant. This closes the partial-response orphan case without ever
    // accepting a caller-supplied user id.
    if (!userId && testEmail && emailProvenUnused) {
      await platformRequest(`/users/lookup?email=${encodeURIComponent(testEmail)}`)
        .then((lookup) => {
          const data = object(lookup.body.data, "cleanup identity lookup");
          if (!data.user || typeof data.user !== "object" || Array.isArray(data.user)) return;
          const candidate = data.user as JsonRecord;
          const candidateId = typeof candidate.userId === "string" ? candidate.userId : undefined;
          const tenantIds = candidate.tenantIds;
          if (candidateId && Array.isArray(tenantIds) && tenantIds.includes(tenantId)) {
            userId = candidateId;
            personalTenantId = `personal-${candidateId}`;
          }
        })
        .catch(() => {});
    }
    if (testAccountEnabled && tenantCreated && !tenantDeleted) {
      await platformRequest(`/tenants/${tenantId}/test-account`, { method: "DELETE" }).catch(
        () => {},
      );
    }
    if (userId && !userDeleted) {
      await platformRequest(`/users/${userId}/deactivate`, {
        method: "PATCH",
        body: JSON.stringify({ deactivated: true }),
      }).catch(() => {});
      if (personalTenantId) {
        await platformRequest(`/tenants/${personalTenantId}`, { method: "DELETE" }).catch(() => {});
      }
      await platformRequest(`/users/${userId}`, { method: "DELETE" }).catch(() => {});
    }
    if (tenantCreated && !tenantDeleted) {
      await platformRequest(`/tenants/${tenantId}`, { method: "DELETE" }).catch(() => {});
    }
  }
}

if (import.meta.main) {
  runAccountDeletionCanary(parseAccountDeletionCanaryConfig(process.env))
    .then(() => console.log("account-deletion canary: PASS"))
    .catch((error: unknown) => {
      console.error(
        `account-deletion canary: FAIL: ${error instanceof Error ? error.message : "unknown error"}`,
      );
      process.exitCode = 1;
    });
}
