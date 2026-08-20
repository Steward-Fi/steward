import { describe, expect, test } from "bun:test";

import {
  parseAccountDeletionCanaryConfig,
  runAccountDeletionCanary,
} from "../account-deletion-canary";

const valid = {
  STEWARD_CANARY_CONFIRM: "DELETE_DISPOSABLE_STAGING_ACCOUNT",
  STEWARD_CANARY_BASE_URL: "https://staging.example.test",
  STEWARD_CANARY_EXPECTED_HOST: "staging.example.test",
  STEWARD_CANARY_PLATFORM_KEY: "not-a-real-key",
};

describe("account-deletion staging canary safety", () => {
  test("accepts an exact HTTPS target and confirmation", () => {
    expect(parseAccountDeletionCanaryConfig(valid)).toEqual({
      baseUrl: "https://staging.example.test",
      expectedHost: "staging.example.test",
      platformKey: "not-a-real-key",
    });
  });

  test("permits loopback HTTP for isolated local proof", () => {
    expect(
      parseAccountDeletionCanaryConfig({
        ...valid,
        STEWARD_CANARY_BASE_URL: "http://127.0.0.1:33203/",
        STEWARD_CANARY_EXPECTED_HOST: "127.0.0.1",
      }).baseUrl,
    ).toBe("http://127.0.0.1:33203");
  });

  test("fails closed without the exact destructive confirmation", () => {
    expect(() =>
      parseAccountDeletionCanaryConfig({ ...valid, STEWARD_CANARY_CONFIRM: "yes" }),
    ).toThrow("must exactly equal DELETE_DISPOSABLE_STAGING_ACCOUNT");
  });

  test("rejects a host mismatch, remote HTTP, and URL credentials", () => {
    expect(() =>
      parseAccountDeletionCanaryConfig({
        ...valid,
        STEWARD_CANARY_EXPECTED_HOST: "production.example.test",
      }),
    ).toThrow("canary host mismatch");
    expect(() =>
      parseAccountDeletionCanaryConfig({
        ...valid,
        STEWARD_CANARY_BASE_URL: "http://staging.example.test",
      }),
    ).toThrow("must use HTTPS");
    expect(() =>
      parseAccountDeletionCanaryConfig({
        ...valid,
        STEWARD_CANARY_BASE_URL: "https://user:password@staging.example.test",
      }),
    ).toThrow("must not contain credentials");
  });

  test("runs the guarded lifecycle and cleans up only its generated resources", async () => {
    const calls: Array<{ method: string; path: string }> = [];
    const reports: string[] = [];
    const userId = "11111111-1111-4111-8111-111111111111";
    let tenantId = "";

    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    const fetchMock = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const method = init?.method ?? "GET";
      calls.push({ method, path: `${url.pathname}${url.search}` });

      if (method === "GET" && url.pathname === "/ready") return json({ status: "ready" });
      if (method === "POST" && url.pathname === "/platform/tenants") {
        tenantId = String(JSON.parse(String(init?.body)).id);
        return json({ ok: true }, 201);
      }
      if (method === "POST" && url.pathname === `/platform/tenants/${tenantId}/test-account`) {
        return json({
          ok: true,
          data: { testAccount: { email: "unique@steward.test", otp: "123456" } },
        });
      }
      if (method === "GET" && url.pathname === "/platform/users/lookup") {
        return json({ ok: true, data: { user: null } });
      }
      if (method === "POST" && url.pathname === "/auth/test/token") {
        return json({ user: { id: userId }, refreshToken: "never-log-this-refresh-token" });
      }
      if (method === "GET" && url.pathname === `/platform/users/${userId}`) {
        const finalRead =
          calls.filter((call) => call.path === `/platform/users/${userId}`).length > 1;
        return finalRead
          ? json({ ok: false, error: "User not found" }, 404)
          : json({
              ok: true,
              data: { tenantIds: [tenantId, `personal-${userId}`] },
            });
      }
      if (method === "PATCH" && url.pathname === `/platform/users/${userId}/deactivate`) {
        return json({ ok: true, data: { deactivatedAt: "2026-08-20T00:00:00.000Z" } });
      }
      if (method === "POST" && url.pathname === "/auth/refresh") {
        return json({ ok: false, error: "Invalid or expired refresh token" }, 401);
      }
      if (method === "DELETE" && url.pathname === `/platform/users/${userId}`) {
        const deletes = calls.filter(
          (call) => call.method === "DELETE" && call.path === `/platform/users/${userId}`,
        ).length;
        return deletes === 1
          ? json({ ok: false, error: "Cannot delete the sole active tenant owner" }, 409)
          : json({ ok: true, data: { userId, deleted: true } });
      }
      if (
        method === "DELETE" &&
        (url.pathname === `/platform/tenants/personal-${userId}` ||
          url.pathname === `/platform/tenants/${tenantId}/test-account` ||
          url.pathname === `/platform/tenants/${tenantId}`)
      ) {
        return json({ ok: true, data: null });
      }
      throw new Error(`unexpected request: ${method} ${url.pathname}`);
    }) as typeof fetch;

    await runAccountDeletionCanary(parseAccountDeletionCanaryConfig(valid), fetchMock, (message) =>
      reports.push(message),
    );

    expect(tenantId).toMatch(/^account-delete-canary-/);
    expect(calls).toHaveLength(14);
    expect(reports.at(-1)).toBe("disposable canary cleanup: PASS");
    expect(reports.join("\n")).not.toContain("never-log-this-refresh-token");
    expect(reports.join("\n")).not.toContain("not-a-real-key");
  });
});
