import { describe, expect, test } from "bun:test";

import { ApnsPushAdapter, ExpoPushAdapter, FcmPushAdapter, MockPushAdapter, type PushFetch } from "../adapters/push.js";
import { AdapterValidationError } from "../types.js";

describe("PushAdapter", () => {
  test("mock records bounded outbound push deliveries", async () => {
    const adapter = new MockPushAdapter({ now: () => 1779819300000 });
    const result = await adapter.send({
      target: {
        id: "push-1",
        userId: "user-1",
        provider: "expo",
        token: "ExpoPushToken[abc123abc123abc123]",
        platform: "ios",
      },
      tenantId: "tenant-1",
      event: "wallet.action_requested",
      idempotencyKey: "event-1",
      message: {
        title: "Approve transaction",
        body: "A wallet action needs your approval.",
        data: { url: "myapp://wallet/action?actionId=act-1" },
      },
    });

    expect(result).toEqual({
      ok: true,
      provider: "mock",
      subscriptionId: "push-1",
      providerMessageId: "mock-push-1",
      deliveredAt: 1779819300000,
    });
    expect(adapter.listDeliveries()).toEqual([result]);
  });

  test("validates provider-specific token shapes", async () => {
    const adapter = new MockPushAdapter();
    await expect(
      adapter.send({
        target: {
          id: "push-2",
          userId: "user-1",
          provider: "apns",
          token: "ExpoPushToken[abc123abc123abc123]",
        },
        message: { title: "Title", body: "Body" },
      }),
    ).rejects.toThrow(AdapterValidationError);
  });

  test("rejects oversized notification fields before provider dispatch", async () => {
    const adapter = new MockPushAdapter();
    await expect(
      adapter.send({
        target: {
          id: "push-3",
          userId: "user-1",
          provider: "fcm",
          token: "fcm-token-without-spaces",
        },
        message: { title: "x".repeat(121), body: "Body" },
      }),
    ).rejects.toThrow("title must be 120 characters or fewer");
  });

  test("expo adapter sends a provider ticket request", async () => {
    const calls: Array<{ input: string; init: Parameters<PushFetch>[1] }> = [];
    const adapter = new ExpoPushAdapter({
      accessToken: "expo-token",
      now: () => 1779819300000,
      fetch: async (input, init) => {
        calls.push({ input, init });
        return {
          ok: true,
          status: 200,
          async json() {
            return { data: { status: "ok", id: "expo-ticket-1" } };
          },
          async text() {
            return "";
          },
        };
      },
    });

    const result = await adapter.send({
      target: {
        id: "push-4",
        userId: "user-1",
        provider: "expo",
        token: "ExpoPushToken[abc123abc123abc123]",
      },
      message: {
        title: "Approve transaction",
        body: "A wallet action needs your approval.",
        data: { url: "myapp://wallet/action?actionId=act-1" },
        badge: 1,
        sound: "default",
      },
    });

    expect(result).toEqual({
      ok: true,
      provider: "expo",
      subscriptionId: "push-4",
      providerMessageId: "expo-ticket-1",
      deliveredAt: 1779819300000,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.input).toBe("https://exp.host/--/api/v2/push/send");
    expect(calls[0]?.init.headers.Authorization).toBe("Bearer expo-token");
    expect(JSON.parse(calls[0]?.init.body ?? "{}")).toEqual({
      to: "ExpoPushToken[abc123abc123abc123]",
      title: "Approve transaction",
      body: "A wallet action needs your approval.",
      data: { url: "myapp://wallet/action?actionId=act-1" },
      badge: 1,
      sound: "default",
    });
  });

  test("expo adapter maps permanent device errors", async () => {
    const adapter = new ExpoPushAdapter({
      now: () => 1779819300001,
      fetch: async () => ({
        ok: true,
        status: 200,
        async json() {
          return {
            data: {
              status: "error",
              message: "Device is not registered",
              details: { error: "DeviceNotRegistered" },
            },
          };
        },
        async text() {
          return "";
        },
      }),
    });

    await expect(
      adapter.send({
        target: {
          id: "push-5",
          userId: "user-1",
          provider: "expo",
          token: "ExpoPushToken[abc123abc123abc123]",
        },
        message: { title: "Title", body: "Body" },
      }),
    ).resolves.toEqual({
      ok: false,
      provider: "expo",
      subscriptionId: "push-5",
      error: "Device is not registered",
      retryable: false,
      deliveredAt: 1779819300001,
    });
  });

  test("expo adapter maps retryable provider failures", async () => {
    const adapter = new ExpoPushAdapter({
      now: () => 1779819300002,
      fetch: async () => ({
        ok: false,
        status: 429,
        async json() {
          return { errors: [{ message: "rate limited", code: "TOO_MANY_REQUESTS" }] };
        },
        async text() {
          return "";
        },
      }),
    });

    await expect(
      adapter.send({
        target: {
          id: "push-6",
          userId: "user-1",
          provider: "expo",
          token: "ExpoPushToken[abc123abc123abc123]",
        },
        message: { title: "Title", body: "Body" },
      }),
    ).resolves.toEqual({
      ok: false,
      provider: "expo",
      subscriptionId: "push-6",
      error: "rate limited",
      retryable: true,
      deliveredAt: 1779819300002,
    });
  });

  test("expo adapter rejects non-expo targets before fetch", async () => {
    let called = false;
    const adapter = new ExpoPushAdapter({
      fetch: async () => {
        called = true;
        throw new Error("should not dispatch");
      },
    });

    await expect(
      adapter.send({
        target: {
          id: "push-7",
          userId: "user-1",
          provider: "fcm",
          token: "fcm-token-without-spaces",
        },
        message: { title: "Title", body: "Body" },
      }),
    ).rejects.toThrow("ExpoPushAdapter only supports Expo push tokens");
    expect(called).toBe(false);
  });

  test("apns adapter sends provider-shaped request", async () => {
    const calls: Array<{ input: string; init: Parameters<PushFetch>[1] }> = [];
    const adapter = new ApnsPushAdapter({
      teamId: "TEAMID1234",
      keyId: "KEYID1234",
      bundleId: "fi.steward.app",
      jwtProvider: () => "apns-jwt",
      now: () => 1779819300003,
      fetch: async (input, init) => {
        calls.push({ input, init });
        return {
          ok: true,
          status: 200,
          headers: { "apns-id": "apns-message-1" },
          async json() {
            return {};
          },
          async text() {
            return "";
          },
        } as Awaited<ReturnType<PushFetch>>;
      },
    });

    const token = "a".repeat(64);
    await expect(
      adapter.send({
        target: { id: "push-8", userId: "user-1", provider: "apns", token },
        message: { title: "Title", body: "Body", badge: 2, data: { url: "myapp://home" } },
      }),
    ).resolves.toEqual({
      ok: true,
      provider: "apns",
      subscriptionId: "push-8",
      providerMessageId: "apns-message-1",
      deliveredAt: 1779819300003,
    });
    expect(calls[0]?.input).toBe(`https://api.push.apple.com/3/device/${token}`);
    expect(calls[0]?.init.headers.Authorization).toBe("bearer apns-jwt");
    expect(calls[0]?.init.headers["apns-topic"]).toBe("fi.steward.app");
    expect(JSON.parse(calls[0]?.init.body ?? "{}")).toEqual({
      aps: { alert: { title: "Title", body: "Body" }, badge: 2 },
      data: { url: "myapp://home" },
    });
  });

  test("apns adapter maps provider failures", async () => {
    const adapter = new ApnsPushAdapter({
      teamId: "TEAMID1234",
      keyId: "KEYID1234",
      bundleId: "fi.steward.app",
      jwtProvider: () => "apns-jwt",
      now: () => 1779819300004,
      fetch: async () =>
        ({
          ok: false,
          status: 410,
          async json() {
            return { reason: "Unregistered" };
          },
          async text() {
            return "";
          },
        }) as Awaited<ReturnType<PushFetch>>,
    });

    await expect(
      adapter.send({
        target: { id: "push-9", userId: "user-1", provider: "apns", token: "a".repeat(64) },
        message: { title: "Title", body: "Body" },
      }),
    ).resolves.toEqual({
      ok: false,
      provider: "apns",
      subscriptionId: "push-9",
      error: "Unregistered",
      retryable: false,
      deliveredAt: 1779819300004,
    });
  });

  test("fcm adapter sends provider-shaped request", async () => {
    const calls: Array<{ input: string; init: Parameters<PushFetch>[1] }> = [];
    const adapter = new FcmPushAdapter({
      projectId: "steward-prod",
      accessTokenProvider: () => "fcm-token",
      now: () => 1779819300005,
      fetch: async (input, init) => {
        calls.push({ input, init });
        return {
          ok: true,
          status: 200,
          async json() {
            return { name: "projects/steward-prod/messages/1" };
          },
          async text() {
            return "";
          },
        };
      },
    });

    await expect(
      adapter.send({
        target: { id: "push-10", userId: "user-1", provider: "fcm", token: "fcm-token-without-spaces" },
        message: { title: "Title", body: "Body", data: { url: "myapp://home" } },
      }),
    ).resolves.toEqual({
      ok: true,
      provider: "fcm",
      subscriptionId: "push-10",
      providerMessageId: "projects/steward-prod/messages/1",
      deliveredAt: 1779819300005,
    });
    expect(calls[0]?.input).toBe("https://fcm.googleapis.com/v1/projects/steward-prod/messages:send");
    expect(calls[0]?.init.headers.Authorization).toBe("Bearer fcm-token");
    expect(JSON.parse(calls[0]?.init.body ?? "{}")).toEqual({
      message: {
        token: "fcm-token-without-spaces",
        notification: { title: "Title", body: "Body" },
        data: { url: "myapp://home" },
      },
    });
  });

  test("fcm adapter maps retryable provider failures", async () => {
    const adapter = new FcmPushAdapter({
      projectId: "steward-prod",
      accessToken: "fcm-token",
      now: () => 1779819300006,
      fetch: async () => ({
        ok: false,
        status: 503,
        async json() {
          return { error: { status: "UNAVAILABLE", message: "backend unavailable" } };
        },
        async text() {
          return "";
        },
      }),
    });

    await expect(
      adapter.send({
        target: { id: "push-11", userId: "user-1", provider: "fcm", token: "fcm-token-without-spaces" },
        message: { title: "Title", body: "Body" },
      }),
    ).resolves.toEqual({
      ok: false,
      provider: "fcm",
      subscriptionId: "push-11",
      error: "backend unavailable",
      retryable: true,
      deliveredAt: 1779819300006,
    });
  });
});
