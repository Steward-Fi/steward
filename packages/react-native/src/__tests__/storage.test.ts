import { afterEach, describe, expect, test } from "bun:test";
import { StewardAuth } from "@stwd/sdk";
import {
  type AsyncKeyValueStorage,
  assertNativePasskeysUnsupported,
  bootstrapNativeCurrentUser,
  completeNativeEmailCallback,
  completeNativeOAuthCallback,
  completeNativePasskeyMfa,
  createNativeEthereumConnectorFromProvider,
  createNativePushTokenRegistration,
  createNativeSolanaConnectorFromAdapter,
  createReactNativeSessionStorage,
  createStewardNativeAuth,
  createStewardNativeClient,
  getNativeTestAccessToken,
  parseNativeEmailCallbackUrl,
  parseNativeNotificationAction,
  registerNativePasskey,
  registerNativePushToken,
  sendNativeOtp,
  signInWithNativeEthereumWallet,
  signInWithNativePasskey,
  signInWithNativeSolanaWallet,
  startNativeOAuthRedirect,
  verifyNativeOtp,
} from "../index";

function memoryAsyncStorage(initial: Record<string, string> = {}): AsyncKeyValueStorage & {
  entries: Map<string, string>;
} {
  const entries = new Map(Object.entries(initial));
  return {
    entries,
    async getItem(key) {
      return entries.get(key) ?? null;
    },
    async setItem(key, value) {
      entries.set(key, value);
    },
    async removeItem(key) {
      entries.delete(key);
    },
  };
}

function fakeJwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url").replace(/=+$/g, "");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.`;
}

type CapturedRequest = {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: Record<string, unknown>;
};

let lastRequest: CapturedRequest | null = null;
let requestLog: CapturedRequest[] = [];
const originalFetch = global.fetch;

function installAuthFetch(responseBody: object, status = 200): void {
  global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;
    lastRequest = {
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    };
    requestLog.push(lastRequest);
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
}

function installAuthFetchSequence(responses: Array<{ body: object; status?: number }>): void {
  let index = 0;
  global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;
    lastRequest = {
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    };
    requestLog.push(lastRequest);
    const response = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return new Response(JSON.stringify(response?.body ?? {}), {
      status: response?.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  };
}

describe("@stwd/react-native storage", () => {
  afterEach(() => {
    lastRequest = null;
    requestLog = [];
    global.fetch = originalFetch;
  });

  const requestFor = (url: string) => requestLog.find((request) => request.url === url);

  test("hydrates existing SDK session keys from async storage", async () => {
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-1",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const asyncStorage = memoryAsyncStorage({
      "tenant-a:steward_session_token": token,
      "tenant-a:steward_refresh_token": "refresh",
      "tenant-a:steward_user": JSON.stringify({ id: "user-1", email: "u@example.com" }),
    });
    const storage = createReactNativeSessionStorage(asyncStorage, { namespace: "tenant-a" });

    await storage.hydrate();

    expect(storage.getItem("steward_session_token")).toBe(token);
    expect(storage.getItem("steward_refresh_token")).toBe("refresh");
  });

  test("writes and removes through the namespaced async backing store", async () => {
    const asyncStorage = memoryAsyncStorage();
    const storage = createReactNativeSessionStorage(asyncStorage, { namespace: "mobile" });

    storage.setItem("steward_session_token", "token-1");
    await storage.flush();
    expect(asyncStorage.entries.get("mobile:steward_session_token")).toBe("token-1");

    storage.removeItem("steward_session_token");
    await storage.flush();
    expect(asyncStorage.entries.has("mobile:steward_session_token")).toBe(false);
  });

  test("createStewardNativeAuth returns a hydrated StewardAuth instance", async () => {
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-1",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const asyncStorage = memoryAsyncStorage({
      "steward:steward_session_token": token,
    });
    installAuthFetch({
      ok: true,
      data: { user: { id: "user-1" }, embeddedWalletConfig: { createOnLogin: "off" } },
    });

    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      storage: asyncStorage,
    });

    expect(auth).toBeInstanceOf(StewardAuth);
    expect(auth.getSession()?.userId).toBe("user-1");
  });

  test("bootstraps the current user with tenant context after hydrating a native session", async () => {
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-bootstrap",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetch({
      ok: true,
      data: {
        user: { id: "user-bootstrap" },
        embeddedWalletConfig: { createOnLogin: "users-without-wallets" },
        walletAutoCreated: { id: "wallet-1" },
      },
    });

    await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage({ "steward:steward_session_token": token }),
    });

    expect(lastRequest).toMatchObject({
      url: "https://api.example.test/user/me?tenantId=tenant-1",
      method: "GET",
      headers: {
        authorization: `Bearer ${token}`,
        "x-steward-tenant": "tenant-1",
      },
    });
  });

  test("native current-user bootstrap is best-effort", async () => {
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-bootstrap-error",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetch({ ok: false, error: "wallet provisioning unavailable" }, 503);
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      bootstrapCurrentUser: false,
      storage: memoryAsyncStorage({ "steward:steward_session_token": token }),
    });

    await expect(bootstrapNativeCurrentUser(auth)).resolves.toBeNull();
    expect(auth.getSession()?.userId).toBe("user-bootstrap-error");
  });

  test("parses and completes native email callback URLs", async () => {
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-email",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetch({
      token,
      refreshToken: "refresh-email",
      user: { id: "user-email", email: "u@example.com" },
      expiresIn: 900,
    });
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage(),
    });

    const callback = parseNativeEmailCallbackUrl(
      "steward://auth/email?token=email-token&email=u%40example.com",
    );
    expect(callback).toEqual({ token: "email-token", email: "u@example.com" });

    const result = await completeNativeEmailCallback(
      auth,
      "steward://auth/email?token=email-token&email=u%40example.com",
    );

    expect(requestFor("https://api.example.test/auth/email/verify")).toMatchObject({
      url: "https://api.example.test/auth/email/verify",
      method: "POST",
      body: { token: "email-token", email: "u@example.com", tenantId: "tenant-1" },
    });
    expect(lastRequest?.url).toBe("https://api.example.test/user/me?tenantId=tenant-1");
    expect("user" in result && result.user.id).toBe("user-email");
    expect(auth.getSession()?.userId).toBe("user-email");
  });

  test("wraps SMS and WhatsApp OTP send and verify flows", async () => {
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage(),
    });

    installAuthFetch({ ok: true, expiresAt: "2026-05-29T12:00:00.000Z" });
    await sendNativeOtp(auth, "+15551234567", "sms", { captchaToken: "captcha-1" });
    expect(lastRequest).toMatchObject({
      url: "https://api.example.test/auth/sms/send",
      method: "POST",
      body: { phone: "+15551234567", captchaToken: "captcha-1", tenantId: "tenant-1" },
    });

    await sendNativeOtp(auth, "+15551234567", "whatsapp");
    expect(lastRequest).toMatchObject({
      url: "https://api.example.test/auth/whatsapp/send",
      method: "POST",
      body: { phone: "+15551234567", tenantId: "tenant-1" },
    });

    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-sms",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetch({
      token,
      refreshToken: "refresh-sms",
      user: { id: "user-sms", phone: "+15551234567" },
      expiresIn: 900,
    });

    await verifyNativeOtp(auth, "+15551234567", "123456", "sms");
    expect(requestFor("https://api.example.test/auth/sms/verify")).toMatchObject({
      url: "https://api.example.test/auth/sms/verify",
      method: "POST",
      body: { phone: "+15551234567", code: "123456", tenantId: "tenant-1" },
    });
    expect(auth.getSession()?.userId).toBe("user-sms");
  });

  test("wraps test credential exchange for native test accounts", async () => {
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage(),
    });
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-test",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetch({
      token,
      refreshToken: "refresh-test",
      user: { id: "user-test", email: "test@example.com" },
      expiresIn: 900,
    });

    const result = await getNativeTestAccessToken(auth, {
      email: "test@example.com",
      otp: "000000",
    });

    expect(requestFor("https://api.example.test/auth/test/token")).toMatchObject({
      url: "https://api.example.test/auth/test/token",
      method: "POST",
      body: { tenantId: "tenant-1", email: "test@example.com", otp: "000000" },
    });
    expect("user" in result && result.user.id).toBe("user-test");
    expect(auth.getSession()?.userId).toBe("user-test");
  });

  test("starts and completes OAuth through native deep links", async () => {
    const openedUrls: string[] = [];
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      storage: memoryAsyncStorage(),
    });

    const authorizeUrl = await startNativeOAuthRedirect(auth, "google", {
      redirectUri: "steward://oauth/google",
      tenantId: "tenant-1",
      openUrl: (url) => openedUrls.push(url),
    });
    const authorize = new URL(authorizeUrl);
    const state = authorize.searchParams.get("state");
    expect(openedUrls).toEqual([authorizeUrl]);
    expect(authorize.pathname).toBe("/auth/oauth/google/authorize");
    expect(authorize.searchParams.get("redirect_uri")).toBe("steward://oauth/google");
    expect(authorize.searchParams.get("tenant_id")).toBe("tenant-1");
    expect(state).toBeTruthy();

    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-oauth",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetch({
      token,
      refreshToken: "refresh-oauth",
      user: { id: "user-oauth" },
      expiresIn: 900,
    });

    const result = await completeNativeOAuthCallback(
      auth,
      "google",
      `steward://oauth/google?code=oauth-code&state=${state}`,
      { redirectUri: "steward://oauth/google" },
    );

    const oauthRequest = requestFor("https://api.example.test/auth/oauth/google/token");
    expect(oauthRequest?.body).toMatchObject({
      code: "oauth-code",
      redirectUri: "steward://oauth/google",
      state,
      tenantId: "tenant-1",
    });
    expect(typeof oauthRequest?.body?.codeVerifier).toBe("string");
    expect("provider" in result && result.provider).toBe("google");
    expect(auth.getSession()?.userId).toBe("user-oauth");
  });

  test("wraps EIP-1193 native wallets for SIWE sign-in", async () => {
    const requests: Array<{ method: string; params?: unknown[] }> = [];
    const provider = {
      async request(args: { method: string; params?: unknown[] }) {
        requests.push(args);
        if (args.method === "eth_requestAccounts") {
          return ["0x0000000000000000000000000000000000000001"];
        }
        if (args.method === "eth_accounts") {
          return ["0x0000000000000000000000000000000000000001"];
        }
        if (args.method === "eth_chainId") return "0x2105";
        if (args.method === "personal_sign") return "0xsigned";
        throw new Error(`unexpected method ${args.method}`);
      },
    };
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage(),
    });
    const token = fakeJwt({
      sub: "0x0000000000000000000000000000000000000001",
      userId: "user-evm",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetchSequence([
      { body: { nonce: "nonce-evm" } },
      {
        body: {
          token,
          refreshToken: "refresh-evm",
          expiresIn: 900,
          address: "0x0000000000000000000000000000000000000001",
          userId: "user-evm",
        },
      },
    ]);

    const result = await signInWithNativeEthereumWallet(
      auth,
      createNativeEthereumConnectorFromProvider(provider),
    );

    expect(requests.map((request) => request.method)).toEqual([
      "eth_requestAccounts",
      "eth_chainId",
      "eth_accounts",
      "personal_sign",
    ]);
    expect((requests.at(-1)?.params ?? [])[1]).toBe("0x0000000000000000000000000000000000000001");
    expect(requestFor("https://api.example.test/auth/verify")).toMatchObject({
      url: "https://api.example.test/auth/verify",
      method: "POST",
      body: { signature: "0xsigned" },
    });
    expect(String(requestFor("https://api.example.test/auth/verify")?.body?.message)).toContain(
      "Chain ID: 8453",
    );
    expect("user" in result && result.user.walletChain).toBe("ethereum");
    expect(auth.getSession()?.userId).toBe("user-evm");
  });

  test("wraps Solana native wallet adapters for SIWS sign-in", async () => {
    let signedMessage: Uint8Array | null = null;
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage(),
    });
    const token = fakeJwt({
      sub: "solana-native-user",
      userId: "user-sol",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    installAuthFetchSequence([
      { body: { nonce: "nonce-sol" } },
      {
        body: {
          token,
          refreshToken: "refresh-sol",
          expiresIn: 900,
          publicKey: "So11111111111111111111111111111111111111112",
          walletChain: "solana",
          userId: "user-sol",
        },
      },
    ]);

    const result = await signInWithNativeSolanaWallet(
      auth,
      createNativeSolanaConnectorFromAdapter({
        publicKey: { toBase58: () => "So11111111111111111111111111111111111111112" },
        async signMessage(message) {
          signedMessage = message;
          return { signature: [1, 2, 3, 4] };
        },
      }),
      { chain: "mainnet" },
    );

    expect(new TextDecoder().decode(signedMessage ?? new Uint8Array())).toContain(
      "So11111111111111111111111111111111111111112",
    );
    expect(requestFor("https://api.example.test/auth/verify/solana")).toMatchObject({
      url: "https://api.example.test/auth/verify/solana",
      method: "POST",
      body: {
        publicKey: "So11111111111111111111111111111111111111112",
        signature: "2VfUX",
      },
    });
    expect("user" in result && result.user.walletChain).toBe("solana");
    expect(auth.getSession()?.userId).toBe("user-sol");
  });

  test("normalizes native push token registration payloads", () => {
    const expo = createNativePushTokenRegistration("ExpoPushToken[abc123abc123abc123]", {
      platform: "ios",
      tenantId: "tenant-1",
      userId: "user-1",
      deviceId: "device-1",
      now: () => new Date("2026-05-30T12:00:00.000Z"),
    });
    expect(expo).toMatchObject({
      provider: "expo",
      token: "ExpoPushToken[abc123abc123abc123]",
      platform: "ios",
      tenantId: "tenant-1",
      userId: "user-1",
      deviceId: "device-1",
      createdAt: "2026-05-30T12:00:00.000Z",
    });

    const apnsToken = "a".repeat(64);
    expect(createNativePushTokenRegistration(apnsToken).provider).toBe("apns");
    expect(createNativePushTokenRegistration("fcm:token:abc123".repeat(2)).provider).toBe("fcm");
    expect(() => createNativePushTokenRegistration("bad", { provider: "apns" })).toThrow(
      "Native push token is invalid",
    );
  });

  test("extracts safe deep links from native notification payloads", () => {
    expect(parseNativeNotificationAction("steward://wallet/action?actionId=act-1")).toEqual({
      url: "steward://wallet/action?actionId=act-1",
      data: {},
    });
    expect(
      parseNativeNotificationAction({
        notification: {
          request: {
            content: {
              data: {
                deepLink: "myapp://wallet/action?actionId=act-2",
                event: "wallet.action_requested",
                action_id: "act-2",
                tenant_id: "tenant-1",
              },
            },
          },
        },
      }),
    ).toMatchObject({
      url: "myapp://wallet/action?actionId=act-2",
      event: "wallet.action_requested",
      actionId: "act-2",
      tenantId: "tenant-1",
    });
    expect(parseNativeNotificationAction({ data: { url: "javascript:alert(1)" } }).url).toBeNull();
  });

  test("registers native push tokens through the shared API client", async () => {
    const client = createStewardNativeClient({
      baseUrl: "https://api.example.test",
      bearerToken: "user-token",
    });
    installAuthFetch({
      ok: true,
      data: {
        subscription: {
          id: "push-1",
          tenantId: "tenant-1",
          provider: "expo",
          token: "ExpoPushToken[abc123abc123abc123]",
          platform: "ios",
          deviceId: "device-1",
          appId: null,
          locale: null,
          timezone: null,
          metadata: {},
          status: "active",
          lastSeenAt: "2026-05-30T12:00:00.000Z",
          createdAt: "2026-05-30T12:00:00.000Z",
          updatedAt: "2026-05-30T12:00:00.000Z",
        },
      },
    });

    const result = await registerNativePushToken(client, "ExpoPushToken[abc123abc123abc123]", {
      platform: "ios",
      tenantId: "tenant-1",
      deviceId: "device-1",
      now: () => new Date("2026-05-30T12:00:00.000Z"),
    });

    expect(lastRequest).toMatchObject({
      url: "https://api.example.test/user/me/push-subscriptions",
      method: "POST",
      body: {
        provider: "expo",
        token: "ExpoPushToken[abc123abc123abc123]",
        platform: "ios",
        tenantId: "tenant-1",
        deviceId: "device-1",
      },
    });
    expect(result.subscription.id).toBe("push-1");
  });

  test("signs in with a native passkey bridge", async () => {
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      storage: memoryAsyncStorage(),
    });
    const token = fakeJwt({
      sub: "user-passkey",
      userId: "user-passkey",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    let bridgeOptions: Record<string, unknown> | null = null;
    installAuthFetchSequence([
      { body: { challengeId: "challenge-login", publicKey: { challenge: "abc" } } },
      {
        body: {
          token,
          refreshToken: "refresh-passkey",
          user: { id: "user-passkey", email: "passkey@example.com" },
          expiresIn: 900,
        },
      },
    ]);

    const result = await signInWithNativePasskey(
      auth,
      "passkey@example.com",
      {
        startAuthentication(options) {
          bridgeOptions = options;
          return { id: "credential-1", response: { authenticatorData: "data" } };
        },
      },
      { origin: "https://app.example.test" },
    );

    expect(bridgeOptions).toMatchObject({ challengeId: "challenge-login" });
    expect(requestFor("https://api.example.test/auth/passkey/login/verify")).toMatchObject({
      url: "https://api.example.test/auth/passkey/login/verify",
      method: "POST",
      headers: { origin: "https://app.example.test" },
      body: {
        email: "passkey@example.com",
        challengeId: "challenge-login",
        tenantId: "tenant-1",
        response: { id: "credential-1", response: { authenticatorData: "data" } },
      },
    });
    expect("user" in result && result.user.id).toBe("user-passkey");
    expect(auth.getSession()?.userId).toBe("user-passkey");
  });

  test("registers a native passkey bridge for an authenticated user", async () => {
    const token = fakeJwt({
      sub: "user-register-passkey",
      userId: "user-register-passkey",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      tenantId: "tenant-1",
      bootstrapCurrentUser: false,
      storage: memoryAsyncStorage({ "steward:steward_session_token": token }),
    });
    let bridgeOptions: Record<string, unknown> | null = null;
    installAuthFetchSequence([
      { body: { challenge: "registration-challenge", user: { id: "user-register-passkey" } } },
      {
        body: {
          token,
          refreshToken: "refresh-register-passkey",
          user: { id: "user-register-passkey", email: "register@example.com" },
          expiresIn: 900,
        },
      },
    ]);

    const result = await registerNativePasskey(
      auth,
      "register@example.com",
      {
        startRegistration(options) {
          bridgeOptions = options;
          return { id: "new-credential", response: { attestationObject: "attestation" } };
        },
      },
      {
        origin: "https://app.example.test",
        authenticatorAttachment: "platform",
      },
    );

    expect(bridgeOptions).toMatchObject({ challenge: "registration-challenge" });
    expect(requestFor("https://api.example.test/auth/passkey/register/verify")).toMatchObject({
      url: "https://api.example.test/auth/passkey/register/verify",
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        origin: "https://app.example.test",
      },
      body: {
        email: "register@example.com",
        tenantId: "tenant-1",
        response: { id: "new-credential", response: { attestationObject: "attestation" } },
      },
    });
    expect("user" in result && result.user.id).toBe("user-register-passkey");
  });

  test("completes native passkey MFA with a platform bridge", async () => {
    const token = fakeJwt({
      sub: "user-mfa-passkey",
      userId: "user-mfa-passkey",
      tenantId: "tenant-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const steppedUpToken = fakeJwt({
      sub: "user-mfa-passkey",
      userId: "user-mfa-passkey",
      tenantId: "tenant-1",
      mfaVerifiedAt: Date.now(),
      mfaMethod: "passkey",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const auth = await createStewardNativeAuth({
      baseUrl: "https://api.example.test",
      bootstrapCurrentUser: false,
      storage: memoryAsyncStorage({ "steward:steward_session_token": token }),
    });
    installAuthFetchSequence([
      { body: { challengeId: "challenge-mfa", publicKey: { challenge: "mfa" } } },
      {
        body: {
          token: steppedUpToken,
          refreshToken: "refresh-mfa-passkey",
          user: { id: "user-mfa-passkey", email: "mfa@example.com" },
          expiresIn: 900,
        },
      },
    ]);

    const result = await completeNativePasskeyMfa(auth, {
      startAuthentication() {
        return { id: "credential-mfa", response: { clientDataJSON: "json" } };
      },
    });

    expect(requestFor("https://api.example.test/auth/mfa/passkey/complete")).toMatchObject({
      url: "https://api.example.test/auth/mfa/passkey/complete",
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      body: {
        challengeId: "challenge-mfa",
        response: { id: "credential-mfa", response: { clientDataJSON: "json" } },
      },
    });
    expect(result.user.id).toBe("user-mfa-passkey");
    expect(auth.getSession()?.token).toBe(steppedUpToken);
  });

  test("throws an explicit native passkey error", () => {
    expect(() => assertNativePasskeysUnsupported()).toThrow("Native apps should use");
  });
});
