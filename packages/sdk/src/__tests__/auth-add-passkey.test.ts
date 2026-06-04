import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test";
import { StewardAuth } from "../auth";
import type { SessionStorage } from "../auth-types";
import { StewardApiError } from "../client";

// Track requests and responses to model an end-to-end addPasskey call.
type Captured = { url: string; body?: Record<string, unknown> };
let captured: Captured[];
let originalFetch: typeof fetch;
let originalWindow: unknown;

const REG_OPTIONS = {
  challenge: "abc",
  rp: { id: "waifu.fun", name: "Steward" },
  user: { id: "u-1", name: "shadow@shad0w.xyz", displayName: "shadow@shad0w.xyz" },
};

// The SDK's authRequest helper returns the raw response body as `data`,
// so the verify endpoint's flat envelope (`{ ok, token, user, ... }`)
// shows up directly on `verifyRes.data`.
const VERIFY_RESPONSE = {
  ok: true,
  token: "test-jwt",
  refreshToken: "test-refresh",
  user: { id: "u-1", email: "shadow@shad0w.xyz" },
  expiresIn: 3600,
};

function installFetch(): void {
  global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;
    const body = init?.body ? JSON.parse(init.body as string) : undefined;
    captured.push({ url, body });
    // /auth/passkey/register/options returns the WebAuthn options directly
    // (no { ok, data } envelope) so the SDK can pass them to startRegistration.
    if (url.endsWith("/auth/passkey/register/options")) {
      return new Response(JSON.stringify(REG_OPTIONS), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.endsWith("/auth/passkey/register/verify")) {
      return new Response(JSON.stringify(VERIFY_RESPONSE), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ ok: false, error: "unexpected" }), { status: 500 });
  }) as typeof fetch;
}

// addPasskey lives in browser-only code paths. Stub `window` so the
// `isBrowser()` gate inside the SDK passes and the dynamic
// `@simplewebauthn/browser` import can be intercepted via `mock.module`.
function installBrowserShim(): void {
  // @ts-expect-error — only present in browser
  originalWindow = globalThis.window;
  // @ts-expect-error — minimal shim
  globalThis.window = { document: {} };
}
function restoreBrowserShim(): void {
  // @ts-expect-error — restore
  globalThis.window = originalWindow;
}

mock.module("@simplewebauthn/browser", () => ({
  startRegistration: async () => ({
    id: "credential-1",
    rawId: "credential-1",
    response: {
      clientDataJSON: "client-data",
      attestationObject: "attestation",
    },
    type: "public-key",
  }),
  startAuthentication: async () => ({
    id: "credential-login",
    rawId: "credential-login",
    response: {
      clientDataJSON: "client-data",
      authenticatorData: "authenticator-data",
      signature: "signature",
      userHandle: "u-1",
    },
    type: "public-key",
  }),
}));

function fakeJwt(claims: Record<string, unknown> = {}): string {
  const header = btoa(JSON.stringify({ alg: "HS256" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(
    JSON.stringify({
      address: "0x1234",
      tenantId: "tenant-passkey",
      userId: "u-1",
      exp: Math.floor(Date.now() / 1000) + 900,
      ...claims,
    }),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.sig`;
}

function memoryStorage(): SessionStorage {
  const store = new Map<string, string>();
  return {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => {
      store.set(key, value);
    },
    removeItem: (key) => {
      store.delete(key);
    },
  };
}

beforeEach(() => {
  captured = [];
  originalFetch = global.fetch;
  installFetch();
  installBrowserShim();
});

afterEach(() => {
  global.fetch = originalFetch;
  restoreBrowserShim();
});

describe("StewardAuth.addPasskey", () => {
  it("registers a fresh credential by going straight to register/options + verify", async () => {
    const auth = new StewardAuth({ baseUrl: "https://api.example.test" });
    const result = await auth.addPasskey("shadow@shad0w.xyz");

    // It must call register/options first, then register/verify.
    const paths = captured.map((c) => c.url.replace("https://api.example.test", ""));
    expect(paths).toEqual(["/auth/passkey/register/options", "/auth/passkey/register/verify"]);

    // The email is forwarded on both calls.
    expect(captured[0]?.body?.email).toBe("shadow@shad0w.xyz");
    expect(captured[1]?.body?.email).toBe("shadow@shad0w.xyz");

    // The browser attestation response is forwarded to verify.
    expect((captured[1]?.body as Record<string, unknown>)?.response).toMatchObject({
      id: "credential-1",
      type: "public-key",
    });

    // And the resulting session reflects the verify payload.
    expect(result.token).toBe("test-jwt");
    expect(result.user?.email).toBe("shadow@shad0w.xyz");
  });

  it("never calls /auth/passkey/login/options — addPasskey skips the login probe", async () => {
    const auth = new StewardAuth({ baseUrl: "https://api.example.test" });
    await auth.addPasskey("shadow@shad0w.xyz");
    const paths = captured.map((c) => c.url.replace("https://api.example.test", ""));
    expect(paths).not.toContain("/auth/passkey/login/options");
  });

  it("surfaces server errors from register/options without falling back", async () => {
    global.fetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/auth/passkey/register/options")) {
        return new Response(JSON.stringify({ ok: false, error: "rate limited" }), { status: 429 });
      }
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const auth = new StewardAuth({ baseUrl: "https://api.example.test" });
    await expect(auth.addPasskey("shadow@shad0w.xyz")).rejects.toBeInstanceOf(StewardApiError);
  });

  it("forwards challengeId when completing passkey login", async () => {
    global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const body = init?.body ? JSON.parse(init.body as string) : undefined;
      captured.push({ url, body });
      if (url.endsWith("/auth/passkey/login/options")) {
        return new Response(
          JSON.stringify({
            challenge: "login-challenge",
            challengeId: "login-challenge",
            rpId: "api.example.test",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.endsWith("/auth/passkey/login/verify")) {
        return new Response(JSON.stringify(VERIFY_RESPONSE), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ ok: false, error: "unexpected" }), { status: 500 });
    }) as typeof fetch;

    const auth = new StewardAuth({ baseUrl: "https://api.example.test" });
    await auth.signInWithPasskey("shadow@shad0w.xyz");

    expect(captured[1]?.url).toBe("https://api.example.test/auth/passkey/login/verify");
    expect(captured[1]?.body).toMatchObject({
      email: "shadow@shad0w.xyz",
      challengeId: "login-challenge",
      response: { id: "credential-login", type: "public-key" },
    });
  });

  it("completes passkey MFA with bearer auth and stores the refreshed session", async () => {
    const storage = memoryStorage();
    const initialToken = fakeJwt();
    const steppedUpToken = fakeJwt({ mfaVerifiedAt: Date.now(), mfaMethod: "passkey" });
    storage.setItem("steward_session_token", initialToken);

    global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const body = init?.body ? JSON.parse(init.body as string) : undefined;
      captured.push({ url, body });
      if (url.endsWith("/auth/mfa/passkey/options")) {
        expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${initialToken}`);
        return new Response(
          JSON.stringify({
            challenge: "mfa-challenge",
            challengeId: "mfa-challenge",
            rpId: "api.example.test",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.endsWith("/auth/mfa/passkey/complete")) {
        expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${initialToken}`);
        return new Response(
          JSON.stringify({
            ok: true,
            token: steppedUpToken,
            refreshToken: "refresh-passkey-mfa",
            expiresIn: 900,
            user: { id: "u-1", email: "shadow@shad0w.xyz", walletAddress: "0x1234" },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ ok: false, error: "unexpected" }), { status: 500 });
    }) as typeof fetch;

    const auth = new StewardAuth({ baseUrl: "https://api.example.test", storage });
    const result = await auth.completePasskeyMfa();

    expect(captured.map((entry) => entry.url.replace("https://api.example.test", ""))).toEqual([
      "/auth/mfa/passkey/options",
      "/auth/mfa/passkey/complete",
    ]);
    expect(captured[1]?.body).toMatchObject({
      challengeId: "mfa-challenge",
      response: { id: "credential-login", type: "public-key" },
    });
    expect(result.token).toBe(steppedUpToken);
    expect(storage.getItem("steward_session_token")).toBe(steppedUpToken);
  });
});
