import { afterEach, describe, expect, it } from "bun:test";
import { Hono } from "hono";
import {
  authorizePlatformKey,
  getPlatformKeyScopes,
  isValidPlatformKey,
  platformAuthMiddleware,
} from "../platform";

const ORIGINAL_PLATFORM_KEY = process.env.STEWARD_PLATFORM_KEY;
const ORIGINAL_PLATFORM_KEYS = process.env.STEWARD_PLATFORM_KEYS;
const ORIGINAL_PLATFORM_KEY_SCOPES = process.env.STEWARD_PLATFORM_KEY_SCOPES;

function resetPlatformKeyEnv() {
  delete process.env.STEWARD_PLATFORM_KEY;
  delete process.env.STEWARD_PLATFORM_KEYS;
  delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
}

afterEach(() => {
  if (ORIGINAL_PLATFORM_KEY === undefined) delete process.env.STEWARD_PLATFORM_KEY;
  else process.env.STEWARD_PLATFORM_KEY = ORIGINAL_PLATFORM_KEY;

  if (ORIGINAL_PLATFORM_KEYS === undefined) delete process.env.STEWARD_PLATFORM_KEYS;
  else process.env.STEWARD_PLATFORM_KEYS = ORIGINAL_PLATFORM_KEYS;

  if (ORIGINAL_PLATFORM_KEY_SCOPES === undefined) delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  else process.env.STEWARD_PLATFORM_KEY_SCOPES = ORIGINAL_PLATFORM_KEY_SCOPES;
});

describe("platform key validation", () => {
  it("accepts the singular STEWARD_PLATFORM_KEY used by integration helpers", () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY = "singular-platform-key-with-enough-entropy";

    expect(isValidPlatformKey("singular-platform-key-with-enough-entropy")).toBe(true);
    expect(isValidPlatformKey("wrong-platform-key")).toBe(false);
  });

  it("keeps accepting comma-separated STEWARD_PLATFORM_KEYS", () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEYS =
      "first-platform-key-with-enough-entropy, second-platform-key-with-enough-entropy";

    expect(isValidPlatformKey("first-platform-key-with-enough-entropy")).toBe(true);
    expect(isValidPlatformKey("second-platform-key-with-enough-entropy")).toBe(true);
    expect(isValidPlatformKey("third-platform-key")).toBe(false);
  });

  it("resolves scopes for keys supplied through the singular env var", () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY = "singular-scoped-platform-key-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      "singular-scoped-platform-key-with-enough-entropy": [
        "platform:write",
        "platform:tenant:create",
      ],
    });

    expect(getPlatformKeyScopes("singular-scoped-platform-key-with-enough-entropy")).toEqual([
      "platform:write",
      "platform:tenant:create",
    ]);
  });

  it("authorizes narrow operator authority and records a non-secret key identity", () => {
    resetPlatformKeyEnv();
    const key = "scoped-trading-operator-key-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEY = key;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [key]: ["platform:trade:operator"],
    });

    const authorization = authorizePlatformKey(key, "platform:trade:operator");
    expect(authorization).toEqual({
      ok: true,
      keyHash: expect.stringMatching(/^[a-f0-9]{64}$/),
      scopes: ["platform:trade:operator"],
    });
  });

  it("denies valid but unscoped or incorrectly scoped operator keys", () => {
    resetPlatformKeyEnv();
    const key = "unprivileged-platform-key-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEY = key;

    expect(authorizePlatformKey(key, "platform:trade:operator")).toEqual({
      ok: false,
      status: 403,
      error: "Forbidden",
    });

    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({ [key]: ["platform:read"] });
    expect(authorizePlatformKey(key, "platform:trade:operator")).toEqual({
      ok: false,
      status: 403,
      error: "Forbidden",
    });
  });

  it("accepts the platform wildcard for operator authority", () => {
    resetPlatformKeyEnv();
    const key = "wildcard-platform-key-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEY = key;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({ [key]: ["platform:*"] });

    expect(authorizePlatformKey(key, "platform:trade:operator")).toMatchObject({ ok: true });
  });

  it("preserves an empty scope map only when the configuration is absent or blank", () => {
    resetPlatformKeyEnv();
    expect(getPlatformKeyScopes("unscoped-platform-key")).toEqual([]);

    process.env.STEWARD_PLATFORM_KEY_SCOPES = "  \n  ";
    expect(getPlatformKeyScopes("unscoped-platform-key")).toEqual([]);
  });

  it.each([
    ["malformed JSON", "{"],
    ["null JSON", "null"],
    ["array JSON", '[["platform:read"]]'],
    ["non-array scope value", '{"platform-key":"platform:read"}'],
    ["mixed non-string scope array", '{"platform-key":["platform:read",7]}'],
  ])("rejects %s instead of silently removing authorization", (_name, raw) => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY_SCOPES = raw;

    expect(() => getPlatformKeyScopes("platform-key")).toThrow(
      "Platform key scope configuration is invalid",
    );
  });

  it("returns a redacted configuration error for a valid platform key", async () => {
    resetPlatformKeyEnv();
    const key = "valid-platform-key-with-enough-entropy";
    const canary = "raw-scope-config-canary";
    process.env.STEWARD_PLATFORM_KEY = key;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = `{"${canary}":["platform:read"]`;

    const app = new Hono();
    app.use("*", platformAuthMiddleware());
    app.get("/", (c) => c.json({ ok: true }));

    const response = await app.request("/", {
      headers: { "X-Steward-Platform-Key": key },
    });
    const body = await response.text();
    expect(response.status).toBe(500);
    expect(body).toContain("Platform key scope configuration is invalid");
    expect(body).not.toContain(canary);
  });
});
