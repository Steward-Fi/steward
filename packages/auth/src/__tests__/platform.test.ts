import { afterEach, describe, expect, it } from "bun:test";
import { Hono } from "hono";
import { getPlatformKeyScopes, isValidPlatformKey, platformAuthMiddleware } from "../platform";

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

  it("rejects malformed platform scope JSON instead of hiding the configuration failure", () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY_SCOPES = "{";

    expect(() => getPlatformKeyScopes("platform-key")).toThrow(
      "STEWARD_PLATFORM_KEY_SCOPES must be valid JSON",
    );
  });

  it("fails a mounted platform request when scope configuration is malformed", async () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY = "mounted-platform-key";
    process.env.STEWARD_PLATFORM_KEY_SCOPES = "{";
    const app = new Hono();
    let reachedRoute = false;
    app.onError((_error, c) => c.json({ ok: false, error: "Internal Server Error" }, 500));
    app.use("*", platformAuthMiddleware());
    app.get("/", (c) => {
      reachedRoute = true;
      return c.json({ ok: true });
    });

    const response = await app.request("/", {
      headers: { "X-Steward-Platform-Key": "mounted-platform-key" },
    });

    expect(response.status).toBe(500);
    expect(reachedRoute).toBe(false);
  });

  it.each([
    ["an array", ["platform:read"]],
    ["a scalar", "platform:read"],
    ["a non-array mapping value", { "platform-key": "platform:read" }],
    ["a mixed-type scope array", { "platform-key": ["platform:read", 1] }],
  ])("rejects %s platform scope configuration", (_label, configuredScopes) => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify(configuredScopes);

    expect(() => getPlatformKeyScopes("platform-key")).toThrow(
      "STEWARD_PLATFORM_KEY_SCOPES must be a JSON object mapping keys or key hashes to string arrays",
    );
  });
});
