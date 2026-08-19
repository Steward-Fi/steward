import { afterEach, describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { getPlatformKeyScopes, isValidPlatformKey } from "../platform";

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

  it("isolates overlapping platform keys and scopes by request", async () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY = "global-platform-key-must-not-leak";
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      "global-platform-key-must-not-leak": ["platform:*"],
    });
    let releaseFirst!: () => void;
    const firstCanRead = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const first = withRuntimeEnvironment(
      {
        STEWARD_PLATFORM_KEY: "first-request-platform-key",
        STEWARD_PLATFORM_KEY_SCOPES: JSON.stringify({
          "first-request-platform-key": ["platform:read"],
        }),
      },
      async () => {
        await firstCanRead;
        return {
          ownValid: isValidPlatformKey("first-request-platform-key"),
          otherValid: isValidPlatformKey("second-request-platform-key"),
          globalValid: isValidPlatformKey("global-platform-key-must-not-leak"),
          scopes: getPlatformKeyScopes("first-request-platform-key"),
        };
      },
    );
    const second = withRuntimeEnvironment(
      {
        STEWARD_PLATFORM_KEYS: "second-request-platform-key",
        STEWARD_PLATFORM_KEY_SCOPES: JSON.stringify({
          "second-request-platform-key": ["platform:write"],
        }),
      },
      async () => {
        releaseFirst();
        await Promise.resolve();
        return {
          ownValid: isValidPlatformKey("second-request-platform-key"),
          otherValid: isValidPlatformKey("first-request-platform-key"),
          globalValid: isValidPlatformKey("global-platform-key-must-not-leak"),
          scopes: getPlatformKeyScopes("second-request-platform-key"),
        };
      },
    );

    expect(await Promise.all([first, second])).toEqual([
      { ownValid: true, otherValid: false, globalValid: false, scopes: ["platform:read"] },
      { ownValid: true, otherValid: false, globalValid: false, scopes: ["platform:write"] },
    ]);
  });

  it("does not inherit a global platform key when the request snapshot omits it", () => {
    resetPlatformKeyEnv();
    process.env.STEWARD_PLATFORM_KEY = "global-platform-key-must-not-leak";
    expect(
      withRuntimeEnvironment({}, () => isValidPlatformKey("global-platform-key-must-not-leak")),
    ).toBe(false);
  });
});
