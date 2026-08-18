import { describe, expect, test } from "bun:test";
import { syncLegacyAuthToken } from "./auth-token-sync";

function harness(overrides: Partial<Parameters<typeof syncLegacyAuthToken>[0]> = {}) {
  const set: string[] = [];
  let clears = 0;
  const input: Parameters<typeof syncLegacyAuthToken>[0] = {
    isAuthenticated: true,
    sessionToken: "session-token",
    lastToken: null,
    getToken: () => "fallback-token",
    setToken: (token) => set.push(token),
    clearToken: () => {
      clears += 1;
    },
    ...overrides,
  };
  return {
    input,
    set,
    get clears() {
      return clears;
    },
  };
}

describe("legacy API auth token synchronization", () => {
  test("installs a new session token and records it as synchronized", () => {
    const state = harness();
    expect(syncLegacyAuthToken(state.input)).toBe("session-token");
    expect(state.set).toEqual(["session-token"]);
    expect(state.clears).toBe(0);
  });

  test("does not rebuild the client when the token is unchanged", () => {
    const state = harness({ lastToken: "session-token" });
    expect(syncLegacyAuthToken(state.input)).toBe("session-token");
    expect(state.set).toEqual([]);
  });

  test("uses the current auth token when the session object has no token", () => {
    const state = harness({ sessionToken: null });
    expect(syncLegacyAuthToken(state.input)).toBe("fallback-token");
    expect(state.set).toEqual(["fallback-token"]);
  });

  test("clears the client and synchronized state on sign-out", () => {
    const state = harness({ isAuthenticated: false, lastToken: "old-token" });
    expect(syncLegacyAuthToken(state.input)).toBeNull();
    expect(state.set).toEqual([]);
    expect(state.clears).toBe(1);
  });
});
