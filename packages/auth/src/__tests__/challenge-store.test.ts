import { describe, expect, it, spyOn } from "bun:test";

import { ChallengeStore } from "../challenge-store";
import type { StoreBackend } from "../store-backends";

function failingBackend(): StoreBackend {
  return {
    set: async () => {},
    setIfNotExists: async () => true,
    get: async () => null,
    consume: async () => null,
    delete: async () => {
      throw new Error("backend unavailable");
    },
  };
}

describe("ChallengeStore.delete", () => {
  it("resolves without an unhandled rejection and warns when the backend fails", async () => {
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      const store = new ChallengeStore({ backend: failingBackend() });
      await expect(store.delete("key")).resolves.toBeUndefined();
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain("[ChallengeStore] delete failed");
    } finally {
      warn.mockRestore();
    }
  });

  it("removes the entry on the happy path", async () => {
    const store = new ChallengeStore();
    try {
      await store.set("key", "challenge");
      await store.delete("key");
      expect(await store.get("key")).toBeNull();
    } finally {
      store.destroy();
    }
  });
});
