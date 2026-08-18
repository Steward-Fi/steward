import { afterEach, describe, expect, test } from "bun:test";
import {
  getGoogleCredentialLifecycleSchedulerHealth,
  startGoogleCredentialLifecycleScheduler,
} from "../services/provider-google-lifecycle-scheduler";

const cleanResult = {
  claimed: 0,
  adopted: 0,
  revoked: 0,
  needsAttention: 0,
  failed: 0,
  remaining: false,
};

const disposers: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (disposers.length) await disposers.pop()?.();
});

describe("Google credential lifecycle scheduler", () => {
  test("runs an immediate bounded sweep and stops without overlap", async () => {
    let calls = 0;
    let concurrent = 0;
    let peak = 0;
    const stop = startGoogleCredentialLifecycleScheduler({
      intervalMs: 1_000,
      sweep: async () => {
        calls += 1;
        concurrent += 1;
        peak = Math.max(peak, concurrent);
        await new Promise((resolve) => setTimeout(resolve, 5));
        concurrent -= 1;
        return cleanResult;
      },
    });
    disposers.push(stop);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(calls).toBe(1);
    expect(peak).toBe(1);
    expect(getGoogleCredentialLifecycleSchedulerHealth().lastSucceededAt).toBeNumber();
    await stop();
    await new Promise((resolve) => setTimeout(resolve, 1_020));
    expect(calls).toBe(1);
  });

  test("drains a clean bounded backlog immediately and awaits shutdown", async () => {
    let calls = 0;
    const stop = startGoogleCredentialLifecycleScheduler({
      intervalMs: 60_000,
      sweep: async () => ({ ...cleanResult, claimed: 1, remaining: ++calls === 1 }),
    });
    disposers.push(stop);
    for (let attempt = 0; attempt < 100 && calls < 2; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    await stop();
    expect(calls).toBe(2);
  });

  test("records unresolved recovery without tight-looping it", async () => {
    let calls = 0;
    const stop = startGoogleCredentialLifecycleScheduler({
      intervalMs: 1_000,
      sweep: async () => {
        calls += 1;
        return { ...cleanResult, needsAttention: 1 };
      },
    });
    disposers.push(stop);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(calls).toBe(1);
    expect(getGoogleCredentialLifecycleSchedulerHealth().lastError).toContain("unresolved");
  });
});
