import { expect, test } from "bun:test";
import { startGoogleCredentialLifecycleScheduler } from "../services/provider-google-lifecycle-scheduler";

test("Google lifecycle scheduler runs immediately, drains bounded pages, and stops cleanly", async () => {
  let calls = 0;
  let concurrent = 0;
  let maxConcurrent = 0;
  const stop = startGoogleCredentialLifecycleScheduler({
    intervalMs: 60_000,
    sweep: async () => {
      calls += 1;
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((resolve) => setTimeout(resolve, 5));
      concurrent -= 1;
      return {
        processed: 1,
        adopted: 1,
        revoked: 0,
        attention: 0,
        remaining: calls === 1,
      };
    },
  });
  for (let attempt = 0; attempt < 100 && calls < 2; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  await stop();
  expect(calls).toBe(2);
  expect(maxConcurrent).toBe(1);
});

test("Google lifecycle scheduler redacts failure logs to class/code only", async () => {
  const canary = "refresh-canary-never-log secret-canary-never-log";
  const logged: string[] = [];
  const originalError = console.error;
  console.error = (...args: unknown[]) => {
    logged.push(
      args.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join(" "),
    );
  };
  try {
    const stop = startGoogleCredentialLifecycleScheduler({
      intervalMs: 60_000,
      sweep: async () => {
        const error = Object.assign(new Error(canary), { code: "ECONNRESET" });
        throw error;
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    await stop();
  } finally {
    console.error = originalError;
  }
  expect(logged.join("\n")).toContain("ECONNRESET");
  expect(logged.join("\n")).not.toContain(canary);
});
