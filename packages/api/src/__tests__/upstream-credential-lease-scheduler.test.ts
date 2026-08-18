import { expect, test } from "bun:test";
import { startUpstreamCredentialLeaseScheduler } from "../services/upstream-credential-lease-scheduler";

test("lease scheduler runs at startup, repeats, and stops cleanly", async () => {
  let calls = 0;
  let notify!: () => void;
  const repeated = new Promise<void>((resolve) => {
    notify = resolve;
  });
  const stop = await startUpstreamCredentialLeaseScheduler({
    intervalMs: 5,
    sweep: async () => {
      calls += 1;
      if (calls >= 2) notify();
      return { unknown: 0, revoked: calls === 1 ? 1 : 0, attention: 0, expired: 0 };
    },
  });
  await repeated;
  await stop();
  const stoppedAt = calls;
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(stoppedAt).toBeGreaterThanOrEqual(2);
  expect(calls).toBe(stoppedAt);
});

test("lease scheduler immediately drains remaining work and waits for an in-flight sweep on stop", async () => {
  let calls = 0;
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  let entered!: () => void;
  const secondEntered = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const stop = await startUpstreamCredentialLeaseScheduler({
    intervalMs: 5,
    sweep: async () => {
      calls += 1;
      if (calls === 1) return { unknown: 0, revoked: 0, attention: 0, expired: 0, remaining: true };
      entered();
      await blocked;
      return { unknown: 0, revoked: 0, attention: 0, expired: 0, remaining: false };
    },
  });
  await secondEntered;
  let stopped = false;
  const stopping = stop().then(() => {
    stopped = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 5));
  expect(stopped).toBe(false);
  release();
  await stopping;
  expect(calls).toBe(2);
});

test("lease scheduler rejects a production interval that cannot honor the ACK deadline", async () => {
  const previous = process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS;
  process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS = "30000";
  try {
    await expect(
      startUpstreamCredentialLeaseScheduler({
        sweep: async () => ({ unknown: 0, revoked: 0, attention: 0, expired: 0 }),
      }),
    ).rejects.toThrow("must be between 1000 and 15000");
  } finally {
    if (previous === undefined) delete process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS;
    else process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS = previous;
  }
});
