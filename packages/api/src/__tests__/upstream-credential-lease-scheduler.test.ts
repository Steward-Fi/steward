import { expect, test } from "bun:test";
import {
  getUpstreamCredentialLeaseSchedulerHealth,
  startUpstreamCredentialLeaseScheduler,
} from "../services/upstream-credential-lease-scheduler";

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
  let durableMutations = 0;
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
      durableMutations += 1;
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
  expect(durableMutations).toBe(1);
  await new Promise((resolve) => setTimeout(resolve, 10));
  expect(durableMutations).toBe(1);
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

test("lease scheduler health fails closed after a sweep error and recovers on success", async () => {
  let calls = 0;
  let firstAttempt!: () => void;
  const attempted = new Promise<void>((resolve) => {
    firstAttempt = resolve;
  });
  let secondAttempt!: () => void;
  const retried = new Promise<void>((resolve) => {
    secondAttempt = resolve;
  });
  const stop = await startUpstreamCredentialLeaseScheduler({
    intervalMs: 5,
    sweep: async () => {
      calls += 1;
      if (calls === 1) {
        firstAttempt();
        throw new Error("provider unavailable");
      }
      secondAttempt();
      return { unknown: 0, revoked: 0, attention: 0, expired: 0 };
    },
  });
  await attempted;
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(getUpstreamCredentialLeaseSchedulerHealth().ok).toBe(false);
  expect(getUpstreamCredentialLeaseSchedulerHealth().lastError).toBe(
    "credential lease recovery failed",
  );
  expect(getUpstreamCredentialLeaseSchedulerHealth().lastError).not.toContain(
    "provider unavailable",
  );
  await retried;
  await new Promise((resolve) => setTimeout(resolve, 1));
  expect(getUpstreamCredentialLeaseSchedulerHealth().ok).toBe(true);
  expect(getUpstreamCredentialLeaseSchedulerHealth().lastError).toBeNull();
  await stop();
});

test("lease scheduler latches unresolved recovery outcomes until restart", async () => {
  let calls = 0;
  let completedCleanPass!: () => void;
  const cleanPass = new Promise<void>((resolve) => {
    completedCleanPass = resolve;
  });
  const stop = await startUpstreamCredentialLeaseScheduler({
    intervalMs: 5,
    sweep: async () => {
      calls += 1;
      if (calls === 1) {
        return { unknown: 1, revoked: 0, attention: 1, expired: 0 };
      }
      completedCleanPass();
      return { unknown: 0, revoked: 0, attention: 0, expired: 0 };
    },
  });
  await cleanPass;
  expect(getUpstreamCredentialLeaseSchedulerHealth().ok).toBe(false);
  expect(getUpstreamCredentialLeaseSchedulerHealth().lastError).toContain(
    "left 2 lease(s) unresolved",
  );
  await stop();
});
