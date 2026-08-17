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

test("lease scheduler advances its tenant cursor and waits for an in-flight sweep on stop", async () => {
  const cursors: Array<string | undefined> = [];
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
    sweep: async (cursor) => {
      cursors.push(cursor);
      if (cursors.length === 1)
        return { unknown: 0, revoked: 0, attention: 0, expired: 0, nextTenantId: "tenant-100" };
      entered();
      await blocked;
      return { unknown: 0, revoked: 0, attention: 0, expired: 0, nextTenantId: null };
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
  expect(cursors).toEqual([undefined, "tenant-100"]);
});
